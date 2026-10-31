from concurrent.futures import Future
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

import dns.message
import dns.rcode
import dns.rrset

from bgp_antifilter import bgp_feed, dns_proxy, dns_sync, live_routes
from tests.test_live_routes import Publisher, policy


class ReplyGateTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.publisher = Publisher()
        self.worker = live_routes.LiveRoutes(self.root, self.publisher, batch_seconds=0.005)
        self.addCleanup(self.worker.close)
        path = self.root / "candidate.json"
        path.write_text(json.dumps(policy()), encoding="utf-8")
        live_routes.install_policy(path, self.root, timeout=3)
        self.worker.flush()
        self.query = dns.message.make_query("cdn.example.test", "A")

    def proxy(self, mode="bgp", timeout=1, on_timeout="servfail"):
        proxy = dns_proxy.Proxy(self.worker, "127.0.0.1", sync=dns_sync.SyncOptions(mode, timeout, on_timeout))
        response = dns.message.make_response(self.query)
        response.answer = [dns.rrset.from_text("cdn.example.test.", 60, "IN", "A", "1.1.1.1")]
        response.additional = [dns.rrset.from_text("cdn.example.test.", 60, "IN", "A", "1.1.1.2")]
        proxy.exchange = lambda *args, **kwargs: response
        return proxy

    def reply(self, proxy):
        return dns.message.from_wire(proxy.handle(self.query.to_wire(), "127.0.0.1"))

    def test_sync_waits_for_publication_but_worker_keeps_accepting_later_work(self):
        entered, release = threading.Event(), threading.Event()
        revisions = []

        def wait_sent(revision, timeout):
            revisions.append(revision)
            entered.set()
            if not release.wait(timeout):
                raise TimeoutError("send blocked")

        self.publisher.wait_sent = wait_sent
        proxy = self.proxy()
        replies = []
        thread = threading.Thread(target=lambda: replies.append(self.reply(proxy)))
        thread.start()
        try:
            self.assertTrue(entered.wait(1))
            self.assertTrue(thread.is_alive())
            self.worker.observe("cdn.example.test", [("1.0.0.1", 60)])
            self.worker.flush()
            self.assertIn("1.0.0.1/32", self.publisher.routes)
            self.assertLess(revisions[0], self.publisher.checkpoint())
        finally:
            release.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(replies[0].rcode(), dns.rcode.NOERROR)

    def test_timeout_choices_remove_all_addresses_or_forward_original_answer(self):
        self.publisher.wait_sent = mock.Mock(side_effect=TimeoutError("BGP unavailable"))
        for action in ("servfail", "forward"):
            with self.subTest(action=action):
                reply = self.reply(self.proxy(on_timeout=action))
                if action == "servfail":
                    self.assertEqual(reply.rcode(), dns.rcode.SERVFAIL)
                    self.assertFalse(reply.answer)
                    self.assertFalse(reply.additional)
                else:
                    self.assertEqual(reply.rcode(), dns.rcode.NOERROR)
                    self.assertEqual(reply.answer[0][0].address, "1.1.1.1")
                    self.assertEqual(reply.additional[0][0].address, "1.1.1.2")
        self.assertIn("1.1.1.1/32", self.publisher.routes)

    def test_unselected_answers_do_not_wait_for_bgp(self):
        self.query = dns.message.make_query("unrelated.test", "A")
        proxy = self.proxy(mode="bird")
        self.publisher.wait_sent = mock.Mock(side_effect=AssertionError("unrelated BGP wait"))
        with mock.patch.object(proxy.gate, "_bird", side_effect=AssertionError("unrelated BIRD query")):
            self.assertEqual(self.reply(proxy).rcode(), dns.rcode.NOERROR)
        self.publisher.wait_sent.assert_not_called()

    def test_receipt_preserves_effective_shared_ip_exclusion(self):
        self.worker.observe("direct.example.test", [("1.1.1.1", 60)])
        ticket = self.worker.observe("cdn.example.test", [("1.1.1.1", 60), ("1.1.1.2", 60)], receipt=True)
        receipt = ticket.result(timeout=1)
        self.assertEqual(receipt.expected, {"1.1.1.1": False, "1.1.1.2": True})
        self.assertEqual(receipt.revision, self.publisher.checkpoint())

    def test_reply_wait_budget_extends_ip_and_alias_lifetime(self):
        with mock.patch.dict(os.environ, {"DNS_ROUTE_GRACE": "0"}):
            now = time.time()
            ticket = self.worker.observe("cdn.example.test", [("1.1.1.1", 1)], now=now,
                                         targets=[("edge.other.test", 1)], receipt=True, reply_budget=0.8)
            ticket.result(timeout=1)
        self.assertAlmostEqual(self.worker.leases["cdn.example.test"]["1.1.1.1"], now + 1.8)
        self.assertAlmostEqual(self.worker.aliases["edge.other.test"]["cdn.example.test"], now + 1.8)

    def test_queue_overload_fails_sync_without_waiting_or_disclosing_ip(self):
        self.publisher.block = True
        self.worker.observe("cdn.example.test", [("1.0.0.1", 60)])
        try:
            self.assertTrue(self.publisher.entered.wait(1))
            self.worker.queue.maxsize = 1
            self.worker.observe("cdn.example.test", [("1.0.0.2", 60)])
            start = time.monotonic()
            reply = self.reply(self.proxy())
            self.assertLess(time.monotonic() - start, 0.5)
            self.assertEqual(reply.rcode(), dns.rcode.SERVFAIL)
            self.assertFalse(reply.answer)
        finally:
            self.publisher.release.set()

    def test_sync_fails_closed_before_initial_policy(self):
        worker = live_routes.LiveRoutes(self.root / "empty", Publisher(), batch_seconds=0.005)
        self.addCleanup(worker.close)
        proxy = self.proxy()
        proxy.gate.manager = worker
        reply = self.reply(proxy)
        self.assertEqual(reply.rcode(), dns.rcode.SERVFAIL)
        self.assertFalse(reply.answer)


class BirdConfirmationTests(unittest.TestCase):
    def setUp(self):
        self.feed = mock.Mock(asn=64500, marker_token=123)
        self.manager = mock.Mock(publisher=self.feed)
        self.gate = dns_sync.ReplyGate(self.manager, dns_sync.SyncOptions("bird", 0.08))
        self.receipt = live_routes.ObservationReceipt(7, {"93.184.216.34": True, "1.1.1.1": False})
        self.header = "BIRD 2.0.12 ready.\n"

    def marker(self, revision=7, token=123):
        return self.header + f"198.18.0.1/32 blackhole [dns_live 12:00] * (100)\n BGP.large_community: (64500, {token}, {revision >> 32}) (64500, {token ^ 0xffffffff}, {revision & 0xffffffff})\n"

    def test_bird_waits_for_current_process_marker_then_checks_include_and_exclude(self):
        self.gate._bird = mock.Mock(side_effect=[self.marker(6), self.marker(8),
                                                self.header + "93.184.216.0/24 blackhole [dns_live 12:00] * (100)\n",
                                                self.header + "Network not found\n"])
        deadline = time.monotonic() + 1
        self.assertFalse(self.gate._confirmed(self.receipt, deadline))
        self.assertEqual(self.gate._bird.call_count, 1)
        self.assertTrue(self.gate._confirmed(self.receipt, deadline))
        self.gate._bird.assert_any_call(deadline, "show", "route", "for", "1.1.1.1", "primary")

    def test_stale_marker_after_restart_and_wrong_effective_routes_are_rejected(self):
        deadline = time.monotonic() + 1
        for marker in (self.marker(99, token=124), self.marker(6)):
            with mock.patch.object(self.gate, "_bird", return_value=marker):
                self.assertFalse(self.gate._confirmed(self.receipt, deadline))
        with mock.patch.object(self.gate, "_bird", side_effect=[self.marker(), self.header + "Network not found\n"]):
            self.assertFalse(self.gate._confirmed(self.receipt, deadline))
        with mock.patch.object(self.gate, "_bird", side_effect=[self.marker(),
                               self.header + "93.184.216.0/24 blackhole [dns_live 12:00] * (100)\n",
                               self.header + "1.1.1.1/32 blackhole [dns_live 12:00] * (100)\n"]):
            self.assertFalse(self.gate._confirmed(self.receipt, deadline))

    def test_marker_supports_64_bit_revisions(self):
        receipt = live_routes.ObservationReceipt((1 << 32) + 7, {})
        with mock.patch.object(self.gate, "_bird", return_value=self.marker((1 << 32) + 8)):
            self.assertTrue(self.gate._confirmed(receipt, time.monotonic() + 1))

    def test_one_deadline_bounds_worker_send_and_bird_wait(self):
        future = Future()
        future.set_result(self.receipt)
        self.manager.observe.return_value = future
        with mock.patch.dict(os.environ, {"HEALTHCHECK_REQUIRE_BGP": "0"}), mock.patch.object(
                self.gate, "_bird", return_value=self.marker(6)):
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                self.gate.observe("cdn.example.test", [("1.1.1.1", 60)])
            self.assertLess(time.monotonic() - started, 0.3)

    def test_bird_cli_errors_are_not_mistaken_for_absent_routes(self):
        for body in ("syntax error", "Access denied", "No such protocol"):
            result = subprocess.CompletedProcess([], 0, "0001 " + self.header + "9001 " + body, "")
            with mock.patch.object(dns_sync.subprocess, "run", return_value=result):
                with self.assertRaises(RuntimeError):
                    self.gate._bird(time.monotonic() + 1, "show", "route", "for", "1.1.1.1")

    def test_numeric_status_does_not_reject_valid_protocol_names_containing_error(self):
        result = subprocess.CompletedProcess([], 0, "0001 " + self.header + "2002-bgperror BGP master4 up Established\n", "")
        with mock.patch.object(dns_sync.subprocess, "run", return_value=result):
            self.assertIn("Established", self.gate._bird(time.monotonic() + 1, "show", "protocols", "bgperror"))

    def test_bird_cli_8001_exit_one_is_valid_route_absence_only(self):
        result = subprocess.CompletedProcess([], 1, "0001 BIRD 2.0.12 ready.\n0018 Access restricted\n8001 Network not found\n", "")
        with mock.patch.object(dns_sync.subprocess, "run", return_value=result):
            self.assertIn("Network not found", self.gate._bird(time.monotonic() + 1, "show", "route", "for", "1.1.1.1"))
            with self.assertRaises(subprocess.CalledProcessError):
                self.gate._bird(time.monotonic() + 1, "show", "protocols", "dns_live")
        result.stdout = "0001 BIRD 2.0.12 ready.\n9001 syntax error\n"
        with mock.patch.object(dns_sync.subprocess, "run", return_value=result):
            with self.assertRaises(subprocess.CalledProcessError):
                self.gate._bird(time.monotonic() + 1, "show", "route", "for", "1.1.1.1")


class FeedBarrierTests(unittest.TestCase):
    def test_marker_carries_revision_and_no_advertise(self):
        with mock.patch.object(threading.Thread, "start"):
            feed = bgp_feed.BGPFeed(64500, sync_marker=True)
        connection = mock.Mock()
        feed._send_marker(connection, (1 << 32) + 7)
        packet = connection.sendall.call_args.args[0]
        self.assertIn(b"\xc0\x08\x04\xff\xff\xff\x02", packet)
        self.assertTrue(packet.endswith(bgp_feed.encode_prefix(bgp_feed.SYNC_PREFIX)))
        with self.assertRaisesRegex(ValueError, "reserved"):
            feed.update({bgp_feed.SYNC_PREFIX}, set())

    def test_barrier_finishes_with_newer_work_still_pending(self):
        with mock.patch.object(threading.Thread, "start"):
            feed = bgp_feed.BGPFeed(64500)
        feed.update({"93.184.216.0/24"}, set())
        connection = mock.Mock()
        queued = []
        rounds = []

        def send(packet):
            if packet == bgp_feed.message(2, b"\0\0\0\0"):
                feed.update({str(ipaddress.IPv4Network((int(ipaddress.IPv4Address("44.0.0.0")) + i, 32))) for i in range(1024)}, set())
                queued.append(feed.checkpoint())

        def select(*args):
            rounds.append(feed.sent_revision)
            feed.update({f"8.8.8.{len(rounds)}/32"}, set())
            if len(rounds) == 1:
                with self.assertRaises(TimeoutError):
                    feed.wait_sent(queued[0], 0.01)
            else:
                feed.wait_sent(queued[0], 0.01)
                self.assertFalse(feed.ready(), "Newer updates must still be pending")
                feed.stop.set()
            return [], [], []

        connection.sendall.side_effect = send
        with mock.patch.object(bgp_feed, "receive_message", side_effect=[
                (1, bgp_feed.open_message(64500, "127.0.0.1")[19:]), (4, b"")]), mock.patch.object(
                bgp_feed.select, "select", side_effect=select):
            feed._session(connection)
        self.assertEqual(len(rounds), 2)

    def test_invalid_sync_settings_fail_at_startup(self):
        for kwargs in ({"mode": "invalid"}, {"on_timeout": "ignore"}, {"timeout": 0},
                       {"timeout": float("nan")}, {"timeout": float("inf")}, {"timeout": 11}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                dns_sync.SyncOptions(**kwargs)
