import ipaddress
from contextlib import closing
import json
import os
from pathlib import Path
import random
import socket
import sqlite3
import struct
import tempfile
import threading
import time
import unittest
from unittest import mock

import dns.message
import dns.rrset

from bgp_antifilter import bgp_feed, dns_proxy, dns_routes, live_routes


def policy(generation=1):
    return {"generation": generation, "routes": ["93.184.216.0/24"], "exclude_routes": [],
            "include_domains": ["example.test"], "exclude_domains": ["direct.example.test"]}


def wait_for(predicate, timeout=4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("Timed out waiting for condition")


class Publisher:
    def __init__(self):
        self.routes = set()
        self.changes = []
        self.block = False
        self.entered = threading.Event()
        self.release = threading.Event()

    def update(self, added, removed):
        if self.block:
            self.entered.set()
            self.release.wait(4)
        self.routes.difference_update(removed)
        self.routes.update(added)
        self.changes.append((set(added), set(removed)))

    def ready(self):
        return True

    def check_running(self):
        pass

    def close(self):
        self.release.set()


class IncrementalIndexTests(unittest.TestCase):
    def test_one_ip_changes_only_its_covering_prefix(self):
        config = policy()
        config["routes"].append("8.8.0.0/16")
        index = live_routes.IncrementalRoutes(config)
        with mock.patch.object(index.cover, "routes", side_effect=AssertionError("full scan")):
            index.change("1.1.1.1", True, False)
            added, removed = index.delta()
            self.assertEqual((added, removed), ({"1.1.1.1/32"}, set()))
            index.change("93.184.216.34", False, True)
            added, removed = index.delta()
            self.assertEqual(removed, {"93.184.216.0/24"})
            self.assertLessEqual(len(added), 8)
            self.assertNotIn("8.8.0.0/16", added | removed)
            index.change("93.184.216.34", False, False)
            added, removed = index.delta()
            self.assertEqual(added, {"93.184.216.0/24"})

    def test_random_live_changes_match_full_reference_without_full_rebuild(self):
        config = policy()
        index = live_routes.IncrementalRoutes(config)
        includes, excludes = set(), set()
        rng = random.Random(1179)
        for _ in range(200):
            value = f"93.184.216.{rng.randrange(256)}" if rng.randrange(2) else f"1.1.1.{rng.randrange(1, 255)}"
            for target in (includes, excludes):
                if rng.randrange(2):
                    target.add(value)
                else:
                    target.discard(value)
            index.change(value, value in includes, value in excludes)
            leases = {"example.test": dict.fromkeys(includes, 100), "direct.example.test": dict.fromkeys(excludes, 100)}
            reference = dns_routes.compose(config, leases, 1)
            expected = set(ipaddress.collapse_addresses(ipaddress.IPv4Network(line.split()[1]) for line in reference.splitlines()))
            actual = set(ipaddress.collapse_addresses(ipaddress.IPv4Network(value) for value in index.cover.routes()))
            self.assertEqual(actual, expected)


class LiveWorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.environment = mock.patch.dict(os.environ, {"DNS_ROUTE_GRACE": "0", "HEALTHCHECK_REQUIRE_BGP": "0"})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.publisher = Publisher()
        self.worker = live_routes.LiveRoutes(self.root, publisher=self.publisher, batch_seconds=0.005)
        self.addCleanup(self.worker.close)
        self.install(policy())
        self.worker.flush()

    def install(self, config):
        path = self.root / "candidate.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        live_routes.install_policy(path, self.root, timeout=3)

    def advertised(self, value):
        return any(ipaddress.IPv4Address(value) in ipaddress.IPv4Network(route) for route in self.publisher.routes)

    def test_new_ip_uses_delta_without_rewriting_route_file_or_scanning_rib(self):
        stamp = (self.root / "routes.conf").stat().st_mtime_ns
        self.publisher.changes.clear()
        with mock.patch.object(self.worker.index.cover, "routes", side_effect=AssertionError("full scan")):
            self.worker.observe("cdn.example.test", [("1.1.1.1", 60)])
            self.worker.flush()
            self.worker.observe("cdn.example.test", [("1.1.1.1", 60)])
            self.worker.flush()
        self.assertEqual(self.publisher.changes, [({"1.1.1.1/32"}, set())])
        self.assertEqual((self.root / "routes.conf").stat().st_mtime_ns, stamp)

    def test_dns_reply_is_available_while_route_publication_is_blocked(self):
        self.publisher.block = True
        try:
            self.worker.observe("cdn.example.test", [("1.1.1.1", 60)])
            self.assertTrue(self.publisher.entered.wait(1))
            proxy = dns_proxy.Proxy(self.worker, "127.0.0.1")
            response = dns.message.make_response(dns.message.make_query("cdn.example.test", "A"))
            response.answer = [dns.rrset.from_text("cdn.example.test.", 60, "IN", "A", "1.1.1.2")]
            proxy.exchange = lambda *args, **kwargs: response
            result = []
            thread = threading.Thread(target=lambda: result.append(proxy.handle(dns.message.make_query("cdn.example.test", "A").to_wire(), "127.0.0.1")))
            thread.start()
            thread.join(timeout=0.5)
            self.assertFalse(thread.is_alive(), "DNS waited for the route worker")
            self.assertEqual(dns.message.from_wire(result[0]).answer[0][0].address, "1.1.1.2")
            self.assertNotIn("1.1.1.2/32", self.publisher.routes)
        finally:
            self.publisher.release.set()
        self.worker.flush()
        self.assertIn("1.1.1.2/32", self.publisher.routes)

    def test_full_update_merges_observed_ips_into_snapshot_and_bgp(self):
        self.worker.observe("cdn.example.test", [("1.1.1.1", 60)])
        self.worker.flush()
        candidate = policy(2)
        candidate["routes"] = ["198.51.100.0/24"]
        self.install(candidate)
        self.assertIn("1.1.1.1/32", self.publisher.routes)
        self.assertNotIn("93.184.216.0/24", self.publisher.routes)
        self.assertIn("1.1.1.1/32", (self.root / "routes.conf").read_text())
        self.assertEqual((self.root / "routes.conf").read_bytes(), (self.root / "routes.last-good.conf").read_bytes())

    def test_restart_restores_sqlite_ips_and_separate_alias_scope(self):
        self.worker.observe("cdn.example.test", [("1.1.1.1", 60)], targets=[("edge.other.test", 60)])
        self.worker.flush()
        self.worker.close()
        other = Publisher()
        restarted = live_routes.LiveRoutes(self.root, publisher=other, batch_seconds=0.005)
        self.addCleanup(restarted.close)
        restarted.flush()
        restarted.observe("edge.other.test", [("1.0.0.1", 60)])
        restarted.flush()
        self.assertIn("1.1.1.1/32", other.routes)
        self.assertIn("1.0.0.1/32", other.routes)

    def test_rejected_full_policy_keeps_committed_state(self):
        before = set(self.publisher.routes)
        candidate = policy(2)
        candidate["routes"] = []
        with self.assertRaisesRegex(RuntimeError, "empty"):
            self.install(candidate)
        self.assertEqual(self.worker.policy["generation"], 1)
        self.assertEqual(self.publisher.routes, before)
        with closing(sqlite3.connect(self.root / "dns-cache.sqlite3")) as db:
            stored = json.loads(db.execute("SELECT value FROM metadata WHERE key='policy'").fetchone()[0])
        self.assertEqual(stored["generation"], 1)

    def test_expiry_and_shared_ip_exclusion_are_incremental(self):
        self.worker.observe("cdn.example.test", [("93.184.216.34", 60)])
        self.worker.observe("direct.example.test", [("93.184.216.34", 1)])
        self.worker.flush()
        self.assertFalse(self.advertised("93.184.216.34"))
        self.assertTrue(self.advertised("93.184.216.35"))
        wait_for(lambda: self.advertised("93.184.216.34"), timeout=3)

    def test_queue_capacity_is_nonblocking_and_marks_readiness_degraded(self):
        self.publisher.block = True
        try:
            self.worker.observe("example.test", [("1.1.1.1", 60)])
            self.assertTrue(self.publisher.entered.wait(1))
            accepted = [self.worker.observe("example.test", [("1.1.1.2", 60)]) for _ in range(1100)]
            self.assertLessEqual(sum(accepted), 1024)
            self.assertGreater(self.worker.dropped, 0)
            with self.assertRaisesRegex(RuntimeError, "overloaded"):
                self.worker.refresh()
        finally:
            self.publisher.release.set()
        self.worker.flush()

    def test_readiness_never_configures_bird(self):
        def bird(*args):
            self.assertNotIn("configure", args)
            return "BIRD up and running" if args == ("show", "status") else "Established"
        with mock.patch.object(dns_routes.RouteManager, "bird", side_effect=bird):
            self.worker.check_bird()


def decode_prefixes(data):
    prefixes = []
    offset = 0
    while offset < len(data):
        length = data[offset]
        size = (length + 7) // 8
        raw = data[offset + 1:offset + 1 + size].ljust(4, b"\0")
        prefixes.append(str(ipaddress.IPv4Network((socket.inet_ntoa(raw), length))))
        offset += size + 1
    return prefixes


class BGPWireTests(unittest.TestCase):
    def test_update_and_withdraw_frames_round_trip_and_respect_size(self):
        values = [f"11.{i // 256}.{i % 256}.1/32" for i in range(3000)]
        for withdrawn in (False, True):
            actual = []
            for packet in bgp_feed.updates(values, "127.0.0.2", withdraw=withdrawn):
                self.assertLessEqual(len(packet), 4096)
                self.assertEqual(packet[:16], bgp_feed.MARKER)
                self.assertEqual(struct.unpack("!HB", packet[16:19]), (len(packet), 2))
                payload = packet[19:]
                withdrawn_length = struct.unpack("!H", payload[:2])[0]
                if withdrawn:
                    actual.extend(decode_prefixes(payload[2:2 + withdrawn_length]))
                else:
                    attrs_length = struct.unpack("!H", payload[2:4])[0]
                    actual.extend(decode_prefixes(payload[4 + attrs_length:]))
            self.assertEqual(actual, values)

    def test_open_negotiates_four_octet_asn_and_rejects_wrong_peer(self):
        packet = bgp_feed.open_message(4200000001, "127.0.0.1")
        self.assertEqual(bgp_feed.parse_open(packet[19:], 4200000001, "127.0.0.2"), 30)
        with self.assertRaisesRegex(RuntimeError, "ASN"):
            bgp_feed.parse_open(packet[19:], 64500, "127.0.0.2")
        with self.assertRaisesRegex(ValueError, "loopback"):
            bgp_feed.BGPFeed(64500, host="192.168.88.1")

    def test_local_bgp_session_sends_deltas_and_replays_after_disconnect(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(0.1)
        stop = threading.Event()
        routes = set()
        connections = []
        received = []
        errors = []

        def peer():
            while not stop.is_set():
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                connections.append(connection)
                routes.clear()
                with connection:
                    connection.settimeout(3)
                    try:
                        kind, payload = bgp_feed.receive_message(connection)
                        self.assertEqual(kind, 1)
                        bgp_feed.parse_open(payload, 64500, "127.0.0.1")
                        connection.sendall(bgp_feed.open_message(64500, "127.0.0.1"))
                        kind, _ = bgp_feed.receive_message(connection)
                        self.assertEqual(kind, 4)
                        connection.sendall(bgp_feed.message(4))
                        while not stop.is_set():
                            kind, payload = bgp_feed.receive_message(connection)
                            if kind == 2:
                                withdrawn = struct.unpack("!H", payload[:2])[0]
                                removed = decode_prefixes(payload[2:2 + withdrawn])
                                attrs = struct.unpack("!H", payload[2 + withdrawn:4 + withdrawn])[0]
                                added = decode_prefixes(payload[4 + withdrawn + attrs:])
                                received.append((set(added), set(removed)))
                                routes.difference_update(removed)
                                routes.update(added)
                    except (OSError, ConnectionError):
                        pass
                    except Exception as exc:
                        errors.append(exc)

        thread = threading.Thread(target=peer, daemon=True)
        thread.start()
        feed = bgp_feed.BGPFeed(64500, port=listener.getsockname()[1])
        try:
            feed.update({"93.184.216.0/24"}, set())
            wait_for(lambda: "93.184.216.0/24" in routes and feed.ready())
            count = len(received)
            feed.update({"1.1.1.1/32"}, set())
            wait_for(lambda: "1.1.1.1/32" in routes)
            self.assertEqual([change for change in received[count:] if change[0] or change[1]], [({"1.1.1.1/32"}, set())])
            feed.update(set(), {"1.1.1.1/32"})
            wait_for(lambda: "1.1.1.1/32" not in routes)
            connections[-1].shutdown(socket.SHUT_RDWR)
            wait_for(lambda: len(connections) >= 2 and "93.184.216.0/24" in routes and feed.ready())
            self.assertFalse(errors)
        finally:
            stop.set()
            feed.close()
            listener.close()
            thread.join(timeout=4)
