import contextlib
import errno
import ipaddress
import io
import json
import os
import random
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rrset

from bgp_antifilter import dns_proxy, dns_routes, update_routes


def policy(generation=1):
    return {"generation": generation, "routes": ["93.184.216.0/24"], "exclude_routes": [],
            "include_domains": ["example.test"], "exclude_domains": ["direct.example.test"]}


def response(name="cdn.example.test", address="1.1.1.1", ttl=60):
    message = dns.message.make_response(dns.message.make_query(name, "A"))
    message.answer.append(dns.rrset.from_text(name.rstrip(".") + ".", ttl, "IN", "A", address))
    return message


class RouteManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {"DNS_ROUTE_GRACE": "0"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.bird = mock.Mock(return_value="Reconfigured")
        self.manager = dns_routes.RouteManager(self.root, bird_command=self.bird)
        self.manager.install(policy(), now=100)

    def advertised(self, ip):
        return any(ipaddress.ip_address(ip) in ipaddress.ip_network(line.split()[1])
                   for line in self.manager.routes.read_text().splitlines())

    def test_changed_answers_keep_each_address_until_its_ttl(self):
        self.manager.observe("cdn.example.test", [("1.1.1.1", 10)], now=100)
        self.manager.observe("cdn.example.test", [("1.1.1.2", 30)], now=105)
        self.assertTrue(self.advertised("1.1.1.1"))
        self.assertTrue(self.advertised("1.1.1.2"))
        self.manager.refresh(now=111)
        self.assertFalse(self.advertised("1.1.1.1"))
        self.assertTrue(self.advertised("1.1.1.2"))
        self.manager.refresh(now=136)
        self.assertFalse(self.advertised("1.1.1.2"))

    def test_exclusion_subtracts_observed_address_from_larger_prefix(self):
        self.manager.observe("direct.example.test", [("93.184.216.34", 10)], now=100)
        self.assertFalse(self.advertised("93.184.216.34"))
        self.assertTrue(self.advertised("93.184.216.35"))
        self.manager.refresh(now=111)
        self.assertTrue(self.advertised("93.184.216.34"))

    def test_static_exclusion_wins_over_observed_include(self):
        candidate = policy(2)
        candidate["exclude_routes"] = ["1.1.1.1/32"]
        self.manager.install(candidate, now=100)
        self.manager.observe("example.test", [("1.1.1.1", 30)], now=100)
        self.assertFalse(self.advertised("1.1.1.1"))

    def test_reload_keeps_live_addresses_and_reclassifies_removed_domains(self):
        self.manager.observe("example.test", [("1.1.1.1", 30)], now=100)
        other = dns_routes.RouteManager(self.root, bird_command=self.bird)
        other.install(policy(2), now=101)
        self.assertTrue(self.advertised("1.1.1.1"))
        candidate = policy(3)
        candidate["include_domains"] = []
        other.install(candidate, now=102)
        self.assertFalse(self.advertised("1.1.1.1"))

    def test_restart_expires_stale_addresses(self):
        self.manager.observe("example.test", [("1.1.1.1", 1)], now=100)
        restarted = dns_routes.RouteManager(self.root, bird_command=self.bird)
        restarted.refresh(now=102)
        self.assertFalse(self.advertised("1.1.1.1"))

    def test_rejected_bird_configuration_restores_last_good(self):
        previous = self.manager.routes.read_text()
        self.bird.side_effect = [RuntimeError("rejected"), "Reconfigured"]
        with self.assertRaisesRegex(RuntimeError, "rejected"):
            self.manager.observe("example.test", [("1.1.1.1", 30)], now=100)
        self.assertEqual(self.manager.routes.read_text(), previous)
        self.assertEqual(self.manager.last_good.read_text(), previous)
        self.assertEqual(self.manager.leases(), {})

    def test_rejected_full_install_keeps_active_policy_and_live_routes(self):
        self.manager.observe("example.test", [("1.1.1.1", 30)], now=100)
        previous = self.manager.routes.read_text()
        self.bird.side_effect = [RuntimeError("rejected"), "Reconfigured"]
        candidate = policy(2)
        candidate["routes"] = ["8.8.8.0/24"]
        with self.assertRaisesRegex(RuntimeError, "rejected"):
            self.manager.install(candidate, now=101)
        self.assertEqual(self.manager.policy()["generation"], 1)
        self.assertEqual(self.manager.routes.read_text(), previous)

    def test_unselected_private_and_blocked_answers_never_add_routes(self):
        self.manager.observe("unrelated.test", [("1.1.1.1", 30)], now=100)
        self.manager.observe("example.test", [("0.0.0.0", 30), ("192.168.1.1", 30)], now=100)
        self.assertFalse(self.advertised("1.1.1.1"))
        self.assertFalse(self.advertised("192.168.1.1"))

    def test_ttl_renewal_does_not_reconfigure_bird(self):
        self.manager.observe("example.test", [("1.1.1.1", 30)], now=100)
        self.bird.reset_mock()
        self.manager.observe("example.test", [("1.1.1.1", 30)], now=101)
        self.bird.assert_not_called()

    def test_file_lock_serializes_independent_writers(self):
        other = dns_routes.RouteManager(self.root, bird_command=self.bird, lock_timeout=0.05)
        with self.manager.locked():
            with self.assertRaisesRegex(RuntimeError, "busy"):
                with other.locked():
                    pass
        with other.locked():
            pass

    def test_readiness_rejects_down_bgp_and_bird(self):
        self.bird.side_effect = ["Reconfigured", "BIRD up and running", "Idle"]
        with mock.patch.dict(os.environ, {"HEALTHCHECK_REQUIRE_BGP": "1"}):
            with self.assertRaisesRegex(RuntimeError, "BGP is not established"):
                self.manager.check_bird()
        self.bird.side_effect = ["Reconfigured", "unavailable"]
        with self.assertRaisesRegex(RuntimeError, "BIRD is not ready"):
            self.manager.check_bird()

    def test_refresh_recovers_uncommitted_route_file_after_writer_crash(self):
        self.manager.routes.write_text("    route 8.8.8.8/32 blackhole;\n")
        self.manager.refresh(now=101)
        self.assertFalse(self.advertised("8.8.8.8"))
        self.assertTrue(self.advertised("93.184.216.34"))

    def test_separate_alias_lookup_is_tracked_after_restart(self):
        self.manager.observe("cdn.example.test", [], targets=[("edge.other.test", 10)], now=100)
        restarted = dns_routes.RouteManager(self.root, bird_command=self.bird)
        restarted.observe("edge.other.test", [("1.1.1.1", 60)], now=105)
        self.assertTrue(self.advertised("1.1.1.1"))
        restarted.refresh(now=111)
        self.assertFalse(restarted.aliases())
        self.assertTrue(self.advertised("1.1.1.1"))
        restarted.refresh(now=166)
        self.assertFalse(self.advertised("1.1.1.1"))

    def test_expired_alias_and_removed_policy_do_not_route_unselected_domains(self):
        self.manager.observe("cdn.example.test", [], targets=[("edge.other.test", 10)], now=100)
        self.manager.observe("edge.other.test", [("1.1.1.1", 60)], now=111)
        self.assertFalse(self.advertised("1.1.1.1"))
        self.manager.observe("cdn.example.test", [], targets=[("edge.other.test", 60)], now=112)
        candidate = policy(2)
        candidate["include_domains"] = []
        self.manager.install(candidate, now=113)
        self.manager.observe("edge.other.test", [("1.1.1.1", 60)], now=114)
        self.assertFalse(self.advertised("1.1.1.1"))

    def test_separate_alias_lookup_preserves_exclusion_precedence(self):
        self.manager.observe("cdn.example.test", [], targets=[("edge.other.test", 60)], now=100)
        self.manager.observe("direct.example.test", [], targets=[("edge.other.test", 60)], now=100)
        self.manager.observe("edge.other.test", [("93.184.216.34", 60)], now=101)
        self.assertFalse(self.advertised("93.184.216.34"))
        self.assertTrue(self.advertised("93.184.216.35"))

    def test_alias_chain_learns_final_address_on_separate_query(self):
        self.manager.observe("cdn.example.test", [], targets=[("edge.other.test", 10)], now=100)
        self.manager.observe("edge.other.test", [], targets=[("last.other.test", 100)], now=101)
        self.manager.observe("last.other.test", [("1.1.1.1", 60)], now=120)
        self.assertTrue(self.advertised("1.1.1.1"))


class WireTests(unittest.TestCase):
    def setUp(self):
        self.manager = mock.Mock()
        self.proxy = dns_proxy.Proxy(self.manager, "127.0.0.1")
        self.proxy.exchange = mock.Mock(return_value=response())

    def test_route_is_applied_before_answer_is_returned(self):
        events = []
        self.manager.observe.side_effect = lambda *args: events.append("applied")
        answer = self.proxy.handle(dns.message.make_query("cdn.example.test", "A").to_wire(), "127.0.0.1")
        self.assertEqual(events, ["applied"])
        self.assertEqual(dns.message.from_wire(answer).answer[0][0].address, "1.1.1.1")

    def test_route_failure_does_not_delay_or_replace_valid_dns_answer(self):
        self.manager.observe.side_effect = RuntimeError("BIRD rejected")
        wire = self.proxy.handle(dns.message.make_query("cdn.example.test", "A").to_wire(), "127.0.0.1")
        answer = dns.message.from_wire(wire)
        self.assertEqual(answer.rcode(), dns.rcode.NOERROR)
        self.assertEqual(answer.answer[0][0].address, "1.1.1.1")

    def test_empty_route_timeout_reports_domain_budget_and_mode_without_relaxing_gate(self):
        self.proxy.sync = dns_proxy.SyncOptions("bgp", timeout=0.25, on_timeout="servfail")
        self.proxy.gate = mock.Mock()
        self.proxy.gate.observe.side_effect = TimeoutError()
        with self.assertLogs("dns-proxy", level="WARNING") as logs:
            wire = self.proxy.handle(dns.message.make_query("cdn.example.test", "A").to_wire(), "127.0.0.1")
        answer = dns.message.from_wire(wire)
        self.assertEqual(answer.rcode(), dns.rcode.SERVFAIL)
        self.assertEqual(answer.answer, [])
        self.assertIn("cdn.example.test (A)", logs.output[0])
        self.assertIn("TimeoutError: route synchronization exceeded 0.25s in bgp mode", logs.output[0])
        self.assertIn("TimeoutError", self.proxy.last_error)

    def test_empty_exception_uses_type_and_keeps_forward_mode(self):
        self.proxy.sync = dns_proxy.SyncOptions("bgp", on_timeout="forward")
        self.proxy.gate = mock.Mock()
        self.proxy.gate.observe.side_effect = RuntimeError()
        with self.assertLogs("dns-proxy", level="WARNING") as logs:
            wire = self.proxy.handle(dns.message.make_query("cdn.example.test", "A").to_wire(), "127.0.0.1")
        self.assertEqual(dns.message.from_wire(wire).rcode(), dns.rcode.NOERROR)
        self.assertIn("RuntimeError", logs.output[0])

    def test_upstream_failure_reports_domain_transport_and_ipv6_endpoint(self):
        self.proxy.upstream, self.proxy.port = "2001:db8::53", 5353
        self.proxy.exchange.side_effect = TimeoutError()
        for tcp, transport in ((False, "UDP (with TCP fallback)"), (True, "TCP")):
            with self.subTest(tcp=tcp), self.assertLogs("dns-proxy", level="WARNING") as logs:
                wire = self.proxy.handle(dns.message.make_query("cdn.example.test", "A").to_wire(), "127.0.0.1", tcp=tcp)
            self.assertEqual(dns.message.from_wire(wire).rcode(), dns.rcode.SERVFAIL)
            self.assertIn(f"{transport} query for cdn.example.test (A) to [2001:db8::53]:5353", logs.output[0])
            self.assertIn("TimeoutError: upstream DNS request exceeded 2s", logs.output[0])

    def test_cname_and_https_hints_are_learned_without_unrelated_glue(self):
        message = response()
        message.answer = [dns.rrset.from_text("cdn.example.test.", 20, "IN", "CNAME", "edge.test."),
                          dns.rrset.from_text("edge.test.", 60, "IN", "A", "1.1.1.2")]
        message.additional = [dns.rrset.from_text("unrelated.test.", 60, "IN", "A", "8.8.8.8")]
        # The client can cache the A RRset independently of the CNAME RRset.
        self.assertEqual(dns_proxy.answer_addresses(message), [("1.1.1.2", 60)])
        message = dns.message.make_response(dns.message.make_query("cdn.example.test", "HTTPS"))
        message.answer = [dns.rrset.from_text("cdn.example.test.", 60, "IN", "HTTPS", '1 . alpn="h2" ipv4hint="1.1.1.1,1.1.1.2"')]
        self.assertEqual(dns_proxy.answer_addresses(message), [("1.1.1.1", 60), ("1.1.1.2", 60)])

    def test_short_cname_does_not_expire_route_while_client_caches_address(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {"DNS_ROUTE_GRACE": "0"}):
            manager = dns_routes.RouteManager(directory, bird_command=mock.Mock(return_value="Reconfigured"))
            manager.install(policy(), now=100)
            message = response()
            message.answer = [dns.rrset.from_text("cdn.example.test.", 5, "IN", "CNAME", "edge.test."),
                              dns.rrset.from_text("edge.test.", 300, "IN", "A", "1.1.1.2")]
            manager.observe("cdn.example.test", dns_proxy.answer_addresses(message), now=100)
            manager.refresh(now=140)
            self.assertIn("1.1.1.2/32", manager.routes.read_text())

    def test_svcb_alias_does_not_shorten_target_address_ttl(self):
        message = dns.message.make_response(dns.message.make_query("cdn.example.test", "HTTPS"))
        message.answer = [dns.rrset.from_text("cdn.example.test.", 5, "IN", "HTTPS", "0 edge.test."),
                          dns.rrset.from_text("edge.test.", 120, "IN", "HTTPS", "1 . ipv4hint=1.1.1.2")]
        self.assertEqual(dns_proxy.answer_addresses(message), [("1.1.1.2", 120)])

    def test_svcb_alias_mode_ignores_ip_hints(self):
        message = dns.message.make_response(dns.message.make_query("cdn.example.test", "HTTPS"))
        rrset = dns.rrset.from_text("cdn.example.test.", 5, "IN", "HTTPS",
                                    "1 edge.test. ipv4hint=192.0.2.10")
        # dnspython rejects AliasMode parameters in text/wire parsing, but
        # its Rdata constructor permits them; extraction still ignores them.
        record = rrset[0].replace(priority=0)
        rrset.clear()
        rrset.add(record)
        message.answer = [rrset]
        self.assertEqual(dns_proxy.answer_addresses(message), [])
        self.assertEqual(dns_proxy.answer_targets(message), [("edge.test", 5)])

    def test_svcb_additional_alias_chain_reaches_only_linked_addresses(self):
        message = dns.message.make_response(dns.message.make_query("cdn.example.test", "HTTPS"))
        message.answer = [dns.rrset.from_text("cdn.example.test.", 5, "IN", "HTTPS", "0 edge.test.")]
        message.additional = [dns.rrset.from_text("edge.test.", 10, "IN", "HTTPS", "1 service.test."),
                              dns.rrset.from_text("service.test.", 30, "IN", "CNAME", "address.test."),
                              dns.rrset.from_text("address.test.", 120, "IN", "A", "192.0.2.10"),
                              dns.rrset.from_text("unrelated.test.", 120, "IN", "A", "192.0.2.11")]
        self.assertEqual(dns_proxy.answer_addresses(message), [("192.0.2.10", 120)])
        self.assertEqual(dict(dns_proxy.answer_targets(message)),
                         {"edge.test": 5, "service.test": 10, "address.test": 30})

    def test_cname_only_answer_saves_scope_for_next_query(self):
        message = response()
        message.answer = [dns.rrset.from_text("cdn.example.test.", 20, "IN", "CNAME", "edge.other.test.")]
        self.proxy.exchange.return_value = message
        answer = self.proxy.handle(dns.message.make_query("cdn.example.test", "A").to_wire(), "127.0.0.1")
        self.assertEqual(dns.message.from_wire(answer).rcode(), dns.rcode.NOERROR)
        self.manager.observe.assert_called_once_with("cdn.example.test", [], targets=[("edge.other.test", 20)])

    def test_unauthorized_client_and_zone_transfer_are_refused(self):
        for address, qtype in [("192.0.2.1", "A"), ("127.0.0.1", "AXFR")]:
            answer = self.proxy.handle(dns.message.make_query("example.test", qtype).to_wire(), address)
            self.assertEqual(dns.message.from_wire(answer).rcode(), dns.rcode.REFUSED)
        self.proxy.exchange.assert_not_called()

    def test_malformed_query_is_dropped(self):
        self.assertIsNone(self.proxy.handle(b"bad", "127.0.0.1"))

    def test_invalid_message_sizes_and_response_packets_are_dropped(self):
        for wire in (b"", b"x" * 65536, response().to_wire()):
            self.assertIsNone(self.proxy.handle(wire, "127.0.0.1"))
        self.proxy.exchange.assert_not_called()

    def test_upstream_wire_preserves_dnssec_flags_edns_and_unknown_records(self):
        query = dns.message.make_query("cdn.example.test", "TYPE65400", want_dnssec=True)
        query.flags |= dns.flags.CD
        message = dns.message.make_response(query)
        message.flags |= dns.flags.AD
        message.answer = [dns.rrset.from_text("cdn.example.test.", 60, "IN", "TYPE65400", r"\# 4 deadbeef")]
        original = message.to_wire()
        self.proxy.exchange.return_value = dns.message.from_wire(original)
        answer = self.proxy.handle(query.to_wire(), "127.0.0.1")
        self.assertEqual(answer, original)
        self.manager.observe.assert_not_called()

    def test_udp_response_respects_client_size_and_tcp_keeps_all_records(self):
        query = dns.message.make_query("cdn.example.test", "A")
        message = dns.message.make_response(query)
        message.answer = [dns.rrset.from_text("cdn.example.test.", 60, "IN", "A",
                                              *(f"192.0.2.{value}" for value in range(1, 80)))]
        original = message.to_wire()
        self.proxy.exchange.return_value = dns.message.from_wire(original)
        wire = self.proxy.handle(query.to_wire(), "127.0.0.1")
        self.assertLessEqual(len(wire), 512)
        self.assertTrue(dns.message.from_wire(wire).flags & dns.flags.TC)
        self.proxy.exchange.return_value = dns.message.from_wire(original)
        wire = self.proxy.handle(query.to_wire(), "127.0.0.1", tcp=True)
        self.assertEqual(len(dns.message.from_wire(wire).answer[0]), 79)

    def test_ipv6_upstream_and_acl_are_supported(self):
        proxy = dns_proxy.Proxy(self.manager, "2001:db8::53", allowed=["2001:db8:1::/64"])
        self.assertTrue(proxy.permits("2001:db8:1::1"))
        self.assertFalse(proxy.permits("2001:db8:2::1"))
        self.assertFalse(proxy.permits("invalid"))
        query = dns.message.make_query("example.test", "AAAA")
        with mock.patch.object(dns.query, "tcp", return_value=dns.message.make_response(query)) as exchange:
            proxy.exchange(query, tcp=True)
        self.assertEqual(exchange.call_args.args[1], "2001:db8::53")

    def test_valid_binary_dns_name_is_forwarded_in_bird_mode(self):
        from bgp_antifilter.domain_rules import DomainRules
        from bgp_antifilter.dns_sync import SyncOptions
        names = [dns.name.Name([b"\x80" * 30, b"example", b"test", b""]),
                 dns.name.Name([b"label.", b""])]
        for name in names:
            with self.subTest(name=name.to_text()):
                query = dns.message.make_query(name, "A")
                reply = dns.message.make_response(query)
                reply.answer = [dns.rrset.from_text(name, 60, "IN", "A", "192.0.2.10")]
                manager = mock.Mock()
                manager.selection_required.side_effect = DomainRules(["selected.test"]).matches
                proxy = dns_proxy.Proxy(manager, "127.0.0.1", sync=SyncOptions("bird"))
                proxy.exchange = mock.Mock(return_value=reply)
                forwarded = dns.message.from_wire(proxy.handle(query.to_wire(), "127.0.0.1"))
                self.assertEqual(forwarded.rcode(), dns.rcode.NOERROR)
                self.assertEqual(forwarded.question[0].name, name)
                self.assertEqual(forwarded.answer[0][0].address, "192.0.2.10")

    def test_nxdomain_is_forwarded_without_learning(self):
        self.proxy.exchange.return_value.set_rcode(dns.rcode.NXDOMAIN)
        answer = self.proxy.handle(dns.message.make_query("cdn.example.test", "A").to_wire(), "127.0.0.1")
        self.assertEqual(dns.message.from_wire(answer).rcode(), dns.rcode.NXDOMAIN)
        self.manager.observe.assert_not_called()


class SocketIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.servers = []
        self.threads = []
        self.addCleanup(self.close_servers)
        self.manager = mock.Mock()
        self.manager.bird_command.side_effect = lambda *args: "Established" if "protocols" in args else "BIRD up and running"
        upstream = dns_proxy.Proxy(mock.Mock(), "127.0.0.1")
        upstream.exchange = lambda request, tcp=False: self.upstream_answer(request, tcp)
        self.transports = []
        upstream_address = self.start_pair(upstream)
        self.proxy = dns_proxy.Proxy(self.manager, "127.0.0.1", port=upstream_address[1])
        self.address = self.start_pair(self.proxy)

    def upstream_answer(self, query, tcp):
        self.transports.append(tcp)
        answer = dns.message.make_response(query)
        answer.answer.append(dns.rrset.from_text(query.question[0].name, 60, "IN", "A", "1.1.1.1"))
        return answer

    def start_pair(self, proxy):
        # A port allocated for UDP may already be occupied by a TCP listener.
        for attempt in range(10):
            udp = dns_proxy.UDPServer(("127.0.0.1", 0), dns_proxy.UDPHandler, proxy)
            try:
                tcp = dns_proxy.TCPServer(udp.server_address, dns_proxy.TCPHandler, proxy)
            except OSError as exc:
                udp.server_close()
                if exc.errno != errno.EADDRINUSE or attempt == 9:
                    raise
            else:
                break
        for server in (udp, tcp):
            self.start_server(server)
        return udp.server_address

    def start_server(self, server):
        self.servers.append(server)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        self.threads.append(thread)

    def close_servers(self):
        for server in reversed(self.servers):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=3)

    def test_actual_udp_and_tcp_forwarding(self):
        for transport in (dns.query.udp, dns.query.tcp):
            query = dns.message.make_query("cdn.example.test", "A")
            answer = transport(query, self.address[0], port=self.address[1], timeout=2)
            self.assertEqual(answer.id, query.id)
            self.assertEqual(answer.answer[0][0].address, "1.1.1.1")
        self.assertEqual(self.transports, [False, True])
        self.assertEqual(self.manager.observe.call_count, 2)

    def test_truncated_upstream_udp_answer_retries_over_tcp(self):
        original = self.upstream_answer

        def answer(query, tcp):
            message = original(query, tcp)
            if not tcp:
                message.flags |= dns.flags.TC
                message.answer.clear()
            return message

        self.upstream_answer = answer
        query = dns.message.make_query("cdn.example.test", "A")
        reply = dns.query.udp(query, self.address[0], port=self.address[1], timeout=2)
        self.assertEqual(reply.answer[0][0].address, "1.1.1.1")
        self.assertEqual(self.transports, [False, True])

    def test_fragmented_and_pipelined_tcp_queries(self):
        queries = [dns.message.make_query(f"cdn{index}.example.test", "A") for index in range(2)]
        frames = [struct.pack("!H", len(query.to_wire())) + query.to_wire() for query in queries]
        with socket.create_connection(self.address, timeout=2) as connection:
            connection.sendall(frames[0][:1])
            connection.sendall(frames[0][1:10])
            connection.sendall(frames[0][10:] + frames[1])
            for query in queries:
                length = struct.unpack("!H", dns_proxy.receive_exact(connection, 2))[0]
                answer = dns.message.from_wire(dns_proxy.receive_exact(connection, length))
                self.assertEqual(answer.id, query.id)
                self.assertEqual(answer.answer[0][0].address, "1.1.1.1")

    def test_unauthorized_tcp_peer_is_closed_before_reading_a_frame(self):
        denied = dns_proxy.Proxy(mock.Mock(), "127.0.0.1", allowed=["192.0.2.0/24"])
        server = dns_proxy.TCPServer(("127.0.0.1", 0), dns_proxy.TCPHandler, denied)
        self.start_server(server)
        with socket.create_connection(server.server_address, timeout=1) as connection:
            # No frame is sent. Rejection must happen before a worker starts
            # waiting for the length prefix (the normal idle timeout is 5 s).
            self.assertEqual(connection.recv(1), b"")
        denied.manager.observe.assert_not_called()

    def test_health_checks_real_listeners_and_bird_failure(self):
        server = dns_proxy.ReadyServer(("127.0.0.1", 0), dns_proxy.ReadyHandler, self.proxy)
        server.dns_address = self.address
        server.check_lock = threading.Lock()
        self.start_server(server)
        url = f"http://127.0.0.1:{server.server_address[1]}/ready"
        with urllib.request.urlopen(url, timeout=3) as reply:
            self.assertEqual(json.load(reply), {"ready": True})
        self.assertEqual(self.transports, [False, True])
        self.manager.record_readiness.assert_called_with(True)
        self.manager.refresh.side_effect = RuntimeError("cannot update routes")
        with self.assertRaises(urllib.error.HTTPError) as failed:
            urllib.request.urlopen(url, timeout=3)
        self.assertEqual(failed.exception.code, 503)
        self.manager.record_readiness.assert_called_with(False, "cannot update routes")

    def readiness_url(self):
        server = dns_proxy.ReadyServer(("127.0.0.1", 0), dns_proxy.ReadyHandler, self.proxy)
        server.dns_address = self.address
        server.check_lock = threading.Lock()
        self.start_server(server)
        return f"http://127.0.0.1:{server.server_address[1]}/ready"

    def test_health_errors_identify_udp_tcp_domain_upstream_and_dns_result(self):
        url = self.readiness_url()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for fail_tcp in (False, True):
            for rcode in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN, dns.rcode.SERVFAIL, dns.rcode.REFUSED):
                with self.subTest(tcp=fail_tcp, rcode=rcode):
                    def answer(query, tcp):
                        message = dns.message.make_response(query)
                        if tcp == fail_tcp:
                            message.set_rcode(rcode)
                        else:
                            message.answer.append(dns.rrset.from_text(query.question[0].name, 60, "IN", "A", "192.0.2.1"))
                        return message
                    self.upstream_answer = answer
                    with mock.patch.dict(os.environ, {"DNS_HEALTH_DOMAIN": "health.example.test"}), \
                         self.assertLogs("dns-proxy", level="WARNING"), self.assertRaises(urllib.error.HTTPError) as failed:
                        opener.open(url, timeout=3)
                    self.assertEqual(failed.exception.code, 503)
                    payload = json.load(failed.exception)
                    self.assertFalse(payload["ready"])
                    self.assertIn(f"DNS {'TCP' if fail_tcp else 'UDP'} probe for health.example.test", payload["error"])
                    self.assertIn(f"via 127.0.0.1:{self.address[1]}", payload["error"])
                    self.assertIn(f"upstream 127.0.0.1:{self.proxy.port}", payload["error"])
                    self.assertIn("NOERROR without an IPv4 answer" if rcode == dns.rcode.NOERROR else dns.rcode.to_text(rcode), payload["error"])

    def test_health_requires_an_ipv4_answer_reachable_from_the_query(self):
        url = self.readiness_url()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for target in (None, "unrelated.example.test.", "alias.example.test."):
            with self.subTest(additional_address_for=target):
                def answer(query, tcp):
                    message = dns.message.make_response(query)
                    message.answer.append(dns.rrset.from_text(query.question[0].name, 60, "IN", "CNAME", "alias.example.test."))
                    if target:
                        message.additional.append(dns.rrset.from_text(target, 60, "IN", "A", "192.0.2.1"))
                    return message
                self.upstream_answer = answer
                if target == "alias.example.test.":
                    with opener.open(url, timeout=3) as reply:
                        self.assertEqual(json.load(reply), {"ready": True})
                    self.manager.record_readiness.assert_called_with(True)
                else:
                    with self.assertRaises(urllib.error.HTTPError) as failed:
                        opener.open(url, timeout=3)
                    self.assertEqual(failed.exception.code, 503)
                    payload = json.load(failed.exception)
                    self.assertIn("NOERROR without an IPv4 answer", payload["error"])
                    self.manager.record_readiness.assert_called_with(False, payload["error"])

    def test_health_connection_failure_reports_failed_listener_transport(self):
        url = self.readiness_url()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        # Keep UDP and both upstream listeners running; only the local TCP
        # listener disappears, so readiness must name the TCP path.
        for server in self.servers:
            if isinstance(server, dns_proxy.TCPServer) and server.server_address == self.address:
                server.shutdown()
                server.server_close()
                break
        with mock.patch.dict(os.environ, {"DNS_HEALTH_DOMAIN": "health.example.test"}), \
             self.assertLogs("dns-proxy", level="WARNING"), self.assertRaises(urllib.error.HTTPError) as failed:
            opener.open(url, timeout=3)
        payload = json.load(failed.exception)
        self.assertIn("DNS TCP probe for health.example.test", payload["error"])
        self.assertIn(f"via 127.0.0.1:{self.address[1]}", payload["error"])
        self.assertIn("failed:", payload["error"])

    def test_health_keeps_accepting_valid_loopback_dns_answer(self):
        def answer(query, tcp):
            message = dns.message.make_response(query)
            message.answer.append(dns.rrset.from_text(query.question[0].name, 60, "IN", "A", "127.0.0.1"))
            return message
        self.upstream_answer = answer
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(self.readiness_url(), timeout=3) as reply:
            self.assertEqual(json.load(reply), {"ready": True})

    def test_health_udp_and_tcp_share_one_total_deadline(self):
        original = self.upstream_answer
        def slow_answer(query, tcp):
            time.sleep(0.2)
            return original(query, tcp)
        self.upstream_answer = slow_answer
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        url = self.readiness_url()
        started = time.monotonic()
        with mock.patch.object(dns_proxy, "READINESS_TIMEOUT", 0.3), \
             self.assertLogs("dns-proxy", level="WARNING"), self.assertRaises(urllib.error.HTTPError) as failed:
            opener.open(url, timeout=1)
        elapsed = time.monotonic() - started
        payload = json.load(failed.exception)
        self.assertIn("DNS TCP probe", payload["error"])
        self.assertLess(elapsed, 0.7)
        self.manager.record_readiness.assert_called_with(False, payload["error"])

    def test_health_lock_wait_is_bounded_by_the_same_deadline(self):
        url = self.readiness_url()
        server = self.servers[-1]
        server.check_lock.acquire()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with mock.patch.object(dns_proxy, "READINESS_TIMEOUT", 0.05), \
                 self.assertLogs("dns-proxy", level="WARNING"), self.assertRaises(urllib.error.HTTPError) as failed:
                opener.open(url, timeout=1)
            payload = json.load(failed.exception)
            self.assertIn("still busy", payload["error"])
            self.manager.check_bird.assert_not_called()
            self.manager.record_readiness.assert_called_with(False, payload["error"])
        finally:
            server.check_lock.release()


class PolicyGenerationTests(unittest.TestCase):
    def test_full_generator_writes_policy_but_dry_run_does_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = {"CACHE_DIR": str(root / "cache"), "RUNTIME_FILE": str(root / "runtime.json"),
                        "DNS_PROXY_ENABLED": "1", "INCLUDE_GOOGLE_RANGES": "0"}
            collected = (False, [], [], ["93.184.216.0/24"], [], ["93.184.216.34/32"])

            def collect(*args, dns_policy=None):
                dns_policy.update(include_domains=["example.test"], exclude_domains=["direct.test"])
                return collected

            output = root / "routes.conf"
            args = ["--output", str(output), "--status", str(root / "status.json"), "--metrics", str(root / "metrics.prom")]
            with mock.patch.dict(os.environ, settings), mock.patch.object(update_routes, "collect_sources", side_effect=collect):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(update_routes.main(args + ["--dry-run"]), 0)
                    self.assertFalse(Path(str(output) + ".dns.json").exists())
                    self.assertEqual(update_routes.main(args), 0)
            snapshot = json.loads(Path(str(output) + ".dns.json").read_text())
            self.assertEqual(snapshot["exclude_routes"], ["93.184.216.34/32"])
            self.assertEqual(snapshot["include_domains"], ["example.test"])

class ComposeTests(unittest.TestCase):
    def test_overlapping_and_nested_exclusions_match_reference_builder(self):
        from bgp_antifilter.generate_routes import build_routes
        rng = random.Random(53)
        for _ in range(60):
            baseline = [ipaddress.ip_network(f"11.0.{rng.randrange(8)}.{rng.randrange(256)}/{rng.randrange(24, 33)}", strict=False)
                        for _ in range(20)]
            excluded = [ipaddress.ip_network(f"11.0.{rng.randrange(8)}.{rng.randrange(256)}/{rng.randrange(22, 33)}", strict=False)
                        for _ in range(15)]
            candidate = policy()
            candidate["routes"] = [str(net) for net in baseline]
            candidate["exclude_routes"] = [str(net) for net in excluded]
            leases = {"example.test": {"11.0.1.34": 100}, "direct.example.test": {"11.0.4.55": 100}}
            actual = dns_routes.compose(candidate, leases, 1)
            expected, _ = build_routes(baseline, excluded + [ipaddress.ip_network("11.0.4.55/32")],
                                       [ipaddress.ip_network("11.0.1.34/32")])
            self.assertEqual(actual, "".join(f"    route {net} blackhole;\n" for net in expected))


class ListenerLifecycleTests(unittest.TestCase):
    def test_dead_listener_exits_so_supervisor_can_restart(self):
        failed = mock.Mock()
        failed.serve_forever.return_value = None
        with self.assertRaisesRegex(RuntimeError, "listener stopped"):
            dns_proxy.serve([failed], mock.Mock(), interval=0.01)
        failed.server_close.assert_called_once()

    def test_slow_tcp_frame_has_one_deadline_across_all_reads(self):
        connection = mock.Mock()
        connection.recv.return_value = b"a"
        with mock.patch.object(dns_proxy.time, "monotonic", side_effect=[10, 16]):
            with self.assertRaises(TimeoutError):
                dns_proxy.receive_exact(connection, 2, deadline=15)
        connection.recv.assert_called_once_with(2)
        connection.settimeout.assert_called_once_with(5)

    def test_enabled_proxy_requires_upstream_without_starting_workers(self):
        with mock.patch.dict(os.environ, {"DNS_PROXY_ENABLED": "1", "DNS_PROXY_UPSTREAM": ""}), mock.patch.object(
                dns_proxy, "load_active_environment"), mock.patch.object(dns_proxy, "LiveRoutes") as manager:
            with self.assertRaisesRegex(ValueError, "DNS_PROXY_UPSTREAM"):
                dns_proxy.main()
        manager.assert_not_called()

    def test_self_upstream_is_rejected_before_starting_workers(self):
        settings = {"DNS_PROXY_ENABLED": "1", "DNS_PROXY_BIND": "127.0.0.1", "DNS_PROXY_PORT": "53",
                    "DNS_PROXY_UPSTREAM": "127.0.0.1", "DNS_PROXY_UPSTREAM_PORT": "53"}
        with mock.patch.dict(os.environ, settings), mock.patch.object(dns_proxy, "load_active_environment"), mock.patch.object(
                dns_proxy, "LiveRoutes") as manager:
            with self.assertRaisesRegex(ValueError, "different upstream"):
                dns_proxy.main()
        manager.assert_not_called()
