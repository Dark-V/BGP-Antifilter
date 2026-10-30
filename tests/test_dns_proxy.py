import contextlib
import importlib.util
import ipaddress
import io
import json
import os
from pathlib import Path
import socket
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
        self.manager.observe("example.test", [("0.0.0.0", 30), ("192.168.88.16", 30)], now=100)
        self.assertFalse(self.advertised("1.1.1.1"))
        self.assertFalse(self.advertised("192.168.88.16"))

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

    def test_apply_failure_returns_servfail_instead_of_new_ip(self):
        self.manager.observe.side_effect = RuntimeError("BIRD rejected")
        wire = self.proxy.handle(dns.message.make_query("cdn.example.test", "A").to_wire(), "127.0.0.1")
        answer = dns.message.from_wire(wire)
        self.assertEqual(answer.rcode(), dns.rcode.SERVFAIL)
        self.assertFalse(answer.answer)

    def test_cname_and_https_hints_are_learned_without_unrelated_glue(self):
        message = response()
        message.answer = [dns.rrset.from_text("cdn.example.test.", 20, "IN", "CNAME", "edge.test."),
                          dns.rrset.from_text("edge.test.", 60, "IN", "A", "1.1.1.2")]
        message.additional = [dns.rrset.from_text("unrelated.test.", 60, "IN", "A", "8.8.8.8")]
        self.assertEqual(dns_proxy.answer_addresses(message), [("1.1.1.2", 20)])
        message = dns.message.make_response(dns.message.make_query("cdn.example.test", "HTTPS"))
        message.answer = [dns.rrset.from_text("cdn.example.test.", 60, "IN", "HTTPS", '1 . alpn="h2" ipv4hint="1.1.1.1,1.1.1.2"')]
        self.assertEqual(dns_proxy.answer_addresses(message), [("1.1.1.1", 60), ("1.1.1.2", 60)])

    def test_unauthorized_client_and_zone_transfer_are_refused(self):
        for address, qtype in [("192.0.2.1", "A"), ("127.0.0.1", "AXFR")]:
            answer = self.proxy.handle(dns.message.make_query("example.test", qtype).to_wire(), address)
            self.assertEqual(dns.message.from_wire(answer).rcode(), dns.rcode.REFUSED)
        self.proxy.exchange.assert_not_called()

    def test_malformed_query_is_dropped(self):
        self.assertIsNone(self.proxy.handle(b"bad", "127.0.0.1"))

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
        udp = dns_proxy.UDPServer(("127.0.0.1", 0), dns_proxy.UDPHandler, proxy)
        tcp = dns_proxy.TCPServer(udp.server_address, dns_proxy.TCPHandler, proxy)
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

    def test_health_checks_real_listeners_and_bird_failure(self):
        server = dns_proxy.ThreadingHTTPServer(("127.0.0.1", 0), dns_proxy.ReadyHandler)
        server.proxy = self.proxy
        server.dns_address = self.address
        server.check_lock = threading.Lock()
        self.start_server(server)
        url = f"http://127.0.0.1:{server.server_address[1]}/ready"
        with urllib.request.urlopen(url, timeout=3) as reply:
            self.assertEqual(json.load(reply), {"ready": True})
        self.assertEqual(self.transports, [False, True])
        self.manager.refresh.side_effect = RuntimeError("cannot update routes")
        with self.assertRaises(urllib.error.HTTPError) as failed:
            urllib.request.urlopen(url, timeout=3)
        self.assertEqual(failed.exception.code, 503)


class PolicyGenerationTests(unittest.TestCase):
    def test_full_generator_writes_policy_but_dry_run_does_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = {"CACHE_DIR": str(root / "cache"), "UPDATE_RUNTIME_FILE": str(root / "runtime.json"),
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

    def test_mikrotik_renderer_validates_addresses_and_uses_single_upstream(self):
        spec = importlib.util.spec_from_file_location("mikrotik", Path(__file__).parents[1] / "scripts/mikrotik-dns-failover.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        text = module.render("192.168.88.17", "192.168.88.16")
        self.assertIn('url="http://192.168.88.17:8053/ready"', text)
        self.assertIn('/ip dns set servers=$proxyDns', text)
        self.assertNotIn("@PROXY@", text)
        self.assertIn('"\\"ready\\":true"', text)
        with self.assertRaises(ValueError):
            module.render('192.168.88.17; /system reboot', "192.168.88.16")
