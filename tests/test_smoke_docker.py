import json
import http.cookiejar
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
import socket
import urllib.error
import urllib.request
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import dns.message
import dns.query
import dns.rcode
import dns.rrset
from bgp_antifilter import dns_proxy, update_routes


class RouteSourceServer(ThreadingHTTPServer):
    def __init__(self, server_address, request_handler_class, state):
        super().__init__(server_address, request_handler_class)
        self.state = state


class RouteSourceHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/routes.txt":
            self.send_error(404)
            return

        time.sleep(self.server.state["delay"])
        body = self.server.state["body"].encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


@unittest.skipUnless(
    os.environ.get("RUN_DOCKER_SMOKE") == "1"
    and sys.platform.startswith("linux")
    and shutil.which("docker"),
    "Docker smoke test requires RUN_DOCKER_SMOKE=1 on Linux with docker installed",
)
class DockerSmokeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.generated_dir = self.root / "generated"
        self.config_dir = self.generated_dir / "config"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        for name in ("domain-list-urls.txt", "include-asns.txt", "include-domains.txt", "exclude-domains.txt"):
            (self.config_dir / name).write_text("", encoding="utf-8")

        self.repo_root = Path(__file__).resolve().parents[1]
        self.compose_file = self.root / "docker-compose.smoke.yml"
        self.project_name = f"bgp-antifilter-smoke-{os.getpid()}-{int(time.time())}"
        self.server_state = {"body": "192.0.2.0/24\n", "delay": 0}
        self.server = RouteSourceServer(("127.0.0.1", 0), RouteSourceHandler, self.server_state)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        self.port = self.server.server_address[1]
        (self.config_dir / "lists.txt").write_text(
            f"http://127.0.0.1:{self.port}/routes.txt\n",
            encoding="utf-8",
        )
        self.compose_file.write_text(self.compose_yaml(), encoding="utf-8")

    def tearDown(self):
        try:
            self.compose("down", "--remove-orphans", check=False)
            self.restore_generated_permissions()
        finally:
            self.server.shutdown()
            self.server.server_close()
            self.server_thread.join(timeout=5)
            self.tmp.cleanup()

    def compose_yaml(self):
        generated = "./generated" if getattr(self, "relative_mounts", False) else self.generated_dir.as_posix()
        template = (self.repo_root / "deploy" / "bird.conf.template").as_posix()
        context = self.repo_root.as_posix()
        return textwrap.dedent(
            f"""
            services:
              bird:
                image: "bgp-antifilter-bird:smoke"
                build:
                  context: "{context}"
                  dockerfile: deploy/Dockerfile
                network_mode: host
                restart: "no"
                volumes:
                  - "{template}:/etc/bird/bird.conf.template:ro"
                  - "{generated}:/etc/bird/generated"
                  - bird-run:/run/bird
                environment:
                  MY_AS: "64500"
                  MT_AS: "65455"
                  MT_IP: "192.168.55.1"
                  BIRD_IP: "192.168.55.5"
                  ROUTER_ID: "192.168.55.5"
                  BGP_COMMUNITY: "65432,500"
                  LISTS_FILE: /etc/bird/generated/config/lists.txt
                  DOMAIN_LIST_URLS_FILE: /etc/bird/generated/config/domain-list-urls.txt
                  INCLUDE_ASNS_FILE: /etc/bird/generated/config/include-asns.txt
                  INCLUDE_DOMAINS_FILE: /etc/bird/generated/config/include-domains.txt
                  EXCLUDE_DOMAINS_FILE: /etc/bird/generated/config/exclude-domains.txt
                  INCLUDE_GOOGLE_RANGES: "0"
                  UPDATE_INTERVAL: "86400"
                  CACHE_MAX_AGE: "604800"
                  MIN_PREFIX_LENGTH: "8"
                  ALLOW_BROAD_ROUTES: "0"
                  UPDATE_LOCK_DIR: /etc/bird/generated/update.lock
                  HEALTHCHECK_REQUIRE_BGP: "0"
                  BGP_PROTOCOL: "mikrotik"
                  ADMIN_ENABLED: "0"
                  ADMIN_PORT: "18080"
                  DNS_PROXY_ENABLED: "{int(getattr(self, 'dns_enabled', False))}"
                  DNS_BGP_PORT: "{getattr(self, 'bgp_feed_port', 1179)}"
                  RUNTIME_FILE: /etc/bird/generated/runtime.json
                  CONTAINER_LOG_FILE: /etc/bird/generated/container.log
                  SETTINGS_FILE: /etc/bird/generated/settings.json
                  SETTINGS_ENV_FILE: /etc/bird/generated/settings.env
              dns-proxy:
                profiles: ["dns"]
                image: "bgp-antifilter-bird:smoke"
                entrypoint: ["/usr/bin/tini", "--", "python3", "-m", "bgp_antifilter.dns_proxy"]
                network_mode: host
                volumes:
                  - "{generated}:/etc/bird/generated"
                  - bird-run:/run/bird
                environment:
                  DNS_PROXY_ENABLED: "{int(getattr(self, 'dns_enabled', False))}"
                  MY_AS: "64500"
                  DNS_BGP_PORT: "{getattr(self, 'bgp_feed_port', 1179)}"
                  DNS_ROUTE_GRACE: "0"
                  DNS_SYNC_MODE: "{getattr(self, 'dns_sync_mode', 'async')}"
                  DNS_SYNC_TIMEOUT: "1"
                  DNS_SYNC_ON_TIMEOUT: "{getattr(self, 'dns_sync_on_timeout', 'servfail')}"
                  DNS_PROXY_BIND: "127.0.0.1"
                  DNS_PROXY_PORT: "{getattr(self, 'dns_port', 15353)}"
                  DNS_PROXY_HEALTH_PORT: "{getattr(self, 'dns_health_port', 18053)}"
                  ADGUARD_DNS: "127.0.0.1"
                  ADGUARD_DNS_PORT: "{getattr(self, 'upstream_port', 15354)}"
                  HEALTHCHECK_REQUIRE_BGP: "0"
                depends_on: [bird]
              admin:
                profiles: ["admin-test"]
                image: "bgp-antifilter-bird:smoke"
                entrypoint: ["/usr/bin/tini", "--", "/admin-server.py"]
                ports: ["127.0.0.1:{getattr(self, 'admin_port', 18081)}:18080"]
                volumes:
                  - "{generated}:/etc/bird/generated"
                  - bird-run:/run/bird
                  - "{context}:/workspace"
                  - "{self.compose_file.as_posix()}:/test-compose.yml:ro"
                  - /var/run/docker.sock:/var/run/docker.sock
                environment:
                  ADMIN_PASSWORD: smoke-password
                  ADMIN_PORT: "18080"
                  COMPOSE_FILE: /test-compose.yml
                  WORKSPACE_DIR: /workspace
                  MY_AS: "64500"
                  MT_AS: "65455"
                  MT_IP: "192.168.55.1"
                  BIRD_IP: "192.168.55.5"
                  ROUTER_ID: "192.168.55.5"
                  BGP_COMMUNITY: "65432,500"
                  HEALTHCHECK_REQUIRE_BGP: "0"
                  DNS_PROXY_ENABLED: "0"
                  UPDATE_INTERVAL: "86400"
                  INCLUDE_GOOGLE_RANGES: "0"
                  LISTS_FILE: /etc/bird/generated/config/lists.txt
                  DOMAIN_LIST_URLS_FILE: /etc/bird/generated/config/domain-list-urls.txt
                  INCLUDE_ASNS_FILE: /etc/bird/generated/config/include-asns.txt
                  INCLUDE_DOMAINS_FILE: /etc/bird/generated/config/include-domains.txt
                  EXCLUDE_DOMAINS_FILE: /etc/bird/generated/config/exclude-domains.txt
                depends_on: [bird]
            volumes:
              bird-run:
            """
        ).strip() + "\n"

    def compose(self, *args, check=True):
        return subprocess.run(
            ["docker", "compose", "-p", self.project_name, "-f", str(self.compose_file), *args],
            cwd=self.repo_root,
            check=check,
            capture_output=True,
            text=True,
        )

    def restore_generated_permissions(self):
        if not self.generated_dir.exists() or not sys.platform.startswith("linux"):
            return
        uid = os.getuid()
        gid = os.getgid()
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--entrypoint",
                "sh",
                "-v",
                f"{self.root.as_posix()}:/work",
                "bgp-antifilter-bird:smoke",
                "-c",
                f"chown -R {uid}:{gid} /work || true",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def wait_until(self, predicate, timeout, message, interval=0.25):
        deadline = time.time() + timeout
        last_error = None
        while time.time() < deadline:
            try:
                if predicate():
                    return
            except AssertionError as exc:
                last_error = exc
            time.sleep(interval)
        logs = self.compose("logs", "bird", "dns-proxy", check=False)
        details = logs.stdout[-4000:] if logs.stdout else ""
        path = self.generated_dir / "container.log"
        if path.exists():
            details += "\n" + path.read_text(encoding="utf-8", errors="replace")[-8000:]
        details += "\n" + getattr(self, "last_ready_error", "")
        if last_error is not None:
            raise AssertionError(f"{message}: {last_error}\n{details}".strip())
        raise AssertionError(f"{message}\n{details}".strip())

    def read_json(self, path):
        return json.loads(path.read_text(encoding="utf-8"))

    def test_admin_dns_settings_save_apply_ports_and_rollback(self):
        self.relative_mounts = True
        self.server_state["body"] = "93.184.216.0/24\n"
        (self.config_dir / "include-domains.txt").write_text("example.test\n")
        def free_port():
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                return reservation.getsockname()[1]
        self.admin_port = free_port()
        dns_port, health_port, bgp_port = free_port(), free_port(), free_port()
        upstream = dns_proxy.Proxy(mock.Mock(), "127.0.0.1")
        def answer(query, tcp=False):
            reply = dns.message.make_response(query)
            reply.answer.append(dns.rrset.from_text(query.question[0].name, 60, "IN", "A", "1.1.1.1"))
            return reply
        upstream.exchange = answer
        udp = dns_proxy.UDPServer(("127.0.0.1", 0), dns_proxy.UDPHandler, upstream)
        tcp = dns_proxy.TCPServer(udp.server_address, dns_proxy.TCPHandler, upstream)
        for server in (udp, tcp):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        base = f"http://127.0.0.1:{self.admin_port}"
        def api(path, method="GET", body=None):
            request = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                                             method=method, headers={"Content-Type": "application/json"})
            with opener.open(request, timeout=15) as response:
                return json.load(response)
        def login():
            try:
                return api("/api/login", "POST", {"password": "smoke-password"}).get("ok")
            except (OSError, ValueError):
                return False
        def apply():
            api("/api/actions/apply-settings", "POST", {})
            state = {}
            def completed():
                nonlocal state
                state = api("/api/settings").get("application", {})
                return state and not state.get("active")
            self.wait_until(completed, 150, "Panel settings application did not finish")
            return state
        def lookup(port):
            query = dns.message.make_query("cdn.example.test", "A")
            return dns.query.udp(query, "127.0.0.1", port=port, timeout=3)
        try:
            self.compose_file.write_text(self.compose_yaml(), encoding="utf-8")
            self.compose("up", "-d", "--build", "bird", "admin")
            self.wait_until(login, 30, "Admin API did not start")
            self.wait_until(lambda: not api("/api/status").get("runtime", {}).get("generation_active"), 30, "Initial generation did not finish")
            data = api("/api/settings")
            self.assertEqual(len(next(section for section in data["sections"] if section["id"] == "dns")["items"]), 13)
            desired = data["values"]
            desired.update(DNS_PROXY_ENABLED="1", DNS_PROXY_BIND="127.0.0.1", ADGUARD_DNS="127.0.0.1",
                           ADGUARD_DNS_PORT=str(udp.server_address[1]), DNS_PROXY_PORT=str(dns_port),
                           DNS_PROXY_HEALTH_PORT=str(health_port), DNS_BGP_PORT=str(bgp_port),
                           DNS_PROXY_ALLOWED_CLIENTS="127.0.0.1/32", DNS_SYNC_MODE="bird", DNS_SYNC_TIMEOUT="0.5",
                           DNS_SYNC_ON_TIMEOUT="servfail", DNS_ROUTE_GRACE="2")
            api("/api/settings", "PUT", {"values": desired})
            self.assertNotIn("DNS_PROXY_ENABLED=1", (self.generated_dir / "settings.env").read_text())
            self.assertFalse(self.compose("ps", "-q", "dns-proxy").stdout.strip(), "Save activated the proxy")
            self.assertTrue(apply().get("ok"))
            self.assertEqual(lookup(dns_port).rcode(), dns.rcode.NOERROR)
            self.assertIn("1.1.1.1/32", self.compose("exec", "-T", "bird", "birdc", "show", "route", "for", "1.1.1.1").stdout)
            bird_id = self.compose("ps", "-q", "bird").stdout.strip()
            desired.update(DNS_SYNC_MODE="async", DNS_SYNC_TIMEOUT="0.2", DNS_SYNC_ON_TIMEOUT="forward")
            api("/api/settings", "PUT", {"values": desired})
            self.assertTrue(apply().get("ok"))
            self.assertEqual(self.compose("ps", "-q", "bird").stdout.strip(), bird_id, "Sync change restarted BIRD")
            dns_port, health_port = free_port(), free_port()
            desired.update(DNS_PROXY_PORT=str(dns_port), DNS_PROXY_HEALTH_PORT=str(health_port))
            api("/api/settings", "PUT", {"values": desired})
            self.assertTrue(apply().get("ok"))
            self.assertEqual(lookup(dns_port).rcode(), dns.rcode.NOERROR)
            with urllib.request.urlopen(f"http://127.0.0.1:{health_port}/ready", timeout=5) as response:
                self.assertTrue(json.load(response)["ready"])
            desired["DNS_PROXY_BIND"] = "198.51.100.254"  # Not an address of this host.
            api("/api/settings", "PUT", {"values": desired})
            failed = apply()
            self.assertFalse(failed["ok"])
            self.assertTrue(failed["rollback"]["ok"], failed)
            self.assertEqual(lookup(dns_port).rcode(), dns.rcode.NOERROR, "Rollback did not restore working DNS")
            self.assertEqual(api("/api/settings")["values"]["DNS_PROXY_BIND"], "198.51.100.254", "Saved draft was lost")
            desired.update(DNS_PROXY_ENABLED="0", DNS_PROXY_BIND="127.0.0.1")
            api("/api/settings", "PUT", {"values": desired})
            self.assertTrue(apply().get("ok"))
            self.assertFalse(self.compose("ps", "-q", "dns-proxy").stdout.strip())
            self.assertIn("static_antifilter", self.compose("exec", "-T", "bird", "birdc", "show", "protocols").stdout)
        except Exception:
            print(self.compose("logs", "admin", "bird", "dns-proxy", check=False).stdout[-14000:])
            raise
        finally:
            for server in (udp, tcp):
                server.shutdown()
                server.server_close()

    def test_dns_proxy_applies_real_bird_routes_and_reports_bird_outage(self):
        self.dns_enabled = True
        self.server_state["body"] = "93.184.216.0/24\n"
        upstream = dns_proxy.Proxy(mock.Mock(), "127.0.0.1")
        answer_address = ["1.1.1.1"]

        def answer(query, tcp=False):
            result = dns.message.make_response(query)
            if query.question[0].name.to_text() == "alias.example.test.":
                result.answer.append(dns.rrset.from_text(query.question[0].name, 60, "IN", "CNAME", "edge.other.test."))
            elif query.question[0].name.to_text() == "direct.example.test.":
                result.answer.append(dns.rrset.from_text(query.question[0].name, 1, "IN", "A", "93.184.216.34"))
            else:
                result.answer.append(dns.rrset.from_text(query.question[0].name, 60, "IN", "A", answer_address[0]))
            return result

        upstream.exchange = answer
        udp = dns_proxy.UDPServer(("127.0.0.1", 0), dns_proxy.UDPHandler, upstream)
        tcp = dns_proxy.TCPServer(udp.server_address, dns_proxy.TCPHandler, upstream)
        self.upstream_port = udp.server_address[1]
        for server in (udp, tcp):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                self.dns_port = reservation.getsockname()[1]
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                self.dns_health_port = reservation.getsockname()[1]
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                self.bgp_feed_port = reservation.getsockname()[1]
            (self.config_dir / "include-domains.txt").write_text("example.test\n", encoding="utf-8")
            (self.config_dir / "exclude-domains.txt").write_text("direct.example.test\n", encoding="utf-8")
            cache = self.generated_dir / "cache"
            cache.mkdir(exist_ok=True)
            update_routes.cache_path(cache, "exclude-domain", "direct.example.test").write_text("93.184.216.254/32\n", encoding="utf-8")
            self.compose_file.write_text(self.compose_yaml(), encoding="utf-8")
            self.compose("up", "-d", "--build", "bird", "dns-proxy")
            ready_url = f"http://127.0.0.1:{self.dns_health_port}/ready"

            def ready():
                with urllib.request.urlopen(ready_url, timeout=5) as reply:
                    return json.load(reply)["ready"]

            def ready_without_errors():
                try:
                    return ready()
                except urllib.error.HTTPError as exc:
                    self.last_ready_error = exc.read().decode("utf-8", errors="replace")
                    exc.close()
                    return False
                except (OSError, ValueError):
                    return False

            self.wait_until(ready_without_errors, 45, "DNS proxy did not become ready")
            def route_present(address):
                table = self.compose("exec", "-T", "bird", "birdc", "show", "route", "for", address, check=False).stdout
                return bool(re.search(r"(?m)^\d+\.\d+\.\d+\.\d+/\d+\s", table))

            def reconfigured_at():
                status = self.compose("exec", "-T", "bird", "birdc", "show", "status").stdout
                return next(line for line in status.splitlines() if "Last reconfiguration" in line)

            initial_configure_time = reconfigured_at()
            query = dns.message.make_query("cdn.example.test", "A")
            reply = dns.query.udp(query, "127.0.0.1", port=self.dns_port, timeout=5)
            self.assertEqual(reply.answer[0][0].address, "1.1.1.1")
            self.wait_until(lambda: route_present("1.1.1.1"), 5, "New IP was not advertised by the local BGP feed")
            answer_address[0] = "1.1.1.2"
            reply = dns.query.tcp(query, "127.0.0.1", port=self.dns_port, timeout=5)
            self.assertEqual(reply.answer[0][0].address, "1.1.1.2")
            self.wait_until(lambda: route_present("1.1.1.2"), 5, "Second IP was not advertised")
            self.assertNotIn("1.1.1.2/32", (self.generated_dir / "routes.conf").read_text(), "DNS rewrote the full route snapshot")
            excluded = dns.message.make_query("direct.example.test", "A")
            dns.query.udp(excluded, "127.0.0.1", port=self.dns_port, timeout=5)
            self.wait_until(lambda: not route_present("93.184.216.34"), 0.9, "Live exclusion did not split the containing prefix", interval=0.03)
            self.wait_until(lambda: route_present("93.184.216.34"), 5, "Expired exclusion was not withdrawn")
            # A full reload must preserve the exact addresses already served.
            self.compose("exec", "-T", "bird", "/reload-routes.sh")
            self.assertIn("1.1.1.2/32", (self.generated_dir / "routes.conf").read_text())
            self.assertEqual(reconfigured_at(), initial_configure_time, "A DNS/full-policy update called birdc configure")
            # A separate lookup outside the include suffix must inherit its
            # original domain's scope, even after restarting the DNS process.
            alias_query = dns.message.make_query("alias.example.test", "A")
            alias_reply = dns.query.udp(alias_query, "127.0.0.1", port=self.dns_port, timeout=5)
            self.assertEqual(alias_reply.answer[0].rdtype, dns.rdatatype.CNAME)
            def alias_persisted():
                result = self.compose("exec", "-T", "dns-proxy", "python3", "-c",
                                      "import sqlite3; d=sqlite3.connect('/etc/bird/generated/dns-cache.sqlite3'); print(d.execute(\"SELECT count(*) FROM aliases WHERE name='edge.other.test'\").fetchone()[0])")
                return result.stdout.strip() == "1"
            self.wait_until(alias_persisted, 5, "Alias observation was not persisted")
            self.compose("restart", "dns-proxy")
            self.wait_until(ready_without_errors, 20, "DNS proxy did not recover after restart")
            answer_address[0] = "1.0.0.1"
            target_query = dns.message.make_query("edge.other.test", "A")
            target_reply = dns.query.tcp(target_query, "127.0.0.1", port=self.dns_port, timeout=5)
            self.assertEqual(target_reply.answer[0][0].address, "1.0.0.1")
            self.wait_until(lambda: route_present("1.0.0.1"), 5, "Persistent alias did not produce a live BGP route")
            self.compose("stop", "bird")
            with self.assertRaises(urllib.error.HTTPError) as failed:
                ready()
            self.assertEqual(failed.exception.code, 503)
            failed.exception.close()
            answer_address[0] = "1.1.1.3"
            reply = dns.query.udp(query, "127.0.0.1", port=self.dns_port, timeout=5)
            self.assertEqual(reply.rcode(), dns.rcode.NOERROR, "A route outage delayed/replaced the valid DNS response")
            self.compose("start", "bird")
            self.wait_until(ready_without_errors, 30, "Local BGP feed did not reconnect after BIRD restart")
            self.wait_until(lambda: route_present("1.1.1.3"), 5, "IP learned during BIRD outage was not replayed")
            strict_configure_time = reconfigured_at()
            # Enable BIRD confirmation. The DNS response itself must now be
            # gated on the real RIB, without a subsequent polling allowance.
            self.dns_sync_mode = "bird"
            self.compose_file.write_text(self.compose_yaml(), encoding="utf-8")
            self.compose("up", "-d", "--no-deps", "--force-recreate", "dns-proxy")
            self.wait_until(ready_without_errors, 20, "Synchronous DNS proxy did not recover")
            answer_address[0] = "1.1.1.4"
            reply = dns.query.udp(query, "127.0.0.1", port=self.dns_port, timeout=5)
            self.assertEqual(reply.rcode(), dns.rcode.NOERROR)
            self.assertEqual(reply.answer[0][0].address, "1.1.1.4")
            self.assertTrue(route_present("1.1.1.4"), "DNS arrived before the route was installed in BIRD")
            reply = dns.query.tcp(excluded, "127.0.0.1", port=self.dns_port, timeout=5)
            self.assertEqual(reply.rcode(), dns.rcode.NOERROR,
                             self.compose("logs", "dns-proxy", check=False).stdout[-5000:] if reply.rcode() else "")
            self.assertFalse(route_present("93.184.216.34"), "DNS arrived before BIRD applied the exclusion")
            # Execute the real export filter even though the smoke test has
            # no external MikroTik peer/channel. Check a positive control too.
            for value, wanted in (("198.18.0.1", False), ("1.1.1.4", True)):
                filtered = self.compose("exec", "-T", "bird", "birdc", "show", "route", "for", value,
                                        "filter", "export_to_mikrotik").stdout
                self.assertEqual(value + "/32" in filtered, wanted, "Unexpected MikroTik export filter result")
            self.assertEqual(reconfigured_at(), strict_configure_time)
            self.compose("stop", "bird")
            answer_address[0] = "1.1.1.5"
            reply = dns.query.udp(query, "127.0.0.1", port=self.dns_port, timeout=5)
            self.assertEqual(reply.rcode(), dns.rcode.SERVFAIL, "Strict synchronization leaked a new IP during BIRD outage")
            self.assertFalse(reply.answer)
            unrelated = dns.message.make_query("unrelated.test", "A")
            reply = dns.query.tcp(unrelated, "127.0.0.1", port=self.dns_port, timeout=5)
            self.assertEqual(reply.rcode(), dns.rcode.NOERROR, "Unselected domain unnecessarily waited for BGP")
            self.dns_sync_on_timeout = "forward"
            self.compose_file.write_text(self.compose_yaml(), encoding="utf-8")
            self.compose("up", "-d", "--no-deps", "--force-recreate", "dns-proxy")

            def forwarding_after_timeout():
                try:
                    return dns.query.tcp(query, "127.0.0.1", port=self.dns_port, timeout=3).rcode() == dns.rcode.NOERROR
                except (OSError, dns.exception.DNSException):
                    return False

            self.wait_until(forwarding_after_timeout, 10, "Configured forward fallback did not return AdGuard's answer")
            self.compose("start", "bird")
            self.wait_until(ready_without_errors, 30, "Synchronous source did not reconnect")
            self.assertTrue(route_present("1.1.1.5"), "Failed/forwarded sync observation was lost")
        except Exception:
            print(self.compose("logs", "bird", "dns-proxy", check=False).stdout[-10000:])
            for value in ("198.18.0.1", "1.1.1.4", "93.184.216.34"):
                print(self.compose("exec", "-T", "bird", "birdc", "-v", "-r", "show", "route", "for", value, "all", check=False).stdout)
            raise
        finally:
            for server in (udp, tcp):
                server.shutdown()
                server.server_close()

    def test_restart_uses_previous_snapshot_until_background_refresh_completes(self):
        old_route = "route 192.0.2.0/24 blackhole;"
        new_route = "route 198.51.100.0/24 blackhole;"

        self.compose("up", "-d", "--build", "bird")

        routes_file = self.generated_dir / "routes.conf"
        last_good_file = self.generated_dir / "routes.last-good.conf"
        status_file = self.generated_dir / "status.json"
        runtime_file = self.generated_dir / "runtime.json"

        self.wait_until(
            lambda: routes_file.exists() and old_route in routes_file.read_text(encoding="utf-8"),
            timeout=60,
            message="Initial startup did not generate the first route snapshot",
        )
        self.wait_until(
            lambda: last_good_file.exists() and old_route in last_good_file.read_text(encoding="utf-8"),
            timeout=30,
            message="Initial startup did not persist the last-known-good snapshot",
        )
        self.wait_until(
            lambda: status_file.exists() and self.read_json(status_file)["success"] is True,
            timeout=30,
            message="Initial startup did not finish with success status",
        )

        self.server_state["body"] = "198.51.100.0/24\n"
        self.server_state["delay"] = 5

        self.compose("down", "--remove-orphans")
        self.compose("up", "-d", "bird")

        self.wait_until(
            lambda: runtime_file.exists() and self.read_json(runtime_file).get("generation_kind") == "startup",
            timeout=10,
            message="Restart did not enter startup background refresh mode",
        )
        runtime_during_refresh = self.read_json(runtime_file)
        self.assertTrue(runtime_during_refresh.get("startup_snapshot_used"))
        self.assertEqual(runtime_during_refresh.get("last_update_reason", ""), "")
        self.assertIn(old_route, routes_file.read_text(encoding="utf-8"))
        self.assertIn(old_route, last_good_file.read_text(encoding="utf-8"))

        self.wait_until(
            lambda: new_route in routes_file.read_text(encoding="utf-8"),
            timeout=45,
            message="Background refresh did not replace the route snapshot",
        )
        self.wait_until(
            lambda: new_route in last_good_file.read_text(encoding="utf-8"),
            timeout=15,
            message="Background refresh did not update the last-known-good snapshot",
        )
        self.wait_until(
            lambda: status_file.exists() and self.read_json(status_file)["success"] is True,
            timeout=15,
            message="Background refresh did not finish successfully",
        )
        # Snapshots/status are committed before the final runtime record.
        self.wait_until(
            lambda: runtime_file.exists() and self.read_json(runtime_file).get("last_update_reason") == "startup"
            and self.read_json(runtime_file).get("last_update_success") is True
            and not self.read_json(runtime_file).get("generation_active"),
            timeout=15,
            message="Background refresh did not publish completed runtime state",
        )
        runtime = self.read_json(runtime_file)
        self.assertFalse(runtime.get("generation_active"))
        self.assertEqual(runtime.get("last_update_reason"), "startup")
        self.assertTrue(runtime.get("last_update_success"))

    def test_failed_refresh_keeps_last_known_good_snapshot_and_sets_degraded_state(self):
        old_route = "route 192.0.2.0/24 blackhole;"

        self.compose("up", "-d", "--build", "bird")

        routes_file = self.generated_dir / "routes.conf"
        last_good_file = self.generated_dir / "routes.last-good.conf"
        status_file = self.generated_dir / "status.json"
        runtime_file = self.generated_dir / "runtime.json"

        self.wait_until(
            lambda: last_good_file.exists() and old_route in last_good_file.read_text(encoding="utf-8"),
            timeout=60,
            message="Initial startup did not persist the last-known-good snapshot",
        )

        self.server_state["body"] = "0.0.0.0/0\n"
        result = self.compose("exec", "-T", "bird", "/reload-routes.sh", check=False)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

        self.wait_until(
            lambda: status_file.exists() and self.read_json(status_file).get("degraded") is True,
            timeout=15,
            message="Failed refresh did not set degraded state in status.json",
        )
        self.wait_until(
            lambda: runtime_file.exists() and self.read_json(runtime_file).get("degraded") is True,
            timeout=15,
            message="Failed refresh did not set degraded state in runtime.json",
        )

        status = self.read_json(status_file)
        runtime = self.read_json(runtime_file)
        self.assertFalse(status.get("success"))
        self.assertTrue(status.get("degraded"))
        self.assertIn("previous route snapshot remains active", status.get("degraded_reason", ""))
        self.assertEqual(runtime.get("last_update_reason"), "manual")
        self.assertFalse(runtime.get("last_update_success"))
        self.assertTrue(runtime.get("degraded"))
        self.assertIn(old_route, routes_file.read_text(encoding="utf-8"))
        self.assertIn(old_route, last_good_file.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
