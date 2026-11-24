"""Exercise the shipped DNS service and BIRD without external networking."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import unittest
import uuid


# All network traffic stays on loopback inside a --network=none container.
# Positive answers use neutral global addresses because the production worker
# deliberately rejects reserved/documentation addresses. No connection is made
# to any address returned by this fixture.
DNS_FIXTURE = r'''
import json
from pathlib import Path
import socketserver
import struct
import threading

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset

log = Path('/tmp/dns-fixture-queries.jsonl')
log.write_text('')
lock = threading.Lock()

def answer(wire, transport):
    query = dns.message.from_wire(wire)
    question = query.question[0]
    name = question.name.to_text().lower()
    with lock, log.open('a') as output:
        output.write(json.dumps({'name': name, 'transport': transport}) + '\n')
    response = dns.message.make_response(query)
    response.flags |= dns.flags.AA | dns.flags.RA
    if name == 'health.fixture.test.' and Path('/tmp/dns-fixture-health-nxdomain').exists():
        response.set_rcode(dns.rcode.NXDOMAIN)
        return response.to_wire()
    if question.rdtype == dns.rdatatype.AAAA:
        response.answer.append(dns.rrset.from_text(name, 120, 'IN', 'AAAA', '2001:db8::10'))
    elif name == 'alias.selected.test.':
        response.answer.append(dns.rrset.from_text(name, 120, 'IN', 'CNAME', 'edge.cdn.test.'))
    elif name == 'hints.selected.test.' and question.rdtype == dns.rdatatype.HTTPS:
        response.answer.append(dns.rrset.from_text(name, 120, 'IN', 'HTTPS', '1 . ipv4hint=1.1.1.5'))
    else:
        entries = {
            'health.fixture.test.': ('1.0.0.254', 120),
            'shared.selected.test.': ('1.1.1.1', 120),
            'direct.selected.test.': ('1.1.1.1', 2),
            'persist.selected.test.': ('1.1.1.2', 120),
            'edge.cdn.test.': ('1.1.1.3', 120),
            'unrelated.test.': ('1.1.1.4', 120),
            'short.selected.test.': ('1.1.1.6', 1),
            'blocked.selected.test.': ('192.0.2.10', 120),
            'playlist.edge.service.test.': ('1.1.2.10', 300),
            'playlist.other.service.test.': ('1.1.3.10', 300),
            'media.edge.service.test.': ('1.1.2.20', 300),
        }
        if name in entries and question.rdtype == dns.rdatatype.A:
            address, ttl = entries[name]
            response.answer.append(dns.rrset.from_text(name, ttl, 'IN', 'A', address))
        else:
            response.set_rcode(dns.rcode.NXDOMAIN)
    return response.to_wire()

def receive(connection, size):
    data = b''
    while len(data) < size:
        part = connection.recv(size - len(data))
        if not part:
            raise EOFError()
        data += part
    return data

class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        wire, connection = self.request
        connection.sendto(answer(wire, 'udp'), self.client_address)

class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            while True:
                size = struct.unpack('!H', receive(self.request, 2))[0]
                response = answer(receive(self.request, size), 'tcp')
                self.request.sendall(struct.pack('!H', len(response)) + response)
        except (EOFError, OSError):
            pass

udp = socketserver.ThreadingUDPServer(('127.0.0.2', 5353), UDP)
tcp = socketserver.ThreadingTCPServer(('127.0.0.2', 5353), TCP)
for server in (udp, tcp):
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
Path('/tmp/dns-fixture-ready').write_text('ready')
threading.Event().wait()
'''


QUERY = r'''
import json
import sys
import time
import dns.message
import dns.query
import dns.rdatatype
query = dns.message.make_query(sys.argv[1], sys.argv[2])
transport = dns.query.tcp if sys.argv[3] == 'tcp' else dns.query.udp
started = time.monotonic()
response = transport(query, '127.0.0.1', port=int(sys.argv[4]), timeout=8)
print(json.dumps({'rcode': response.rcode(), 'id_matches': query.id == response.id,
                  'elapsed_seconds': time.monotonic() - started,
                  'answer': [rrset.to_text() for rrset in response.answer],
                  'ipv4': [record.address for rrset in response.answer
                           if rrset.rdtype == dns.rdatatype.A for record in rrset]}))
'''


PROCESS_CREDENTIALS = r'''
import json
from pathlib import Path

result = {}
for directory in Path('/proc').iterdir():
    if not directory.name.isdigit():
        continue
    try:
        arguments = [part.decode() for part in (directory / 'cmdline').read_bytes().split(b'\0') if part]
        if not arguments:
            continue
        if any(Path(argument).name == 'supervisord' for argument in arguments[:2]):
            name = 'supervisor'
        elif Path(arguments[0]).name == 'bird' and '/etc/bird/bird.conf' in arguments:
            name = 'bird'
        elif '/admin-server.py' in arguments:
            name = 'admin'
        elif 'bgp_antifilter.dns_proxy' in arguments:
            name = 'dns'
        elif '/run-scheduler.sh' in arguments:
            name = 'scheduler'
        else:
            continue
        fields = dict(line.split(':', 1) for line in (directory / 'status').read_text().splitlines() if ':' in line)
    except (FileNotFoundError, ProcessLookupError):
        continue
    assert name not in result, name + ' has duplicate processes'
    result[name] = {'pid': int(directory.name),
                    'uid': [int(value) for value in fields['Uid'].split()],
                    'gid': [int(value) for value in fields['Gid'].split()],
                    'no_new_privileges': int(fields['NoNewPrivs']),
                    'caps': {key: int(fields[key], 16) for key in ('CapEff', 'CapPrm', 'CapAmb')}}
print(json.dumps(result))
'''


ADMIN_REQUEST = r'''
import http.cookiejar
import json
import sys
import urllib.request

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
login = urllib.request.Request('http://127.0.0.1:8082/api/login',
    json.dumps({'password': 'privilege-test'}).encode(), {'Content-Type': 'application/json'})
opener.open(login, timeout=3).close()
body = None if sys.argv[3] == 'null' else sys.argv[3].encode()
request = urllib.request.Request('http://127.0.0.1:8082' + sys.argv[1], body,
    {'Content-Type': 'application/json'}, method=sys.argv[2])
with opener.open(request, timeout=5) as response:
    print(response.read().decode())
'''


@unittest.skipUnless(os.environ.get("RUN_DOCKER_DNS_PROXY") == "1" and shutil.which("docker"),
                     "Requires RUN_DOCKER_DNS_PROXY=1 and Docker")
class DnsProxyDockerTests(unittest.TestCase):
    def setUp(self):
        self.image = os.environ.get("DNS_PROXY_TEST_IMAGE", "ghcr.io/leonidoz/bgp-antifilter:dev")
        self.prefix = "bgp-dns-test-" + uuid.uuid4().hex[:12]
        self.repo = Path(__file__).resolve().parents[1]
        self.containers = []
        self.volumes = []
        self.addCleanup(self.cleanup)

    def docker(self, *args, check=True, input=None, timeout=30):
        result = subprocess.run(["docker", *args], cwd=self.repo, input=input, capture_output=True,
                                text=True, timeout=timeout)
        if check:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def cleanup(self):
        for name in reversed(self.containers):
            self.docker("rm", "-f", name, check=False)
        for name in reversed(self.volumes):
            self.docker("volume", "rm", name, check=False)

    def prepare_volumes(self, include, exclude=""):
        config, generated = self.prefix + "-config", self.prefix + "-data"
        for name in (config, generated):
            self.docker("volume", "create", name)
            self.volumes.append(name)
        files = {name: "" for name in ("lists.txt", "domain-list-urls.txt", "include-asns.txt",
                                       "include-countries.txt", "include-domains.txt", "exclude-domains.txt")}
        files.update({"include-domains.txt": include, "exclude-domains.txt": exclude})
        seed = ("from pathlib import Path\nimport json\nroot=Path('/etc/bird/config')\n"
                "root.mkdir(parents=True, exist_ok=True)\n"
                "for name, content in json.loads(" + repr(json.dumps(files)) + ").items():\n"
                "    (root/name).write_text(content, encoding='utf-8')\n")
        self.docker("run", "--rm", "--pull=never", "--network", "none", "-i", "-v",
                    config + ":/etc/bird/config", "--entrypoint", "python3", self.image, "-", input=seed)
        return config, generated

    def start_runtime(self, volumes, enabled, suffix="runtime", overrides=None, docker_options=()):
        name = self.prefix + "-" + suffix
        environment = {
            "MY_AS": "64500", "PEER_AS": "64501", "PEER_IP": "127.0.0.3",
            "BIRD_IP": "127.0.0.1", "ROUTER_ID": "192.0.2.1", "BGP_PROTOCOL": "test_peer",
            "HEALTHCHECK_REQUIRE_BGP": "0", "INCLUDE_GOOGLE_RANGES": "0", "ADMIN_ENABLED": "0",
            "UPDATE_INTERVAL": "86400", "FETCH_ATTEMPTS": "1", "FETCH_RETRY_DELAY": "0",
            "DNS_PROXY_ENABLED": "1" if enabled else "0", "DNS_PROXY_BIND": "127.0.0.1",
            "DNS_PROXY_PORT": "5353", "DNS_PROXY_UPSTREAM": "127.0.0.2" if enabled else "",
            "DNS_PROXY_UPSTREAM_PORT": "5353", "DNS_PROXY_HEALTH_PORT": "8053",
            "DNS_PROXY_ALLOWED_CLIENTS": "127.0.0.1/32", "DNS_BGP_PORT": "1179",
            "DNS_HEALTH_DOMAIN": "health.fixture.test", "DNS_ROUTE_GRACE": "0",
            "DNS_SYNC_MODE": "bird", "DNS_SYNC_TIMEOUT": "2", "DNS_SYNC_ON_TIMEOUT": "servfail",
            "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "", "NO_PROXY": "*",
        }
        environment.update(overrides or {})
        args = ["run", "--detach", "--pull=never", "--network", "none", "--name", name, *docker_options,
                "-v", volumes[0] + ":/etc/bird/config", "-v", volumes[1] + ":/etc/bird/generated"]
        for key, value in environment.items():
            args.extend(("-e", f"{key}={value}"))
        self.containers.append(name)
        self.docker(*args, self.image)
        return name

    def python(self, container, code, *args, check=True, user=None):
        options = ["--user", user] if user else []
        return self.docker("exec", *options, container, "python3", "-c", code, *args, check=check, timeout=15)

    def wait_until(self, container, predicate, message, timeout=45):
        deadline = time.monotonic() + timeout
        last_error = ""
        while time.monotonic() < deadline:
            try:
                if predicate():
                    return
            except (AssertionError, json.JSONDecodeError) as exc:
                last_error = str(exc)
            time.sleep(0.2)
        logs = self.docker("logs", "--tail", "120", container, check=False)
        self.fail(f"{message}\n{last_error}\n{logs.stdout}{logs.stderr}")

    def start_fixture(self, container, user=None):
        options = ["--user", user] if user else []
        self.docker("exec", "-d", *options, container, "python3", "-u", "-c", DNS_FIXTURE)
        self.wait_until(container, lambda: self.python(container,
                        "from pathlib import Path; print(Path('/tmp/dns-fixture-ready').exists())").stdout.strip() == "True",
                        "DNS fixture did not start", timeout=10)

    def ready(self, container):
        code = ("import json,urllib.request; "
                "opener=urllib.request.build_opener(urllib.request.ProxyHandler({})); "
                "response=opener.open('http://127.0.0.1:8053/ready', timeout=4); "
                "assert json.load(response)['ready'] is True")
        return self.python(container, code, check=False).returncode == 0

    def query(self, container, name, qtype="A", transport="udp", port=5353):
        reply = json.loads(self.python(container, QUERY, name, qtype, transport, str(port)).stdout)
        self.assertEqual(reply["rcode"], 0, reply)
        self.assertTrue(reply["id_matches"], reply)
        return reply

    def route(self, container, address):
        return self.docker("exec", container, "birdc", "show", "route", "for", address, "primary",
                           check=False).stdout

    def assert_live_route(self, container, address, present=True):
        output = self.route(container, address)
        self.assertEqual("[dns_live " in output, present, output)

    def assert_service_credentials(self, container):
        expected = {"supervisor", "bird", "admin", "dns", "scheduler"}
        self.wait_until(container, lambda: set(json.loads(self.python(container, PROCESS_CREDENTIALS).stdout)) == expected,
                        "Not all application services started")
        records = json.loads(self.python(container, PROCESS_CREDENTIALS).stdout)
        self.assertEqual(records["supervisor"]["pid"], 1)
        for name, record in records.items():
            with self.subTest(service=name):
                self.assertEqual(record["uid"], [10001] * 4, record)
                self.assertEqual(record["gid"], [10001] * 4, record)
                self.assertEqual(record["no_new_privileges"], 1, record)
                capability = 0 if name in {"admin", "scheduler"} else 0x400
                self.assertEqual(record["caps"], {key: capability for key in ("CapEff", "CapPrm", "CapAmb")}, record)

    def admin_request(self, container, path, method="GET", payload=None):
        return json.loads(self.python(container, ADMIN_REQUEST, path, method, json.dumps(payload), user="10001:10001").stdout)

    def start_privilege_peer(self, container):
        config = r'''
log "/tmp/privilege-peer.log" all;
router id 192.0.2.2;
protocol device {}
protocol static reachability { ipv4; route 127.0.0.1/32 via "lo"; }
protocol bgp origin {
    local 127.0.0.3 port 2179 as 64501;
    neighbor 127.0.0.1 port 179 as 64500;
    multihop;
    connect retry time 1;
    ipv4 { import all; export none; };
}
'''
        self.python(container, "from pathlib import Path; import sys; "
                    "Path('/tmp/privilege-peer.conf').write_text(sys.argv[1]); "
                    "Path('/tmp/privilege-peer.ctl').unlink(missing_ok=True); "
                    "Path('/tmp/privilege-peer.pid').unlink(missing_ok=True)", config, user="10001:10001")
        self.docker("exec", "-d", "--user", "10001:10001", container, "bird", "-f", "-c", "/tmp/privilege-peer.conf",
                    "-s", "/tmp/privilege-peer.ctl", "-P", "/tmp/privilege-peer.pid")
        self.wait_until(container, lambda: "Established" in self.docker(
                        "exec", "--user", "10001:10001", container, "birdc", "show", "protocols", "test_peer", check=False).stdout,
                        "Non-root BIRD did not establish BGP on port 179")

    def privilege_peer_route(self, container):
        return self.docker("exec", container, "birdc", "-s", "/tmp/privilege-peer.ctl",
                           "show", "route", "for", "1.1.1.2", "all", check=False).stdout

    def test_nonroot_services_migrate_private_volumes_and_keep_dns_bgp_settings_after_restart(self):
        volumes = self.prepare_volumes(r"regex:^persist\.selected\.test$" + "\n")
        seed = r'''
import json
import os
from pathlib import Path
config = Path('/etc/bird/config')
generated = Path('/etc/bird/generated')
(config / 'settings.json').write_text(json.dumps({'values': {'FETCH_TIMEOUT': '11',
    'HTTP_PROXY_TYPE': 'none', 'HTTP_PROXY_USERNAME': 'legacy-reader', 'HTTP_PROXY_PASSWORD': 'legacy-test-secret'}}))
(config / 'settings.env').write_text('FETCH_TIMEOUT=11\nHTTP_PROXY_TYPE=none\nHTTP_PROXY_USERNAME=legacy-reader\nHTTP_PROXY_PASSWORD=legacy-test-secret\n')
(config / 'list-backups').mkdir()
(config / 'list-backups/include-domains.txt.old.bak').write_text('retained backup\n')
(generated / 'cache').mkdir(parents=True, exist_ok=True)
(generated / 'cache/legacy.cache').write_text('retained cache\n')
for root in (config, generated):
    for path in [root, *root.rglob('*')]:
        os.chown(path, 0, 0)
        path.chmod(0o700 if path.is_dir() else 0o600)
        assert path.stat().st_uid == 0 and path.stat().st_gid == 0
'''
        self.docker("run", "--rm", "--pull=never", "--network", "none", "--user", "0:0", "-i",
                    "-v", volumes[0] + ":/etc/bird/config", "-v", volumes[1] + ":/etc/bird/generated",
                    "--entrypoint", "python3", self.image, "-", input=seed)
        container = self.start_runtime(volumes, enabled=True,
            overrides={"ADMIN_ENABLED": "1", "ADMIN_PORT": "8082", "ADMIN_PASSWORD": "privilege-test", "DNS_PROXY_PORT": "53"},
            docker_options=("--cap-drop", "NET_ADMIN", "--sysctl", "net.ipv4.ip_unprivileged_port_start=1024"))
        self.start_fixture(container, user="10001:10001")
        self.wait_until(container, lambda: self.ready(container), "Non-root DNS service did not become ready on port 53")
        self.assert_service_credentials(container)
        self.assertEqual(self.python(container, "from pathlib import Path; print(Path('/proc/sys/net/ipv4/ip_unprivileged_port_start').read_text().strip())").stdout.strip(), "1024")
        self.start_privilege_peer(container)
        for transport in ("udp", "tcp"):
            self.assertEqual(self.query(container, "persist.selected.test", transport=transport, port=53)["ipv4"], ["1.1.1.2"])
        self.wait_until(container, lambda: "1.1.1.2/32" in self.privilege_peer_route(container),
                        "DNS route was not exported by non-root BIRD on port 179")
        self.assertIn("Reconfigured", self.docker("exec", "--user", "10001:10001", container, "birdc", "configure").stdout)

        ownership = r'''
from pathlib import Path
import os
import stat
for name in ('/etc/bird/bird.conf', '/run/bird/bird.ctl', '/etc/bird/generated/status.json',
             '/etc/bird/generated/runtime.json', '/etc/bird/generated/dns-settings.active.json',
             '/etc/bird/generated/dns-runtime.json', '/etc/bird/generated/dns-cache.sqlite3',
             '/etc/bird/generated/dns-policy.json',
             '/etc/bird/generated/cache/legacy.cache', '/etc/bird/config/settings.json',
             '/etc/bird/config/settings.env', '/etc/bird/config/list-backups/include-domains.txt.old.bak'):
    path = Path(name)
    info = path.stat()
    assert (info.st_uid, info.st_gid) == (10001, 10001), name
    assert os.access(path, os.R_OK | os.W_OK), name
for name in ('settings.json', 'settings.env'):
    assert stat.S_IMODE((Path('/etc/bird/config') / name).stat().st_mode) == 0o600, name
assert Path('/etc/bird/generated/cache/legacy.cache').read_text() == 'retained cache\n'
assert Path('/etc/bird/config/list-backups/include-domains.txt.old.bak').read_text() == 'retained backup\n'
'''
        self.python(container, ownership, user="10001:10001")
        for user_options in ((), ("--user", "10001:10001")):
            with self.subTest(reload_user="application" if user_options else "root"):
                self.docker("exec", *user_options, container, "/reload-routes.sh", timeout=90)
                self.wait_until(container, lambda: self.ready(container), "DNS service did not recover after manual reload")
                self.python(container, ownership, user="10001:10001")
                self.assertEqual(self.query(container, "persist.selected.test", port=53)["ipv4"], ["1.1.1.2"])
                self.assert_live_route(container, "1.1.1.2")
        settings = self.admin_request(container, "/api/settings")
        self.assertEqual(settings["values"]["FETCH_TIMEOUT"], "11")
        self.assertNotIn("HTTP_PROXY_PASSWORD", settings["values"])
        saved = self.admin_request(container, "/api/settings", "PUT", {"values": {
            "FETCH_TIMEOUT": "17", "DNS_WORKERS": "32", "DNS_QPS": "25", "DNS_ROUTE_GRACE": "10",
            "BGP_COMMUNITY": "64500,42", "HTTP_PROXY_USERNAME": "test-reader", "HTTP_PROXY_PASSWORD": "neutral-proxy-secret"}})
        self.assertEqual(saved["values"]["FETCH_TIMEOUT"], "17")
        self.assertNotIn("HTTP_PROXY_PASSWORD", saved["values"])
        self.python(container, ownership, user="10001:10001")

        self.docker("restart", container, timeout=45)
        self.start_fixture(container, user="10001:10001")
        self.wait_until(container, lambda: self.ready(container), "Non-root services did not recover after restart")
        self.assert_service_credentials(container)
        self.start_privilege_peer(container)
        self.python(container, ownership, user="10001:10001")
        restored = self.admin_request(container, "/api/settings")["values"]
        for key, value in {"FETCH_TIMEOUT": "17", "DNS_WORKERS": "32", "DNS_QPS": "25", "DNS_ROUTE_GRACE": "10", "BGP_COMMUNITY": "64500,42"}.items():
            self.assertEqual(restored[key], value, key)
        self.python(container, r'''
import json
from pathlib import Path
config = Path('/etc/bird/config')
assert json.loads((config / 'settings.json').read_text())['values']['HTTP_PROXY_PASSWORD'] == 'neutral-proxy-secret'
assert 'neutral-proxy-secret' in (config / 'settings.env').read_text()
active = json.loads(Path('/etc/bird/generated/dns-settings.active.json').read_text())
assert active['DNS_PROXY_PORT'] == '53' and active['DNS_ROUTE_GRACE'] == '10'
assert '(64500,42)' in Path('/etc/bird/bird.conf').read_text()
''', user="10001:10001")
        for transport in ("udp", "tcp"):
            self.assertEqual(self.query(container, "persist.selected.test", transport=transport, port=53)["ipv4"], ["1.1.1.2"])
        self.wait_until(container, lambda: "(64500,42)" in self.privilege_peer_route(container),
                        "Persisted BIRD settings were not applied to the exported DNS route")

    def test_dns_routes_regex_exclusions_ttl_and_restart(self):
        volumes = self.prepare_volumes(
            r"regex:^(shared|persist|short|alias|hints|blocked)\.selected\.test$" + "\n",
            r"regex:^direct\.selected\.test$" + "\n")
        container = self.start_runtime(volumes, enabled=True)
        self.start_fixture(container)
        self.wait_until(container, lambda: self.ready(container), "DNS service did not become ready")

        # The bird gate must confirm each change before exposing its DNS answer.
        self.assertEqual(self.query(container, "shared.selected.test")["ipv4"], ["1.1.1.1"])
        self.assert_live_route(container, "1.1.1.1")
        self.assertEqual(self.query(container, "persist.selected.test", transport="tcp")["ipv4"], ["1.1.1.2"])
        self.assert_live_route(container, "1.1.1.2")
        self.assertIn("2001:db8::10", "\n".join(self.query(container, "persist.selected.test", "AAAA")["answer"]))
        self.query(container, "unrelated.test")
        self.assert_live_route(container, "1.1.1.4", present=False)
        self.query(container, "blocked.selected.test")
        self.assert_live_route(container, "192.0.2.10", present=False)
        self.assert_live_route(container, "1.0.0.254", present=False)

        alias = self.query(container, "alias.selected.test")
        self.assertIn("edge.cdn.test.", "\n".join(alias["answer"]))
        self.query(container, "edge.cdn.test")
        self.assert_live_route(container, "1.1.1.3")
        self.query(container, "hints.selected.test", "HTTPS")
        self.assert_live_route(container, "1.1.1.5")

        self.query(container, "direct.selected.test")
        self.assert_live_route(container, "1.1.1.1", present=False)
        self.assert_live_route(container, "1.1.1.2")
        self.wait_until(container, lambda: "[dns_live " in self.route(container, "1.1.1.1"),
                        "Expired exclusion did not restore the included address", timeout=12)
        self.query(container, "short.selected.test")
        self.assert_live_route(container, "1.1.1.6")
        self.wait_until(container, lambda: "[dns_live " not in self.route(container, "1.1.1.6"),
                        "Expired DNS address remained in BIRD", timeout=12)

        events = json.loads(self.python(container,
            "import json; from pathlib import Path; "
            "print(json.dumps([json.loads(line) for line in Path('/tmp/dns-fixture-queries.jsonl').read_text().splitlines()]))").stdout)
        self.assertIn({"name": "shared.selected.test.", "transport": "udp"}, events)
        self.assertIn({"name": "persist.selected.test.", "transport": "tcp"}, events)

        # Recreate the whole container with only the named volumes retained.
        # The new fixture receives no selected query before these assertions.
        self.docker("rm", "-f", container)
        container = self.start_runtime(volumes, enabled=True, suffix="recreated")
        self.start_fixture(container)
        self.wait_until(container, lambda: self.ready(container), "DNS service did not recover after recreation")
        for address in ("1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.5"):
            self.assert_live_route(container, address)
        self.assert_live_route(container, "1.1.1.6", present=False)
        events = self.python(container,
            "from pathlib import Path; print(Path('/tmp/dns-fixture-queries.jsonl').read_text())").stdout
        self.assertNotIn("selected.test", events)
        self.assertNotIn("edge.cdn.test", events)

    def test_internal_wildcards_exclude_media_from_escaped_json_prefix_after_recreation(self):
        volumes = self.prepare_volumes("playlist.*.service.test\n", "media.*.service.test\n")
        seed = r'''
from pathlib import Path
config = Path('/etc/bird/config')
(config / 'fixture-prefixes.json').write_text(r'{"prefixes": ["1.1.2.0\/24"]}' + '\n')
(config / 'lists.txt').write_text('file:///etc/bird/config/fixture-prefixes.json\n')
'''
        self.docker("run", "--rm", "--pull=never", "--network", "none", "-i",
                    "-v", volumes[0] + ":/etc/bird/config", "--entrypoint", "python3", self.image, "-", input=seed)
        container = self.start_runtime(volumes, enabled=True)
        self.start_fixture(container)
        self.wait_until(container, lambda: self.ready(container), "Wildcard DNS policy did not become ready")
        # The source must really cover the media address before its DNS exclusion.
        self.assert_live_route(container, "1.1.2.20")
        self.assert_live_route(container, "1.1.3.10", present=False)
        for domain, address, transport in (("playlist.edge.service.test", "1.1.2.10", "udp"),
                                            ("playlist.other.service.test", "1.1.3.10", "tcp"),
                                            ("media.edge.service.test", "1.1.2.20", "udp")):
            self.assertEqual(self.query(container, domain, transport=transport)["ipv4"], [address])

        def assert_routes(current):
            for address in ("1.1.2.10", "1.1.2.30", "1.1.3.10"):
                self.assert_live_route(current, address)
            self.assertIn("Network not found", self.route(current, "1.1.2.20"))

        assert_routes(container)
        self.docker("rm", "-f", container)
        container = self.start_runtime(volumes, enabled=True, suffix="recreated")
        self.start_fixture(container)
        self.wait_until(container, lambda: self.ready(container), "Wildcard DNS policy did not recover after recreation")
        assert_routes(container)
        events = self.python(container,
            "from pathlib import Path; print(Path('/tmp/dns-fixture-queries.jsonl').read_text())").stdout
        self.assertNotIn("service.test", events)

    def test_disabled_proxy_keeps_static_routes_without_dns_listeners(self):
        volumes = self.prepare_volumes("192.0.2.10\n")
        container = self.start_runtime(volumes, enabled=False)
        self.wait_until(container, lambda: "[static_antifilter " in self.route(container, "192.0.2.10"),
                        "Static route was not installed with DNS proxy disabled")
        check = r'''
from pathlib import Path
import socket
for kind, port in ((socket.SOCK_DGRAM, 5353), (socket.SOCK_STREAM, 5353), (socket.SOCK_STREAM, 8053)):
    with socket.socket(socket.AF_INET, kind) as connection:
        connection.bind(('127.0.0.1', port))
assert not Path('/etc/bird/generated/dns-cache.sqlite3').exists()
'''
        self.python(container, check)
        protocols = self.docker("exec", container, "birdc", "show", "protocols").stdout
        self.assertNotIn("dns_live", protocols)

    def test_large_snapshot_selected_health_and_routes_with_one_second_bgp_gate(self):
        volumes = self.prepare_volumes(r"regex:^(health\.fixture|shared\.selected|persist\.selected)\.test$" + "\n")
        seed = r'''
from pathlib import Path
config = Path('/etc/bird/config')
generated = Path('/etc/bird/generated')
routes = [f'11.{index // 256}.{index % 256}.1/32' for index in range(63065)]
(config / 'large-source.txt').write_text('\n'.join(routes) + '\n')
(config / 'lists.txt').write_text('file:///etc/bird/config/large-source.txt\n')
generated.mkdir(parents=True, exist_ok=True)
(generated / 'routes.last-good.conf').write_text(''.join(f'route {route} blackhole;\n' for route in routes))
'''
        self.docker("run", "--rm", "--pull=never", "--network", "none", "-i",
                    "-v", volumes[0] + ":/etc/bird/config", "-v", volumes[1] + ":/etc/bird/generated",
                    "--entrypoint", "python3", self.image, "-", input=seed)
        container = self.start_runtime(volumes, enabled=True,
                                       overrides={"DNS_SYNC_MODE": "bgp", "DNS_SYNC_TIMEOUT": "1"})
        self.start_fixture(container)
        self.wait_until(container, lambda: self.ready(container), "Large DNS policy did not become ready", timeout=90)
        # Unlike the small fixture, the health query itself selects a route.
        self.wait_until(container, lambda: "[dns_live " in self.route(container, "1.0.0.254"),
                        "Selected health-domain route did not reach BIRD", timeout=10)
        for name, address, transport in (("shared.selected.test", "1.1.1.1", "udp"),
                                         ("persist.selected.test", "1.1.1.2", "tcp")):
            reply = self.query(container, name, transport=transport)
            self.assertEqual(reply["ipv4"], [address])
            self.assertLess(reply["elapsed_seconds"], 1.5)
            # bgp mode confirms sendall; BIRD processes the received update
            # asynchronously, unlike the bird-mode assertions above.
            self.wait_until(container, lambda: "[dns_live " in self.route(container, address),
                            f"Selected route {address} did not reach BIRD", timeout=10)
        check = r'''
import json
from pathlib import Path
from bgp_antifilter.bird_cli import IPV4_ROUTE_ROW, query
routes = [network for network, _ in IPV4_ROUTE_ROW.findall(query(10, 'show', 'route', 'protocol', 'dns_live'))]
assert sum(network.startswith('11.') for network in routes) == 63065, len(routes)
for address in ('1.0.0.254/32', '1.1.1.1/32', '1.1.1.2/32'):
    assert address in routes, address
'''
        self.python(container, check)
        self.python(container, "from pathlib import Path; Path('/tmp/dns-fixture-health-nxdomain').touch()")
        self.assertFalse(self.ready(container))
        state = ("import json; from pathlib import Path; "
                 "s=json.loads(Path('/etc/bird/generated/dns-runtime.json').read_text()); ")
        self.wait_until(container, lambda: self.python(container, state +
                        "print(s['routes_ready'] and not s['ready'] and 'NXDOMAIN' in s['last_error'])").stdout.strip() == "True",
                        "Runtime incorrectly stayed ready after a failed health-domain lookup")
        self.python(container, check)  # A healthy BGP feed cannot hide failed DNS readiness.
        self.python(container, "from pathlib import Path; Path('/tmp/dns-fixture-health-nxdomain').unlink()")
        self.wait_until(container, lambda: self.ready(container), "Readiness did not recover after DNS recovered")
        self.wait_until(container, lambda: self.python(container, state + "print(s['ready'])").stdout.strip() == "True",
                        "Runtime readiness did not recover")
        self.docker("restart", container, timeout=45)
        self.start_fixture(container)
        self.wait_until(container, lambda: self.ready(container), "Large DNS policy did not recover after container restart", timeout=90)
        self.python(container, check)


if __name__ == "__main__":
    unittest.main()
