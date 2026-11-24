"""Proxy configuration and real HTTP/TLS/SOCKS transport on loopback."""

import contextlib
import base64
import errno
import io
import json
import os
from pathlib import Path
import shutil
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from unittest import mock

from bgp_antifilter import container_runtime, http_proxy
from bgp_antifilter.admin import diagnostics, updates
from bgp_antifilter.admin.storage import write_text_atomic
from bgp_antifilter.sources import fetch
from tests.admin_support import admin_application


class HttpProxySettingsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.app = admin_application(Path(temporary.name))
        for path in self.app.config.list_files.values():
            path.write_text("", encoding="utf-8")

    def test_invalid_proxy_settings_rejected_without_writes(self):
        for change in ({"HTTP_PROXY_TYPE": "http"}, {"HTTP_PROXY_TYPE": "ftp"},
                       {"HTTP_PROXY_HOST": "proxy.invalid/path"}, {"HTTP_PROXY_PORT": "0"},
                       {"HTTP_PROXY_PORT": "65536"}, {"HTTP_PROXY_PORT": "1.5"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.app.settings.update_settings(change)
            self.assertFalse(self.app.config.settings_file.exists())

    def test_ipv6_and_legacy_backup_defaults(self):
        old = self.app.backups.export()
        for key in http_proxy.HTTP_PROXY_DEFAULTS:
            del old["settings"][key]
        self.app.settings.update_settings({"HTTP_PROXY_TYPE": "socks5", "HTTP_PROXY_HOST": "2001:db8::80",
                                           "HTTP_PROXY_PORT": "1080"})
        self.assertEqual(http_proxy.configured_proxy(self.app.settings.effective_settings()), "socks5h://[2001:db8::80]:1080")
        self.app.backups.restore(self.app.backups.preview(old)["id"])
        for key, value in http_proxy.HTTP_PROXY_DEFAULTS.items():
            self.assertEqual(self.app.settings.effective_settings()[key], value)

    def test_invalid_proxy_in_backup_rejected_before_restore(self):
        backup = self.app.backups.export()
        backup["settings"]["HTTP_PROXY_TYPE"] = "https"
        with self.assertRaisesRegex(ValueError, "HTTP_PROXY_HOST"):
            self.app.backups.preview(backup)

    def test_password_is_preserved_exactly_but_not_returned_in_settings_or_preview(self):
        secret = '  pw:"\\$?&=☃  '
        self.app.settings.update_settings({"HTTP_PROXY_TYPE": "http", "HTTP_PROXY_HOST": "192.0.2.80",
                                           "HTTP_PROXY_USERNAME": "user", "HTTP_PROXY_PASSWORD": secret})
        self.assertEqual(self.app.settings.effective_settings()["HTTP_PROXY_PASSWORD"], secret)
        self.assertEqual(self.app.settings.command_environment()["HTTP_PROXY_PASSWORD"], secret)
        payload = self.app.settings.settings_payload()
        self.assertNotIn("HTTP_PROXY_PASSWORD", payload["values"])
        self.assertNotIn("HTTP_PROXY_PASSWORD", payload["overrides"])
        item = next(item for section in payload["sections"] for item in section["items"] if item["key"] == "HTTP_PROXY_PASSWORD")
        self.assertEqual((item["value"], item["env_value"], item["has_value"]), ("", "", True))
        self.assertNotIn(secret, json.dumps(payload, ensure_ascii=False))
        self.app.settings.update_settings({"FETCH_TIMEOUT": "15"})
        self.assertEqual(self.app.settings.effective_settings()["HTTP_PROXY_PASSWORD"], secret)
        backup = self.app.backups.export()
        self.assertEqual(backup["settings"]["HTTP_PROXY_PASSWORD"], secret)
        backup["settings"]["HTTP_PROXY_PASSWORD"] = "other secret"
        preview = self.app.backups.preview(backup)
        self.assertEqual(preview["settings"]["HTTP_PROXY_PASSWORD"], {"before": "••••••", "after": "••••••"})
        self.app.backups.restore(preview["id"])
        self.assertEqual(self.app.settings.effective_settings()["HTTP_PROXY_PASSWORD"], "other secret")
        self.app.settings.update_settings({"HTTP_PROXY_PASSWORD": ""})
        self.assertEqual(self.app.settings.effective_settings()["HTTP_PROXY_PASSWORD"], "")
        item = next(item for section in self.app.settings.settings_payload()["sections"] for item in section["items"] if item["key"] == "HTTP_PROXY_PASSWORD")
        self.assertFalse(item["has_value"])

    def test_credentials_reject_controls_colon_user_and_invalid_socks_lengths_without_echoing(self):
        base = {"HTTP_PROXY_TYPE": "http", "HTTP_PROXY_HOST": "192.0.2.80", "HTTP_PROXY_USERNAME": "user"}
        for change in ({"HTTP_PROXY_USERNAME": "user:other"}, {"HTTP_PROXY_PASSWORD": "secret\nline"},
                       {"HTTP_PROXY_PASSWORD": "secret\x00zero"}, {"HTTP_PROXY_PASSWORD": "secret\tvalue"},
                       {"HTTP_PROXY_USERNAME": "", "HTTP_PROXY_PASSWORD": "secret"},
                       {"HTTP_PROXY_TYPE": "socks5", "HTTP_PROXY_PASSWORD": ""},
                       {"HTTP_PROXY_TYPE": "socks5", "HTTP_PROXY_PASSWORD": "я" * 128}):
            with self.subTest(change=list(change)), self.assertRaises(ValueError) as raised:
                self.app.settings.update_settings({**base, **change})
            self.assertNotIn("secret", str(raised.exception))
            self.assertFalse(self.app.config.settings_file.exists())

    @unittest.skipIf(os.name == "nt", "POSIX file permissions")
    def test_private_settings_imports_and_backups_are_created_with_restricted_permissions(self):
        original = Path.replace
        published = []
        def check_temporary(source, target):
            if target.name in {"settings.json", "settings.env"} or target.parent.name in {"config-imports", "config-backups"}:
                self.assertEqual(source.stat().st_mode & 0o777, 0o600)
                published.append(target)
            return original(source, target)
        with mock.patch.object(Path, "replace", check_temporary):
            self.app.settings.update_settings({"HTTP_PROXY_USERNAME": "user", "HTTP_PROXY_PASSWORD": "secret"})
            backup = self.app.backups.export()
            backup["settings"]["HTTP_PROXY_PASSWORD"] = "replacement"
            self.app.backups.restore(self.app.backups.preview(backup)["id"])
        self.assertGreaterEqual(len(published), 6)
        for path in published:
            if path.exists():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        target = self.app.config.settings_env_file
        target.chmod(0o644)
        with mock.patch.object(Path, "replace", side_effect=OSError(errno.EBUSY, "busy")):
            write_text_atomic(target, "private", mode=0o600)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(target.read_text(), "private")

    @unittest.skipUnless(shutil.which("sh"), "Credential reload requires POSIX sh")
    def test_credentials_roundtrip_through_scheduler_shell_and_reset_in_child(self):
        credentials = ['user "\\$ ', '  pw:"\\$?&=☃  ']
        self.app.settings.update_settings({"HTTP_PROXY_TYPE": "http", "HTTP_PROXY_HOST": "192.0.2.80",
                                           "HTTP_PROXY_USERNAME": credentials[0], "HTTP_PROXY_PASSWORD": credentials[1]})
        probe = self.app.config.config_dir / "credentials-probe.py"
        probe.write_text('import json, os\nprint(json.dumps([os.environ["HTTP_PROXY_USERNAME"], os.environ["HTTP_PROXY_PASSWORD"]]))\n', encoding="utf-8")
        environment = {key: value for key, value in os.environ.items() if key not in http_proxy.HTTP_PROXY_DEFAULTS
                       and not key.startswith("BGP_BASE_HTTP_PROXY_")}
        environment.update(LIB=(Path(__file__).resolve().parents[1] / "deploy/lib.sh").as_posix(),
                           SETTINGS_ENV_FILE=self.app.config.settings_env_file.as_posix(),
                           PYTHON=sys.executable, PROBE=probe.as_posix())
        script = '''. "$LIB"
load_settings_env
"$PYTHON" "$PROBE"
: > "$SETTINGS_ENV_FILE"
sh -eu -c '. "$LIB"; load_settings_env; "$PYTHON" "$PROBE"'
load_settings_env
"$PYTHON" "$PROBE"
'''
        result = subprocess.run(["sh", "-eu", "-c", script], env=environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([json.loads(line) for line in result.stdout.splitlines()], [credentials, ["", ""], ["", ""]])

    def test_panel_uses_container_base_after_shell_loads_overrides(self):
        env = {"HTTP_PROXY_TYPE": "socks5", "HTTP_PROXY_HOST": "192.0.2.10", "HTTP_PROXY_PORT": "1080",
               "BGP_BASE_HTTP_PROXY_TYPE": "environment", "BGP_BASE_HTTP_PROXY_HOST": "", "BGP_BASE_HTTP_PROXY_PORT": "8080"}
        with mock.patch.dict(os.environ, env):
            self.assertEqual(self.app.settings.effective_settings()["HTTP_PROXY_TYPE"], "environment")
            self.assertEqual(self.app.settings.effective_settings()["HTTP_PROXY_HOST"], "")

    def test_release_cache_refreshes_when_proxy_settings_change(self):
        release = {"version": "9.9.9", "tag_name": "v9.9.9", "html_url": "https://example.test/release",
                   "name": "Test", "published_at": ""}
        with mock.patch.object(updates, "github_latest_release", return_value=release) as request:
            self.app.updates.update_status_payload()
            self.app.updates.update_status_payload()
            self.assertEqual(request.call_count, 1)
            self.app.settings.update_settings({"HTTP_PROXY_TYPE": "http", "HTTP_PROXY_HOST": "192.0.2.80"})
            self.app.updates.update_status_payload()
            self.assertEqual(request.call_count, 2)
            self.assertEqual(request.call_args.kwargs["settings"]["HTTP_PROXY_HOST"], "192.0.2.80")
            self.app.settings.update_settings({"HTTP_PROXY_USERNAME": "user", "HTTP_PROXY_PASSWORD": "updated"})
            self.app.updates.update_status_payload()
            self.assertEqual(request.call_count, 3)

    def test_environment_proxy_precedes_custom_dns_and_respects_no_proxy(self):
        with mock.patch.dict(os.environ, {"HTTP_PROXY_TYPE": "environment"}), \
             mock.patch.object(urllib.request, "getproxies", return_value={"http": "http://127.0.0.1:8080"}), \
             mock.patch.object(urllib.request, "proxy_bypass", return_value=False) as bypass, \
             mock.patch.object(fetch, "fetch_via_custom_dns", return_value="direct") as custom, \
             mock.patch.object(fetch, "open_url", return_value=io.BytesIO(b"proxy")):
            self.assertEqual(fetch.fetch_url("http://sources.test/routes", attempts=1, dns_nameservers=["192.0.2.53"]), "proxy")
            custom.assert_not_called()
            bypass.return_value = True
            self.assertEqual(fetch.fetch_url("http://sources.test/routes", attempts=1, dns_nameservers=["192.0.2.53"]), "direct")
            custom.assert_called_once()

    def test_internal_dns_health_ignores_environment_proxy(self):
        response = mock.MagicMock()
        response.__enter__.return_value.status = 200
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch("bgp_antifilter.dns_settings.load_active_environment", return_value={"DNS_PROXY_ENABLED": "1"}), \
             mock.patch.object(urllib.request, "build_opener", return_value=opener) as build, \
             mock.patch.dict(os.environ, {"HTTP_PROXY": "http://192.0.2.80:8080"}), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(container_runtime.main(["dns-health"]), 0)
        self.assertEqual(build.call_args.args[0].proxies, {})
        opener.open.assert_called_once_with("http://127.0.0.1:8053/ready", timeout=3)

    def test_custom_dns_redirect_rechecks_environment_proxy_after_no_proxy_host(self):
        connection = mock.MagicMock()
        connection.getresponse.return_value.status = 302
        connection.getresponse.return_value.getheader.return_value = "https://external.example/routes"
        with mock.patch.dict(os.environ, {"HTTP_PROXY_TYPE": "environment"}), \
             mock.patch.object(urllib.request, "getproxies", return_value={"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}), \
             mock.patch.object(urllib.request, "proxy_bypass", side_effect=lambda host: host == "internal.example"), \
             mock.patch.object(fetch.http.client, "HTTPConnection", return_value=connection), \
             mock.patch.object(fetch.dns_resolver, "resolve_ipv4_addresses", return_value=["192.0.2.1"]) as resolve, \
             mock.patch.object(fetch, "open_url", return_value=io.BytesIO(b"192.0.2.0/24\n")) as proxy:
            self.assertEqual(fetch.fetch_url("http://internal.example/routes", attempts=1, dns_nameservers=["192.0.2.53"]), "192.0.2.0/24\n")
        self.assertEqual(resolve.call_count, 1)
        self.assertEqual(resolve.call_args.args, ("internal.example",))
        self.assertEqual(proxy.call_count, 1)
        self.assertEqual(proxy.call_args.args[0].full_url, "https://external.example/routes")


class _ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ProxyHandler(socketserver.StreamRequestHandler):
    def read_headers(self):
        headers = {}
        while True:
            line = self.rfile.readline()
            if line in {b"\r\n", b"\n", b""}:
                return headers
            name, value = line.decode("ascii").split(":", 1)
            headers[name.lower()] = value.strip()

    def finish(self):
        try:
            super().finish()
        finally:
            self.connection.close()

    def handle(self):
        if self.server.tls_proxy:
            self.connection = self.server.tls.wrap_socket(self.request, server_side=True)
            self.rfile = self.connection.makefile("rb")
            self.wfile = self.connection.makefile("wb")
        if self.server.socks:
            header = self.rfile.read(2)
            methods = self.rfile.read(header[1])
            method = 2 if self.server.credentials else 0
            if method not in methods:
                self.wfile.write(b"\x05\xff")
                self.wfile.flush()
                return
            self.wfile.write(bytes((5, method)))
            self.wfile.flush()
            if method == 2:
                version, length = self.rfile.read(2)
                username = self.rfile.read(length).decode("utf-8")
                password = self.rfile.read(self.rfile.read(1)[0]).decode("utf-8")
                success = version == 1 and (username, password) == self.server.credentials
                self.wfile.write(bytes((1, 0 if success else 1)))
                self.wfile.flush()
                if not success:
                    return
            command = self.rfile.read(4)
            if command[3] != 3:
                return
            host = self.rfile.read(self.rfile.read(1)[0]).decode("ascii")
            port = int.from_bytes(self.rfile.read(2), "big")
            self.server.events.append(("SOCKS", host, port))
            self.wfile.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50")
            self.wfile.flush()
            if port == 443:
                self._tls_tunnel()
        line = self.rfile.readline().decode("ascii").strip()
        headers = self.read_headers()
        self.server.events.append(line)
        if self.server.credentials and not self.server.socks:
            expected = "Basic " + base64.b64encode(":".join(self.server.credentials).encode("utf-8")).decode("ascii")
            if headers.get("proxy-authorization") != expected:
                self.wfile.write(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="test"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                self.wfile.flush()
                return
        if line.startswith("CONNECT "):
            self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            self.wfile.flush()
            self._tls_tunnel()
            line = self.rfile.readline().decode("ascii").strip()
            self.server.origin_headers = self.read_headers()
            self.server.events.append(line)
        target = line.split(" ")[1]
        if urlsplit(target).path == "/redirect":
            self.wfile.write(b"HTTP/1.1 302 Found\r\nLocation: http://redirect.invalid/routes\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        elif urlsplit(target).path == "/fail":
            self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        else:
            payload = self.server.payload
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(payload)).encode() + b"\r\nConnection: close\r\n\r\n" + payload)
        self.wfile.flush()

    def _tls_tunnel(self):
        self.wfile.flush()
        self.connection = self.server.tls.wrap_socket(self.connection, server_side=True)
        self.rfile = self.connection.makefile("rb")
        self.wfile = self.connection.makefile("wb")


class HttpProxyTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("curl"):
            raise unittest.SkipTest("curl is required for proxy transport tests")
        openssl = shutil.which("openssl")
        if not openssl and os.name == "nt":
            candidate = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/usr/bin/openssl.exe"
            openssl = str(candidate) if candidate.exists() else None
        if not openssl:
            raise unittest.SkipTest("openssl is required for local TLS fixtures")
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.certificate = Path(temporary.name) / "certificate.pem"
        key = Path(temporary.name) / "key.pem"
        subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-keyout", str(key), "-out", str(cls.certificate), "-subj", "/CN=origin.invalid",
                        "-addext", "subjectAltName=DNS:origin.invalid,IP:127.0.0.1"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=15)
        cls.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.tls.load_cert_chain(cls.certificate, key)

    def proxy(self, kind="http", payload=b"192.0.2.0/24\r\n", credentials=None):
        server = _ProxyServer(("127.0.0.1", 0), _ProxyHandler)
        server.socks, server.tls_proxy = kind == "socks5", kind == "https"
        server.tls, server.events, server.payload = self.tls, [], payload
        server.credentials = credentials
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        values = {"HTTP_PROXY_TYPE": kind, "HTTP_PROXY_HOST": "127.0.0.1", "HTTP_PROXY_PORT": str(server.server_address[1])}
        return server, values

    def test_http_proxy_handles_sources_and_redirects_without_local_dns_or_bypass(self):
        server, values = self.proxy()
        with mock.patch.dict(os.environ, {**values, "NO_PROXY": "*"}), \
             mock.patch.object(fetch, "fetch_via_custom_dns", side_effect=AssertionError("direct DNS used")), \
             mock.patch.object(urllib.request, "urlopen", side_effect=AssertionError("direct fallback used")):
            self.assertEqual(fetch.fetch_url("http://origin.invalid/redirect", attempts=1, timeout=3,
                                            dns_nameservers=["192.0.2.53"]), "192.0.2.0/24\n")
        self.assertIn("GET http://origin.invalid/redirect HTTP/1.1", server.events)
        self.assertIn("GET http://redirect.invalid/routes HTTP/1.1", server.events)

    def test_socks5_sends_hostname_to_proxy_for_remote_resolution(self):
        server, values = self.proxy("socks5")
        with http_proxy.open_url("http://origin.invalid/routes", timeout=3, settings=values) as result:
            self.assertEqual(result.read(), b"192.0.2.0/24\r\n")
        self.assertIn(("SOCKS", "origin.invalid", 80), server.events)

    def test_http_https_and_socks5_authenticate_with_exact_special_characters(self):
        credentials = ('user "\\$ ', '  pw:"\\$?&=☃  ')
        run = subprocess.run
        for kind in ("http", "https", "socks5"):
            with self.subTest(kind=kind):
                server, values = self.proxy(kind, credentials=credentials)
                values.update(HTTP_PROXY_USERNAME=credentials[0], HTTP_PROXY_PASSWORD=credentials[1])
                def trusted_fixture(command, **kwargs):
                    if kind == "https":
                        command = [*command[:2], "--proxy-cacert", str(self.certificate), *command[2:]]
                    return run(command, **kwargs)
                with mock.patch.object(http_proxy.subprocess, "run", side_effect=trusted_fixture) as invoke:
                    with http_proxy.open_url("http://origin.invalid/routes", timeout=3, settings=values) as result:
                        self.assertEqual(result.read(), server.payload)
                command = invoke.call_args.args[0]
                self.assertNotIn(credentials[0], " ".join(command))
                self.assertNotIn(credentials[1], " ".join(command))
                self.assertNotIn("HTTP_PROXY_PASSWORD", invoke.call_args.kwargs["env"])
                self.assertNotIn("BGP_BASE_HTTP_PROXY_PASSWORD", invoke.call_args.kwargs["env"])
                self.assertIn(b"proxy-user", invoke.call_args.kwargs["input"])

    def test_wrong_credentials_fail_without_direct_fallback_or_password_in_errors(self):
        credentials = ("user", "correct password")
        for kind in ("http", "socks5"):
            with self.subTest(kind=kind):
                _, values = self.proxy(kind, credentials=credentials)
                values.update(HTTP_PROXY_USERNAME="user", HTTP_PROXY_PASSWORD="wrong password")
                with mock.patch.object(urllib.request, "urlopen", side_effect=AssertionError("direct fallback")), \
                     self.assertRaises(urllib.error.URLError) as raised:
                    http_proxy.open_url("http://origin.invalid/routes", timeout=3, settings=values)
                self.assertNotIn("wrong password", str(raised.exception))
                self.assertNotIn("correct password", str(raised.exception))

    def test_authenticated_connect_does_not_forward_proxy_authorization_to_origin(self):
        server, values = self.proxy(credentials=("user", "secret"))
        values.update(HTTP_PROXY_USERNAME="user", HTTP_PROXY_PASSWORD="secret")
        run = subprocess.run
        def trusted_fixture(command, **kwargs):
            return run([*command[:2], "--cacert", str(self.certificate), *command[2:]], **kwargs)
        with mock.patch.object(http_proxy.subprocess, "run", side_effect=trusted_fixture):
            with http_proxy.open_url("https://origin.invalid/routes", timeout=3, settings=values) as result:
                self.assertEqual(result.read(), server.payload)
        self.assertNotIn("proxy-authorization", server.origin_headers)

    def test_authentication_error_cannot_echo_secrets_from_proxy_stderr(self):
        values = {"HTTP_PROXY_TYPE": "http", "HTTP_PROXY_HOST": "192.0.2.80", "HTTP_PROXY_PORT": "8080",
                  "HTTP_PROXY_USERNAME": "private-user", "HTTP_PROXY_PASSWORD": "private-password"}
        result = subprocess.CompletedProcess([], 22, b"", b"private-user:private-password")
        with mock.patch.object(http_proxy.subprocess, "run", return_value=result), self.assertRaises(urllib.error.URLError) as raised:
            http_proxy.open_url("https://origin.invalid/routes", timeout=3, settings=values)
        self.assertEqual(str(raised.exception), "<urlopen error HTTP proxy request failed (curl exit code 22)>")

    def test_https_origin_uses_connect_and_validates_its_certificate(self):
        server, values = self.proxy()
        run = subprocess.run
        def trusted_fixture(command, **kwargs):
            return run([*command[:2], "--cacert", str(self.certificate), *command[2:]], **kwargs)
        with mock.patch.object(http_proxy.subprocess, "run", side_effect=trusted_fixture):
            with http_proxy.open_url("https://origin.invalid/routes", timeout=3, settings=values) as result:
                self.assertEqual(result.read(), b"192.0.2.0/24\r\n")
        self.assertIn("CONNECT origin.invalid:443 HTTP/1.1", server.events)

    def test_tls_validation_and_timeout_are_not_disabled_by_proxy_selection(self):
        _, values = self.proxy()
        with mock.patch.object(http_proxy.subprocess, "run", return_value=subprocess.CompletedProcess([], 60, b"", b"certificate verify failed")) as run, \
             self.assertRaisesRegex(urllib.error.URLError, "certificate verify failed"):
            http_proxy.open_url("https://origin.invalid/routes", timeout=3, settings=values)
        command = run.call_args.args[0]
        self.assertEqual(command[:2], ["curl", "--disable"])
        self.assertNotIn("--insecure", command)
        self.assertNotIn("--proxy-insecure", command)
        self.assertEqual(command[command.index("--noproxy") + 1], "")
        self.assertEqual(command[command.index("--proto-redir") + 1], "=http,https")
        self.assertEqual(run.call_args.kwargs["timeout"], 5)

    def test_https_proxy_tls_is_supported_with_a_trusted_certificate(self):
        server, values = self.proxy("https")
        run = subprocess.run
        def trusted_fixture(command, **kwargs):
            return run([*command[:2], "--proxy-cacert", str(self.certificate), *command[2:]], **kwargs)
        with mock.patch.object(http_proxy.subprocess, "run", side_effect=trusted_fixture):
            with http_proxy.open_url("http://origin.invalid/routes", timeout=3, settings=values) as result:
                self.assertEqual(result.read(), b"192.0.2.0/24\r\n")
        self.assertIn("GET http://origin.invalid/routes HTTP/1.1", server.events)

    def test_proxy_failure_does_not_attempt_direct_transport(self):
        _, values = self.proxy()
        with mock.patch.object(urllib.request, "urlopen", side_effect=AssertionError("direct fallback used")), \
             self.assertRaises(urllib.error.URLError):
            http_proxy.open_url("http://origin.invalid/fail", timeout=3, settings=values)

    def test_external_ip_and_release_checks_share_the_selected_proxy(self):
        server, values = self.proxy(payload=json.dumps({"status": "success", "query": "192.0.2.7"}).encode())
        with mock.patch.object(diagnostics, "IP_API_URL", "http://origin.invalid/ip"):
            self.assertEqual(diagnostics.external_ip_summary(settings=values)["query"], "192.0.2.7")
        server.payload = json.dumps({"tag_name": "v9.9.9"}).encode()
        with mock.patch.object(updates, "LATEST_RELEASE_API_URL", "http://origin.invalid/latest"):
            self.assertEqual(updates.github_latest_release(settings=values)["version"], "9.9.9")
        self.assertEqual(len(server.events), 2)

    def test_none_ignores_environment_proxy(self):
        server, values = self.proxy()
        url = f"http://127.0.0.1:{server.server_address[1]}/direct"
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:1", "http_proxy": "http://127.0.0.1:1", "NO_PROXY": ""}):
            with http_proxy.open_url(url, timeout=3, settings={"HTTP_PROXY_TYPE": "none"}) as result:
                self.assertEqual(result.read(), server.payload)
        self.assertIn("GET /direct HTTP/1.1", server.events)


if __name__ == "__main__":
    unittest.main()
