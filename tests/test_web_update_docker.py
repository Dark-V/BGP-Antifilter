"""Real image pull, self-replacement and rollback through the admin HTTP API.

Opt in with RUN_DOCKER_WEB_UPDATE=1. Only GitHub release discovery is replaced
with a local fixture; Docker, Compose, BIRD, health checks and HTTP are real.
All containers, image tags and volumes belong to a unique temporary project.
"""

import http.cookiejar
import inspect
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import uuid
from unittest import mock

from bgp_antifilter import updater_server


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get("RUN_DOCKER_WEB_UPDATE") == "1" and shutil.which("docker") and os.name != "nt",
                     "requires RUN_DOCKER_WEB_UPDATE=1 and a Linux Docker engine")
class WebUpdateDockerTests(unittest.TestCase):
    def docker(self, *args, check=True, input=None):
        result = subprocess.run(["docker", *args], text=True, input=input, capture_output=True, timeout=240)
        if check and result.returncode:
            self.fail(f"docker {' '.join(args)} failed:\n{result.stdout[-3000:]}\n{result.stderr[-3000:]}")
        return result.stdout.strip()

    def compose(self, *args, check=True):
        options = ["--env-file", str(self.env_file), "-p", self.project,
                   "-f", str(self.root / "compose.yaml"), *args]
        if self.compose_v2:
            return self.docker("compose", *options, check=check)
        result = subprocess.run(["docker-compose", *options], text=True, capture_output=True, timeout=240)
        if check and result.returncode:
            self.fail(f"compose failed:\n{result.stdout[-3000:]}\n{result.stderr[-3000:]}")
        return result.stdout.strip()

    def wait(self, predicate, message, timeout=90):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            try:
                value = predicate()
                if value:
                    return value
            except (OSError, ValueError, urllib.error.URLError) as exc:
                last = exc
            time.sleep(0.5)
        runtime = (self.root / "generated/update-runtime.json")
        try:
            details = runtime.read_text(encoding="utf-8")
        except OSError as exc:
            details = f"update runtime is unavailable to the test runner: {exc}"
        self.fail(f"{message}: {last}\n{details}\n{self.compose('logs', '--tail=50', check=False)}")

    def setUp(self):
        self.compose_v2 = subprocess.run(["docker", "compose", "version"], capture_output=True).returncode == 0
        self.project = "bgp-web-test-" + uuid.uuid4().hex[:10]
        self.tags = []
        self.registry_name = self.project + "-registry"
        self.temporary = tempfile.TemporaryDirectory(prefix=self.project)
        self.root = Path(self.temporary.name)
        # The host workspace remains private; self-update must still work.
        self.root.chmod(0o700)
        self.workspace_owner = (self.root.stat().st_uid, self.root.stat().st_gid)
        self.env_file = self.root / ".env"
        self.addCleanup(self.cleanup)
        if self.docker("info", "--format", "{{.OSType}}") != "linux":
            self.skipTest("requires a Linux Docker engine")
        base = os.environ.get("WEB_UPDATE_TEST_IMAGE", "bgp-antifilter:web-update-test")
        correction = os.environ.get("WEB_UPDATE_VERSION_CORRECTION") == "1"
        self.correction = correction
        self.initial_version, self.updated_version, self.missing_version, self.broken_version = (
            ("6.0.2", "1.0.1", "1.0.2", "1.0.3") if correction else ("1.0.0", "1.0.1", "1.0.2", "1.0.3"))
        if "WEB_UPDATE_TEST_IMAGE" not in os.environ:
            self.docker("build", "-t", base, "-f", str(ROOT / "deploy/Dockerfile"), str(ROOT))
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.registry_port = reservation.getsockname()[1]
        self.docker("run", "-d", "--rm", "--name", self.registry_name, "--network", "host",
                    "-e", f"REGISTRY_HTTP_ADDR=127.0.0.1:{self.registry_port}", "registry:2")
        self.repository = f"127.0.0.1:{self.registry_port}/{self.project}"
        # The admin uses the real application, with deterministic release metadata.
        (self.root / "admin-fixture.py").write_text(
            "#!/usr/bin/env python3\nfrom pathlib import Path\n"
            "from bgp_antifilter.admin import updates\n"
            "from bgp_antifilter.admin.server import main\n"
            "def latest(timeout=5, settings=None):\n"
            "    v = Path('/test-release').read_text().strip()\n"
            "    return dict(version=v, tag_name='v'+v, html_url='https://example.test/release', name='Test', published_at='')\n"
            "updates.github_latest_release = latest\nraise SystemExit(main())\n", encoding="utf-8")
        helper = inspect.getsource(updater_server.is_newer_version)
        (self.root / "transition-fixture.py").write_text(
            "from pathlib import Path\n"
            "p=Path('/bgp_antifilter/updater_server.py')\ns=p.read_text()\n"
            "old='if tuple(map(int, target_version.split(\".\"))) <= tuple(map(int, validate_version(previous_version).split(\".\"))):'\n"
            "assert s.count(old)==1\n"
            "s=s.replace(old,'if not is_newer_version(target_version, previous_version):')\n"
            f"s=s.replace('def runtime_payload():',{(helper + chr(10) + 'def runtime_payload():')!r},1)\np.write_text(s)\n"
            "p=Path('/bgp_antifilter/admin/updates.py')\ns=p.read_text()\n"
            "old='parse_semver(latest[\"version\"]) > parse_semver(current_version)'\nassert s.count(old)==1\n"
            "p.write_text(s.replace(old,'updater_server.is_newer_version(latest[\"version\"], current_version)'))\n", encoding="utf-8")
        for version in (self.initial_version, self.updated_version, self.broken_version):
            tag = f"{self.repository}:{version}"
            self.tags.append(tag)
            broken = "RUN printf '#!/bin/sh\\nexit 1\\n' > /healthcheck.sh\n" if version == self.broken_version else ""
            source = "ghcr.io/leonidoz/bgp-antifilter:6.0.2" if correction and version == self.initial_version else base
            bootstrap = "COPY transition-fixture.py /tmp/transition.py\nRUN python3 /tmp/transition.py\n" if correction and version == self.initial_version else ""
            dockerfile = (f"FROM {source}\n" + bootstrap + "COPY admin-fixture.py /admin-server.py\n"
                          f"RUN chmod +x /admin-server.py && echo {version} > /VERSION\n" + broken)
            self.docker("build", "-t", tag, "-f", "-", str(self.root), input=dockerfile)
            self.docker("push", tag)
        # The target image must actually be pulled from the registry during update.
        for tag in self.tags[1:]:
            self.docker("image", "rm", tag)
        self.env_file.write_text(f"# preserve this file on rollback\nBGP_ANTIFILTER_VERSION={self.initial_version}\n", encoding="utf-8")
        if not correction:
            self.env_file.chmod(0o600)
        self.env_owner = (self.env_file.stat().st_uid, self.env_file.stat().st_gid)
        (self.root / "latest").write_text(self.updated_version, encoding="utf-8")
        config = self.root / "config"
        config.mkdir()
        (self.root / "generated").mkdir()
        (config / "source.txt").write_text("192.0.2.0/24\n", encoding="utf-8")
        (config / "lists.txt").write_text("file:///etc/bird/config/source.txt\n", encoding="utf-8")
        for name in ("domain-list-urls", "include-asns", "include-countries", "include-domains", "exclude-domains"):
            (config / f"{name}.txt").write_text("# retain user data\n", encoding="utf-8")
        self.marker = (config / "include-domains.txt").read_bytes()
        (self.root / "compose.yaml").write_text(
            f"services:\n  bgp-antifilter:\n    image: '{self.repository}:${{BGP_ANTIFILTER_VERSION}}'\n"
            "    hostname: custom-updater-host\n"
            "    ports: ['127.0.0.1::8080']\n"
            "    volumes:\n      - './:/workspace'\n      - './config:/etc/bird/config'\n"
            "      - './latest:/test-release:ro'\n"
            "      - './generated:/etc/bird/generated'\n      - '/var/run/docker.sock:/var/run/docker.sock'\n"
            "    environment:\n      ADMIN_ENABLED: '1'\n      ADMIN_PASSWORD: test-password\n"
            "      HOSTNAME: deliberately-wrong-hostname\n"
            "      HEALTHCHECK_REQUIRE_BGP: '0'\n      INCLUDE_GOOGLE_RANGES: '0'\n"
            "      BIRD_IP: '127.0.0.1'\n      ROUTER_ID: '127.0.0.1'\n      UPDATE_INTERVAL: '86400'\n"
            "      COMPOSE_FILE: /workspace/compose.yaml\n      UPDATER_HEALTH_TIMEOUT: '8'\n"
            "      UPDATE_RUNTIME_FILE: /etc/bird/generated/update-runtime.json\n"
            "    healthcheck:\n      test: ['CMD', '/healthcheck.sh']\n      interval: 1s\n"
            "      timeout: 3s\n      retries: 1\n      start_period: 1s\n", encoding="utf-8")
        self.compose("up", "-d")
        self.wait(lambda: self.info()["State"].get("Health", {}).get("Status") == "healthy", "initial image unhealthy")
        if not correction:
            self.make_private_runtime()
        self.login()

    def cleanup(self):
        if (self.root / "compose.yaml").exists():
            self.docker("rm", "-f", self.project + "-image-updater", check=False)
            self.compose("down", "--volumes", "--remove-orphans", check=False)
        self.docker("rm", "-f", self.registry_name, check=False)
        for tag in self.tags:
            self.docker("image", "rm", tag, check=False)
        if os.name != "nt":
            # Restore the isolated fixture to the test runner after both uids wrote files.
            base = os.environ.get("WEB_UPDATE_TEST_IMAGE", "bgp-antifilter:web-update-test")
            self.docker("run", "--rm", "--entrypoint", "chown", "-v", f"{self.root}:/test",
                        base, "-R", f"{os.getuid()}:{os.getgid()}", "/test", check=False)
        self.temporary.cleanup()

    def info(self):
        cid = self.compose("ps", "-q", "bgp-antifilter")
        if not cid:
            raise ValueError("application is restarting")
        result = subprocess.run(["docker", "inspect", cid], text=True, capture_output=True, timeout=20)
        if result.returncode:
            if any(message in result.stderr.lower() for message in
                   (f"no such object: {cid}", f"no such container: {cid}")):
                raise ValueError("application is restarting")
            self.fail(f"docker inspect {cid} failed:\n{result.stdout[-3000:]}\n{result.stderr[-3000:]}")
        return json.loads(result.stdout)[0]

    def api(self, path, data=None):
        info = self.info()
        if os.environ.get("WEB_UPDATE_TEST_INTERNAL") == "1":
            host = next(iter(info["NetworkSettings"]["Networks"].values()))["IPAddress"]
            port = "8080"
        else:
            host = "127.0.0.1"
            port = info["NetworkSettings"]["Ports"]["8080/tcp"][0]["HostPort"]
        body = json.dumps(data).encode() if data is not None else None
        request = urllib.request.Request(f"http://{host}:{port}{path}", body,
                                         {"Content-Type": "application/json"})
        with self.opener.open(request, timeout=20) as response:
            return response.status, json.load(response)

    def login(self):
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                  urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.wait(lambda: self.api("/api/login", {"password": "test-password"})[1].get("ok"), "login failed")

    def finished(self):
        # Check from the app uid: a root-owned 0600 publish must fail this test.
        info = self.info()
        cid = info["Id"]
        # The original 6.0.2 image still runs as root and has /etc/bird 0750.
        legacy = self.correction and info.get("Config", {}).get("Image") == f"{self.repository}:{self.initial_version}"
        runtime_user = "0:0" if legacy else "10001:10001"
        result = subprocess.run([
            "docker", "exec", "--user", runtime_user, cid, "python3", "-c",
            "from pathlib import Path; print(Path('/etc/bird/generated/update-runtime.json').read_text())",
        ], text=True, capture_output=True, timeout=20)
        if result.returncode:
            if any(message in result.stderr.lower() for message in
                   (f"no such container: {cid}", f"container {cid} is not running",
                    f"container {cid} is restarting")):
                return None
            if "PermissionError" in result.stderr and info.get("State", {}).get("Health", {}).get("Status") == "starting":
                # Bootstrap has not yet reassigned the previous image's files.
                return None
            self.fail(f"cannot read update runtime as {runtime_user}:\n{result.stderr[-3000:]}")
        value = json.loads(result.stdout)
        return value if value.get("active") is False else None

    def make_private_runtime(self):
        self.docker("exec", "--user", "10001:10001", self.info()["Id"], "python3", "-c",
                    "from pathlib import Path; p=Path('/etc/bird/generated/update-runtime.json'); "
                    "p.write_text('{}'); p.chmod(0o600)")

    def assert_nonroot_update_access(self):
        info = self.info()
        status = self.docker("exec", info["Id"], "python3", "-c",
                             "from pathlib import Path\n"
                             "for p in Path('/proc').glob('[0-9]*'):\n"
                             "    try:\n"
                             "        if b'/admin-server.py' in (p/'cmdline').read_bytes().split(b'\\0'):\n"
                             "            print((p/'status').read_text()); break\n"
                             "    except OSError: pass\n"
                             "else: raise SystemExit('admin process is missing')\n")
        self.assertIn("Uid:\t10001\t10001\t10001\t10001", status)
        self.assertEqual((self.root.stat().st_uid, self.root.stat().st_gid), self.workspace_owner)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        if not self.correction:
            self.assertEqual((self.env_file.stat().st_uid, self.env_file.stat().st_gid), self.env_owner)
            self.assertEqual(self.env_file.stat().st_mode & 0o777, 0o600)
            runtime = self.root / "generated/update-runtime.json"
            self.assertEqual((runtime.stat().st_uid, runtime.stat().st_gid), (10001, 10001))
            self.assertEqual(runtime.stat().st_mode & 0o777, 0o600)

    def test_real_http_upgrade_pull_failure_and_unhealthy_rollback(self):
        original_id = self.info()["Id"]
        code, payload = self.api("/api/update/status?force=1")
        self.assertTrue(payload["apply_available"], payload)
        self.assertEqual(self.api("/api/update/apply", {"version": self.updated_version})[0], 202)
        result = self.wait(self.finished, "upgrade did not finish")
        self.assertTrue(result["success"], result)
        self.assertNotEqual(self.info()["Id"], original_id)
        self.assertTrue(self.info()["Config"]["Image"].endswith(":" + self.updated_version))
        self.assertEqual(self.info()["State"]["Health"]["Status"], "healthy")
        self.assertEqual((self.root / "config/include-domains.txt").read_bytes(), self.marker)
        self.assert_nonroot_update_access()
        self.login()
        self.assertEqual(self.api("/api/update/status?force=1")[1]["current_version"], self.updated_version)

        stable_id = self.info()["Id"]
        stable_env = self.env_file.read_bytes()
        (self.root / "latest").write_text(self.missing_version, encoding="utf-8")  # missing registry tag
        self.assertEqual(self.api("/api/update/apply", {"version": self.missing_version})[0], 202)
        result = self.wait(self.finished, "pull failure did not finish")
        self.assertFalse(result["success"], result)
        self.assertTrue(result["rollback"]["ok"], result)
        self.assertEqual(self.info()["Id"], stable_id, "failed pull must not restart the working container")
        self.assertEqual(self.env_file.read_bytes(), stable_env)

        (self.root / "latest").write_text(self.broken_version, encoding="utf-8")  # starts, but fails health check
        self.assertEqual(self.api("/api/update/apply", {"version": self.broken_version})[0], 202)
        result = self.wait(self.finished, "unhealthy upgrade did not roll back")
        self.assertFalse(result["success"], result)
        self.assertIn("health verification failed", result["error"])
        self.assertTrue(result["rollback"]["ok"], result)
        self.assertTrue(self.info()["Config"]["Image"].endswith(":" + self.updated_version))
        self.assertEqual(self.info()["State"]["Health"]["Status"], "healthy")
        self.assertEqual(self.env_file.read_bytes(), stable_env)
        self.assertEqual((self.root / "config/include-domains.txt").read_bytes(), self.marker)
        self.assert_nonroot_update_access()
        self.login()
        payload = self.api("/api/update/status?force=1")[1]
        self.assertEqual(payload["current_version"], self.updated_version)
        self.assertFalse(payload["runtime"]["success"])


@unittest.skipUnless(os.environ.get("RUN_DOCKER_WEB_UPDATE") == "1" and shutil.which("docker") and os.name == "nt",
                     "Windows launcher for the Linux integration test")
class WindowsWebUpdateDockerTests(unittest.TestCase):
    def test_update_in_linux_workspace(self):
        base = os.environ.get("WEB_UPDATE_TEST_IMAGE", "bgp-antifilter:web-update-test")
        if "WEB_UPDATE_TEST_IMAGE" not in os.environ:
            subprocess.run(["docker", "build", "-t", base, "-f", str(ROOT / "deploy/Dockerfile"), str(ROOT)], check=True)
        volume = "bgp-web-test-workspace-" + uuid.uuid4().hex[:10]
        runner = volume + "-runner"
        subprocess.run(["docker", "volume", "create", volume], check=True, capture_output=True)
        mountpoint = json.loads(subprocess.check_output(["docker", "volume", "inspect", volume], text=True))[0]["Mountpoint"]
        try:
            result = subprocess.run([
                "docker", "run", "--rm", "--name", runner, "--network", "host", "--entrypoint", "python3",
                "-v", f"{ROOT}:/test-repo:ro", "-v", "/var/run/docker.sock:/var/run/docker.sock",
                "-v", f"{volume}:{mountpoint}", "-e", f"TMPDIR={mountpoint}",
                "-e", "PYTHONPATH=/test-repo:/", "-e", "RUN_DOCKER_WEB_UPDATE=1",
                "-e", "WEB_UPDATE_TEST_INTERNAL=1",
                "-e", "WEB_UPDATE_VERSION_CORRECTION=" + os.environ.get("WEB_UPDATE_VERSION_CORRECTION", "0"),
                "-e", f"WEB_UPDATE_TEST_IMAGE={base}", "-w", "/test-repo", base,
                "-m", "unittest", "tests.test_web_update_docker.WebUpdateDockerTests", "-v",
            ], text=True, capture_output=True, timeout=600)
            self.assertEqual(result.returncode, 0, result.stdout[-6000:] + result.stderr[-6000:])
        finally:
            subprocess.run(["docker", "rm", "-f", runner], capture_output=True)
            subprocess.run(["docker", "volume", "rm", volume], check=True, capture_output=True)


class UpdatePollingTests(unittest.TestCase):
    def setUp(self):
        self.integration = WebUpdateDockerTests("test_real_http_upgrade_pull_failure_and_unhealthy_rollback")
        self.integration.correction = False
        self.integration.repository = "example.test/update-fixture"
        self.integration.initial_version = "6.0.2"
        self.cid = "a" * 64

    def test_removed_container_between_compose_ps_and_inspect_is_transient(self):
        result = subprocess.CompletedProcess([], 1, "[]", f"Error: No such object: {self.cid}")
        with mock.patch.object(self.integration, "compose", return_value=self.cid), \
             mock.patch.object(subprocess, "run", return_value=result):
            with self.assertRaisesRegex(ValueError, "restarting"):
                self.integration.info()

    def test_unexpected_inspect_failure_is_not_retried(self):
        result = subprocess.CompletedProcess([], 1, "", "permission denied connecting to Docker")
        with mock.patch.object(self.integration, "compose", return_value=self.cid), \
             mock.patch.object(subprocess, "run", return_value=result):
            with self.assertRaisesRegex(AssertionError, "permission denied"):
                self.integration.info()

    def test_runtime_poll_waits_for_recreated_container_but_rejects_unreadable_state(self):
        for error in (f"Error: No such container: {self.cid}", f"Error: Container {self.cid} is not running"):
            result = subprocess.CompletedProcess([], 1, "", error)
            with self.subTest(error=error), mock.patch.object(self.integration, "info", return_value={"Id": self.cid}), \
                 mock.patch.object(subprocess, "run", return_value=result):
                self.assertIsNone(self.integration.finished())
        result = subprocess.CompletedProcess([], 1, "", "PermissionError: update-runtime.json")
        with mock.patch.object(self.integration, "info", return_value={"Id": self.cid}), \
             mock.patch.object(subprocess, "run", return_value=result) as run:
            with self.assertRaisesRegex(AssertionError, "PermissionError"):
                self.integration.finished()
            self.assertEqual(run.call_args.args[0][2:4], ["--user", "10001:10001"])

    def test_root_poll_is_limited_to_original_legacy_image(self):
        result = subprocess.CompletedProcess([], 0, '{"active": false}', "")
        for correction, version, user in ((True, "6.0.2", "0:0"), (True, "1.0.1", "10001:10001"),
                                           (False, "6.0.2", "10001:10001")):
            self.integration.correction = correction
            info = {"Id": self.cid, "Config": {"Image": f"{self.integration.repository}:{version}"}}
            with self.subTest(correction=correction, version=version), \
                 mock.patch.object(self.integration, "info", return_value=info), \
                 mock.patch.object(subprocess, "run", return_value=result) as run:
                self.assertEqual(self.integration.finished(), {"active": False})
                self.assertEqual(run.call_args.args[0][2:4], ["--user", user])

    def test_unreadable_runtime_is_transient_only_during_bootstrap(self):
        result = subprocess.CompletedProcess([], 1, "", "PermissionError: update-runtime.json")
        info = {"Id": self.cid, "State": {"Health": {"Status": "starting"}}}
        with mock.patch.object(self.integration, "info", return_value=info), \
             mock.patch.object(subprocess, "run", return_value=result) as run:
            self.assertIsNone(self.integration.finished())
            info["State"]["Health"]["Status"] = "healthy"
            with self.assertRaisesRegex(AssertionError, "PermissionError"):
                self.integration.finished()
            self.assertEqual(run.call_args.args[0][2:4], ["--user", "10001:10001"])


if __name__ == "__main__":
    unittest.main()
