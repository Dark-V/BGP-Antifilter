import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from bgp_antifilter import admin_server as admin, dns_settings, updater_server


class DNSSettingsTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.settings = self.root / "settings.json"
        patches = [mock.patch.object(admin, "SETTINGS_FILE", self.settings),
                   mock.patch.object(admin, "SETTINGS_ENV_FILE", self.root / "settings.env"),
                   mock.patch.object(admin, "SETTINGS_APPLY_THREAD", None),
                   mock.patch.dict(os.environ, {"SETTINGS_FILE": str(self.settings), "DNS_PROXY_ENABLED": "0",
                                                "BIRD_IP": "127.0.0.1", "MT_IP": "127.0.0.2", "HEALTHCHECK_REQUIRE_BGP": "0"})]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def save(self, **changes):
        desired = admin.effective_settings()
        desired.update(changes)
        admin.save_settings(desired)
        return admin.effective_settings()

    def apply(self, desired, ready=None):
        commands = []
        with mock.patch.object(admin, "settings_compose_context", return_value=("context",)), mock.patch.object(
                admin, "settings_compose", side_effect=lambda context, *args: commands.append(args)), mock.patch.object(
                admin, "wait_settings_ready", side_effect=ready), mock.patch.object(
                admin, "run_command", return_value={"ok": True}) as reload_command:
            admin.apply_settings(desired, admin.active_settings())
        return commands, reload_command

    def test_schema_exposes_every_dns_runtime_setting(self):
        section = next(section for section in admin.settings_payload()["sections"] if section["id"] == "dns")
        self.assertEqual({item["key"] for item in section["items"]}, dns_settings.DNS_KEYS)
        modes = next(item for item in section["items"] if item["key"] == "DNS_SYNC_MODE")
        self.assertEqual(modes["options"], ["async", "bgp", "bird"])

    def test_save_does_not_activate_pending_dns_configuration(self):
        desired = self.save(DNS_PROXY_ENABLED="1", DNS_SYNC_MODE="bird", DNS_SYNC_TIMEOUT="0.25")
        self.assertEqual(desired["DNS_PROXY_ENABLED"], "1")
        self.assertEqual(admin.active_settings()["DNS_PROXY_ENABLED"], "0")
        self.assertEqual(admin.command_environment()["DNS_PROXY_ENABLED"], "0")
        self.assertIn("DNS_SYNC_MODE", admin.settings_payload()["pending_keys"])
        self.assertNotIn("DNS_PROXY_ENABLED=1", (self.root / "settings.env").read_text())
        with mock.patch.dict(os.environ):
            dns_settings.load_active_environment()
            self.assertEqual(os.environ["DNS_PROXY_ENABLED"], "0")

    def test_enable_apply_starts_both_services_and_preserves_original_env_file(self):
        env_file = self.root / ".env"
        env_file.write_text("DNS_PROXY_ENABLED=0\nCOMPOSE_PROFILES=\n")
        desired = self.save(DNS_PROXY_ENABLED="1", DNS_SYNC_MODE="bird", DNS_SYNC_TIMEOUT="0.25", DNS_SYNC_ON_TIMEOUT="forward")
        commands, _ = self.apply(desired)
        self.assertIn(("up", "-d", "--no-deps", "--no-build", "bird"), commands)
        self.assertIn(("up", "-d", "--no-deps", "--no-build", "dns-proxy"), commands)
        self.assertEqual(admin.active_settings()["DNS_SYNC_MODE"], "bird")
        self.assertTrue(admin.settings_apply_payload()["ok"])
        self.assertEqual(env_file.read_text(), "DNS_PROXY_ENABLED=0\nCOMPOSE_PROFILES=\n")
        with mock.patch.dict(os.environ):
            dns_settings.load_active_environment()
            self.assertEqual(os.environ["DNS_SYNC_ON_TIMEOUT"], "forward")

    def test_sync_change_does_not_restart_bird_or_rebuild_routes(self):
        self.apply(self.save(DNS_PROXY_ENABLED="1"))
        desired = self.save(DNS_SYNC_MODE="bird")
        self.assertIn("DNS_SYNC_MODE", admin.settings_payload()["pending_keys"])
        commands, reload_command = self.apply(desired)
        self.assertFalse(any(args[-1] == "bird" for args in commands))
        self.assertIn(("up", "-d", "--no-deps", "--no-build", "dns-proxy"), commands)
        reload_command.assert_not_called()
        self.assertFalse(admin.settings_payload()["pending_keys"])

    def test_disable_removes_dns_proxy_and_restores_static_source(self):
        self.apply(self.save(DNS_PROXY_ENABLED="1"))
        commands, _ = self.apply(self.save(DNS_PROXY_ENABLED="0"))
        self.assertIn(("rm", "-f", "-s", "dns-proxy"), commands)
        self.assertIn(("up", "-d", "--no-deps", "--no-build", "bird"), commands)
        self.assertNotIn(("up", "-d", "--no-deps", "--no-build", "dns-proxy"), commands)
        self.assertEqual(admin.active_settings()["DNS_PROXY_ENABLED"], "0")

    def test_failed_apply_restores_active_config_but_retains_saved_draft(self):
        self.apply(self.save(DNS_PROXY_ENABLED="1"))
        desired = self.save(ADGUARD_DNS="192.0.2.55")
        commands, _ = self.apply(desired, ready=[TimeoutError("AdGuard unreachable"), None])
        state = admin.settings_apply_payload()
        self.assertFalse(state["ok"])
        self.assertTrue(state["rollback"]["ok"])
        self.assertIn("AdGuard unreachable", state["error"])
        self.assertEqual(admin.effective_settings()["ADGUARD_DNS"], "192.0.2.55")
        self.assertEqual(admin.active_settings()["ADGUARD_DNS"], "192.168.88.16")
        self.assertEqual(commands.count(("up", "-d", "--no-deps", "--no-build", "dns-proxy")), 2)

    def test_invalid_values_and_listener_conflicts_do_not_write_settings(self):
        invalid = [{"DNS_SYNC_MODE": "other"}, {"DNS_SYNC_ON_TIMEOUT": "ignore"},
                   {"DNS_SYNC_TIMEOUT": "nan"}, {"DNS_SYNC_TIMEOUT": "inf"}, {"DNS_SYNC_TIMEOUT": "0"},
                   {"DNS_SYNC_TIMEOUT": "10.1"}, {"DNS_BGP_PORT": "53"}, {"ADGUARD_DNS_PORT": "65536"},
                   {"DNS_PROXY_ALLOWED_CLIENTS": "::/0"}, {"DNS_PROXY_BIND": "0.0.0.0"},
                   {"DNS_HEALTH_DOMAIN": "https://example.org"},
                   {"DNS_PROXY_ENABLED": "1", "DNS_PROXY_PORT": "8053"},
                   {"DNS_PROXY_ENABLED": "1", "ADGUARD_DNS": "127.0.0.1"}]
        for change in invalid:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.save(**change)
            self.assertFalse(self.settings.exists())

    def test_cidr_list_and_domain_are_normalized(self):
        values = self.save(DNS_PROXY_ALLOWED_CLIENTS="192.168.88.1 192.168.88.7/24,192.168.88.0/24",
                           DNS_HEALTH_DOMAIN="EXAMPLE.ORG.")
        self.assertEqual(values["DNS_PROXY_ALLOWED_CLIENTS"], "192.168.88.1/32,192.168.88.0/24")
        self.assertEqual(values["DNS_HEALTH_DOMAIN"], "example.org")

    def test_legacy_bgp_overrides_are_preserved_before_new_apply(self):
        self.settings.write_text(json.dumps({"values": {"MY_AS": "64555"}}))
        self.save(MY_AS="64566", DNS_SYNC_MODE="bird")
        self.assertEqual(admin.active_settings()["MY_AS"], "64555")
        self.assertIn("MY_AS=64555", (self.root / "settings.env").read_text())

    def test_overlapping_save_and_reload_are_rejected(self):
        thread = mock.Mock()
        thread.is_alive.return_value = True
        with mock.patch.object(admin, "SETTINGS_APPLY_THREAD", thread):
            with self.assertRaises(RuntimeError):
                self.save(DNS_SYNC_MODE="bird")
            with self.assertRaises(RuntimeError):
                admin.start_reload()

    def test_updater_includes_dns_service_from_applied_panel_setting(self):
        self.apply(self.save(DNS_PROXY_ENABLED="1"))
        with mock.patch.object(updater_server, "uses_legacy_docker_compose", return_value=False), mock.patch.object(
                updater_server, "COMPOSE_SERVICES", ("bird", "admin")):
            self.assertIn("dns-proxy", updater_server.restart_services_for_update())

    def test_compose_uses_host_project_path_and_name(self):
        container = {"Config": {"Labels": {"com.docker.compose.project.working_dir": "/srv/antifilter",
                                            "com.docker.compose.project": "my-bgp"}}}
        with mock.patch.object(admin, "run_command", return_value={"ok": True, "stdout": json.dumps([container])}):
            context = admin.settings_compose_context()
        self.assertEqual(context[:4], ("--project-directory", "/srv/antifilter", "--project-name", "my-bgp"))

    def test_runtime_compose_omits_build_contexts_and_preserves_bind_paths(self):
        path = self.root / "compose.yml"
        path.write_text("name: example\nservices:\n  bird:\n    image: bird:test\n    build:\n      context: .\n      args:\n        ONE: two\n    volumes:\n      - ./generated:/etc/bird/generated\n  dns-proxy:\n    image: bird:test\n    build: .\n    profiles: [dns]\n")
        with mock.patch.object(updater_server, "COMPOSE_FILE", path), mock.patch.object(
                updater_server, "docker_compose_v2_command", return_value=None), mock.patch.object(
                updater_server.shutil, "which", return_value="docker-compose"):
            command, temporary = updater_server.compose_base_command(runtime_only=True)
        try:
            text = temporary.read_text()
            self.assertNotIn("build:", text)
            self.assertNotIn("ONE:", text)
            self.assertIn("./generated:/etc/bird/generated", text)
            self.assertIn("profiles: [dns]", text)
        finally:
            temporary.unlink()


if __name__ == "__main__":
    unittest.main()
