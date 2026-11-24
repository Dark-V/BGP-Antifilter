import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from bgp_antifilter import dns_settings
from bgp_antifilter.admin.settings import validate_setting
from tests.admin_support import admin_application


class DnsSettingsTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.app = admin_application(self.root)
        for path in self.app.config.list_files.values():
            path.write_text("", encoding="utf-8")

    def test_enable_requires_upstream_and_rejects_invalid_combinations_atomically(self):
        original = self.app.settings.effective_settings()
        for change in ({"DNS_PROXY_ENABLED": "1"},
                       {"DNS_PROXY_ENABLED": "1", "DNS_PROXY_UPSTREAM": "127.0.0.1"},
                       {"DNS_PROXY_ENABLED": "1", "DNS_PROXY_UPSTREAM": "192.0.2.53", "DNS_PROXY_BIND": "0.0.0.0"},
                       {"DNS_PROXY_ENABLED": "1", "DNS_PROXY_UPSTREAM": "192.0.2.53", "DNS_PROXY_HEALTH_PORT": "53"},
                       {"DNS_SYNC_MODE": "invalid"}, {"DNS_SYNC_ON_TIMEOUT": "ignore"},
                       {"DNS_SYNC_TIMEOUT": "0"}, {"DNS_SYNC_TIMEOUT": "nan"},
                       {"DNS_PROXY_ALLOWED_CLIENTS": ""}, {"DNS_PROXY_ALLOWED_CLIENTS": "example.org"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.app.settings.update_settings(change)
            self.assertEqual(self.app.settings.effective_settings(), original)
            self.assertFalse(self.app.config.settings_file.exists())

    def test_ipv6_and_cidr_normalization(self):
        self.app.settings.update_settings({"DNS_PROXY_ENABLED": "1", "DNS_PROXY_UPSTREAM": "2001:db8::53",
                                           "DNS_PROXY_BIND": "::1", "DNS_PROXY_ALLOWED_CLIENTS": "127.0.0.1,::1/128,192.0.2.45/24"})
        values = self.app.settings.effective_settings()
        self.assertEqual(values["DNS_PROXY_ALLOWED_CLIENTS"], "127.0.0.1/32 ::1/128 192.0.2.0/24")
        self.assertEqual(dns_settings.health_url(values), "http://[::1]:8053/ready")
        self.assertEqual(validate_setting("DNS_HEALTH_DOMAIN", "ПРИМЕР.РФ."), "xn--e1afmkfd.xn--p1ai")

    def test_legacy_backups_disable_proxy_and_fill_all_new_defaults(self):
        backup = self.app.backups.export()
        for key in dns_settings.DNS_KEYS | {"DNS_WORKERS", "DNS_QPS", "FETCH_WORKERS"}:
            backup["settings"].pop(key)
        self.app.settings.update_settings({"DNS_PROXY_ENABLED": "1", "DNS_PROXY_UPSTREAM": "192.0.2.53"})
        self.app.backups.restore(self.app.backups.preview(backup)["id"])
        values = self.app.settings.effective_settings()
        for item in dns_settings.DNS_SETTINGS:
            self.assertEqual(values[item["key"]], item["default"])

    def test_invalid_regex_in_backup_is_rejected_before_writes(self):
        backup = self.app.backups.export()
        backup["lists"]["exclude-domains"] = "regex:(\n"
        with self.assertRaisesRegex(ValueError, "Line 1"):
            self.app.backups.preview(backup)
        self.assertEqual(self.app.lists.read("exclude-domains")["content"], "")

    def test_saved_settings_wait_for_restart_and_activation_reads_new_values(self):
        env = {"GENERATED_DIR": str(self.root), "CONFIG_DIR": str(self.app.config.config_dir)}
        with mock.patch.dict(os.environ, env):
            dns_settings.activate()
            self.app.settings.update_settings({"DNS_PROXY_ENABLED": "1", "DNS_PROXY_UPSTREAM": "192.0.2.53"})
            self.assertEqual(self.app.settings.command_environment()["DNS_PROXY_ENABLED"], "0")
            status = self.app.dns_proxy.status()
            self.assertFalse(status["enabled"])
            self.assertTrue(status["configured_enabled"])
            self.assertTrue(status["requires_restart"])
            dns_settings.activate()
            self.assertEqual(self.app.settings.command_environment()["DNS_PROXY_ENABLED"], "1")
            self.assertFalse(self.app.dns_proxy.status()["requires_restart"])

    def test_status_does_not_treat_dead_worker_heartbeat_as_healthy(self):
        self.app.settings.update_settings({"DNS_PROXY_ENABLED": "1", "DNS_PROXY_UPSTREAM": "192.0.2.53"})
        path = self.root / "dns-runtime.json"
        state = {"updated_at_unix": time.time(), "running": True, "ready": True, "dynamic_routes": 7}
        path.write_text(json.dumps(state))
        self.assertTrue(self.app.dns_proxy.status()["ready"])
        self.assertEqual(self.app.dns_proxy.status()["routes"], 7)
        state["running"] = False
        path.write_text(json.dumps(state))
        self.assertFalse(self.app.dns_proxy.status()["running"])
        state.update(running=True, updated_at_unix=time.time() - 60)
        path.write_text(json.dumps(state))
        self.assertFalse(self.app.dns_proxy.status()["ready"])

    def test_equivalent_environment_formats_do_not_request_restart(self):
        env = {"GENERATED_DIR": str(self.root), "CONFIG_DIR": str(self.app.config.config_dir),
               "DNS_PROXY_ENABLED": "true", "DNS_PROXY_UPSTREAM": "2001:db8:0:0:0:0:0:53",
               "DNS_PROXY_ALLOWED_CLIENTS": "127.0.0.1,::1/128"}
        with mock.patch.dict(os.environ, env):
            dns_settings.activate()
            status = self.app.dns_proxy.status()
        self.assertTrue(status["enabled"])
        self.assertTrue(status["configured_enabled"])
        self.assertFalse(status["requires_restart"])

    def test_rule_preview_uses_exclusion_priority_without_saving(self):
        rules = {"include": "*.google.com\nregex:(^|\\.)googlevideo\\.com$\nscam1.example.ru\n",
                 "exclude": "mail.google.com\nscam2.example.ru\n"}
        for domain, action in (("mail.google.com", "exclude"), ("www.google.com", "include"),
                               ("scam1.example.ru", "include"), ("scam2.example.ru", "exclude"),
                               ("rr1---sn-abc.googlevideo.com", "include"), ("example.org", "none")):
            with self.subTest(domain=domain):
                result = self.app.dns_proxy.test_rule({**rules, "domain": domain})
                self.assertEqual(result["action"], action)
        self.assertEqual(self.app.lists.read("include-domains")["content"], "")

    def test_pathological_rule_preview_times_out_instead_of_ignoring_exclusion(self):
        with self.assertRaises(TimeoutError):
            self.app.dns_proxy.test_rule({"domain": "a" * 60 + "b", "exclude": "regex:^(a|aa)+$"})
