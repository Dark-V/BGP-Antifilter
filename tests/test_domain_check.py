"""One domain/IP check reports rule matches without learning DNS routes."""

from http import HTTPStatus
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from bgp_antifilter import bgp_feed, dns_resolver, dns_settings, live_routes
from bgp_antifilter.admin.actions import ActionsService
from bgp_antifilter.admin.server import AdminHandler
from tests.admin_support import admin_application


class DomainCheckTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        environment = mock.patch.dict(os.environ, {"DNS_PROXY_ENABLED": "0", "DNS_RESOLVERS": ""})
        environment.start()
        self.addCleanup(environment.stop)
        self.app = admin_application(self.root)
        for path in self.app.config.list_files.values():
            path.write_text("", encoding="utf-8")

    def active(self, enabled):
        values = self.app.settings.effective_settings()
        values.update(DNS_PROXY_ENABLED="1" if enabled else "0", DNS_PROXY_UPSTREAM="192.0.2.53")
        (self.root / "dns-settings.active.json").write_text(json.dumps({key: values[key] for key in dns_settings.DNS_KEYS}))

    def manual(self, include="", exclude=""):
        self.app.config.list_files["include-domains"].write_text(include, encoding="utf-8")
        self.app.config.list_files["exclude-domains"].write_text(exclude, encoding="utf-8")

    def policy(self, include=(), exclude=(), generation="committed"):
        return {"generation": generation, "include_domains": list(include), "exclude_domains": list(exclude)}

    def database(self, policy):
        database = self.root / "dns-cache.sqlite3"
        connection = sqlite3.connect(database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        connection.execute("INSERT OR REPLACE INTO metadata VALUES('policy', ?)", (json.dumps(policy),))
        connection.commit()
        return connection

    def command_result(self, address="192.0.2.10", matched=False):
        return {"ok": matched, "returncode": 0 if matched else 1,
                "stdout": json.dumps({"ip": address, "matched": matched, "routes": [], "sources": []}),
                "stderr": "", "duration_seconds": 0}

    def http_check(self, target):
        handler = object.__new__(AdminHandler)
        handler.server = SimpleNamespace(app=self.app)
        handler.require_auth = mock.Mock(return_value=True)
        handler.read_json_or_error = mock.Mock(return_value={"target": target})
        replies = []
        handler.send_json = lambda data, status=HTTPStatus.OK, **_kwargs: replies.append((status, data))
        handler.handle_api_post("/api/tools/check-ip")
        return replies[0]

    def test_saved_manual_rules_match_without_fetching_sources_or_dns(self):
        self.manual("*.example.test\nregex:^api[0-9]+\\.other\\.test$\n", "direct.example.test\n")
        self.app.config.list_files["domain-list-urls"].write_text("https://source.test/domains.txt\n")
        with mock.patch.object(dns_resolver, "resolve_ipv4_addresses", side_effect=AssertionError("no DNS for rule matching")):
            for domain, action in (("www.example.test", "include"), ("direct.example.test", "exclude"),
                                   ("api12.other.test", "include"), ("unlisted.test", "none")):
                with self.subTest(domain=domain):
                    result = self.app.dns_proxy.check_domain(domain)
                    self.assertEqual((result["scope"], result["action"]), ("saved", action))
                    self.assertNotIn("error", result)
        self.assertFalse((self.root / "dns-cache.sqlite3").exists())

    def test_pending_enable_still_uses_saved_manual_rules(self):
        self.active(False)
        self.app.settings.update_settings({"DNS_PROXY_ENABLED": "1", "DNS_PROXY_UPSTREAM": "192.0.2.53"})
        self.manual("saved.test\n")
        self.database(self.policy(exclude=["saved.test"]))
        result = self.app.dns_proxy.check_domain("saved.test")
        self.assertEqual((result["scope"], result["action"]), ("saved", "include"))

    def test_pending_disable_still_uses_committed_active_rules(self):
        self.active(True)
        self.app.settings.update_settings({"DNS_PROXY_ENABLED": "0"})
        self.manual(exclude="active.test\n")
        self.database(self.policy(include=["active.test"]))
        result = self.app.dns_proxy.check_domain("active.test")
        self.assertEqual((result["scope"], result["action"]), ("active", "include"))
        self.assertEqual(result["generation"], "committed")

    def test_active_policy_reads_committed_wal_not_pending_transaction_or_json_mirror(self):
        self.active(True)
        committed = self.policy(include=["active.test"])
        connection = self.database(committed)
        pending = self.policy(exclude=["active.test"], generation="uncommitted")
        (self.root / "dns-policy.json").write_text(json.dumps(pending))
        connection.execute("UPDATE metadata SET value=? WHERE key='policy'", (json.dumps(pending),))
        self.assertTrue((self.root / "dns-cache.sqlite3-wal").exists())
        result = self.app.dns_proxy.check_domain("active.test")
        self.assertEqual((result["scope"], result["action"], result["generation"]),
                         ("active", "include", "committed"))
        connection.rollback()
        self.assertEqual(json.loads(connection.execute("SELECT value FROM metadata WHERE key='policy'").fetchone()[0]), committed)

    def test_missing_active_policy_is_unknown_and_does_not_fall_back_or_create_database(self):
        self.active(True)
        self.manual("active.test\n")
        (self.root / "dns-policy.json").write_text(json.dumps(self.policy(include=["active.test"])))
        result = self.app.dns_proxy.check_domain("active.test")
        self.assertEqual((result["scope"], result["action"]), ("active", "unknown"))
        self.assertTrue(result["error"])
        self.assertFalse((self.root / "dns-cache.sqlite3").exists())

    def test_invalid_active_policy_is_unknown_instead_of_no_match(self):
        self.active(True)
        connection = self.database(self.policy())
        for value in ("not json", json.dumps({"include_domains": "active.test", "exclude_domains": []}),
                      json.dumps({"include_domains": []})):
            with self.subTest(value=value):
                connection.execute("UPDATE metadata SET value=? WHERE key='policy'", (value,))
                connection.commit()
                result = self.app.dns_proxy.check_domain("active.test")
                self.assertEqual(result["action"], "unknown")
                self.assertTrue(result["error"])

    def test_exclusion_does_not_evaluate_timed_out_include(self):
        domain = "a" * 60 + "b"
        self.manual("regex:^(a|aa)+$\n", domain + "\n")
        result = self.app.dns_proxy.check_domain(domain)
        self.assertEqual(result["action"], "exclude")
        self.assertEqual(result["exclude_rule"], domain)
        self.assertIsNone(result["include_rule"])
        self.assertNotIn("error", result)

    def test_regex_timeout_is_unknown_not_a_negative_match(self):
        self.manual(exclude="regex:^(a|aa)+$\n")
        result = self.app.dns_proxy.check_domain("a" * 60 + "b")
        self.assertEqual(result["action"], "unknown")
        self.assertTrue(result["error"])

    def test_dns_failure_returns_http_200_with_rule_and_no_route_conclusion(self):
        self.manual("missing.test\n")
        with mock.patch.object(dns_resolver, "resolve_ipv4_addresses", side_effect=OSError("NXDOMAIN")) as resolve, \
             mock.patch.object(self.app.actions, "run_command") as command:
            status, result = self.http_check("missing.test")
        self.assertEqual(status, HTTPStatus.OK)
        self.assertFalse(result["ok"])
        self.assertEqual(result["domain_rule"]["action"], "include")
        self.assertIn("NXDOMAIN", result["lookup_error"])
        self.assertEqual(result["addresses"], [])
        self.assertEqual(result["results"], [])
        self.assertIsNone(result["result"])
        resolve.assert_called_once()
        command.assert_not_called()

    def test_one_diagnostic_lookup_and_route_check_do_not_observe_or_publish(self):
        self.active(True)
        self.database(self.policy(include=["selected.test"]))
        with mock.patch.object(dns_resolver, "resolve_ipv4_addresses", return_value=["192.0.2.10"]) as resolve, \
             mock.patch.object(live_routes.LiveRoutes, "observe", side_effect=AssertionError("must not observe")), \
             mock.patch.object(bgp_feed.BGPFeed, "update", side_effect=AssertionError("must not publish")), \
             mock.patch.object(self.app.actions, "run_command", return_value=self.command_result()) as command:
            result = self.app.actions.check_target("selected.test", self.app.diagnostics)
        resolve.assert_called_once()
        command.assert_called_once()
        self.assertIn("--live", command.call_args.args[0])
        self.assertEqual(result["domain_rule"]["action"], "include")
        self.assertFalse(result["result"]["matched"])
        self.assertNotIn("lookup_error", result)

    def test_ipv4_literal_skips_rule_matching_and_dns_resolution(self):
        with mock.patch.object(self.app.dns_proxy, "check_domain", side_effect=AssertionError("no domain rule for IP")), \
             mock.patch.object(dns_resolver, "resolve_ipv4_addresses", side_effect=AssertionError("no DNS for IP")), \
             mock.patch.object(self.app.actions, "run_command", return_value=self.command_result()) as command:
            result = self.app.actions.check_target("192.0.2.10", self.app.diagnostics)
        self.assertEqual(result["addresses"], ["192.0.2.10"])
        self.assertNotIn("domain_rule", result)
        command.assert_called_once()

    def test_invalid_input_remains_http_400_without_dns(self):
        with mock.patch.object(dns_resolver, "resolve_ipv4_addresses", side_effect=AssertionError("invalid input must not resolve")):
            for target in ("", "bad domain", "https://example.test/", "*.example.test", "regex:example", "2001:db8::1"):
                with self.subTest(target=target):
                    status, result = self.http_check(target)
                    self.assertEqual(status, HTTPStatus.BAD_REQUEST)
                    self.assertIn("error", result)

    def test_optional_rule_service_preserves_existing_error_contract(self):
        service = ActionsService(self.app.config, self.app.settings)
        with mock.patch.object(self.app.diagnostics, "resolve_ipv4_targets", return_value=([], "lookup failed")):
            with self.assertRaisesRegex(ValueError, "lookup failed"):
                service.check_target("missing.test", self.app.diagnostics)


if __name__ == "__main__":
    unittest.main()
