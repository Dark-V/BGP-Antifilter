import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from bgp_antifilter import admin_server, domain_rules, update_routes


class DomainRuleTests(unittest.TestCase):
    def test_literal_keeps_suffix_boundaries_and_idna(self):
        rules = domain_rules.DomainRules(["Forge.COM.", "пример.рф"])
        for name in ("forge.com", "a.forge.com", "x.a.FORGE.com.", "пример.рф", "а.пример.рф"):
            self.assertTrue(rules.matches(name), name)
        for name in ("notforge.com", "forge.com.evil.test", "other.test"):
            self.assertFalse(rules.matches(name), name)

    def test_wildcard_matches_only_subdomains_at_any_depth(self):
        rules = domain_rules.DomainRules(["*.Forge.COM."])
        self.assertFalse(rules.matches("forge.com"))
        self.assertTrue(rules.matches("a.forge.com"))
        self.assertTrue(rules.matches("x.a.forge.com"))
        self.assertFalse(rules.matches("notforge.com"))

    def test_regex_groups_alternation_quantifiers_and_boundaries(self):
        rules = domain_rules.DomainRules([r"regex:^(api|cdn)[0-9]{1,3}\.forge\.com$"])
        self.assertTrue(rules.matches("API12.forge.com."))
        self.assertTrue(rules.matches("cdn1.forge.com"))
        for name in ("cdn.forge.com", "cdn1234.forge.com", "cdn1.forge.com.evil.test"):
            self.assertFalse(rules.matches(name), name)

    def test_regex_search_and_anchors_have_explicit_semantics(self):
        self.assertTrue(domain_rules.DomainRules([r"regex:forge\.com"]).matches("a.forge.com"))
        self.assertFalse(domain_rules.DomainRules([r"regex:^forge\.com$"]).matches("a.forge.com"))

    def test_lookaround_backreferences_and_escape_case_are_preserved(self):
        rule = r"regex:^(?!admin\.)(?P<label>\D+)\.(?P=label)\.forge\.com$"
        self.assertEqual(domain_rules.normalize_rule(rule), rule)
        rules = domain_rules.DomainRules([rule])
        self.assertTrue(rules.matches("api.api.forge.com"))
        self.assertFalse(rules.matches("api.cdn.forge.com"))
        self.assertFalse(rules.matches("12.12.forge.com"))
        self.assertFalse(rules.matches("admin.admin.forge.com"))
        self.assertTrue(domain_rules.DomainRules([r"regex:(?<=\.)forge\.com$"]).matches("a.forge.com"))

    def test_regex_receives_punycode_not_unicode(self):
        self.assertTrue(domain_rules.DomainRules([r"regex:^xn--e1afmkfd\.xn--p1ai$"]).matches("пример.рф"))

    def test_invalid_rule_reports_line_number_before_save(self):
        with self.assertRaisesRegex(ValueError, "Line 3: invalid regex"):
            domain_rules.validate_rule_list("# comment\nforge.com\nregex:([\n")
        for value in ("regex:", "regex:" + "a" * 1025, "*forge.com", "https://forge.com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                domain_rules.normalize_rule(value)

    def test_successful_matches_are_cached_per_policy(self):
        first = domain_rules.DomainRules([r"regex:^api\.forge\.com$"])
        self.assertTrue(first.matches("api.forge.com"))
        self.assertTrue(first.matches("api.forge.com"))
        self.assertEqual(first.matches.cache_info().hits, 1)
        replacement = domain_rules.DomainRules([r"regex:^cdn\.forge\.com$"])
        self.assertFalse(replacement.matches("api.forge.com"))

    def test_backtracking_is_bounded_and_timeout_is_not_a_negative_match(self):
        rules = domain_rules.DomainRules([r"regex:^(a|aa)+$"])
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            rules.matches("a" * 60 + "b")
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertTrue(rules.matches("aaa"))

    def test_admin_rejects_bad_regex_without_changing_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "include-domains.txt"
            path.write_text("forge.com\n", encoding="utf-8")
            handler = object.__new__(admin_server.AdminHandler)
            handler.require_auth = mock.Mock(return_value=True)
            handler.read_json_or_error = mock.Mock(return_value={"content": "regex:("})
            handler.send_json = mock.Mock()
            with mock.patch.dict(admin_server.LIST_FILES, {"include-domains": path}), mock.patch.object(admin_server, "backup_file") as backup:
                handler.handle_api_put("/api/lists/include-domains")
            self.assertEqual(handler.send_json.call_args.args[1], admin_server.HTTPStatus.BAD_REQUEST)
            self.assertIn("Line 1", handler.send_json.call_args.args[0]["error"])
            backup.assert_not_called()
            self.assertEqual(path.read_text(encoding="utf-8"), "forge.com\n")

    def test_admin_saves_regex_and_backslashes_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "exclude-domains.txt"
            text = "# direct\n" + r"regex:^(api|cdn)\D+\.forge\.com$" + "\n*.direct.test\n"
            handler = object.__new__(admin_server.AdminHandler)
            handler.require_auth = mock.Mock(return_value=True)
            handler.read_json_or_error = mock.Mock(return_value={"content": text})
            handler.send_json = mock.Mock()
            with mock.patch.dict(admin_server.LIST_FILES, {"exclude-domains": path}), mock.patch.object(admin_server, "backup_file", return_value=None):
                handler.handle_api_put("/api/lists/exclude-domains")
            self.assertTrue(handler.send_json.call_args.args[0]["ok"])
            self.assertEqual(path.read_text(encoding="utf-8"), text)


class DomainRuleSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.paths = {key: self.root / (key + ".txt") for key in update_routes.LIST_FILE_SPECS}
        for path in self.paths.values():
            path.write_text("", encoding="utf-8")
        patch = mock.patch.object(update_routes, "env_paths", return_value=self.paths)
        patch.start()
        self.addCleanup(patch.stop)
        self.cache = self.root / "cache"
        self.cache.mkdir()

    def collect(self, policy=None):
        return update_routes.collect_sources(self.cache, 604800, include_google=False, dns_policy=policy)

    def test_patterns_are_saved_to_policy_and_never_resolved_as_hostnames(self):
        pattern = r"regex:^(api|cdn)\d+\.forge\.com$"
        self.paths["include-domains"].write_text("forge.com\n*.forge.com\n" + pattern + "\n")
        self.paths["exclude-domains"].write_text(r"regex:^direct\." + "\n")
        policy = {}
        with mock.patch.object(update_routes.dns_resolver, "resolve_ipv4_addresses", return_value=["1.1.1.1"]) as resolve:
            failed, sources, errors, _, included, _ = self.collect(policy)
        self.assertFalse(failed)
        self.assertEqual(errors, [])
        self.assertEqual([call.args[0] for call in resolve.call_args_list], ["forge.com"])
        self.assertEqual(policy["include_domains"], ["forge.com", "*.forge.com", pattern])
        self.assertEqual(policy["exclude_domains"], [r"regex:^direct\."])
        self.assertEqual(included, ["1.1.1.1/32\n"])
        self.assertEqual(sum(bool(source.get("dns_only")) for source in sources), 3)

    def test_patterns_without_dns_integration_report_an_error(self):
        self.paths["include-domains"].write_text("*.forge.com\n")
        with mock.patch.object(update_routes, "resolve_domain") as resolve:
            failed, _, errors, *_ = self.collect()
        self.assertTrue(failed)
        self.assertIn("DNS_PROXY_ENABLED", errors[0]["error"])
        resolve.assert_not_called()

    def test_invalid_manual_regex_is_a_source_error(self):
        self.paths["exclude-domains"].write_text("regex:(\n")
        failed, _, errors, *_ = self.collect({})
        self.assertTrue(failed)
        self.assertIn("invalid regex", errors[0]["error"])

    def test_remote_domain_lists_preserve_patterns_and_only_resolve_literals(self):
        self.paths["domain-list-urls"].write_text("Rules | https://example.test/domains.txt\n")
        text = "forge.com\n*.forge.com\n" + r"regex:^(api|cdn)\.forge\.com$" + "\nregex:(\n"
        record = {"kind": "domain-list-url", "name": "Rules", "status": "fresh"}
        policy = {}
        with mock.patch.object(update_routes, "fetch_text_source", return_value=(text, record, True)), mock.patch.object(
            update_routes.dns_resolver, "resolve_ipv4_addresses", return_value=["1.1.1.1"]
        ) as resolve:
            failed, sources, errors, *_ = self.collect(policy)
        self.assertFalse(failed)
        self.assertEqual(errors, [])
        self.assertEqual([call.args[0] for call in resolve.call_args_list], ["forge.com"])
        source = next(source for source in sources if source["kind"] == "domain-list-url")
        self.assertEqual(source["dns_patterns"], 2)
        self.assertEqual(source["invalid_lines"], 1)
        self.assertEqual(len(policy["include_domains"]), 3)


if __name__ == "__main__":
    unittest.main()
