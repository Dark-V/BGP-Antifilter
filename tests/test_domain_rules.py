import contextlib
import io
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from bgp_antifilter import dns_resolver, domain_rules, sources
from bgp_antifilter.admin.lists import ListService
from bgp_antifilter.runtime_paths import LIST_FILE_SPECS
from bgp_antifilter.sources import fetch


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

    def test_internal_wildcard_matches_one_complete_label_and_whole_hostname(self):
        rule = "video-weaver.*.hls.ttvnw.net"
        rules = domain_rules.DomainRules([rule])
        for name in ("video-weaver.eu.hls.ttvnw.net", "VIDEO-WEAVER.eu-1.HLS.TTVNW.NET."):
            self.assertEqual(rules.matching_rule(name), rule)
        for name in ("video-weaver.hls.ttvnw.net", "video-weaver.eu.west.hls.ttvnw.net",
                     "video-edge.eu.hls.ttvnw.net", "prefix.video-weaver.eu.hls.ttvnw.net",
                     "video-weaver.eu.hls.ttvnw.net.evil.test", "video-weaver..hls.ttvnw.net"):
            self.assertFalse(rules.matches(name), name)

    def test_internal_wildcards_preserve_idna_and_can_match_multiple_labels(self):
        self.assertEqual(domain_rules.normalize_rule("API.*.ПРИМЕР.РФ."), "api.*.xn--e1afmkfd.xn--p1ai")
        self.assertTrue(domain_rules.DomainRules(["api.*.пример.рф"]).matches("api.тест.пример.рф"))
        rules = domain_rules.DomainRules(["*.api.*.example.test"])
        self.assertTrue(rules.matches("one.api.two.example.test"))
        self.assertFalse(rules.matches("one.extra.api.two.example.test"))
        self.assertFalse(rules.matches("one.api.two.extra.example.test"))

    def test_internal_wildcards_use_dns_labels_including_escaped_dots(self):
        rules = domain_rules.DomainRules(["api.*.example.test"])
        self.assertTrue(rules.matches(r"api.a\.b.example.test."))
        self.assertTrue(rules.matches(r"\065PI.\200.example.test."))
        self.assertFalse(rules.matches(r"api\.a.b.example.test."))
        self.assertFalse(rules.matches("api.a.b.example.test"))

    def test_only_complete_wildcard_labels_are_accepted_and_classified_as_patterns(self):
        for rule in ("*.example.test", "api.*.example.test", "*.api.*.example.test"):
            self.assertTrue(domain_rules.is_pattern(domain_rules.normalize_rule(rule)), rule)
            self.assertIsNone(domain_rules.normalize_domain_name(rule))
        for rule in ("*", "*.*", "api-*.example.test", "api.**.example.test", "api.*suffix.example.test",
                     r"/^video-weaver\.[a-z0-9-]+\.hls\.ttvnw\.net$/i",
                     r"video-weaver\.[a-z0-9-]+\.hls\.ttvnw\.net"):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                domain_rules.normalize_rule(rule)

    def test_internal_wildcard_matches_are_cached_per_policy(self):
        first = domain_rules.DomainRules(["api.*.example.test"])
        self.assertTrue(first.matches("api.one.example.test"))
        self.assertTrue(first.matches("api.one.example.test"))
        self.assertEqual(first.matching_rule.cache_info().hits, 1)
        replacement = domain_rules.DomainRules(["cdn.*.example.test"])
        self.assertFalse(replacement.matches("api.one.example.test"))

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

    def test_escaped_binary_dns_label_is_not_reencoded_as_idna(self):
        name = r"\200" * 30 + ".example.test."
        self.assertEqual(domain_rules.domain_key(name), name[:-1])
        self.assertTrue(domain_rules.DomainRules(["example.test"]).matches(name))
        self.assertFalse(domain_rules.DomainRules(["other.test"]).matches(name))

    def test_root_dot_removal_preserves_escaped_label_dot(self):
        self.assertEqual(domain_rules.domain_key(r"label\.."), r"label\.")
        self.assertEqual(domain_rules.domain_key(domain_rules.domain_key(r"label\..")), r"label\.")
        self.assertTrue(domain_rules.DomainRules([r"regex:^label\\\.$"]).matches(r"label\.."))

    def test_escaped_dots_do_not_create_false_domain_suffixes(self):
        rules = domain_rules.DomainRules(["example.test"])
        self.assertFalse(rules.matches(r"bad\.example.test."))
        self.assertTrue(rules.matches(r"bad\.label.example.test."))
        self.assertTrue(rules.matches(r"backslash\\.example.test."))

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
        self.assertEqual(first.matching_rule.cache_info().hits, 1)
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
            service = ListService(SimpleNamespace(config_dir=Path(tmp), list_files={"include-domains": path},
                                                  list_backup_dir=Path(tmp) / "backups"))
            with mock.patch.object(service, "backup_file") as backup:
                with self.assertRaisesRegex(ValueError, "Line 1"):
                    service.save("include-domains", "regex:(")
            backup.assert_not_called()
            self.assertEqual(path.read_text(encoding="utf-8"), "forge.com\n")

    def test_admin_saves_regex_and_backslashes_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "exclude-domains.txt"
            text = "# direct\n" + r"regex:^(api|cdn)\D+\.forge\.com$" + "\n*.direct.test\napi.*.direct.test\n"
            service = ListService(SimpleNamespace(config_dir=Path(tmp), list_files={"exclude-domains": path},
                                                  list_backup_dir=Path(tmp) / "backups"))
            self.assertTrue(service.save("exclude-domains", text)["ok"])
            self.assertEqual(path.read_text(encoding="utf-8"), text)


class DomainRuleSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.paths = {key: self.root / (key + ".txt") for key in LIST_FILE_SPECS}
        for path in self.paths.values():
            path.write_text("", encoding="utf-8")
        environment = {variable: str(self.paths[key]) for key, (variable, _) in LIST_FILE_SPECS.items()}
        environment.update(RUNTIME_FILE=str(self.root / "runtime.json"), FETCH_ATTEMPTS="1", FETCH_RETRY_DELAY="0")
        patch = mock.patch.dict(os.environ, environment, clear=True)
        patch.start()
        self.addCleanup(patch.stop)
        self.cache = self.root / "cache"
        self.cache.mkdir()

    def collect(self, policy=None):
        with contextlib.redirect_stdout(io.StringIO()):
            return sources.collect_sources(self.cache, 604800, include_google=False, dns_policy=policy)

    def test_patterns_are_saved_to_policy_and_never_resolved_as_hostnames(self):
        pattern = r"regex:^(api|cdn)\d+\.forge\.com$"
        self.paths["include-domains"].write_text("forge.com\n*.forge.com\napi.*.forge.com\n" + pattern + "\n")
        self.paths["exclude-domains"].write_text(r"regex:^direct\." + "\ndirect.*.forge.com\n")
        policy = {}
        with mock.patch.object(dns_resolver, "resolve_ipv4_addresses", return_value=["1.1.1.1"]) as resolve:
            failed, sources, errors, _, included, _ = self.collect(policy)
        self.assertFalse(failed)
        self.assertEqual(errors, [])
        self.assertEqual([call.args[0] for call in resolve.call_args_list], ["forge.com"])
        self.assertEqual(policy["include_domains"], ["forge.com", "*.forge.com", "api.*.forge.com", pattern])
        self.assertEqual(policy["exclude_domains"], [r"regex:^direct\.", "direct.*.forge.com"])
        self.assertEqual(included, ["1.1.1.1/32\n"])
        self.assertEqual(sum(bool(source.get("dns_only")) for source in sources), 5)

    def test_patterns_without_dns_integration_report_an_error(self):
        for rule in ("*.forge.com", "api.*.forge.com"):
            with self.subTest(rule=rule):
                self.paths["include-domains"].write_text(rule + "\n")
                with mock.patch.object(dns_resolver, "resolve_ipv4_addresses") as resolve:
                    failed, _, errors, *_ = self.collect()
                self.assertTrue(failed)
                self.assertIn("DNS_PROXY_ENABLED", errors[0]["error"])
                resolve.assert_not_called()

    def test_existing_mixed_case_cache_and_source_label_survive_dns_failure(self):
        from bgp_antifilter.sources.fetch import cache_path
        name = "Example.TEST."
        self.paths["exclude-domains"].write_text(name + "\n")
        cache_path(self.cache, "exclude-domain", name).write_text("1.1.1.1/32\n")
        policy = {}
        with mock.patch.object(dns_resolver, "resolve_ipv4_addresses", side_effect=RuntimeError("offline")):
            failed, sources, errors, _, _, excluded = self.collect(policy)
        self.assertFalse(failed)
        self.assertEqual(errors, [])
        self.assertEqual(sources[-1]["name"], name)
        self.assertEqual(sources[-1]["status"], "cache")
        self.assertEqual(excluded, ["1.1.1.1/32\n"])
        self.assertEqual(policy["exclude_domains"], ["example.test"])

    def test_invalid_manual_regex_is_a_source_error(self):
        self.paths["exclude-domains"].write_text("regex:(\n")
        failed, _, errors, *_ = self.collect({})
        self.assertTrue(failed)
        self.assertIn("invalid regex", errors[0]["error"])

    def test_remote_domain_lists_preserve_patterns_and_only_resolve_literals(self):
        self.paths["domain-list-urls"].write_text("Rules | https://example.test/domains.txt\n")
        text = "forge.com\n*.forge.com\napi.*.forge.com\n" + r"regex:^(api|cdn)\.forge\.com$" + "\nregex:(\n"
        policy = {}
        with mock.patch.object(fetch, "fetch_url", return_value=text), mock.patch.object(
            dns_resolver, "resolve_ipv4_addresses", return_value=["1.1.1.1"]
        ) as resolve:
            failed, sources, errors, *_ = self.collect(policy)
        self.assertFalse(failed)
        self.assertEqual(errors, [])
        self.assertEqual([call.args[0] for call in resolve.call_args_list], ["forge.com"])
        source = next(source for source in sources if source["kind"] == "domain-list-url")
        self.assertEqual(source["dns_patterns"], 3)
        self.assertEqual(source["invalid_lines"], 1)
        self.assertEqual(policy["include_domains"], ["forge.com", "*.forge.com", "api.*.forge.com",
                                                    r"regex:^(api|cdn)\.forge\.com$"])


if __name__ == "__main__":
    unittest.main()
