import unittest

from bgp_antifilter import dynamic_dns


class PatternTests(unittest.TestCase):
    def test_parse_patterns_supports_exact_suffix_and_glob(self):
        patterns, invalid = dynamic_dns.parse_patterns(
            "# comment\n"
            "GQL.TWITCH.TV\n"
            "domain:ttvnw.net\n"
            "+.live-video.net\n"
            "video-weaver.*.hls.ttvnw.net\n"
            "regexp:^unsupported$\n"
        )

        self.assertEqual(invalid, 1)
        self.assertEqual(
            [(item["kind"], item["value"]) for item in patterns],
            [
                ("exact", "gql.twitch.tv"),
                ("suffix", "ttvnw.net"),
                ("suffix", "live-video.net"),
                ("glob", "video-weaver.*.hls.ttvnw.net"),
            ],
        )

    def test_host_matching_preserves_suffix_and_glob_semantics(self):
        suffix = {"kind": "suffix", "value": "ttvnw.net"}
        glob = {
            "kind": "glob",
            "value": "video-weaver.*.hls.ttvnw.net",
        }

        self.assertTrue(dynamic_dns.host_matches("ttvnw.net", suffix))
        self.assertTrue(dynamic_dns.host_matches("foo.ttvnw.net", suffix))
        self.assertTrue(
            dynamic_dns.host_matches(
                "video-weaver.fra02.hls.ttvnw.net",
                glob,
            )
        )
        self.assertFalse(dynamic_dns.host_matches("foo.twitch.tv", glob))

    def test_search_hint_groups_service_subdomains(self):
        self.assertEqual(
            dynamic_dns.search_hint(
                {"kind": "exact", "value": "gql.twitch.tv"}
            ),
            "twitch.tv",
        )
        self.assertEqual(
            dynamic_dns.search_hint(
                {
                    "kind": "glob",
                    "value": "video-weaver.*.hls.ttvnw.net",
                }
            ),
            "ttvnw.net",
        )


class AdGuardTests(unittest.TestCase):
    def test_querylog_url_accepts_root_or_control_base(self):
        root = dynamic_dns.adguard_querylog_url(
            "http://192.0.2.10:3000",
            limit=100,
            search="ttvnw.net",
        )
        control = dynamic_dns.adguard_querylog_url(
            "http://192.0.2.10:3000/control",
            limit=100,
            search="ttvnw.net",
        )

        self.assertEqual(root, control)
        self.assertIn("/control/querylog?", root)
        self.assertIn("search=ttvnw.net", root)

    def test_extract_observations_uses_a_answers_and_ttl(self):
        patterns, _ = dynamic_dns.parse_patterns("*.ttvnw.net\n")
        items = [{
            "time": "2026-09-26T04:00:00Z",
            "question": {"name": "edge.ttvnw.net", "type": "A"},
            "answer": [
                {"type": "CNAME", "value": "alias.example", "ttl": 60},
                {"type": "A", "value": "8.8.8.8", "ttl": 60},
                {"type": "A", "value": "192.168.1.1", "ttl": 60},
            ],
        }]

        observations, matched = dynamic_dns.extract_observations(
            items,
            patterns,
            now=1790395220,
        )

        self.assertEqual(matched, 1)
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["ip"], "8.8.8.8")
        self.assertGreater(observations[0]["expires_at"], 1790395220)


class StateTests(unittest.TestCase):
    def test_prune_state_removes_expired_and_unmatched_routes(self):
        patterns, _ = dynamic_dns.parse_patterns("*.ttvnw.net\n")
        state = {
            "routes": {
                "8.8.8.8": {
                    "expires_at": 200,
                    "domains": ["edge.ttvnw.net"],
                },
                "1.1.1.1": {
                    "expires_at": 200,
                    "domains": ["example.com"],
                },
                "9.9.9.9": {
                    "expires_at": 50,
                    "domains": ["old.ttvnw.net"],
                },
            }
        }

        dynamic_dns.prune_state(state, patterns, now=100)

        self.assertEqual(set(state["routes"]), {"8.8.8.8"})
        rendered = dynamic_dns.render_routes(state)
        self.assertIn("route 8.8.8.8/32 blackhole;", rendered)


if __name__ == "__main__":
    unittest.main()
