import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from bgp_antifilter import dynamic_dns


class DynamicDnsTests(unittest.TestCase):
    def test_domain_matches_wildcard_matches_root_and_subdomains(self):
        self.assertTrue(dynamic_dns.domain_matches("ttvnw.net", "*.ttvnw.net"))
        self.assertTrue(dynamic_dns.domain_matches("video-weaver.fra05.hls.ttvnw.net", "*.ttvnw.net"))
        self.assertFalse(dynamic_dns.domain_matches("not-ttvnw.net", "*.ttvnw.net"))

    def test_collect_adguard_entries_filters_search_false_positives_and_ipv6(self):
        payload = {
            "data": [
                {
                    "time": "2026-09-27T10:00:00Z",
                    "question": {"name": "video-weaver.fra05.hls.ttvnw.net", "type": "A"},
                    "answer": [
                        {"type": "CNAME", "value": "edge.example"},
                        {"type": "A", "value": "52.223.201.15", "ttl": 60},
                        {"type": "AAAA", "value": "2001:db8::1", "ttl": 60},
                    ],
                },
                {
                    "time": "2026-09-27T10:00:01Z",
                    "question": {"name": "not-ttvnw.net", "type": "A"},
                    "answer": [{"type": "A", "value": "203.0.113.10", "ttl": 60}],
                },
            ]
        }
        with mock.patch.object(dynamic_dns, "fetch_adguard_querylog", return_value=payload):
            entries = dynamic_dns.collect_adguard_entries(
                "http://192.0.2.53:3000",
                ["*.ttvnw.net"],
                limit=200,
                now=1790506800,
                max_age=21600,
            )

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["address"], "52.223.201.15")
        self.assertEqual(entries[0]["rule"], "*.ttvnw.net")

    def test_merge_state_prunes_expired_entries(self):
        state = {
            "192.0.2.1": {"hostname": "old.example", "rule": "*.example", "last_seen": 100},
            "192.0.2.2": {"hostname": "new.example", "rule": "*.example", "last_seen": 190},
        }
        merged = dynamic_dns.merge_state(state, [], now=200, max_age=50)

        self.assertNotIn("192.0.2.1", merged)
        self.assertIn("192.0.2.2", merged)

    def test_routes_text_emits_bird_static_routes(self):
        text = dynamic_dns.routes_text({
            "203.0.113.2": {"last_seen": 1},
            "192.0.2.1": {"last_seen": 1},
        })
        self.assertEqual(
            text,
            "    route 192.0.2.1/32 blackhole;\n"
            "    route 203.0.113.2/32 blackhole;\n",
        )

    def test_apply_routes_rolls_back_when_bird_rejects_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            routes = root / "dynamic-routes.conf"
            state_file = root / "state.json"
            lock_dir = root / "update.lock"
            routes.write_text("    route 192.0.2.1/32 blackhole;\n", encoding="utf-8")
            state = {"203.0.113.2": {"hostname": "x", "rule": "*.x", "last_seen": 1}}

            rejected = mock.Mock(returncode=1, stdout="", stderr="syntax error")
            accepted_rollback = mock.Mock(returncode=0, stdout="", stderr="")
            with mock.patch.object(
                dynamic_dns.subprocess,
                "run",
                side_effect=[rejected, accepted_rollback],
            ):
                with self.assertRaisesRegex(RuntimeError, "syntax error"):
                    dynamic_dns.apply_routes(
                        routes,
                        state_file,
                        state,
                        lock_dir=lock_dir,
                    )

            self.assertEqual(routes.read_text(encoding="utf-8"), "    route 192.0.2.1/32 blackhole;\n")
            self.assertFalse(lock_dir.exists())

    def test_fetch_adguard_querylog_uses_basic_auth_and_search(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps({"data": []}).encode("utf-8")
        response.__exit__.return_value = False

        with mock.patch.object(dynamic_dns.urllib.request, "urlopen", return_value=response) as urlopen:
            dynamic_dns.fetch_adguard_querylog(
                "http://192.0.2.53:3000/",
                "ttvnw.net",
                limit=200,
                username="admin",
                password="secret",
                timeout=5,
            )

        request = urlopen.call_args.args[0]
        self.assertIn("/control/querylog?", request.full_url)
        self.assertIn("search=ttvnw.net", request.full_url)
        self.assertTrue(request.get_header("Authorization").startswith("Basic "))


if __name__ == "__main__":
    unittest.main()
