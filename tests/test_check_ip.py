import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from bgp_antifilter import check_ip


def run_main_quiet(argv):
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
        exit_code = check_ip.main(argv)
    return exit_code, stdout.getvalue()


class CheckIpTests(unittest.TestCase):
    def test_main_reports_route_and_source_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            routes = root / "routes.conf"
            cache = root / "source.cache"
            status = root / "status.json"

            routes.write_text("    route 192.0.2.0/24 blackhole;\n", encoding="utf-8")
            cache.write_text("192.0.2.0/24\n", encoding="utf-8")
            status.write_text(
                json.dumps(
                    {
                        "sources": [
                            {
                                "kind": "url",
                                "name": "local",
                                "url": "file:///local",
                                "status": "fresh",
                                "cache_file": str(cache),
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            exit_code, _ = run_main_quiet(["192.0.2.10", "--routes", str(routes), "--status", str(status)])

            self.assertEqual(exit_code, 0)

    def test_main_returns_one_when_ip_is_not_in_generated_routes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            routes = root / "routes.conf"
            status = root / "status.json"

            routes.write_text("    route 192.0.2.0/24 blackhole;\n", encoding="utf-8")
            status.write_text('{"sources":[]}', encoding="utf-8")

            exit_code, _ = run_main_quiet(["198.51.100.1", "--routes", str(routes), "--status", str(status)])

            self.assertEqual(exit_code, 1)

    def test_main_can_print_json_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            routes = root / "routes.conf"
            status = root / "status.json"

            routes.write_text("    route 192.0.2.0/24 blackhole;\n", encoding="utf-8")
            status.write_text('{"sources":[]}', encoding="utf-8")

            exit_code, output = run_main_quiet([
                "192.0.2.10",
                "--routes",
                str(routes),
                "--status",
                str(status),
                "--json",
            ])

            data = json.loads(output)
            self.assertEqual(exit_code, 0)
            self.assertTrue(data["matched"])
            self.assertEqual(data["routes"], ["192.0.2.0/24"])


if __name__ == "__main__":
    unittest.main()


class DomainListSourceTests(unittest.TestCase):
    def test_source_matches_uses_resolved_cache_for_domain_list_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "resolved.cache"
            cache.write_text("192.0.2.55/32\n", encoding="utf-8")
            source = {
                "kind": "domain-list-url",
                "name": "https://example.com/domains.txt",
                "url": "https://example.com/domains.txt",
                "status": "fresh",
                "cache_file": str(Path(tmp) / "domains.cache"),
                "resolved_cache_file": str(cache),
            }

            matches = check_ip.source_matches(ipaddress.ip_address("192.0.2.55"), source)

        self.assertEqual(matches, [ipaddress.ip_network("192.0.2.55/32")])
