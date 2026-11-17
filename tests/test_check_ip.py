import contextlib
import io
import ipaddress
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

    def test_domain_list_source_uses_resolved_route_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            domain_cache = root / "domains.cache"
            resolved_cache = root / "resolved.cache"

            domain_cache.write_text("bato.to\n", encoding="utf-8")
            resolved_cache.write_text("3.164.110.54/32\n", encoding="utf-8")

            source = {
                "kind": "domain-list-url",
                "name": "anime",
                "url": "https://example.com/anime.txt",
                "status": "fresh",
                "cache_file": str(domain_cache),
                "resolved_cache_file": str(resolved_cache),
            }

            matches = check_ip.source_matches(ipaddress.ip_address("3.164.110.54"), source)

            self.assertEqual(matches, [ipaddress.ip_network("3.164.110.54/32")])

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

    def test_live_lookup_does_not_use_generated_routes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = root / "routes.conf"
            snapshot.write_text("route 192.0.2.10/32 blackhole;\n", encoding="utf-8")
            argv = ["192.0.2.10", "--live", "--json", "--routes", str(snapshot), "--status", str(root / "status.json")]
            greeting = "0001 BIRD 2.0.12 ready.\n0018 Access restricted\n"
            live = greeting + "1007-Table master4:\n     192.0.2.0/24 blackhole [dns_live 12:00] * (100)\n"
            absent = greeting + "8001 Network not found\n"
            for code, output, routes in [(0, live, ["192.0.2.0/24"]), (1, absent, [])]:
                with mock.patch("bgp_antifilter.bird_cli.subprocess.run",
                                return_value=subprocess.CompletedProcess([], code, output, "")) as run:
                    exit_code, result = run_main_quiet(argv)
                self.assertEqual(exit_code, code)
                self.assertEqual(json.loads(result)["routes"], routes)
                self.assertEqual(run.call_args.args[0], ["birdc", "-v", "-r", "show", "route", "for", "192.0.2.10", "primary"])

    def test_live_lookup_failure_has_distinct_exit_status(self):
        with mock.patch("bgp_antifilter.bird_cli.subprocess.run",
                        side_effect=subprocess.TimeoutExpired("birdc", 3)):
            exit_code, result = run_main_quiet(["192.0.2.10", "--live", "--json"])
        self.assertEqual(exit_code, 2)
        self.assertEqual(result, "")


if __name__ == "__main__":
    unittest.main()
