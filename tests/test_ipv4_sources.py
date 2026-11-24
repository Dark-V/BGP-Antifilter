import contextlib
import io
import ipaddress
from pathlib import Path
import tempfile
import unittest

from bgp_antifilter import check_ip, generate_routes, route_builder
from bgp_antifilter.sources.fetch import count_source_routes


class IPv4SourceParsingTests(unittest.TestCase):
    def parse(self, text, *, extract=True):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source.txt"
            path.write_text(text, encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                networks, invalid = generate_routes.read_networks(path, extract=extract)
        self.assertEqual(check_ip.parse_networks_from_text(text, extract=extract), networks)
        self.assertEqual(count_source_routes(text, extract=extract), len(networks))
        return [str(network) for network in networks], invalid

    def test_escaped_json_and_plain_sources_share_networks_and_counts(self):
        text = (
            '{"service.test":["192.0.2.0\\/24","198.51.100.128\\/25"]}\n'
            '{\n "prefixes": ["203.0.113.0\\/26"]\n}\n'
            'IP-CIDR,203.0.113.64/26,no-resolve\n'
            'DOMAIN-SUFFIX,service.test\n'
            '198.51.100.12\n'
        )
        self.assertEqual(self.parse(text), (["192.0.2.0/24", "198.51.100.128/25", "203.0.113.0/26",
                                            "203.0.113.64/26", "198.51.100.12/32"], 0))

    def test_invalid_masks_are_rejected_without_bare_address_fallback(self):
        text = '\n'.join(f'"192.0.2.1{slash}{mask}"'
                         for slash in ("/", "\\/") for mask in ("33", "129", "999", "-1"))
        self.assertEqual(self.parse(text), ([], 8))

    def test_strict_plain_list_parsing_does_not_decode_json_escapes(self):
        self.assertEqual(self.parse("192.0.2.0\\/24\n198.51.100.0/24\n", extract=False),
                         (["198.51.100.0/24"], 1))

    def test_diagnostics_match_an_address_inside_escaped_source_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source.cache"
            path.write_text('{"service.test":["192.0.2.0\\/24"]}', encoding="utf-8")
            source = {"kind": "url", "cache_file": str(path), "status": "fresh"}
            self.assertEqual(check_ip.source_matches(ipaddress.IPv4Address("192.0.2.42"), source),
                             [ipaddress.IPv4Network("192.0.2.0/24")])

    def test_combined_generation_preserves_exclusion_from_escaped_prefix(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            networks, stats = route_builder.parse_and_build_routes(
                Path(tmp) / "routes.conf",
                ['{"service.test":["192.0.2.0\\/24"]}', 'IP-CIDR,198.51.100.0/24,no-resolve'],
                [], ["192.0.2.7/32"], 8, False,
            )
        self.assertEqual(stats["base"], 2)
        self.assertEqual(stats["invalid"], 0)
        self.assertFalse(any(ipaddress.IPv4Address("192.0.2.7") in network for network in networks))
        self.assertTrue(any(ipaddress.IPv4Address("192.0.2.42") in network for network in networks))
        self.assertIn(ipaddress.IPv4Network("198.51.100.0/24"), networks)

    def test_escaped_mask_cannot_bypass_broad_route_guard(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "refusing broad IPv4 routes"):
                route_builder.parse_and_build_routes(
                    Path(tmp) / "routes.conf", ['{"service.test":["192.0.2.0\\/7"]}'],
                    [], [], 8, False,
                )


if __name__ == "__main__":
    unittest.main()
