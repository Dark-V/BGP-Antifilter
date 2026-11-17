import argparse
from contextlib import closing
import ipaddress
import json
import re
from pathlib import Path
import sqlite3
import subprocess
import sys

from . import bird_cli
from .bgp_feed import SYNC_PREFIX


IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\d.])")


def parse_networks_from_text(text, *, extract):
    networks = []
    values = IPV4_RE.findall(text) if extract else text.splitlines()

    for value in values:
        value = value.strip()
        if not value:
            continue

        if "/" not in value:
            value = f"{value}/32"

        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue

    return networks


def read_networks(path, *, extract):
    if not path.exists():
        return []

    return parse_networks_from_text(path.read_text(encoding="utf-8", errors="replace"), extract=extract)


def matching_networks(address, networks):
    return [network for network in networks if address in network]


def describe_source(source):
    kind = source.get("kind", "source")
    name = source.get("name", "")
    url = source.get("url")
    status = source.get("status", "unknown")

    if url and url != name:
        return f"{kind} {name} ({status}) - {url}"

    return f"{kind} {name} ({status})"


def source_matches(address, source):
    kind = source.get("kind")
    if kind == "domain-list-url":
        cache_file = source.get("resolved_cache_file")
    else:
        cache_file = source.get("cache_file")

    if not cache_file or source.get("status") in {"failed", "skipped", "disabled"}:
        return []

    path = Path(cache_file)
    extract = kind in {"url", "asn", "google", "domain-list-url"}
    networks = read_networks(path, extract=extract)
    return matching_networks(address, networks)


def google_default_matches(address, sources):
    google = next((source for source in sources if source.get("kind") == "google" and source.get("name") == "goog.json"), None)
    cloud = next((source for source in sources if source.get("kind") == "google" and source.get("name") == "cloud.json"), None)

    if not google or not cloud:
        return []

    google_matches = source_matches(address, google)
    cloud_matches = source_matches(address, cloud)

    if google_matches and not cloud_matches:
        return google_matches

    return []


def find_sources(address, status):
    result = []
    sources = status.get("sources", [])

    for source in sources:
        if source.get("kind") == "google":
            continue

        matches = source_matches(address, source)
        if matches:
            result.append((source, matches))

    google_matches = google_default_matches(address, sources)
    if google_matches:
        result.append((
            {"kind": "google", "name": "default ranges minus cloud", "status": "derived"},
            google_matches,
        ))

    return result


def find_dns_origin(address, database):
    if not database.is_file():
        return None
    try:
        with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.5)) as db:
            row = db.execute("SELECT domain, rule, added_at FROM dns_route_origins WHERE address=?",
                             (str(address),)).fetchone()
    except sqlite3.Error as exc:
        if str(exc) != "no such table: dns_route_origins":
            print(f"DNS route origin lookup failed: {exc}", file=sys.stderr)
        return None
    if row is not None:
        domain, rule, added_at = row
        return {"domain": domain, "rule": rule, "added_at": added_at}
    return None


def load_status(path):
    if not path.exists():
        return {"sources": []}

    with path.open(encoding="utf-8") as file:
        return json.load(file)


def render_result(address, route_matches, source_results, *, live=False):
    scope = "BIRD routes" if live else "Generated routes"
    lines = [f"IP: {address}", f"{scope}: {'yes' if route_matches else 'no'}"]

    for network in route_matches:
        lines.append(f"  - {network}")

    if source_results:
        lines.append("Sources:")
        for source, matches in source_results:
            lines.append(f"  - {describe_source(source)}")
            for network in matches[:5]:
                lines.append(f"    match: {network}")
            if len(matches) > 5:
                lines.append(f"    ... and {len(matches) - 5} more")
    else:
        lines.append("Sources: no cache match found")

    return "\n".join(lines)


def build_result(address, route_matches, source_results):
    return {
        "ip": str(address),
        "matched": bool(route_matches),
        "routes": [str(network) for network in route_matches],
        "sources": [
            {
                "kind": source.get("kind", "source"),
                "name": source.get("name", ""),
                "url": source.get("url"),
                "status": source.get("status", "unknown"),
                "matches": [str(network) for network in matches],
            }
            for source, matches in source_results
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check whether an IPv4 address is present in generated BIRD routes.")
    parser.add_argument("ip", help="IPv4 address to check")
    parser.add_argument("--routes", default="/etc/bird/generated/routes.conf")
    parser.add_argument("--status", default="/etc/bird/generated/status.json")
    parser.add_argument("--live", action="store_true", help="Query BIRD's current routing table.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON output.")
    args = parser.parse_args(argv)

    try:
        address = ipaddress.ip_address(args.ip)
    except ValueError as exc:
        print(f"Invalid IP address: {exc}", file=sys.stderr)
        return 2

    if address.version != 4:
        print("Only IPv4 addresses are supported by this project", file=sys.stderr)
        return 2

    dns_origin = None
    if args.live:
        try:
            output = bird_cli.query(3, "show", "route", "for", str(address), "primary")
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            detail = getattr(exc, "stderr", None) or str(exc)
            print(f"BIRD route lookup failed: {detail.strip()}", file=sys.stderr)
            return 2
        # The DNS synchronization marker is internal to BIRD.
        rows = bird_cli.IPV4_ROUTE_ROW.findall(output)
        rows = [(prefix, row) for prefix, row in rows if prefix != SYNC_PREFIX or "[dns_live " not in row]
        routes = [ipaddress.IPv4Network(prefix) for prefix, _ in rows]
        if any(prefix == f"{address}/32" and "[dns_live " in row for prefix, row in rows):
            dns_origin = find_dns_origin(address, Path(args.routes).with_name("dns-cache.sqlite3"))
    else:
        routes = read_networks(Path(args.routes), extract=True)
    route_matches = matching_networks(address, routes)
    status = load_status(Path(args.status))
    source_results = find_sources(address, status)

    if args.json:
        result = build_result(address, route_matches, source_results)
        if dns_origin is not None:
            result["dns_origin"] = dns_origin
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(render_result(address, route_matches, source_results, live=args.live))

    return 0 if route_matches else 1
