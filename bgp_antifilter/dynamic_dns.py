import argparse
import base64
import fnmatch
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime


DEFAULT_INTERVAL = 2.0
DEFAULT_QUERY_LIMIT = 1000
DEFAULT_HTTP_TIMEOUT = 5.0
DEFAULT_FALLBACK_TTL = 300
DEFAULT_MAX_TTL = 86400


def normalize_hostname(value):
    host = str(value or "").strip().rstrip(".").lower()
    if not host:
        return ""
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return ""


def parse_patterns(text):
    patterns = []
    invalid = 0
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        kind = "exact"
        value = line
        lowered = line.lower()
        if lowered.startswith("full:"):
            value = line[5:].strip()
        elif lowered.startswith("domain:"):
            kind = "suffix"
            value = line[7:].strip()
        elif line.startswith("+."):
            kind = "suffix"
            value = line[2:].strip()
        elif lowered.startswith(("regexp:", "keyword:")):
            invalid += 1
            continue
        elif "*" in line or "?" in line:
            kind = "glob"

        if kind == "glob":
            value = str(value).strip().rstrip(".").lower()
            if not re.fullmatch(r"[a-z0-9._*?-]+", value):
                invalid += 1
                continue
        else:
            value = normalize_hostname(value)
            if not value or not re.fullmatch(r"[a-z0-9._-]+", value):
                invalid += 1
                continue

        if not value or "://" in value or "/" in value or ":" in value:
            invalid += 1
            continue

        item = {"raw": line, "kind": kind, "value": value}
        if item not in patterns:
            patterns.append(item)

    return patterns, invalid


def host_matches(host, pattern):
    host = normalize_hostname(host)
    if not host:
        return False
    kind = pattern["kind"]
    value = pattern["value"]
    if kind == "exact":
        return host == value
    if kind == "suffix":
        return host == value or host.endswith("." + value)
    return fnmatch.fnmatchcase(host, value)


def matching_patterns(host, patterns):
    return [item for item in patterns if host_matches(host, item)]


def search_hint(pattern):
    value = pattern["value"]
    if pattern["kind"] == "glob":
        parts = [part.strip(".") for part in re.split(r"[*?]+", value) if part.strip(".")]
        value = max(parts, key=len, default="")

    labels = [label for label in value.strip(".").split(".") if label]
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in {"ac", "co", "com", "edu", "gov", "net", "org"}:
        return ".".join(labels[-3:])
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return value


def adguard_querylog_url(base_url, *, limit, search):
    base = str(base_url or "").strip().rstrip("/")
    if not base:
        raise ValueError("DYNAMIC_DNS_URL is required")

    if base.endswith("/control/querylog"):
        endpoint = base
    elif base.endswith("/control"):
        endpoint = base + "/querylog"
    else:
        endpoint = base + "/control/querylog"

    query = {"limit": int(limit)}
    if search:
        query["search"] = search
    return endpoint + "?" + urllib.parse.urlencode(query)


def fetch_adguard_querylog(
    base_url,
    *,
    username="",
    password="",
    limit=DEFAULT_QUERY_LIMIT,
    search="",
    timeout=DEFAULT_HTTP_TIMEOUT,
):
    url = adguard_querylog_url(base_url, limit=limit, search=search)
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "BGP-Antifilter/0.4.6"},
    )

    if username or password:
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        request.add_header("Authorization", f"Basic {token}")

    # The AdGuard endpoint is normally a local-LAN service. Do not inherit an
    # outbound HTTP(S) proxy that may be configured for external feed downloads.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"AdGuard query log request failed: {exc}") from exc

    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise RuntimeError("AdGuard query log returned an unexpected payload")
    return payload["data"]


def parse_event_time(value, fallback):
    raw = str(value or "").strip()
    if not raw:
        return fallback

    # AdGuard timestamps may contain nanoseconds while datetime.fromisoformat
    # accepts microseconds. Trim only the excess fractional digits.
    raw = re.sub(r"(\.\d{6})\d+(?=(?:Z|[+-]\d\d:\d\d)$)", r"\1", raw)
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"

    try:
        return datetime.fromisoformat(raw).timestamp()
    except ValueError:
        return fallback


def extract_observations(
    items,
    patterns,
    *,
    now=None,
    fallback_ttl=DEFAULT_FALLBACK_TTL,
    max_ttl=DEFAULT_MAX_TTL,
):
    now = time.time() if now is None else float(now)
    observations = []
    matched_queries = 0

    for item in items:
        if not isinstance(item, dict):
            continue

        question = item.get("question") or {}
        # "name" is current OpenAPI; "host" keeps compatibility with older
        # AdGuard Home query-log payloads.
        host = normalize_hostname(question.get("name") or question.get("host"))
        if not host or not matching_patterns(host, patterns):
            continue

        matched_queries += 1
        event_time = parse_event_time(item.get("time"), now)

        for answer in item.get("answer") or []:
            if not isinstance(answer, dict) or str(answer.get("type", "")).upper() != "A":
                continue
            try:
                address = ipaddress.IPv4Address(str(answer.get("value", "")).strip())
            except ipaddress.AddressValueError:
                continue

            # Never teach BIRD loopback/private/link-local/unspecified routes
            # from local DNS rewrites.
            if not address.is_global:
                continue

            try:
                ttl = int(answer.get("ttl"))
            except (TypeError, ValueError):
                ttl = int(fallback_ttl)
            if ttl <= 0:
                ttl = int(fallback_ttl)
            ttl = min(ttl, int(max_ttl))

            expires_at = event_time + ttl
            if expires_at <= now:
                continue

            observations.append(
                {
                    "ip": str(address),
                    "domain": host,
                    "expires_at": int(expires_at),
                }
            )

    return observations, matched_queries


def load_state(path):
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"routes": {}}

    routes = payload.get("routes")
    return {"routes": routes if isinstance(routes, dict) else {}}


def prune_state(state, patterns, *, now=None):
    now = int(time.time() if now is None else now)
    kept = {}

    for ip, record in (state.get("routes") or {}).items():
        try:
            address = ipaddress.IPv4Address(ip)
            expires_at = int(record.get("expires_at") or 0)
        except (ipaddress.AddressValueError, TypeError, ValueError, AttributeError):
            continue

        if expires_at <= now or not address.is_global:
            continue

        domains = [normalize_hostname(value) for value in (record.get("domains") or [])]
        domains = [value for value in domains if value]
        if not patterns or not any(matching_patterns(domain, patterns) for domain in domains):
            continue

        kept[str(address)] = {
            "expires_at": expires_at,
            "domains": sorted(set(domains))[:16],
        }

    state["routes"] = kept
    return state


def merge_observations(state, observations):
    routes = state.setdefault("routes", {})

    for item in observations:
        ip = item["ip"]
        existing = routes.get(ip) or {"expires_at": 0, "domains": []}
        existing["expires_at"] = max(
            int(existing.get("expires_at") or 0),
            int(item["expires_at"]),
        )
        domains = set(existing.get("domains") or [])
        domains.add(item["domain"])
        existing["domains"] = sorted(domains)[:16]
        routes[ip] = existing

    return state


def render_routes(state):
    addresses = []
    for value in (state.get("routes") or {}):
        try:
            addresses.append(ipaddress.IPv4Address(value))
        except ipaddress.AddressValueError:
            continue

    addresses.sort(key=int)
    header = "# Generated by BGP-Antifilter dynamic DNS watcher. Do not edit.\n"
    return header + "".join(
        f"    route {address}/32 blackhole;\n"
        for address in addresses
    )


def write_json_atomic(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    tmp.replace(path)


def write_text_atomic(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def apply_routes(path, content, *, birdc="birdc", lock_dir=None):
    path = Path(path)

    try:
        old_content = path.read_text(encoding="utf-8")
    except OSError:
        old_content = ""

    if old_content == content:
        return False, None

    # Avoid racing the normal route generator while it is swapping routes.conf
    # and running birdc configure.
    if lock_dir and Path(lock_dir).exists():
        return False, "route update lock is active"

    write_text_atomic(path, content)

    try:
        completed = subprocess.run(
            [birdc, "configure"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        write_text_atomic(path, old_content)
        return False, str(exc)

    if completed.returncode == 0:
        return True, None

    write_text_atomic(path, old_content)
    try:
        subprocess.run(
            [birdc, "configure"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass

    error = (completed.stderr or completed.stdout or "birdc configure failed").strip()
    return False, error


def load_patterns(path):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        text = ""
    return parse_patterns(text)


def run_once(config):
    now = int(time.time())
    patterns, invalid_patterns = load_patterns(config["patterns_file"])

    state = load_state(config["state_file"])
    prune_state(state, patterns, now=now)

    items = []
    errors = []

    if patterns:
        # Query AdGuard by service-root hints instead of downloading the whole
        # DNS log every poll. For the Twitch example this groups lookups into
        # twitch.tv, ttvnw.net and live-video.net.
        hints = sorted(
            {search_hint(pattern) for pattern in patterns if search_hint(pattern)}
        ) or [""]

        seen = set()
        for hint in hints:
            try:
                batch = fetch_adguard_querylog(
                    config["url"],
                    username=config["username"],
                    password=config["password"],
                    limit=config["query_limit"],
                    search=hint,
                    timeout=config["http_timeout"],
                )
            except RuntimeError as exc:
                errors.append(str(exc))
                continue

            for item in batch:
                question = item.get("question") if isinstance(item, dict) else {}
                host = normalize_hostname(
                    (question or {}).get("name") or (question or {}).get("host")
                )
                key = (
                    str(item.get("time", "")),
                    host,
                    str(item.get("client", "")),
                    str((question or {}).get("type", "")),
                )
                if key in seen:
                    continue
                seen.add(key)
                items.append(item)

    observations, matched_queries = extract_observations(
        items,
        patterns,
        now=now,
        fallback_ttl=config["fallback_ttl"],
        max_ttl=config["max_ttl"],
    )

    merge_observations(state, observations)
    prune_state(state, patterns, now=now)

    content = render_routes(state)
    changed, apply_error = apply_routes(
        config["routes_file"],
        content,
        birdc=config["birdc"],
        lock_dir=config["lock_dir"],
    )

    if apply_error and apply_error != "route update lock is active":
        errors.append(apply_error)

    write_json_atomic(
        config["state_file"],
        {
            "updated_at_unix": now,
            "routes": state["routes"],
        },
    )

    write_json_atomic(
        config["status_file"],
        {
            "updated_at_unix": now,
            "provider": "adguard",
            "url": config["url"],
            "patterns": len(patterns),
            "invalid_patterns": invalid_patterns,
            "query_items": len(items),
            "matched_queries": matched_queries,
            "observed_answers": len(observations),
            "active_routes": len(state["routes"]),
            "routes_changed": changed,
            "deferred": apply_error == "route update lock is active",
            "errors": errors,
            "success": not errors,
        },
    )

    if errors:
        print("dynamic-dns: " + "; ".join(errors), flush=True)
    elif changed:
        print(
            f"dynamic-dns: applied {len(state['routes'])} active routes",
            flush=True,
        )

    return 0 if not errors else 1


def config_from_env():
    return {
        "url": os.environ.get("DYNAMIC_DNS_URL", "").strip(),
        "username": os.environ.get("DYNAMIC_DNS_USERNAME", ""),
        "password": os.environ.get("DYNAMIC_DNS_PASSWORD", ""),
        "interval": float(
            os.environ.get("DYNAMIC_DNS_INTERVAL", str(DEFAULT_INTERVAL))
        ),
        "query_limit": int(
            os.environ.get("DYNAMIC_DNS_QUERY_LIMIT", str(DEFAULT_QUERY_LIMIT))
        ),
        "http_timeout": float(
            os.environ.get(
                "DYNAMIC_DNS_HTTP_TIMEOUT",
                str(DEFAULT_HTTP_TIMEOUT),
            )
        ),
        "fallback_ttl": int(
            os.environ.get(
                "DYNAMIC_DNS_FALLBACK_TTL",
                str(DEFAULT_FALLBACK_TTL),
            )
        ),
        "max_ttl": int(
            os.environ.get("DYNAMIC_DNS_MAX_TTL", str(DEFAULT_MAX_TTL))
        ),
        "patterns_file": os.environ.get(
            "DYNAMIC_DOMAINS_FILE",
            "/etc/bird/generated/config/dynamic-domains.txt",
        ),
        "routes_file": os.environ.get(
            "DYNAMIC_ROUTES_FILE",
            "/etc/bird/generated/dynamic-routes.conf",
        ),
        "state_file": os.environ.get(
            "DYNAMIC_DNS_STATE_FILE",
            "/etc/bird/generated/dynamic-dns-state.json",
        ),
        "status_file": os.environ.get(
            "DYNAMIC_DNS_STATUS_FILE",
            "/etc/bird/generated/dynamic-dns-status.json",
        ),
        "lock_dir": os.environ.get(
            "UPDATE_LOCK_DIR",
            "/etc/bird/generated/update.lock",
        ),
        "birdc": os.environ.get("BIRDC", "birdc"),
    }


def validate_config(config):
    if not config["url"]:
        raise ValueError(
            "DYNAMIC_DNS_URL must be set when dynamic DNS is enabled"
        )
    if config["interval"] <= 0:
        raise ValueError("DYNAMIC_DNS_INTERVAL must be greater than zero")
    if config["query_limit"] <= 0:
        raise ValueError("DYNAMIC_DNS_QUERY_LIMIT must be greater than zero")
    if config["http_timeout"] <= 0:
        raise ValueError("DYNAMIC_DNS_HTTP_TIMEOUT must be greater than zero")
    if config["fallback_ttl"] <= 0 or config["max_ttl"] <= 0:
        raise ValueError("dynamic DNS TTL values must be greater than zero")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Learn wildcard domain IPv4 routes from an "
            "AdGuard Home query log."
        )
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Poll once, update routes, and exit.",
    )
    args = parser.parse_args(argv)

    config = config_from_env()
    try:
        validate_config(config)
    except (TypeError, ValueError) as exc:
        print(f"dynamic-dns: invalid configuration: {exc}", flush=True)
        return 2

    while True:
        run_once(config)
        if args.once:
            return 0
        time.sleep(config["interval"])


if __name__ == "__main__":
    raise SystemExit(main())
