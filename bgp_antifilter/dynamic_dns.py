import argparse
import base64
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_PROVIDER = ""
DEFAULT_POLL_INTERVAL = 5
DEFAULT_MAX_AGE = 6 * 60 * 60
DEFAULT_QUERY_LIMIT = 200
DEFAULT_TIMEOUT = 5
DEFAULT_RULES_FILE = "/etc/bird/dynamic-domains.txt"
DEFAULT_ROUTES_FILE = "/etc/bird/generated/dynamic-routes.conf"
DEFAULT_STATE_FILE = "/etc/bird/generated/dynamic-dns-cache.json"
DEFAULT_LOCK_DIR = "/etc/bird/generated/update.lock"


def read_rules(path):
    rules = []
    seen = set()
    if not path.exists():
        return rules

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        value = raw_line.strip().lower().rstrip(".")
        if not value or value.startswith("#"):
            continue
        if value.startswith("*."):
            base = value[2:]
            if not base or "*" in base:
                continue
            value = f"*.{base}"
        elif "*" in value:
            continue
        if value not in seen:
            seen.add(value)
            rules.append(value)
    return rules


def rule_search_term(rule):
    return rule[2:] if rule.startswith("*.") else rule


def domain_matches(name, rule):
    name = str(name or "").strip().lower().rstrip(".")
    rule = str(rule or "").strip().lower().rstrip(".")
    if not name or not rule:
        return False
    if rule.startswith("*."):
        base = rule[2:]
        return name == base or name.endswith(f".{base}")
    return name == rule


def parse_timestamp(value):
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def basic_auth_header(username, password):
    if not username and not password:
        return None
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def fetch_adguard_querylog(base_url, search, *, limit, username="", password="", timeout=DEFAULT_TIMEOUT):
    base_url = str(base_url or "").strip().rstrip("/")
    if not base_url:
        raise RuntimeError("DYNAMIC_DNS_URL is required for the adguard provider")

    query = urllib.parse.urlencode({"limit": int(limit), "search": search})
    request = urllib.request.Request(
        f"{base_url}/control/querylog?{query}",
        headers={"User-Agent": "BGP-Antifilter/1.0"},
    )
    auth = basic_auth_header(username, password)
    if auth:
        request.add_header("Authorization", auth)

    try:
        with urllib.request.urlopen(request, timeout=float(timeout)) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(str(exc)) from exc

    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise RuntimeError("AdGuard query log response does not contain a data array")
    return payload


def collect_adguard_entries(
    base_url,
    rules,
    *,
    limit,
    username="",
    password="",
    timeout=DEFAULT_TIMEOUT,
    now=None,
    max_age=DEFAULT_MAX_AGE,
):
    now = int(time.time()) if now is None else int(now)
    entries = []
    fetched_terms = set()

    for rule in rules:
        term = rule_search_term(rule)
        if term in fetched_terms:
            continue
        fetched_terms.add(term)
        payload = fetch_adguard_querylog(
            base_url,
            term,
            limit=limit,
            username=username,
            password=password,
            timeout=timeout,
        )
        for item in payload.get("data", []):
            if not isinstance(item, dict):
                continue
            question = item.get("question")
            if not isinstance(question, dict):
                continue
            hostname = str(question.get("name") or "").strip().lower().rstrip(".")
            matched_rule = next((candidate for candidate in rules if domain_matches(hostname, candidate)), None)
            if matched_rule is None:
                continue

            seen_at = parse_timestamp(item.get("time"))
            if seen_at is None:
                seen_at = now
            if max_age > 0 and seen_at < now - max_age:
                continue

            for answer in item.get("answer") or []:
                if not isinstance(answer, dict) or str(answer.get("type") or "").upper() != "A":
                    continue
                value = str(answer.get("value") or "").strip()
                try:
                    address = str(ipaddress.IPv4Address(value))
                except ipaddress.AddressValueError:
                    continue
                entries.append({
                    "address": address,
                    "hostname": hostname,
                    "rule": matched_rule,
                    "last_seen": seen_at,
                })

    return entries


def load_state(path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    result = {}
    for address, item in data.items():
        try:
            normalized = str(ipaddress.IPv4Address(address))
        except ipaddress.AddressValueError:
            continue
        if not isinstance(item, dict):
            continue
        try:
            last_seen = int(item.get("last_seen", 0))
        except (TypeError, ValueError):
            continue
        if last_seen <= 0:
            continue
        result[normalized] = {
            "hostname": str(item.get("hostname") or ""),
            "rule": str(item.get("rule") or ""),
            "last_seen": last_seen,
        }
    return result


def merge_state(state, entries, *, now=None, max_age=DEFAULT_MAX_AGE):
    now = int(time.time()) if now is None else int(now)
    merged = dict(state)
    for entry in entries:
        address = entry["address"]
        existing = merged.get(address)
        if existing is None or int(entry["last_seen"]) >= int(existing.get("last_seen", 0)):
            merged[address] = {
                "hostname": entry.get("hostname", ""),
                "rule": entry.get("rule", ""),
                "last_seen": int(entry["last_seen"]),
            }

    if max_age > 0:
        cutoff = now - int(max_age)
        merged = {
            address: item
            for address, item in merged.items()
            if int(item.get("last_seen", 0)) >= cutoff
        }
    return merged


def routes_text(state):
    networks = sorted(
        (ipaddress.IPv4Network(f"{address}/32") for address in state),
        key=lambda network: int(network.network_address),
    )
    return "".join(f"    route {network} blackhole;\n" for network in networks)


def write_text_atomic(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def save_state(path, state):
    write_text_atomic(path, json.dumps(state, indent=2, sort_keys=True) + "\n")


def acquire_lock(path):
    try:
        path.mkdir(parents=False)
    except FileExistsError:
        return False
    return True


def release_lock(path):
    try:
        path.rmdir()
    except OSError:
        pass


def apply_routes(routes_file, state_file, state, *, lock_dir, birdc="birdc"):
    new_text = routes_text(state)
    old_text = routes_file.read_text(encoding="utf-8") if routes_file.exists() else ""
    if new_text == old_text:
        save_state(state_file, state)
        return False

    lock_dir.parent.mkdir(parents=True, exist_ok=True)
    if not acquire_lock(lock_dir):
        return False

    try:
        write_text_atomic(routes_file, new_text)
        completed = subprocess.run(
            [birdc, "configure"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            write_text_atomic(routes_file, old_text)
            subprocess.run(
                [birdc, "configure"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "birdc configure failed")
        save_state(state_file, state)
        return True
    finally:
        release_lock(lock_dir)


def provider_entries(provider, rules, settings, *, now=None):
    if provider == "adguard":
        return collect_adguard_entries(
            settings["url"],
            rules,
            limit=settings["query_limit"],
            username=settings["username"],
            password=settings["password"],
            timeout=settings["timeout"],
            now=now,
            max_age=settings["max_age"],
        )
    raise RuntimeError(f"unsupported dynamic DNS provider: {provider}")


def env_int(name, default, minimum=1):
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value < minimum:
        raise RuntimeError(f"{name} must be at least {minimum}")
    return value


def settings_from_env():
    return {
        "provider": os.environ.get("DYNAMIC_DNS_PROVIDER", DEFAULT_PROVIDER).strip().lower(),
        "url": os.environ.get("DYNAMIC_DNS_URL", "").strip(),
        "username": os.environ.get("DYNAMIC_DNS_USERNAME", ""),
        "password": os.environ.get("DYNAMIC_DNS_PASSWORD", ""),
        "poll_interval": env_int("DYNAMIC_DNS_POLL_INTERVAL", DEFAULT_POLL_INTERVAL),
        "max_age": env_int("DYNAMIC_DNS_MAX_AGE", DEFAULT_MAX_AGE),
        "query_limit": env_int("DYNAMIC_DNS_QUERY_LIMIT", DEFAULT_QUERY_LIMIT),
        "timeout": env_int("DYNAMIC_DNS_TIMEOUT", DEFAULT_TIMEOUT),
        "rules_file": Path(os.environ.get("DYNAMIC_DOMAINS_FILE", DEFAULT_RULES_FILE)),
        "routes_file": Path(os.environ.get("DYNAMIC_ROUTES_FILE", DEFAULT_ROUTES_FILE)),
        "state_file": Path(os.environ.get("DYNAMIC_DNS_STATE_FILE", DEFAULT_STATE_FILE)),
        "lock_dir": Path(os.environ.get("UPDATE_LOCK_DIR", DEFAULT_LOCK_DIR)),
        "birdc": os.environ.get("BIRDC", "birdc"),
    }


def run_once(settings=None, *, now=None):
    settings = settings_from_env() if settings is None else settings
    provider = settings["provider"]
    if provider in {"", "off", "none", "disabled"}:
        return {"enabled": False, "routes": 0, "changed": False}

    rules = read_rules(settings["rules_file"])
    current_time = int(time.time()) if now is None else int(now)
    if not rules:
        changed = apply_routes(
            settings["routes_file"],
            settings["state_file"],
            {},
            lock_dir=settings["lock_dir"],
            birdc=settings["birdc"],
        )
        return {"enabled": True, "routes": 0, "changed": changed}

    entries = provider_entries(provider, rules, settings, now=current_time)
    state = merge_state(
        load_state(settings["state_file"]),
        entries,
        now=current_time,
        max_age=settings["max_age"],
    )
    changed = apply_routes(
        settings["routes_file"],
        settings["state_file"],
        state,
        lock_dir=settings["lock_dir"],
        birdc=settings["birdc"],
    )
    return {"enabled": True, "routes": len(state), "changed": changed}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)

    settings = settings_from_env()
    if args.once:
        result = run_once(settings)
        print(json.dumps(result, sort_keys=True))
        return 0

    while True:
        try:
            result = run_once(settings)
            if result["enabled"]:
                print(
                    f"dynamic-dns routes={result['routes']} changed={'yes' if result['changed'] else 'no'}",
                    flush=True,
                )
            else:
                print("dynamic-dns disabled", flush=True)
                return 0
        except Exception as exc:
            print(f"dynamic-dns error: {exc}", flush=True)
        time.sleep(settings["poll_interval"])


if __name__ == "__main__":
    raise SystemExit(main())
