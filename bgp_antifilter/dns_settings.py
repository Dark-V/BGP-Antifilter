"""DNS UI schema and the explicitly applied runtime configuration."""
import json
import os
from pathlib import Path
import sys
import urllib.request


DNS_SETTINGS = [
    {"key": "DNS_PROXY_ENABLED", "type": "bool", "default": "0"},
    {"key": "ADGUARD_DNS", "type": "ipv4", "default": "192.168.88.16"},
    {"key": "ADGUARD_DNS_PORT", "type": "int", "default": "53", "min": 1, "max": 65535},
    {"key": "DNS_PROXY_BIND", "type": "ipv4", "default": "", "allow_empty": True},
    {"key": "DNS_PROXY_PORT", "type": "int", "default": "53", "min": 1, "max": 65535},
    {"key": "DNS_PROXY_ALLOWED_CLIENTS", "type": "cidr_list", "default": "", "allow_empty": True},
    {"key": "DNS_PROXY_HEALTH_PORT", "type": "int", "default": "8053", "min": 1, "max": 65535},
    {"key": "DNS_HEALTH_DOMAIN", "type": "domain", "default": "example.org"},
    {"key": "DNS_BGP_PORT", "type": "int", "default": "1179", "min": 1024, "max": 65535},
    {"key": "DNS_ROUTE_GRACE", "type": "int", "default": "30", "min": 0, "max": 604800, "unit": "sec"},
    {"key": "DNS_SYNC_MODE", "type": "enum", "default": "async", "options": ["async", "bgp", "bird"]},
    {"key": "DNS_SYNC_TIMEOUT", "type": "number", "default": "1", "min": 0, "exclusive_min": True, "max": 10, "step": "any", "unit": "sec"},
    {"key": "DNS_SYNC_ON_TIMEOUT", "type": "enum", "default": "servfail", "options": ["servfail", "forward"]},
]
DNS_KEYS = frozenset(item["key"] for item in DNS_SETTINGS)
BIRD_RESTART_KEYS = frozenset(("MY_AS", "MT_AS", "MT_IP", "BIRD_IP", "ROUTER_ID", "BGP_COMMUNITY",
                               "DNS_PROXY_ENABLED", "DNS_BGP_PORT"))
COMMON_KEYS = BIRD_RESTART_KEYS - DNS_KEYS | {"BGP_PROTOCOL", "HEALTHCHECK_REQUIRE_BGP"}
ACTIVE_KEYS = DNS_KEYS | COMMON_KEYS


def active_path(settings_file):
    return Path(settings_file).with_name("dns-active.json")


def read_values(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    if not isinstance(data, dict) or not isinstance(data.get("values", data), dict):
        raise ValueError(f"Invalid settings document: {path}")
    return data.get("values", data)


def active_overrides(settings_file):
    path = active_path(settings_file)
    # Preserve BGP overrides from versions preceding the active/saved split.
    allowed = ACTIVE_KEYS if path.exists() else COMMON_KEYS
    values = read_values(path if path.exists() else settings_file)
    return {key: str(value) for key, value in values.items() if key in allowed}


def load_active_environment():
    settings_file = os.environ.get("SETTINGS_FILE", "/etc/bird/generated/settings.json")
    os.environ.update(active_overrides(settings_file))


def listener_address(values):
    return values.get("DNS_PROXY_BIND") or values.get("BIRD_IP", "127.0.0.1")


def health_url(values):
    return f"http://{listener_address(values)}:{values.get('DNS_PROXY_HEALTH_PORT', '8053')}/ready"


def check_health():
    load_active_environment()
    if os.environ.get("DNS_PROXY_ENABLED", "0") == "0":
        return
    with urllib.request.urlopen(health_url(os.environ), timeout=10) as reply:
        if json.load(reply).get("ready") is not True:
            raise RuntimeError("DNS proxy is not ready")


if __name__ == "__main__":
    try:
        check_health()
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
