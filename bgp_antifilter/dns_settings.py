"""DNS proxy configuration shared by the admin API and service startup."""

import ipaddress
import os
import json
from pathlib import Path


DNS_SETTINGS = [
    {"key": "DNS_PROXY_ENABLED", "type": "bool", "default": "0"},
    {"key": "DNS_PROXY_UPSTREAM", "type": "ip", "default": "", "allow_empty": True},
    {"key": "DNS_PROXY_UPSTREAM_PORT", "type": "int", "default": "53", "min": 1, "max": 65535},
    {"key": "DNS_PROXY_BIND", "type": "ip", "default": "127.0.0.1"},
    {"key": "DNS_PROXY_PORT", "type": "int", "default": "53", "min": 1, "max": 65535},
    {"key": "DNS_PROXY_ALLOWED_CLIENTS", "type": "cidr_list", "default": "127.0.0.1/32 ::1/128"},
    {"key": "DNS_PROXY_HEALTH_PORT", "type": "int", "default": "8053", "min": 1, "max": 65535},
    {"key": "DNS_HEALTH_DOMAIN", "type": "domain", "default": "example.org"},
    {"key": "DNS_BGP_PORT", "type": "int", "default": "1179", "min": 1024, "max": 65535},
    {"key": "DNS_ROUTE_GRACE", "type": "int", "default": "30", "min": 0, "max": 604800, "unit": "sec"},
    {"key": "DNS_SYNC_MODE", "type": "enum", "default": "async", "options": ["async", "bgp", "bird"]},
    {"key": "DNS_SYNC_TIMEOUT", "type": "number", "default": "1", "min": 0.01, "max": 10, "unit": "sec", "step": "any"},
    {"key": "DNS_SYNC_ON_TIMEOUT", "type": "enum", "default": "servfail", "options": ["servfail", "forward"]},
]
for _spec in DNS_SETTINGS:
    _spec.update(legacy_backup_default=True, requires_restart=True)
DNS_KEYS = frozenset(spec["key"] for spec in DNS_SETTINGS)


def validate_configuration(values):
    if values.get("DNS_PROXY_ENABLED", "0") != "1":
        return
    upstream = values.get("DNS_PROXY_UPSTREAM", "").strip()
    if not upstream:
        raise ValueError("DNS_PROXY_UPSTREAM is required when DNS proxy is enabled")
    bind = ipaddress.ip_address(values["DNS_PROXY_BIND"])
    target = ipaddress.ip_address(upstream)
    if bind.is_unspecified or bind.is_multicast or target.is_unspecified or target.is_multicast:
        raise ValueError("DNS listener and upstream must use concrete unicast IP addresses")
    port = int(values["DNS_PROXY_PORT"])
    if bind == target and port == int(values["DNS_PROXY_UPSTREAM_PORT"]):
        raise ValueError("DNS proxy cannot use its own listener as upstream")
    if port == int(values["DNS_PROXY_HEALTH_PORT"]):
        raise ValueError("DNS listener and health endpoint must use different ports")
    if bind.is_loopback and int(values["DNS_BGP_PORT"]) in {port, int(values["DNS_PROXY_HEALTH_PORT"])}:
        raise ValueError("DNS and health ports must differ from the local BGP port")


def active_environment(environ=None):
    """Overlay the DNS configuration activated at container startup."""
    env = dict(os.environ if environ is None else environ)
    path = Path(env.get("GENERATED_DIR", "/etc/bird/generated")) / "dns-settings.active.json"
    if path.exists():
        from .admin.settings import validate_setting
        values = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(values, dict) or set(values) != DNS_KEYS:
            raise ValueError("invalid active DNS configuration")
        values = {key: validate_setting(key, value) for key, value in values.items()}
        validate_configuration(values)
        env.update(values)
    return env


def activate():
    from .admin.config import AdminConfig
    from .admin.settings import SettingsService, validate_setting
    from .state_store import write_state
    service = SettingsService(AdminConfig.from_env())
    desired = service.effective_settings()
    values = {key: validate_setting(key, desired[key]) for key in DNS_KEYS}
    validate_configuration(values)
    write_state(service.config.generated_dir / "dns-settings.active.json", values)
    return values


def load_active_environment():
    # Import lazily: SettingsService includes DNS_SETTINGS in its schema.
    from .admin.config import AdminConfig
    from .admin.settings import SettingsService, validate_setting
    service = SettingsService(AdminConfig.from_env())
    desired = service.effective_settings()
    env = active_environment({**os.environ, **desired})
    values = {key: validate_setting(key, env[key]) for key in desired}
    validate_configuration(values)
    os.environ.update(values)
    return values


def health_url(values):
    bind = values.get("DNS_PROXY_BIND", "127.0.0.1")
    host = f"[{bind}]" if ":" in bind else bind
    return f"http://{host}:{values.get('DNS_PROXY_HEALTH_PORT', '8053')}/ready"


if __name__ == "__main__":
    import sys
    if sys.argv[1:] != ["activate"]:
        raise SystemExit("usage: python -m bgp_antifilter.dns_settings activate")
    print(activate()["DNS_PROXY_ENABLED"])
