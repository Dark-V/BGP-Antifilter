"""Authenticated diagnostics for the optional DNS proxy."""

from contextlib import closing
import json
import sqlite3
import time

from ..domain_rules import DomainRules, normalize_domain_name, validate_rule_list
from ..dns_settings import active_environment, DNS_KEYS
from .storage import json_load
from .settings import validate_setting


class DnsProxyService:
    def __init__(self, config, settings):
        self.config, self.settings = config, settings

    def status(self):
        desired = self.settings.effective_settings()
        desired.update({key: validate_setting(key, desired[key]) for key in DNS_KEYS})
        values = active_environment({**desired, "GENERATED_DIR": str(self.config.generated_dir)})
        enabled = values["DNS_PROXY_ENABLED"] == "1"
        state = json_load(self.config.generated_dir / "dns-runtime.json", {})
        fresh = isinstance(state, dict) and bool(state.get("running")) and 0 <= time.time() - state.get("updated_at_unix", 0) < 15
        return {"enabled": enabled, "configured_enabled": desired["DNS_PROXY_ENABLED"] == "1",
                "requires_restart": any(desired[key] != values[key] for key in DNS_KEYS),
                "running": enabled and fresh,
                "ready": enabled and fresh and bool(state.get("ready")),
                "bind": values["DNS_PROXY_BIND"], "port": int(values["DNS_PROXY_PORT"]),
                "upstream": values["DNS_PROXY_UPSTREAM"], "upstream_port": int(values["DNS_PROXY_UPSTREAM_PORT"]),
                "sync_mode": values["DNS_SYNC_MODE"],
                "routes": state.get("dynamic_routes", 0) if enabled and fresh else 0,
                "last_error": state.get("last_error") if enabled and isinstance(state, dict) else None}

    def check_domain(self, value, *, environment=None):
        """Match saved or committed rules without resolving or observing DNS."""
        domain = normalize_domain_name(value)
        if domain is None:
            raise ValueError("Enter a valid domain name")
        environment = self.settings.command_environment() if environment is None else environment
        active = environment.get("DNS_PROXY_ENABLED", "0") == "1"
        result = {"domain": domain, "scope": "active" if active else "saved", "action": "unknown",
                  "include_rule": None, "exclude_rule": None}
        try:
            if active:
                database = self.config.generated_dir / "dns-cache.sqlite3"
                with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.5)) as db:
                    row = db.execute("SELECT value FROM metadata WHERE key='policy'").fetchone()
                if row is None:
                    raise ValueError("Applied DNS policy is not available yet")
                policy = json.loads(row[0])
                if not isinstance(policy, dict):
                    raise ValueError("Applied DNS policy is invalid")
                for name in ("include_domains", "exclude_domains"):
                    if not isinstance(policy.get(name), list) or any(not isinstance(rule, str) for rule in policy[name]):
                        raise ValueError("Applied DNS policy contains an invalid rule list")
                result["generation"] = policy.get("generation")

                def entries(role):
                    return policy[role + "_domains"]
            else:
                def entries(role):
                    path = self.config.list_files[role + "-domains"]
                    try:
                        content = path.read_text(encoding="utf-8")
                    except FileNotFoundError:
                        return []
                    return [line.strip() for line in content.splitlines()
                            if line.strip() and not line.strip().startswith("#")]

            # Exclusion is final, just as in the running route worker. An
            # unrelated include regex must not delay or invalidate that result.
            excluded = DomainRules(entries("exclude")).matching_rule(domain)
            if excluded is not None:
                result.update(action="exclude", exclude_rule=excluded)
            else:
                included = DomainRules(entries("include")).matching_rule(domain)
                result.update(action="include" if included is not None else "none", include_rule=included)
        except (OSError, sqlite3.Error, ValueError, TypeError, KeyError, TimeoutError) as exc:
            result["error"] = str(exc)
        return result

    def test_rule(self, data):
        domain = normalize_domain_name(data.get("domain"))
        if domain is None:
            raise ValueError("Enter a valid domain name")
        matches = {}
        for name in ("include", "exclude"):
            content = data.get(name, "")
            if not isinstance(content, str) or len(content.encode("utf-8")) > 1_000_000:
                raise ValueError("Rule list must be text up to 1 MB")
            validate_rule_list(content)
            rules = [line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith("#")]
            matches[name] = DomainRules(rules).matching_rule(domain)
        return {"domain": domain,
                "action": "exclude" if matches["exclude"] else "include" if matches["include"] else "none",
                "include_rule": matches["include"], "exclude_rule": matches["exclude"]}
