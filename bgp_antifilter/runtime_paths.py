import os
from pathlib import Path


LIST_FILE_SPECS = {
    "urls": ("LISTS_FILE", "/etc/bird/lists.txt"),
    "domain-list-urls": ("DOMAIN_LIST_URLS_FILE", "/etc/bird/domain-list-urls.txt"),
    "asns": ("INCLUDE_ASNS_FILE", "/etc/bird/include-asns.txt"),
    "countries": ("INCLUDE_COUNTRIES_FILE", "/etc/bird/include-countries.txt"),
    "include-domains": ("INCLUDE_DOMAINS_FILE", "/etc/bird/include-domains.txt"),
    "exclude-domains": ("EXCLUDE_DOMAINS_FILE", "/etc/bird/exclude-domains.txt"),
    "dynamic-domains": ("DYNAMIC_DOMAINS_FILE", "/etc/bird/generated/config/dynamic-domains.txt"),
}

GENERATED_PATH_SPECS = {
    "generated_dir": ("GENERATED_DIR", "/etc/bird/generated"),
    "routes_file": ("ROUTES_FILE", "/etc/bird/generated/routes.conf"),
    "status_file": ("STATUS_FILE", "/etc/bird/generated/status.json"),
    "metrics_file": ("METRICS_FILE", "/etc/bird/generated/metrics.prom"),
    "runtime_file": ("RUNTIME_FILE", "/etc/bird/generated/runtime.json"),
    "update_runtime_file": ("UPDATE_RUNTIME_FILE", "/etc/bird/generated/update-runtime.json"),
    "container_log_file": ("CONTAINER_LOG_FILE", "/etc/bird/generated/container.log"),
    "settings_file": ("SETTINGS_FILE", "/etc/bird/generated/settings.json"),
    "settings_env_file": ("SETTINGS_ENV_FILE", "/etc/bird/generated/settings.env"),
    "cache_dir": ("CACHE_DIR", "/etc/bird/generated/cache"),
    "dynamic_routes_file": ("DYNAMIC_ROUTES_FILE", "/etc/bird/generated/dynamic-routes.conf"),
    "dynamic_dns_state_file": ("DYNAMIC_DNS_STATE_FILE", "/etc/bird/generated/dynamic-dns-state.json"),
    "dynamic_dns_status_file": ("DYNAMIC_DNS_STATUS_FILE", "/etc/bird/generated/dynamic-dns-status.json"),
}


def env_path(name, default):
    return Path(os.environ.get(name, default))


def env_paths(specs):
    return {
        key: env_path(env_name, default)
        for key, (env_name, default) in specs.items()
    }
