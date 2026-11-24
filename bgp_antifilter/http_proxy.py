"""Shared proxy selection for the application's external HTTP requests."""

import io
import ipaddress
import os
import subprocess
import urllib.error
import urllib.request
from urllib.parse import urlsplit


HTTP_PROXY_SETTINGS = [
    {"key": "HTTP_PROXY_TYPE", "type": "enum", "default": "environment",
     "options": ["environment", "none", "http", "https", "socks5"], "legacy_backup_default": True},
    {"key": "HTTP_PROXY_HOST", "type": "ip", "default": "", "allow_empty": True, "legacy_backup_default": True},
    {"key": "HTTP_PROXY_PORT", "type": "int", "default": "8080", "min": 1, "max": 65535, "legacy_backup_default": True},
    {"key": "HTTP_PROXY_USERNAME", "type": "credential", "default": "", "allow_empty": True, "legacy_backup_default": True},
    {"key": "HTTP_PROXY_PASSWORD", "type": "password", "default": "", "allow_empty": True, "secret": True, "legacy_backup_default": True},
]
HTTP_PROXY_DEFAULTS = {item["key"]: item["default"] for item in HTTP_PROXY_SETTINGS}


def base_environment(environ):
    result = dict(environ)
    for key in HTTP_PROXY_DEFAULTS:
        if "BGP_BASE_" + key in environ:
            result[key] = environ["BGP_BASE_" + key]
    return result


def validate_credential(key, value):
    if not isinstance(value, str):
        raise ValueError(f"{key} must be text")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{key} must not contain control characters")
    if len(value.encode("utf-8")) > 4096:
        raise ValueError(f"{key} must not exceed 4096 UTF-8 bytes")
    if key == "HTTP_PROXY_USERNAME" and ":" in value:
        raise ValueError("HTTP_PROXY_USERNAME must not contain a colon")
    return value


def proxy_credentials(values):
    username = validate_credential("HTTP_PROXY_USERNAME", values.get("HTTP_PROXY_USERNAME", ""))
    password = validate_credential("HTTP_PROXY_PASSWORD", values.get("HTTP_PROXY_PASSWORD", ""))
    if password and not username:
        raise ValueError("HTTP_PROXY_USERNAME is required when a proxy password is set")
    if values.get("HTTP_PROXY_TYPE") == "socks5" and username:
        if not 1 <= len(username.encode("utf-8")) <= 255 or not 1 <= len(password.encode("utf-8")) <= 255:
            raise ValueError("SOCKS5 username and password must each contain 1 to 255 UTF-8 bytes")
    return username, password


def credential_config(username, password):
    # curl's config grammar supports backslash escapes inside double quotes.
    value = f"{username}:{password}".replace("\\", "\\\\").replace('"', '\\"')
    return f'proxy-user = "{value}"\n'.encode("utf-8")


def configured_proxy(values=None):
    values = os.environ if values is None else values
    kind = values.get("HTTP_PROXY_TYPE", "environment")
    proxy_credentials(values)
    if kind in {"environment", "none"}:
        return None
    if kind not in {"http", "https", "socks5"}:
        raise ValueError("HTTP_PROXY_TYPE must be environment, none, http, https or socks5")
    try:
        address = ipaddress.ip_address(values.get("HTTP_PROXY_HOST", ""))
    except ValueError as exc:
        raise ValueError("HTTP_PROXY_HOST must be a valid IP address when a proxy is enabled") from exc
    try:
        port = int(values.get("HTTP_PROXY_PORT", "8080"))
    except ValueError as exc:
        raise ValueError("HTTP_PROXY_PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("HTTP_PROXY_PORT must be between 1 and 65535")
    host = f"[{address}]" if address.version == 6 else str(address)
    scheme = "socks5h" if kind == "socks5" else kind
    return f"{scheme}://{host}:{port}"


def uses_proxy(url, values=None):
    values = os.environ if values is None else values
    if configured_proxy(values):
        return True
    if values.get("HTTP_PROXY_TYPE", "environment") == "none":
        return False
    parts = urlsplit(url)
    return bool(urllib.request.getproxies().get(parts.scheme) and
                not urllib.request.proxy_bypass(parts.hostname or ""))


def open_url(request, *, timeout, settings=None):
    """Return a readable context manager; an explicit proxy never falls back."""
    values = os.environ if settings is None else settings
    proxy = configured_proxy(values)
    if not proxy:
        if values.get("HTTP_PROXY_TYPE", "environment") == "none":
            return urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=timeout)
        return urllib.request.urlopen(request, timeout=timeout)

    request = urllib.request.Request(request) if isinstance(request, str) else request
    if urlsplit(request.full_url).scheme not in {"http", "https"}:
        # Local file sources do not go over the network.
        if urlsplit(request.full_url).scheme == "file":
            return urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=timeout)
        raise ValueError("Proxy requests must use HTTP or HTTPS")
    if request.get_method() != "GET" or request.data is not None:
        raise ValueError("Only GET requests are supported")
    command = ["curl", "--disable", "--silent", "--show-error", "--fail", "--location",
               "--max-redirs", "5", "--max-time", str(timeout), "--connect-timeout", str(timeout),
               "--proxy", proxy, "--noproxy", "", "--proto", "=http,https", "--proto-redir", "=http,https",
               "--globoff"]
    for name, value in request.header_items():
        command.extend(["--header", f"{name}: {value}"])
    command.extend(["--url", request.full_url])
    username, password = proxy_credentials(values)
    config = None
    if username:
        config = credential_config(username, password)
        command.extend(["--config", "-", "--socks5-basic" if values.get("HTTP_PROXY_TYPE") == "socks5" else "--proxy-basic"])
    private_keys = {"HTTP_PROXY_USERNAME", "HTTP_PROXY_PASSWORD", "BGP_BASE_HTTP_PROXY_USERNAME", "BGP_BASE_HTTP_PROXY_PASSWORD"}
    environment = {key: value for key, value in os.environ.items() if key not in private_keys}
    try:
        result = subprocess.run(command, input=config, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=float(timeout) + 2, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise urllib.error.URLError(f"HTTP proxy request failed: {exc}") from exc
    if result.returncode:
        if username:
            # A proxy can echo credentials in an error; keep diagnostics bounded
            # to curl's exit code when authentication is enabled.
            raise urllib.error.URLError(f"HTTP proxy request failed (curl exit code {result.returncode})")
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise urllib.error.URLError(message or f"HTTP proxy request failed ({result.returncode})")
    return io.BytesIO(result.stdout)
