"""Compose static routes and TTL leases from client DNS answers.

The generation lock remains owned by reload-routes.sh.  This module uses a
separate, short apply lock, so downloading lists never blocks client DNS.
"""
import argparse
from contextlib import contextmanager
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import time

from .generate_routes import build_routes


def atomic_write(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def write_json(path, value):
    atomic_write(path, json.dumps(value, sort_keys=True) + "\n")


def domain_key(value):
    return str(value).rstrip(".").encode("idna").decode("ascii").lower()


def match_domain(domain, roots):
    labels = domain_key(domain).split(".")
    return any(".".join(labels[index:]) in roots for index in range(len(labels)))


def lease_sets(policy, leases, now):
    includes, excludes = set(), set()
    include_roots = set(policy["include_domains"])
    exclude_roots = set(policy["exclude_domains"])
    for domain, addresses in leases.items():
        target = excludes if match_domain(domain, exclude_roots) else includes
        if target is includes and not match_domain(domain, include_roots):
            continue
        for address, expires in addresses.items():
            if expires > now:
                target.add(str(ipaddress.IPv4Address(address)))
    return includes, excludes


def compose(policy, leases, now):
    includes, excludes = lease_sets(policy, leases, now)
    networks, _ = build_routes(
        [ipaddress.IPv4Network(value) for value in policy["routes"]],
        [ipaddress.IPv4Network(value) for value in policy["exclude_routes"]]
        + [ipaddress.IPv4Network(value) for value in excludes],
        [ipaddress.IPv4Network(value) for value in includes],
    )
    return "".join(f"    route {network} blackhole;\n" for network in networks)


class RouteManager:
    def __init__(self, directory=None, bird_command=None, lock_timeout=2.0):
        self.directory = Path(directory or os.environ.get("GENERATED_DIR", "/etc/bird/generated"))
        self.routes = Path(os.environ.get("ROUTES_FILE", str(self.directory / "routes.conf")))
        self.last_good = Path(os.environ.get("LAST_GOOD_ROUTES_FILE", str(self.directory / "routes.last-good.conf")))
        self.policy_file = self.directory / "dns-policy.json"
        self.state_file = self.directory / "dns-leases.json"
        self.lock = self.directory / "dns-apply.lock"
        self.lock_timeout = lock_timeout
        self.bird_command = bird_command or self.bird
        self._policy_stamp = None
        self._policy = None
        self._signature = None
        self._routes_stamp = None
        self._selected_roots = set()

    @staticmethod
    def bird(*arguments):
        result = subprocess.run(["birdc", *arguments], capture_output=True, text=True, timeout=5)
        if result.returncode:
            raise RuntimeError(f"birdc failed: {result.stdout} {result.stderr}".strip())
        if arguments == ("configure",) and "Reconfigured" not in result.stdout:
            raise RuntimeError(f"BIRD did not confirm configuration: {result.stdout}".strip())
        return result.stdout

    @contextmanager
    def locked(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.lock_timeout
        # Advisory file locks are released by the OS even on SIGKILL. Never
        # unlink the lock file: another process may already have it open.
        with self.lock.open("a+b") as handle:
            if not self.lock.stat().st_size:
                handle.write(b"\0")
                handle.flush()
            while True:
                try:
                    handle.seek(0)
                    if os.name == "nt":
                        import msvcrt
                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("DNS route apply is busy")
                    time.sleep(0.02)
            try:
                yield
            finally:
                handle.seek(0)
                if os.name == "nt":
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(handle, fcntl.LOCK_UN)

    def policy(self):
        stat = self.policy_file.stat()
        stamp = (stat.st_mtime_ns, stat.st_size)
        if self._policy_stamp != stamp:
            self._policy = json.loads(self.policy_file.read_text(encoding="utf-8"))
            self._selected_roots = set(self._policy["include_domains"]) | set(self._policy["exclude_domains"])
            self._policy_stamp = stamp
        return self._policy

    def leases(self):
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}

    def selected(self, domain):
        self.policy()
        return match_domain(domain, self._selected_roots)

    def _commit(self, policy, leases, now, install=False, configure=True):
        includes, excludes = lease_sets(policy, leases, now)
        signature = (policy["generation"], frozenset(includes), frozenset(excludes))
        stat = self.routes.stat() if self.routes.exists() else None
        stamp = (stat.st_mtime_ns, stat.st_size) if stat else None
        if not install and self._signature == signature and self._routes_stamp == stamp:
            write_json(self.state_file, leases)
            return
        # Compare with the active file, not only the old leases: expired entries
        # must also be withdrawn after a restart.
        text = compose(policy, leases, now)
        if not text.strip():
            raise RuntimeError("DNS update would leave an empty route table")
        previous = self.routes.read_text(encoding="utf-8") if self.routes.exists() else ""
        previous_good = self.last_good.read_text(encoding="utf-8") if self.last_good.exists() else previous
        changed = text != previous
        if changed or install:
            previous_policy = self.policy_file.read_text(encoding="utf-8") if self.policy_file.exists() else None
            try:
                atomic_write(self.routes, text)
                if configure:
                    self.bird_command("configure")
                atomic_write(self.last_good, text)
                if install:
                    write_json(self.policy_file, policy)
                    self._policy_stamp = None
                write_json(self.state_file, leases)
            except Exception:
                atomic_write(self.routes, previous_good)
                atomic_write(self.last_good, previous_good)
                if install:
                    if previous_policy is None:
                        self.policy_file.unlink(missing_ok=True)
                    else:
                        atomic_write(self.policy_file, previous_policy)
                    self._policy_stamp = None
                if configure:
                    self.bird_command("configure")
                raise
        else:
            write_json(self.state_file, leases)
        self._signature = signature
        stat = self.routes.stat()
        self._routes_stamp = (stat.st_mtime_ns, stat.st_size)

    def install(self, policy, configure=True, now=None):
        now = time.time() if now is None else now
        with self.locked():
            self._commit(policy, self.leases(), now, install=True, configure=configure)

    def observe(self, domain, addresses, now=None):
        now = time.time() if now is None else now
        domain = domain_key(domain)
        if not self.selected(domain) or not addresses:
            return
        with self.locked():
            policy = self.policy()
            leases = self.leases()
            leases = {name: {ip: expiry for ip, expiry in items.items() if expiry > now}
                      for name, items in leases.items()}
            leases = {name: items for name, items in leases.items() if items}
            current = leases.setdefault(domain, {})
            for address, ttl in addresses:
                ip = ipaddress.IPv4Address(address)
                if ip.is_global:
                    # A zero-TTL reply may be used immediately; retain a short
                    # grace period for connection setup and BGP propagation.
                    expiry = now + max(1, ttl) + int(os.environ.get("DNS_ROUTE_GRACE", "30"))
                    current[str(ip)] = max(current.get(str(ip), 0), expiry)
            if sum(len(items) for items in leases.values()) > 50000:
                raise RuntimeError("DNS route lease limit exceeded")
            self._commit(policy, leases, now)

    def refresh(self, now=None):
        now = time.time() if now is None else now
        with self.locked():
            policy = self.policy()
            leases = {name: {ip: expiry for ip, expiry in items.items() if expiry > now}
                      for name, items in self.leases().items()}
            leases = {name: items for name, items in leases.items() if items}
            self._commit(policy, leases, now)

    def check_bird(self):
        # All configure commands, including probes, participate in the apply
        # lock. A readiness probe must never apply another writer's candidate.
        with self.locked():
            # Recover a candidate left on disk by a killed writer before
            # probing configure; only committed policy and leases are trusted.
            self._commit(self.policy(), self.leases(), time.time())
            self.bird_command("configure")
            if "up and running" not in self.bird_command("show", "status"):
                raise RuntimeError("BIRD is not ready")
            if os.environ.get("HEALTHCHECK_REQUIRE_BGP", "1") == "1":
                protocol = os.environ.get("BGP_PROTOCOL", "mikrotik")
                if "Established" not in self.bird_command("show", "protocols", protocol):
                    raise RuntimeError("BGP is not established")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("policy")
    parser.add_argument("--no-configure", action="store_true")
    args = parser.parse_args()
    manager = RouteManager()
    manager.install(json.loads(Path(args.policy).read_text(encoding="utf-8")), configure=not args.no_configure)


if __name__ == "__main__":
    main()
