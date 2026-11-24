"""A bounded DNS observation queue, durable TTL state, and incremental BGP RIB."""
from collections import Counter
from contextlib import closing
from concurrent.futures import Future
from dataclasses import dataclass
import ipaddress
import json
import logging
import os
from pathlib import Path
import queue
import sqlite3
import threading
import time

from .bgp_feed import BGPFeed, SYNC_PREFIX
from .dns_routes import RouteManager, atomic_write, domain_key, write_json
from .domain_rules import DomainRules
from .route_snapshot import confirmed_snapshot, digest, publish_checkpoint, read_confirmed, route_text, snapshot_path


LOG = logging.getLogger("dns-routes")


@dataclass(frozen=True)
class ObservationReceipt:
    revision: int
    expected: dict[str, bool]


class PrefixSet:
    def __init__(self, values=()):
        self.levels = [set() for _ in range(33)]
        for value in values:
            self.add(ipaddress.IPv4Network(value))

    def add(self, network):
        self.levels[network.prefixlen].add(int(network.network_address))

    def remove(self, network):
        self.levels[network.prefixlen].remove(int(network.network_address))

    def contains(self, network):
        return int(network.network_address) in self.levels[network.prefixlen]

    def find(self, address):
        value = int(address)
        for length in range(32, -1, -1):
            start = (value >> (32 - length)) << (32 - length) if length else 0
            if start in self.levels[length]:
                return ipaddress.IPv4Network((start, length))
        return None

    def routes(self):
        return {str(ipaddress.IPv4Network((address, length)))
                for length, addresses in enumerate(self.levels) for address in addresses}


class IncrementalRoutes:
    """Touch at most the owning prefix and its 32 siblings for one IPv4 change."""
    def __init__(self, policy):
        baseline = list(ipaddress.collapse_addresses(ipaddress.IPv4Network(value) for value in policy["routes"]))
        self.baseline = PrefixSet(baseline)
        self.denied = PrefixSet(policy["exclude_routes"])
        self.cover = PrefixSet(baseline)
        self.added, self.removed = set(), set()
        self.dynamic_routes = 0

    def _add(self, network):
        self.cover.add(network)
        value = str(network)
        if value in self.removed:
            self.removed.remove(value)
        else:
            self.added.add(value)

    def _remove(self, network):
        self.cover.remove(network)
        value = str(network)
        if value in self.added:
            self.added.remove(value)
        else:
            self.removed.add(value)

    def change(self, value, included, excluded):
        """Update one address and report whether DNS alone supplies its route."""
        address = ipaddress.IPv4Address(value)
        owner = self.baseline.find(address)
        current = self.cover.find(address)
        wanted = (owner is not None or included) and not excluded and self.denied.find(address) is None
        if owner is None:
            self.dynamic_routes += int(wanted) - int(current is not None)
        if wanted and current is None:
            network = ipaddress.IPv4Network((address, 32))
            self._add(network)
            # Merge only within this baseline prefix. Independent learned /32
            # routes stay independent, so another IP never forces a RIB scan.
            while owner is not None and network.prefixlen > owner.prefixlen:
                sibling_address = int(network.network_address) ^ (1 << (32 - network.prefixlen))
                sibling = ipaddress.IPv4Network((sibling_address, network.prefixlen))
                if not self.cover.contains(sibling):
                    break
                self._remove(network)
                self._remove(sibling)
                network = network.supernet()
                self._add(network)
        elif not wanted and current is not None:
            self._remove(current)
            if current.prefixlen < 32:
                for remaining in current.address_exclude(ipaddress.IPv4Network((address, 32))):
                    self._add(remaining)
        return wanted and owner is None

    def delta(self):
        added, removed = self.added, self.removed
        self.added, self.removed = set(), set()
        return added, removed


class LiveRoutes:
    def __init__(self, directory=None, publisher=None, capacity=1024, batch_seconds=0.02):
        self.directory = Path(directory or os.environ.get("GENERATED_DIR", "/etc/bird/generated"))
        self.directory.mkdir(parents=True, exist_ok=True)
        self.publisher = publisher or BGPFeed(int(os.environ.get("MY_AS", "64500")),
                                             port=int(os.environ.get("DNS_BGP_PORT", "1179")),
                                             sync_marker=True)
        self.queue = queue.Queue(maxsize=capacity)
        self.weight_lock = threading.Lock()
        self.pending_weight = 0
        self.pending_alias_targets = Counter()
        self.selection_rules = None
        self.selection_aliases = {}
        self.batch_seconds = batch_seconds
        self.stop = threading.Event()
        self.initialized = threading.Event()
        self.readiness_lock = threading.Lock()
        self.readiness = None
        self.error = "Starting live route worker"
        self.drop_until = 0
        self.dropped = 0
        self.last_progress = time.monotonic()
        self.policy = None
        self.index = None
        self.bootstrap_routes = set()
        self.leases, self.aliases = {}, {}
        self.included, self.excluded = {}, Counter()
        self.lease_dirty, self.alias_dirty = {}, {}
        self.lease_count = self.alias_count = 0
        self.include_roots, self.exclude_roots = DomainRules(), DomainRules()
        self._pending_stamp = None
        self.db = None
        self._status_at = 0
        self.thread = threading.Thread(target=self._run, name="dns-route-worker", daemon=True)
        self.thread.start()

    def observe(self, domain, addresses, now=None, targets=(), receipt=False, reply_budget=0):
        """Non-blocking admission only: no file, BGP, or policy work here."""
        ticket = Future() if receipt else None
        weight = len(addresses) + len(targets)
        with self.weight_lock:
            if self.pending_weight + weight > 16384:
                self.dropped += 1
                self.drop_until = time.monotonic() + 5
                if ticket is not None:
                    ticket.set_exception(RuntimeError("DNS observation queue overloaded"))
                    return ticket
                return False
            self.pending_weight += weight
            self.pending_alias_targets.update(domain_key(target) for target, _ in targets)
        try:
            self.queue.put_nowait((domain, tuple(addresses), tuple(targets), time.time() if now is None else now, weight, ticket, reply_budget))
            return ticket if ticket is not None else True
        except queue.Full:
            with self.weight_lock:
                self.pending_weight -= weight
                self._release_alias_targets(targets)
            self.dropped += 1
            self.drop_until = time.monotonic() + 5
            if ticket is not None:
                ticket.set_exception(RuntimeError("DNS observation queue overloaded"))
                return ticket
            return False

    def _release_alias_targets(self, targets):
        """Caller holds weight_lock; keep admission metadata bounded too."""
        for target, _ in targets:
            target = domain_key(target)
            self.pending_alias_targets[target] -= 1
            if self.pending_alias_targets[target] <= 0:
                del self.pending_alias_targets[target]

    def selection_required(self, domain):
        """Skip known unrelated queries without waiting for a busy route worker.

        Alias admissions count immediately: an async CNAME reply can cause its
        target lookup before the worker persists that CNAME observation.
        """
        domain = domain_key(domain)
        with self.weight_lock:
            rules = self.selection_rules
            aliases = self.selection_aliases.get(domain, ())
            pending_alias = bool(self.pending_alias_targets.get(domain))
        if rules is None or pending_alias:
            return True
        includes, excludes = rules
        now = time.time()
        # Timeouts propagate: a failed exclusion check is not a negative match.
        return any(excludes.matches(origin) or includes.matches(origin)
                   for origin in [domain, *(origin for origin, expiry in aliases if expiry > now)])

    def flush(self, timeout=5):
        deadline = time.monotonic() + timeout
        while not self.initialized.is_set() or self.queue.unfinished_tasks:
            if not self.thread.is_alive():
                raise RuntimeError(self.error)
            if time.monotonic() >= deadline:
                raise TimeoutError("Live route worker did not drain")
            time.sleep(0.005)
        if self.error:
            raise RuntimeError(self.error)

    def refresh(self):
        if not self.thread.is_alive() or not self.initialized.is_set() or self.error:
            raise RuntimeError(self.error or "Live route worker is unavailable")
        if self.policy is None:
            raise RuntimeError("Waiting for initial route policy")
        if time.monotonic() < self.drop_until:
            raise RuntimeError("DNS observation queue overloaded")
        if time.monotonic() - self.last_progress > 3:
            raise RuntimeError("Live route worker is stalled")

    def supervise(self):
        if not self.thread.is_alive():
            raise RuntimeError(self.error or "Live route worker stopped")
        self.publisher.check_running()

    def record_readiness(self, ready, error=""):
        with self.readiness_lock:
            self.readiness = {"ready": bool(ready), "error": str(error), "checked_at_unix": time.time()}

    def _write_runtime(self, *, stopped=False):
        now = time.monotonic()
        if not stopped and now - self._status_at < 1:
            return
        self._status_at = now
        routes = sum(map(len, self.index.cover.levels)) if self.index is not None else len(self.bootstrap_routes)
        dynamic = self.index.dynamic_routes if self.index is not None else 0
        routes_ready = not stopped and self.policy is not None and not self.error and now >= self.drop_until and self.publisher.ready()
        with self.readiness_lock:
            readiness = self.readiness
        if readiness is None:
            readiness_error = "DNS readiness has not been checked yet"
        elif not 0 <= time.time() - readiness["checked_at_unix"] < 90:
            readiness_error = "DNS readiness check is stale"
        elif not readiness["ready"]:
            readiness_error = readiness["error"] or "DNS end-to-end readiness check failed"
        else:
            readiness_error = ""
        write_json(self.directory / "dns-runtime.json", {
            "running": not stopped, "routes_ready": routes_ready, "ready": routes_ready and not readiness_error,
            "routes": routes, "dynamic_routes": dynamic, "leases": self.lease_count,
            "updated_at_unix": int(time.time()), "last_error": self.error or readiness_error,
        })

    def check_bird(self, deadline=None):
        def query(*args):
            if deadline is None:
                return RouteManager.bird(*args)
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                raise TimeoutError("DNS readiness deadline exceeded before BIRD confirmation")
            return RouteManager.bird(*args, timeout=timeout)

        self.refresh()
        if not self.publisher.ready():
            raise RuntimeError("Local BGP feed is not synchronized")
        if "up and running" not in query("show", "status"):
            raise RuntimeError("BIRD is not ready")
        if "Established" not in query("show", "protocols", "dns_live"):
            raise RuntimeError("BIRD has not established the local feed")
        if os.environ.get("HEALTHCHECK_REQUIRE_BGP", "1") == "1":
            if "Established" not in query("show", "protocols", os.environ.get("BGP_PROTOCOL", "mikrotik")):
                raise RuntimeError("BGP peer session is not established")

    def _classify(self, domain):
        if self.exclude_roots.matches(domain):
            return True, None
        return False, self.include_roots.matching_rule(domain)

    def _lease(self, domain, address, expiry, excluded, rule):
        current = self.leases.setdefault(domain, {})
        if address not in current:
            if self.lease_count >= 50000:
                self.drop_until = time.monotonic() + 5
                raise RuntimeError("DNS route lease limit exceeded")
            self.lease_count += 1
            if excluded:
                self.excluded[address] += 1
            else:
                self.included.setdefault(address, {})[domain] = rule
            self.index.change(address, address in self.included, address in self.excluded)
        current[address] = max(current.get(address, 0), expiry)
        self.lease_dirty[domain, address] = current[address]

    def _observe(self, event):
        domain, addresses, targets, received, _, ticket, reply_budget = event
        if self.policy is None:
            if ticket is not None:
                raise RuntimeError("Waiting for initial route policy")
            return False
        domain = domain_key(domain)
        now = time.time()
        candidates = {domain: self._classify(domain)}
        for origin, expiry in self.aliases.get(domain, {}).items():
            if expiry > now and origin not in candidates:
                candidates[origin] = self._classify(origin)
        # Client cache lifetime begins after the gated reply. Keep both IPs
        # and aliases alive for the entire possible reply delay as well.
        grace = int(os.environ.get("DNS_ROUTE_GRACE", "30")) + reply_budget
        tracked = False
        for origin, (excluded, rule) in candidates.items():
            if not excluded and rule is None:
                continue
            tracked = True
            for address, ttl in addresses:
                ip = ipaddress.IPv4Address(address)
                expiry = received + max(1, ttl) + grace
                if ip.is_global and expiry > now:
                    self._lease(origin, str(ip), expiry, excluded, rule)
            for target, ttl in targets:
                target = domain_key(target)
                expiry = received + max(1, ttl) + grace
                if expiry <= now:
                    continue
                current = self.aliases.setdefault(target, {})
                if origin not in current:
                    if self.alias_count >= 50000:
                        self.drop_until = time.monotonic() + 5
                        raise RuntimeError("DNS alias limit exceeded")
                    self.alias_count += 1
                current[origin] = max(current.get(origin, 0), expiry)
                self.alias_dirty[target, origin] = current[origin]
                with self.weight_lock:
                    self.selection_aliases[target] = tuple(current.items())
        return tracked

    def _expire(self, now):
        for domain, items in list(self.leases.items()):
            for address, expiry in list(items.items()):
                if expiry > now:
                    continue
                del items[address]
                self.lease_count -= 1
                if self.index is not None:
                    excluded, rule = self._classify(domain)
                    if excluded:
                        self.excluded[address] -= 1
                        if self.excluded[address] == 0:
                            del self.excluded[address]
                    elif rule is not None:
                        domains = self.included[address]
                        del domains[domain]
                        if not domains:
                            del self.included[address]
                    if excluded or rule is not None:
                        self.index.change(address, address in self.included, address in self.excluded)
                self.lease_dirty[domain, address] = None
            if not items:
                del self.leases[domain]
        for target, origins in list(self.aliases.items()):
            for origin, expiry in list(origins.items()):
                if expiry <= now or (self.policy is not None and not any(self._classify(origin))):
                    del origins[origin]
                    self.alias_count -= 1
                    self.alias_dirty[target, origin] = None
            if not origins:
                del self.aliases[target]
            with self.weight_lock:
                if origins:
                    self.selection_aliases[target] = tuple(origins.items())
                else:
                    self.selection_aliases.pop(target, None)

    def _save_route_origins(self, added, removed):
        # Keep the original cause while a route remains active.
        self.db.executemany("DELETE FROM dns_route_origins WHERE address=?", ((address,) for address in removed))
        self.db.executemany("INSERT OR IGNORE INTO dns_route_origins VALUES(?,?,?,?)", added)

    def _persist(self):
        added, removed = (self.index.added, self.index.removed) if self.index is not None else ((), ())
        if self.lease_dirty or self.alias_dirty or added or removed:
            now = time.time()
            new_origins = []
            for route in added:
                if route.endswith("/32"):
                    address = route[:-3]
                    domains = self.included.get(address)
                    if domains and self.index.baseline.find(ipaddress.IPv4Address(address)) is None:
                        domain, rule = next(iter(domains.items()))
                        new_origins.append((address, domain, rule, now))
            with self.db:
                for table, changes in (("leases", self.lease_dirty), ("aliases", self.alias_dirty)):
                    self.db.executemany(f"DELETE FROM {table} WHERE name=? AND value=?",
                                        [(name, value) for (name, value), expiry in changes.items() if expiry is None])
                    self.db.executemany(f"INSERT INTO {table} VALUES(?,?,?) ON CONFLICT(name,value) DO UPDATE SET expiry=excluded.expiry",
                                        [(name, value, expiry) for (name, value), expiry in changes.items() if expiry is not None])
                self._save_route_origins(new_origins, (route[:-3] for route in removed if route.endswith("/32")))
            self.lease_dirty.clear()
            self.alias_dirty.clear()
        if added or removed:
            self.publisher.update(added, removed)
            self.index.delta()

    def _new_policy(self, policy, *, restoring=False, snapshot=None, publication=None, deadline=None):
        index = IncrementalRoutes(policy)
        if getattr(self.publisher, "sync_marker", False) and index.baseline.contains(ipaddress.IPv4Network(SYNC_PREFIX)):
            raise ValueError(f"{SYNC_PREFIX} is reserved for DNS/BIRD synchronization")
        includes, excludes = DomainRules(policy["include_domains"]), DomainRules(policy["exclude_domains"])
        included, excluded = {}, Counter()
        now = time.time()
        # Remove expired owners using the old policy's counters before
        # rebuilding them. Otherwise a later expiry would subtract twice and
        # could withdraw an IP still owned by another live domain.
        self._expire(now)
        for domain, addresses in self.leases.items():
            if excludes.matches(domain):
                excluded.update(addresses.keys())
            elif (rule := includes.matching_rule(domain)) is not None:
                for address in addresses:
                    included.setdefault(address, {})[domain] = rule
        origins = {}
        for address in included.keys() | excluded.keys():
            if index.change(address, address in included, address in excluded):
                origins[address] = next(iter(included[address].items()))
        routes = index.cover.routes()  # Full scan only on policy load/update.
        self._persist()
        previous = self.index.cover.routes() if self.index is not None else self.bootstrap_routes
        # Only static source routes belong in the confirmed checkpoint. Leases
        # are reconstructed from SQLite and pruned before the feed is ready.
        files = [self.directory / "dns-policy.json"]
        if snapshot is not None:
            if snapshot.get("dns_policy") != policy or set(snapshot["prefixes"]) != set(policy["routes"]):
                raise ValueError("DNS policy does not match its source snapshot")
            if snapshot.get("routes_sha256") != digest(route_text(snapshot["prefixes"])):
                raise ValueError("Invalid DNS source snapshot digest")
            publication = publication or self._publication_paths()
            files.extend(Path(value) for value in publication.values())
            files.append(snapshot_path(publication["last_good_routes_file"]))
            snapshot = snapshot if restoring else confirmed_snapshot(snapshot)
        else:
            files.extend(self.directory / name for name in ("routes.conf", "routes.last-good.conf"))
        backups = {path: path.read_bytes().decode("utf-8") if path.exists() else None for path in files}
        published = False
        try:
            self.publisher.update(routes - previous, previous - routes)
            published = True
            # Startup replay must not wait for BIRD before supervisor starts it.
            # New transactions do wait for the marker in BIRD before success.
            if not restoring and hasattr(self.publisher, "confirm_policy"):
                self.publisher.confirm_policy(timeout=max(0.01, min(30, deadline - time.time())) if deadline else 30)
            if deadline is not None and time.time() >= deadline:
                raise TimeoutError("DNS policy request expired before commit")
            with self.db:
                self.db.execute("INSERT INTO metadata VALUES('policy',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (json.dumps(policy),))
                if snapshot is not None:
                    checkpoint = {"snapshot": snapshot, "publication": publication}
                    self.db.execute("INSERT INTO metadata VALUES('checkpoint',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (json.dumps(checkpoint),))
                    publish_checkpoint(snapshot, publication)
                else:
                    self.db.execute("DELETE FROM metadata WHERE key='checkpoint'")
                    atomic_write(self.directory / "routes.conf", route_text(policy["routes"]))
                    atomic_write(self.directory / "routes.last-good.conf", route_text(policy["routes"]))
                write_json(files[0], policy)
                previous_origins = {address for address, in self.db.execute("SELECT address FROM dns_route_origins")}
                added_at = None if restoring else time.time()
                self._save_route_origins(
                    ((address, *origins[address], added_at) for address in origins.keys() - previous_origins),
                    previous_origins - origins.keys(),
                )
                # File publication can consume the remaining request budget.
                # Reject before SQLite commits, so rollback also restores the
                # files and feed when the caller has already timed out.
                if deadline is not None and time.time() >= deadline:
                    raise TimeoutError("DNS policy request expired before commit")
        except Exception:
            # SQLite rolls back the policy; restore the feed and file mirrors.
            if published:
                try:
                    self.publisher.update(previous - routes, routes - previous)
                except Exception:
                    LOG.exception("Could not restore BGP policy after failed transaction")
            for path, previous_text in backups.items():
                try:
                    if previous_text is None:
                        path.unlink(missing_ok=True)
                    else:
                        atomic_write(path, previous_text)
                except OSError:
                    LOG.exception("Could not restore policy checkpoint %s", path)
            raise
        self.policy, self.index = policy, index
        self.bootstrap_routes = set()
        self.include_roots, self.exclude_roots = includes, excludes
        selection_aliases = {target: tuple(origins.items()) for target, origins in self.aliases.items()}
        with self.weight_lock:
            self.selection_rules = includes, excludes
            self.selection_aliases = selection_aliases
        self.included, self.excluded = included, excluded
        index.delta()  # Initial exclusions were incorporated in the full diff.

    def _publication_paths(self):
        names = {"routes_file": ("ROUTES_FILE", "routes.conf"),
                 "last_good_routes_file": ("LAST_GOOD_ROUTES_FILE", "routes.last-good.conf"),
                 "status_file": ("STATUS_FILE", "status.json"), "metrics_file": ("METRICS_FILE", "metrics.prom")}
        return {key: os.environ.get(variable, str(self.directory / name)) for key, (variable, name) in names.items()}

    def _check_policy(self):
        path = self.directory / "dns-policy.pending.json"
        try:
            stat = path.stat()
        except FileNotFoundError:
            return
        stamp = (stat.st_mtime_ns, stat.st_size)
        if stamp == self._pending_stamp:
            return
        self._pending_stamp = stamp
        request = json.loads(path.read_text(encoding="utf-8"))
        policy = request.get("policy", request)
        generation = policy["generation"]
        try:
            deadline = request.get("deadline_unix")
            if deadline is not None and time.time() >= deadline:
                raise TimeoutError("DNS policy request expired before application")
            if self.policy is None or self.policy["generation"] != generation:
                self._new_policy(policy, snapshot=request.get("snapshot"), publication=request.get("publication"), deadline=deadline)
            write_json(self.directory / "dns-policy.applied.json", {"generation": generation, "success": True})
        except Exception as exc:
            write_json(self.directory / "dns-policy.applied.json", {"generation": generation, "success": False, "error": str(exc)})
            raise

    def _initialize(self):
        self.db = sqlite3.connect(self.directory / "dns-cache.sqlite3")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        for table in ("leases", "aliases"):
            self.db.execute(f"CREATE TABLE IF NOT EXISTS {table} (name TEXT NOT NULL, value TEXT NOT NULL, expiry REAL NOT NULL, PRIMARY KEY(name,value))")
        self.db.execute("""CREATE TABLE IF NOT EXISTS dns_route_origins (
            address TEXT PRIMARY KEY, domain TEXT NOT NULL, rule TEXT NOT NULL, added_at REAL
        )""")
        row = self.db.execute("SELECT value FROM metadata WHERE key='policy'").fetchone()
        policy = json.loads(row[0]) if row else None
        checkpoint_row = self.db.execute("SELECT value FROM metadata WHERE key='checkpoint'").fetchone()
        checkpoint = json.loads(checkpoint_row[0]) if checkpoint_row else {}
        publication = checkpoint.get("publication") or self._publication_paths()
        confirmed = read_confirmed(publication["last_good_routes_file"])
        if confirmed and "dns_policy" not in confirmed:
            # A static-mode update supersedes the previous DNS checkpoint,
            # including when both happen to contain identical route prefixes.
            # Keep leases for the next policy, but do not reuse its old rules.
            with self.db:
                self.db.execute("DELETE FROM metadata WHERE key IN ('policy', 'checkpoint')")
                self.db.execute("DELETE FROM dns_route_origins")
            (self.directory / "dns-policy.json").unlink(missing_ok=True)
            policy, checkpoint = None, {}
        elif policy is None and confirmed.get("dns_policy") is not None:
            policy = confirmed["dns_policy"]
            checkpoint = {"snapshot": confirmed, "publication": publication}
        elif policy is None and (self.directory / "dns-policy.json").exists():
            policy = json.loads((self.directory / "dns-policy.json").read_text(encoding="utf-8"))
            for table, file in (("leases", "dns-leases.json"), ("aliases", "dns-aliases.json")):
                path = self.directory / file
                if path.exists():
                    previous = json.loads(path.read_text(encoding="utf-8"))
                    self.db.executemany(f"INSERT OR REPLACE INTO {table} VALUES(?,?,?)",
                                        [(name, value, expiry) for name, items in previous.items() for value, expiry in items.items()])
            self.db.commit()
        now = time.time()
        for table, target in (("leases", self.leases), ("aliases", self.aliases)):
            self.db.execute(f"DELETE FROM {table} WHERE expiry<=?", (now,))
            for name, value, expiry in self.db.execute(f"SELECT name,value,expiry FROM {table} WHERE expiry>?", (now,)):
                target.setdefault(name, {})[value] = expiry
        self.db.commit()
        self.lease_count = sum(map(len, self.leases.values()))
        self.alias_count = sum(map(len, self.aliases.values()))
        if policy is not None:
            # When SQLite has a committed DNS policy it remains authoritative:
            # newer file mirrors can belong to a transaction killed pre-commit.
            self._new_policy(policy, restoring=True, **checkpoint)
        else:
            # Upgrading a static deployment has a last-good snapshot but no
            # DNS metadata yet. Keep its BGP routes while sources refresh;
            # this is not a usable DNS policy and must not pass readiness.
            snapshot = Path(publication["last_good_routes_file"])
            if snapshot.exists():
                routes = set()
                for line in snapshot.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    fields = line.split()
                    if len(fields) != 3 or fields[0] != "route" or fields[2] != "blackhole;":
                        raise ValueError("Invalid last-good route snapshot")
                    routes.add(str(ipaddress.IPv4Network(fields[1])))
                self.bootstrap_routes = routes
                self.publisher.update(routes, set())
                if routes:
                    LOG.info("Restored %d BGP routes from last-good snapshot; waiting for initial DNS policy", len(routes))

    def _run(self):
        owner = RouteManager(self.directory)
        owner.lock = self.directory / "dns-worker.lock"
        try:
            with owner.locked():
                self._initialize()
                self.error = ""
                self.initialized.set()
                last_expire = 0
                while not self.stop.is_set():
                    batch = []
                    try:
                        self._check_policy()
                        # Batch queue admissions, durable state writes, and BGP
                        # deltas. None of this work runs in DNS listener threads.
                        self.stop.wait(self.batch_seconds)
                        for _ in range(128):
                            try:
                                batch.append(self.queue.get_nowait())
                            except queue.Empty:
                                break
                        now = time.time()
                        if self.policy is not None and now - last_expire >= 0.5:
                            self._expire(now)
                            last_expire = now
                        tracked = [self._observe(event) for event in batch]
                        self._persist()
                        # Resolve each receipt only after its durable state and
                        # delta are accepted. Snapshot the effective policy of
                        # this batch, including shared-IP exclusion precedence.
                        revision = self.publisher.checkpoint() if any(event[5] is not None for event in batch) else 0
                        for event, selected in zip(batch, tracked):
                            ticket = event[5]
                            if ticket is not None:
                                expected = {}
                                if selected:
                                    for value, _ in event[1]:
                                        ip = ipaddress.IPv4Address(value)
                                        if ip.is_global:
                                            expected[str(ip)] = self.index.cover.find(ip) is not None
                                ticket.set_result(ObservationReceipt(revision, expected))
                        self.error = ""
                    except Exception as exc:
                        self.error = str(exc)
                        for event in batch:
                            if event[5] is not None and not event[5].done():
                                event[5].set_exception(exc)
                        LOG.warning("Live route update failed: %s", exc)
                        self.stop.wait(0.1)
                    finally:
                        for event in batch:
                            with self.weight_lock:
                                self.pending_weight -= event[4]
                                self._release_alias_targets(event[2])
                            self.queue.task_done()
                        self.last_progress = time.monotonic()
                        self._write_runtime()
        except Exception as exc:
            self.error = str(exc)
            LOG.exception("Live route worker stopped")
        finally:
            try:
                self._write_runtime(stopped=True)
            except OSError:
                LOG.exception("Could not save DNS worker shutdown status")
            if self.db is not None:
                self.db.close()

    def close(self):
        self.stop.set()
        # Wake an in-flight policy barrier before joining the route worker.
        self.publisher.close()
        self.thread.join(timeout=5)


def _committed_generation(directory, generation):
    path = directory / "dns-cache.sqlite3"
    if not path.exists():
        return False
    try:
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.5)) as db:
            row = db.execute("SELECT value FROM metadata WHERE key='policy'").fetchone()
            return row is not None and json.loads(row[0]).get("generation") == generation
    except (sqlite3.Error, ValueError):
        return False


def install_policy(path, directory=None, timeout=60, *, snapshot=None, publication=None):
    directory = Path(directory or os.environ.get("GENERATED_DIR", "/etc/bird/generated"))
    policy = json.loads(Path(path).read_text(encoding="utf-8"))
    owner = RouteManager(directory, lock_timeout=timeout)
    with owner.locked():
        request = {"policy": policy, "snapshot": snapshot, "publication": publication,
                   "deadline_unix": time.time() + timeout}
        write_json(directory / "dns-policy.pending.json", request)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                result = json.loads((directory / "dns-policy.applied.json").read_text(encoding="utf-8"))
            except FileNotFoundError:
                result = {}
            # A crash or disk error can lose the ACK after the durable commit.
            # SQLite is authoritative; repeating an accepted generation is safe.
            if _committed_generation(directory, policy["generation"]):
                (directory / "dns-policy.pending.json").unlink(missing_ok=True)
                return
            if result.get("generation") == policy["generation"]:
                if not result.get("success"):
                    # A rejected request must not be replayed after the worker
                    # restarts with a fresh pending-file modification stamp.
                    (directory / "dns-policy.pending.json").unlink(missing_ok=True)
                    raise RuntimeError(result.get("error", "Live policy update failed"))
                (directory / "dns-policy.pending.json").unlink(missing_ok=True)
                return
            time.sleep(0.05)
        if _committed_generation(directory, policy["generation"]):
            (directory / "dns-policy.pending.json").unlink(missing_ok=True)
            return
        (directory / "dns-policy.pending.json").unlink(missing_ok=True)
        raise TimeoutError("DNS route worker did not acknowledge the policy update")
