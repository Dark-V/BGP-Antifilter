"""A bounded DNS observation queue, durable TTL state, and incremental BGP RIB."""
from collections import Counter
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
from .dns_routes import RouteManager, atomic_write, domain_key, match_domain, write_json


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
        if not baseline:
            raise ValueError("Live route baseline is empty")
        self.baseline = PrefixSet(baseline)
        self.denied = PrefixSet(policy["exclude_routes"])
        self.cover = PrefixSet(baseline)
        self.added, self.removed = set(), set()

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
        address = ipaddress.IPv4Address(value)
        owner = self.baseline.find(address)
        current = self.cover.find(address)
        wanted = (owner is not None or included) and not excluded and self.denied.find(address) is None
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
                                             sync_marker=os.environ.get("DNS_SYNC_MODE", "async") == "bird")
        self.queue = queue.Queue(maxsize=capacity)
        self.weight_lock = threading.Lock()
        self.pending_weight = 0
        self.batch_seconds = batch_seconds
        self.stop = threading.Event()
        self.initialized = threading.Event()
        self.error = "Starting live route worker"
        self.drop_until = 0
        self.dropped = 0
        self.last_progress = time.monotonic()
        self.policy = None
        self.index = None
        self.leases, self.aliases = {}, {}
        self.included, self.excluded = Counter(), Counter()
        self.lease_dirty, self.alias_dirty = {}, {}
        self.lease_count = self.alias_count = 0
        self.include_roots, self.exclude_roots = set(), set()
        self._pending_stamp = None
        self.db = None
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
        try:
            self.queue.put_nowait((domain, tuple(addresses), tuple(targets), time.time() if now is None else now, weight, ticket, reply_budget))
            return ticket if ticket is not None else True
        except queue.Full:
            with self.weight_lock:
                self.pending_weight -= weight
            self.dropped += 1
            self.drop_until = time.monotonic() + 5
            if ticket is not None:
                ticket.set_exception(RuntimeError("DNS observation queue overloaded"))
                return ticket
            return False

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

    def check_bird(self):
        self.refresh()
        if not self.publisher.ready():
            raise RuntimeError("Local BGP feed is not synchronized")
        if "up and running" not in RouteManager.bird("show", "status"):
            raise RuntimeError("BIRD is not ready")
        if "Established" not in RouteManager.bird("show", "protocols", "dns_live"):
            raise RuntimeError("BIRD has not established the local feed")
        if os.environ.get("HEALTHCHECK_REQUIRE_BGP", "1") == "1":
            if "Established" not in RouteManager.bird("show", "protocols", os.environ.get("BGP_PROTOCOL", "mikrotik")):
                raise RuntimeError("MikroTik BGP is not established")

    def _classify(self, domain):
        if match_domain(domain, self.exclude_roots):
            return self.excluded
        if match_domain(domain, self.include_roots):
            return self.included
        return None

    def _lease(self, domain, address, expiry):
        current = self.leases.setdefault(domain, {})
        if address not in current:
            if self.lease_count >= 50000:
                self.drop_until = time.monotonic() + 5
                raise RuntimeError("DNS route lease limit exceeded")
            self.lease_count += 1
            target = self._classify(domain)
            if target is not None:
                target[address] += 1
                self.index.change(address, self.included[address] > 0, self.excluded[address] > 0)
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
        origins = {domain} if self._classify(domain) is not None else set()
        origins.update(origin for origin, expiry in self.aliases.get(domain, {}).items()
                       if expiry > now and self._classify(origin) is not None)
        # Client cache lifetime begins after the gated reply. Keep both IPs
        # and aliases alive for the entire possible reply delay as well.
        grace = int(os.environ.get("DNS_ROUTE_GRACE", "30")) + reply_budget
        for origin in origins:
            for address, ttl in addresses:
                ip = ipaddress.IPv4Address(address)
                expiry = received + max(1, ttl) + grace
                if ip.is_global and expiry > now:
                    self._lease(origin, str(ip), expiry)
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
        return bool(origins)

    def _expire(self, now):
        for domain, items in list(self.leases.items()):
            for address, expiry in list(items.items()):
                if expiry > now:
                    continue
                del items[address]
                self.lease_count -= 1
                target = self._classify(domain)
                if target is not None and self.index is not None:
                    target[address] -= 1
                    if target[address] <= 0:
                        del target[address]
                    self.index.change(address, self.included[address] > 0, self.excluded[address] > 0)
                self.lease_dirty[domain, address] = None
            if not items:
                del self.leases[domain]
        for target, origins in list(self.aliases.items()):
            for origin, expiry in list(origins.items()):
                if expiry <= now or (self.policy is not None and self._classify(origin) is None):
                    del origins[origin]
                    self.alias_count -= 1
                    self.alias_dirty[target, origin] = None
            if not origins:
                del self.aliases[target]

    def _persist(self):
        if self.lease_dirty or self.alias_dirty:
            with self.db:
                for table, changes in (("leases", self.lease_dirty), ("aliases", self.alias_dirty)):
                    self.db.executemany(f"DELETE FROM {table} WHERE name=? AND value=?",
                                        [(name, value) for (name, value), expiry in changes.items() if expiry is None])
                    self.db.executemany(f"INSERT INTO {table} VALUES(?,?,?) ON CONFLICT(name,value) DO UPDATE SET expiry=excluded.expiry",
                                        [(name, value, expiry) for (name, value), expiry in changes.items() if expiry is not None])
            self.lease_dirty.clear()
            self.alias_dirty.clear()
        if self.index is not None:
            added, removed = self.index.added, self.index.removed
            if added or removed:
                self.publisher.update(added, removed)
                self.index.delta()

    def _new_policy(self, policy):
        index = IncrementalRoutes(policy)
        if getattr(self.publisher, "sync_marker", False) and index.baseline.contains(ipaddress.IPv4Network(SYNC_PREFIX)):
            raise ValueError(f"{SYNC_PREFIX} is reserved for DNS/BIRD synchronization")
        includes, excludes = set(policy["include_domains"]), set(policy["exclude_domains"])
        included, excluded = Counter(), Counter()
        now = time.time()
        # Remove expired owners using the old policy's counters before
        # rebuilding them. Otherwise a later expiry would subtract twice and
        # could withdraw an IP still owned by another live domain.
        self._expire(now)
        for domain, addresses in self.leases.items():
            target = excluded if match_domain(domain, excludes) else included if match_domain(domain, includes) else None
            if target is not None:
                target.update(address for address, expiry in addresses.items() if expiry > now)
        for address in included.keys() | excluded.keys():
            index.change(address, included[address] > 0, excluded[address] > 0)
        routes = index.cover.routes()  # Full scan only on policy load/update.
        text = "".join(f"    route {value} blackhole;\n" for value in sorted(routes, key=lambda x: (int(ipaddress.IPv4Network(x).network_address), ipaddress.IPv4Network(x).prefixlen)))
        self._persist()
        previous = self.index.cover.routes() if self.index is not None else set()
        files = [self.directory / name for name in ("dns-policy.json", "routes.conf", "routes.last-good.conf")]
        backups = {path: path.read_text(encoding="utf-8") if path.exists() else None for path in files}
        try:
            write_json(files[0], policy)
            atomic_write(files[1], text)
            atomic_write(files[2], text)
            with self.db:
                self.db.execute("INSERT INTO metadata VALUES('policy',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (json.dumps(policy),))
        except Exception:
            # The in-memory RIB/publisher remain unchanged on snapshot errors.
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
        self.include_roots, self.exclude_roots = includes, excludes
        self.included, self.excluded = included, excluded
        index.delta()  # Initial exclusions were incorporated in the full diff.
        self.publisher.update(routes - previous, previous - routes)

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
        policy = json.loads(path.read_text(encoding="utf-8"))
        generation = policy["generation"]
        try:
            if self.policy is None or self.policy["generation"] != generation:
                self._new_policy(policy)
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
        row = self.db.execute("SELECT value FROM metadata WHERE key='policy'").fetchone()
        policy = json.loads(row[0]) if row else None
        if policy is None and (self.directory / "dns-policy.json").exists():
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
            self._new_policy(policy)

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
                            self.queue.task_done()
                        self.last_progress = time.monotonic()
        except Exception as exc:
            self.error = str(exc)
            LOG.exception("Live route worker stopped")
        finally:
            if self.db is not None:
                self.db.close()

    def close(self):
        self.stop.set()
        self.thread.join(timeout=5)
        self.publisher.close()


def install_policy(path, directory=None, timeout=60):
    directory = Path(directory or os.environ.get("GENERATED_DIR", "/etc/bird/generated"))
    policy = json.loads(Path(path).read_text(encoding="utf-8"))
    owner = RouteManager(directory, lock_timeout=timeout)
    with owner.locked():
        write_json(directory / "dns-policy.pending.json", policy)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                result = json.loads((directory / "dns-policy.applied.json").read_text(encoding="utf-8"))
            except FileNotFoundError:
                result = {}
            if result.get("generation") == policy["generation"]:
                if not result.get("success"):
                    raise RuntimeError(result.get("error", "Live policy update failed"))
                (directory / "dns-policy.pending.json").unlink(missing_ok=True)
                return
            time.sleep(0.05)
        raise TimeoutError("DNS route worker did not acknowledge the policy update")
