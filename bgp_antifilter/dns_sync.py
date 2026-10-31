"""Optional, bounded DNS reply gates; none confirms the MikroTik FIB."""
from dataclasses import dataclass
import ipaddress
import math
import os
import re
import subprocess
import threading
import time

from .bgp_feed import SYNC_PREFIX


@dataclass(frozen=True)
class SyncOptions:
    mode: str = "async"
    timeout: float = 1.0
    on_timeout: str = "servfail"

    def __post_init__(self):
        if self.mode not in ("async", "bgp", "bird"):
            raise ValueError("DNS_SYNC_MODE must be async, bgp, or bird")
        if not math.isfinite(self.timeout) or not 0 < self.timeout <= 10:
            raise ValueError("DNS_SYNC_TIMEOUT must be greater than 0 and at most 10 seconds")
        if self.on_timeout not in ("servfail", "forward"):
            raise ValueError("DNS_SYNC_ON_TIMEOUT must be servfail or forward")

    @classmethod
    def from_env(cls):
        return cls(os.environ.get("DNS_SYNC_MODE", "async"),
                   float(os.environ.get("DNS_SYNC_TIMEOUT", "1")),
                   os.environ.get("DNS_SYNC_ON_TIMEOUT", "servfail"))


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError("DNS route synchronization deadline exceeded")
    return value


class ReplyGate:
    def __init__(self, manager, options):
        self.manager, self.options = manager, options
        # DNS listener concurrency is bounded too. Limit birdc processes even
        # when a single answer contains many different addresses.
        self.readers = threading.BoundedSemaphore(4)

    def _bird(self, deadline, *args):
        if not self.readers.acquire(timeout=remaining(deadline)):
            raise TimeoutError("BIRD confirmation readers are busy")
        try:
            reply = subprocess.run(["birdc", "-v", "-r", *args], capture_output=True, text=True,
                                   timeout=remaining(deadline), check=False)
            codes = [int(value) for value in re.findall(r"(?m)^(\d{4})[ -]", reply.stdout)]
            # BIRD's explicit "Network not found" is CLI 8001 / exit 1.
            # It is a valid absence result, unlike every other CLI failure.
            absent = (args[:2] == ("show", "route") and reply.returncode == 1
                      and codes and codes[-1] == 8001 and all(code < 8000 or code == 8001 for code in codes))
            if reply.returncode and not absent:
                reply.check_returncode()
            # birdc -v prefixes continuation rows with five spaces instead of
            # repeating their numeric code (client/client.c:server_got_reply).
            output = re.sub(r"(?m)^(?:\d{4}[ -]| {5})", "", reply.stdout)
            if (any(code >= 8000 for code in codes) and not absent) or 1 not in codes or not re.search(r"BIRD .* ready\.", output):
                raise RuntimeError("BIRD rejected the route confirmation query")
            return output
        finally:
            self.readers.release()

    def _confirmed(self, receipt, deadline):
        feed = self.manager.publisher
        marker = self._bird(deadline, "show", "route", SYNC_PREFIX, "protocol", "dns_live", "all")
        communities = {(int(asn), int(tag)): int(value) for asn, tag, value in re.findall(
            r"\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)", marker)}
        high = communities.get((feed.asn, feed.marker_token))
        low = communities.get((feed.asn, feed.marker_token ^ 0xffffffff))
        if high is None or low is None or (high << 32 | low) < receipt.revision:
            return False
        for value, wanted in receipt.expected.items():
            table = self._bird(deadline, "show", "route", "for", value, "primary")
            rows = re.findall(r"(?m)^(\d+\.\d+\.\d+\.\d+/\d+)\s+([^\n]+)", table)
            covering = [row for network, row in rows if ipaddress.IPv4Address(value) in ipaddress.IPv4Network(network)]
            if wanted:
                if not any(re.search(r"\[dns_live\s", row) for row in covering):
                    return False
            elif covering:
                return False
        return True

    def observe(self, domain, addresses, targets=()):
        if self.options.mode == "async":
            if targets:
                return self.manager.observe(domain, addresses, targets=targets)
            return self.manager.observe(domain, addresses)
        deadline = time.monotonic() + self.options.timeout
        ticket = self.manager.observe(domain, addresses, targets=targets, receipt=True, reply_budget=self.options.timeout)
        receipt = ticket.result(timeout=remaining(deadline))
        if not receipt.expected:
            return  # Unselected domain or alias-only answer; no route to wait for.
        self.manager.publisher.wait_sent(receipt.revision, remaining(deadline))
        if self.options.mode == "bird":
            if os.environ.get("HEALTHCHECK_REQUIRE_BGP", "1") == "1":
                status = self._bird(deadline, "show", "protocols", os.environ.get("BGP_PROTOCOL", "mikrotik"))
                if "Established" not in status:
                    raise RuntimeError("MikroTik BGP is not established")
            while not self._confirmed(receipt, deadline):
                time.sleep(min(0.01, remaining(deadline)))
        remaining(deadline)
