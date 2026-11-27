"""DNS forwarder with background routes and optional bounded reply gates."""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import logging
import os
import socket
import socketserver
import struct
import threading
import time

import dns.exception
import dns.flags
import dns.message
import dns.opcode
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype

from .dns_routes import domain_key
from .live_routes import LiveRoutes
from .state_log import StateLog
from .dns_sync import ReplyGate, SyncOptions
from .dns_settings import load_active_environment


LOG = logging.getLogger("dns-proxy")
READINESS_TIMEOUT = 2.5


def error_text(error, timeout_reason="operation timed out"):
    message = str(error).strip()
    if message:
        return message
    name = type(error).__name__
    return f"{name}: {timeout_reason}" if isinstance(error, TimeoutError) else name


def endpoint(address, port):
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def readiness_remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(f"DNS readiness probe exceeded {READINESS_TIMEOUT:g}s")
    return remaining


def reachable_names(response):
    """Names linked to the question, with each alias RRset's cache lifetime."""
    if response.rcode() != dns.rcode.NOERROR or response.flags & dns.flags.TC:
        return {}
    if not response.question:
        return {}
    reachable = {response.question[0].name: 0}
    records = response.answer + response.additional
    for _ in range(32):
        changed = False
        for rrset in records:
            if rrset.name not in reachable or rrset.rdclass != dns.rdataclass.IN:
                continue
            if rrset.rdtype not in (dns.rdatatype.CNAME, dns.rdatatype.HTTPS, dns.rdatatype.SVCB):
                continue
            for record in rrset:
                target = record.target
                if target.is_absolute() and target != dns.name.root and target not in reachable:
                    reachable[target] = rrset.ttl
                    changed = True
        if not changed:
            break
    return reachable


def answer_targets(response):
    reachable = reachable_names(response)
    if not response.question:
        return []
    return [(domain_key(name.to_text()), ttl) for name, ttl in reachable.items()
            if name != response.question[0].name]


def answer_addresses(response):
    """Follow the question's CNAME/SVCB chain; never learn unrelated glue."""
    reachable = reachable_names(response)
    addresses = []
    for rrset in response.answer + response.additional:
        if rrset.name not in reachable or rrset.rdclass != dns.rdataclass.IN:
            continue
        # Each RRset has its own cache lifetime. A short CNAME/SVCB alias
        # must not withdraw an address the client may still cache longer.
        ttl = rrset.ttl
        for record in rrset:
            if rrset.rdtype == dns.rdatatype.A:
                addresses.append((record.address, ttl))
            elif rrset.rdtype in (dns.rdatatype.HTTPS, dns.rdatatype.SVCB):
                # RFC 9460: AliasMode parameters are ignored by clients.
                if record.priority == 0:
                    continue
                hint = record.params.get(4)  # ipv4hint
                if hint is not None:
                    addresses.extend((address, ttl) for address in hint.addresses)
    return addresses


def receive_exact(connection, size, deadline=None):
    data = bytearray()
    while len(data) < size:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("DNS TCP frame deadline exceeded")
            connection.settimeout(remaining)
        part = connection.recv(size - len(data))
        if not part:
            raise EOFError("DNS TCP connection closed")
        data.extend(part)
    return bytes(data)


class Proxy:
    def __init__(self, manager, upstream, port=53, timeout=2.0, allowed=None, sync=None):
        self.manager = manager
        upstream = ipaddress.ip_address(upstream)
        if upstream.is_unspecified or upstream.is_multicast:
            raise ValueError("DNS proxy upstream must be a unicast IP address")
        self.upstream = str(upstream)
        self.port = port
        self.timeout = timeout
        self.allowed = [ipaddress.ip_network(value, strict=False) for value in
                        (allowed if allowed is not None else ["127.0.0.1/32", "::1/128"])]
        self.last_error = ""
        self.sync = sync or SyncOptions.from_env()
        self.gate = ReplyGate(manager, self.sync)

    def permits(self, address):
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        return any(ip in network for network in self.allowed)

    def exchange(self, request, tcp=False):
        if tcp:
            return dns.query.tcp(request, self.upstream, port=self.port, timeout=self.timeout)
        response, _ = dns.query.udp_with_fallback(request, self.upstream, port=self.port, timeout=self.timeout)
        return response

    def handle(self, wire, address, tcp=False):
        if not 12 <= len(wire) <= 65535:
            return None
        try:
            request = dns.message.from_wire(wire)
            if request.flags & dns.flags.QR:
                return None
            response = dns.message.make_response(request)
        except dns.exception.DNSException:
            return None
        response.set_rcode(dns.rcode.SERVFAIL)
        if not self.permits(address):
            response.set_rcode(dns.rcode.REFUSED)
        elif (request.opcode() != dns.opcode.QUERY
              or len(request.question) != 1
              or request.question[0].rdclass != dns.rdataclass.IN
              or request.question[0].rdtype in (dns.rdatatype.AXFR, dns.rdatatype.IXFR)):
            response.set_rcode(dns.rcode.REFUSED)
        else:
            domain = domain_key(request.question[0].name.to_text())
            query_type = dns.rdatatype.to_text(request.question[0].rdtype)
            transport_name = "TCP" if tcp else "UDP (with TCP fallback)"
            try:
                response = self.exchange(request, tcp=tcp)
                addresses = answer_addresses(response)
                targets = answer_targets(response)
                try:
                    if targets or addresses:
                        self.gate.observe(domain, addresses, targets)
                except Exception as exc:
                    detail = error_text(exc, f"route synchronization exceeded {self.sync.timeout:g}s in {self.sync.mode} mode")
                    self.last_error = f"Route synchronization for {domain} ({query_type}): {detail}"
                    LOG.warning("DNS route observation/synchronization failed for %s (%s): %s", domain, query_type, detail)
                    if self.sync.mode != "async" and self.sync.on_timeout == "servfail":
                        # Never leave new IPs/hints in the answer or additional
                        # sections of a failed synchronization response.
                        response = dns.message.make_response(request)
                        response.set_rcode(dns.rcode.SERVFAIL)
            except Exception as exc:
                detail = error_text(exc, f"upstream DNS request exceeded {self.timeout:g}s")
                self.last_error = f"{transport_name} query for {domain} ({query_type}) to {endpoint(self.upstream, self.port)}: {detail}"
                LOG.warning("DNS request failed: %s", self.last_error)
                response = dns.message.make_response(request)
                response.set_rcode(dns.rcode.SERVFAIL)
        size = 65535 if tcp else max(512, min(request.payload or 512, 4096))
        # Preserve the upstream packet, including unknown records and EDNS
        # options, unless the client's transport needs a truncated response.
        if response.wire is not None and len(response.wire) <= size:
            return response.wire
        return response.to_wire(max_size=size, prefer_truncation=True)


class BoundedServer:
    """Bound concurrent connections and queued work, including slow TCP peers."""
    allow_reuse_address = True

    def __init__(self, address, handler, proxy):
        self.proxy = proxy
        self.slots = threading.BoundedSemaphore(64)
        self.pool = ThreadPoolExecutor(max_workers=16)
        self.address_family = socket.AF_INET6 if ipaddress.ip_address(address[0]).version == 6 else socket.AF_INET
        try:
            super().__init__(address, handler)
        except BaseException:
            self.pool.shutdown(wait=True)
            raise

    def process_request(self, request, client_address):
        # Reject peers before allocating a worker or reading a TCP frame.
        if not self.proxy.permits(client_address[0]):
            self.shutdown_request(request)
            return
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        self.pool.submit(self._process, request, client_address)

    def _process(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            LOG.exception("DNS connection failed")
        finally:
            self.shutdown_request(request)
            self.slots.release()

    def server_close(self):
        super().server_close()
        self.pool.shutdown(wait=True)


class UDPServer(BoundedServer, socketserver.UDPServer):
    max_packet_size = 65535


class TCPServer(BoundedServer, socketserver.TCPServer):
    pass


class ReadyServer(BoundedServer, HTTPServer):
    def __init__(self, *args):
        self.state_log = StateLog(LOG, "DNS readiness")
        super().__init__(*args)


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        wire, connection = self.request
        response = self.server.proxy.handle(wire, self.client_address[0])
        if response is not None:
            connection.sendto(response, self.client_address)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            # Multiple messages per connection are supported, with an idle
            # timeout and a work bound so a client cannot hold a worker forever.
            for _ in range(64):
                deadline = time.monotonic() + 5
                length = struct.unpack("!H", receive_exact(self.request, 2, deadline))[0]
                if length < 12:
                    return
                wire = receive_exact(self.request, length, deadline)
                response = self.server.proxy.handle(wire, self.client_address[0], tcp=True)
                if response is None:
                    return
                self.request.settimeout(5)
                self.request.sendall(struct.pack("!H", len(response)) + response)
        except (EOFError, OSError):
            return


class ReadyHandler(BaseHTTPRequestHandler):
    timeout = 5

    def do_GET(self):
        if not self.server.proxy.permits(self.client_address[0]):
            self.send_error(403)
            return
        if self.path != "/ready":
            self.send_error(404)
            return
        record_readiness = getattr(self.server.proxy.manager, "record_readiness", None)
        deadline = time.monotonic() + READINESS_TIMEOUT
        acquired = False
        try:
            acquired = self.server.check_lock.acquire(timeout=readiness_remaining(deadline))
            if not acquired:
                raise TimeoutError("DNS readiness check is still busy after the probe deadline")
            self.server.proxy.manager.refresh()
            self.server.proxy.manager.check_bird(deadline=deadline)
            # Exercise both actual listeners and upstream transports.
            query = dns.message.make_query(os.environ.get("DNS_HEALTH_DOMAIN", "example.org"), "A")
            domain = domain_key(query.question[0].name.to_text())
            listener = endpoint(self.server.dns_address[0], self.server.dns_address[1])
            upstream = endpoint(self.server.proxy.upstream, self.server.proxy.port)
            for transport_name, transport in (("UDP", dns.query.udp), ("TCP", dns.query.tcp)):
                description = f"DNS {transport_name} probe for {domain} via {listener} (upstream {upstream})"
                try:
                    response = transport(query, self.server.dns_address[0], port=self.server.dns_address[1],
                                         timeout=readiness_remaining(deadline))
                except Exception as exc:
                    detail = error_text(exc, f"DNS readiness probe exceeded {READINESS_TIMEOUT:g}s")
                    raise RuntimeError(f"{description} failed: {detail}") from exc
                code = dns.rcode.to_text(response.rcode())
                if response.rcode() != dns.rcode.NOERROR:
                    raise RuntimeError(f"{description} returned {code}")
                reachable = reachable_names(response)
                if not any(rrset.rdtype == dns.rdatatype.A and rrset.rdclass == dns.rdataclass.IN
                           and rrset.name in reachable and len(rrset)
                           for rrset in response.answer + response.additional):
                    raise RuntimeError(f"{description} returned NOERROR without an IPv4 answer")
            readiness_remaining(deadline)
            if callable(record_readiness):
                record_readiness(True)
            body = b'{"ready":true}\n'
            code = 200
            self.server.state_log.healthy()
        except Exception as exc:
            detail = error_text(exc)
            if callable(record_readiness):
                record_readiness(False, detail)
            self.server.state_log.failure(detail)
            body = json.dumps({"ready": False, "error": detail}).encode() + b"\n"
            code = 503
        finally:
            if acquired:
                self.server.check_lock.release()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    load_active_environment()
    enabled = os.environ.get("DNS_PROXY_ENABLED", "0")
    if enabled == "0":
        # A supervised optional service stays idle without workers or ports.
        LOG.info("DNS integration is disabled")
        threading.Event().wait()
        return
    if enabled != "1":
        raise ValueError("DNS_PROXY_ENABLED must be 0 or 1")
    bind = str(ipaddress.ip_address(os.environ.get("DNS_PROXY_BIND", "127.0.0.1")))
    port = int(os.environ.get("DNS_PROXY_PORT", "53"))
    upstream = os.environ.get("DNS_PROXY_UPSTREAM", "").strip()
    if not upstream:
        raise ValueError("DNS_PROXY_UPSTREAM must be configured when the proxy is enabled")
    upstream = str(ipaddress.ip_address(upstream))
    upstream_port = int(os.environ.get("DNS_PROXY_UPSTREAM_PORT", "53"))
    health_port = int(os.environ.get("DNS_PROXY_HEALTH_PORT", "8053"))
    if any(not 1 <= value <= 65535 for value in (port, upstream_port, health_port)):
        raise ValueError("DNS proxy ports must be between 1 and 65535")
    if ipaddress.ip_address(bind).is_unspecified or (bind == upstream and port == upstream_port):
        raise ValueError("Bind DNS proxy to a specific address and use a different upstream endpoint")
    if int(os.environ.get("DNS_ROUTE_GRACE", "30")) < 0:
        raise ValueError("DNS_ROUTE_GRACE must not be negative")
    allowed = os.environ.get("DNS_PROXY_ALLOWED_CLIENTS", "127.0.0.1/32 ::1/128")
    prefix = 32 if ipaddress.ip_address(bind).version == 4 else 128
    allowed = allowed.replace(",", " ").split() + [f"{bind}/{prefix}", "127.0.0.1/32", "::1/128"]
    sync = SyncOptions.from_env()  # Validate before starting route/BGP workers.
    proxy = Proxy(LiveRoutes(), upstream, port=upstream_port, allowed=allowed, sync=sync)
    servers = []
    try:
        udp = UDPServer((bind, port), UDPHandler, proxy)
        servers.append(udp)
        tcp = TCPServer((bind, port), TCPHandler, proxy)
        servers.append(tcp)
        ready = ReadyServer((bind, health_port), ReadyHandler, proxy)
        servers.append(ready)
    except BaseException:
        for server in reversed(servers):
            server.server_close()
        proxy.manager.close()
        raise
    ready.dns_address = udp.server_address
    ready.check_lock = threading.Lock()
    LOG.info("DNS proxy %s:%s -> %s:%s (sync=%s, timeout=%ss, on_timeout=%s)",
             bind, port, upstream, upstream_port, sync.mode, sync.timeout, sync.on_timeout)
    try:
        serve(servers, proxy.manager)
    except KeyboardInterrupt:
        pass


def serve(servers, manager, interval=5):
    threads = []
    state_log = StateLog(LOG, "Route maintenance")
    try:
        for server in servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
        while True:
            if not all(thread.is_alive() for thread in threads):
                # Exit so the supervisor can restart a failed listener.
                raise RuntimeError("DNS proxy listener stopped unexpectedly")
            manager.supervise()
            threading.Event().wait(interval)
            try:
                manager.refresh()
                state_log.healthy()
            except Exception as exc:
                state_log.failure(exc)
    finally:
        for index, server in enumerate(servers):
            if index < len(threads) and threads[index].is_alive():
                server.shutdown()
            server.server_close()
        manager.close()


if __name__ == "__main__":
    main()
