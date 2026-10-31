"""DNS forwarder which applies observed IPv4 routes before returning answers."""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import logging
import os
import socketserver
import struct
import threading

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


LOG = logging.getLogger("dns-proxy")


def reachable_names(response):
    """Names linked to the question, with each alias RRset's cache lifetime."""
    if response.rcode() != dns.rcode.NOERROR or response.flags & dns.flags.TC:
        return {}
    if not response.question:
        return {}
    reachable = {response.question[0].name: 0}
    records = response.answer
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
                hint = record.params.get(4)  # ipv4hint
                if hint is not None:
                    addresses.extend((address, ttl) for address in hint.addresses)
    return addresses


def receive_exact(connection, size):
    data = bytearray()
    while len(data) < size:
        part = connection.recv(size - len(data))
        if not part:
            raise EOFError("DNS TCP connection closed")
        data.extend(part)
    return bytes(data)


class Proxy:
    def __init__(self, manager, upstream, port=53, timeout=2.0, allowed=None):
        self.manager = manager
        self.upstream = str(ipaddress.IPv4Address(upstream))
        self.port = port
        self.timeout = timeout
        self.allowed = [ipaddress.ip_network(value, strict=False) for value in (allowed or ["127.0.0.1/32"])]
        self.last_error = ""

    def permits(self, address):
        ip = ipaddress.ip_address(address)
        return any(ip in network for network in self.allowed)

    def exchange(self, request, tcp=False):
        if tcp:
            return dns.query.tcp(request, self.upstream, port=self.port, timeout=self.timeout)
        response, _ = dns.query.udp_with_fallback(request, self.upstream, port=self.port, timeout=self.timeout)
        return response

    def handle(self, wire, address, tcp=False):
        try:
            request = dns.message.from_wire(wire)
        except dns.exception.DNSException:
            return None
        response = dns.message.make_response(request)
        response.set_rcode(dns.rcode.SERVFAIL)
        if not self.permits(address):
            response.set_rcode(dns.rcode.REFUSED)
        elif (request.flags & dns.flags.QR or request.opcode() != dns.opcode.QUERY
              or len(request.question) != 1
              or request.question[0].rdclass != dns.rdataclass.IN
              or request.question[0].rdtype in (dns.rdatatype.AXFR, dns.rdatatype.IXFR)):
            response.set_rcode(dns.rcode.REFUSED)
        else:
            try:
                response = self.exchange(request, tcp=tcp)
                addresses = answer_addresses(response)
                targets = answer_targets(response)
                try:
                    # Queue admission only. Route failures/overload affect
                    # readiness, never turn a valid AdGuard answer into SERVFAIL.
                    if targets:
                        self.manager.observe(domain_key(request.question[0].name.to_text()), addresses, targets=targets)
                    elif addresses:
                        self.manager.observe(domain_key(request.question[0].name.to_text()), addresses)
                except Exception as exc:
                    self.last_error = str(exc)
                    LOG.warning("Could not queue DNS observation: %s", exc)
            except Exception as exc:
                self.last_error = str(exc)
                LOG.warning("DNS request failed: %s", exc)
                response = dns.message.make_response(request)
                response.set_rcode(dns.rcode.SERVFAIL)
        size = 65535 if tcp else max(512, min(request.payload or 512, 4096))
        return response.to_wire(max_size=size, prefer_truncation=True)


class BoundedServer:
    """Bound concurrent connections and queued work, including slow TCP peers."""
    allow_reuse_address = True

    def __init__(self, address, handler, proxy):
        self.proxy = proxy
        self.slots = threading.BoundedSemaphore(64)
        self.pool = ThreadPoolExecutor(max_workers=16)
        super().__init__(address, handler)

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
    pass


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
                length = struct.unpack("!H", receive_exact(self.request, 2))[0]
                response = self.server.proxy.handle(receive_exact(self.request, length), self.client_address[0], tcp=True)
                if response is None:
                    return
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
        try:
            with self.server.check_lock:
                self.server.proxy.manager.refresh()
                self.server.proxy.manager.check_bird()
                # Exercise both actual listeners and upstream transports.
                query = dns.message.make_query(os.environ.get("DNS_HEALTH_DOMAIN", "example.org"), "A")
                for transport in (dns.query.udp, dns.query.tcp):
                    response = transport(query, self.server.dns_address[0], port=self.server.dns_address[1], timeout=3)
                    if response.rcode() != dns.rcode.NOERROR or not response.answer:
                        raise RuntimeError("DNS end-to-end probe failed")
            body = b'{"ready":true}\n'
            code = 200
        except Exception as exc:
            LOG.warning("Not ready: %s", exc)
            body = json.dumps({"ready": False, "error": str(exc)}).encode() + b"\n"
            code = 503
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if os.environ.get("DNS_PROXY_ENABLED", "0") != "1":
        raise ValueError("Set DNS_PROXY_ENABLED=1 for both bird and dns-proxy")
    bind = str(ipaddress.IPv4Address(os.environ.get("DNS_PROXY_BIND", os.environ.get("BIRD_IP", "127.0.0.1"))))
    port = int(os.environ.get("DNS_PROXY_PORT", "53"))
    upstream = os.environ.get("ADGUARD_DNS", "192.168.88.16")
    upstream_port = int(os.environ.get("ADGUARD_DNS_PORT", "53"))
    if bind == "0.0.0.0" or (bind == upstream and port == upstream_port):
        raise ValueError("Bind DNS proxy to its own specific address, different from AdGuard")
    if int(os.environ.get("DNS_ROUTE_GRACE", "30")) < 0:
        raise ValueError("DNS_ROUTE_GRACE must not be negative")
    allowed = os.environ.get("DNS_PROXY_ALLOWED_CLIENTS", os.environ.get("MT_IP", "127.0.0.1") + "/32")
    allowed = allowed.replace(",", " ").split() + [bind + "/32", "127.0.0.1/32"]
    proxy = Proxy(LiveRoutes(), upstream, port=upstream_port, allowed=allowed)
    udp = UDPServer((bind, port), UDPHandler, proxy)
    tcp = TCPServer((bind, port), TCPHandler, proxy)
    ready = ReadyServer((bind, int(os.environ.get("DNS_PROXY_HEALTH_PORT", "8053"))), ReadyHandler, proxy)
    ready.dns_address = udp.server_address
    ready.check_lock = threading.Lock()
    LOG.info("DNS proxy %s:%s -> %s:%s", bind, port, upstream, upstream_port)
    try:
        serve((udp, tcp, ready), proxy.manager)
    except KeyboardInterrupt:
        pass


def serve(servers, manager, interval=5):
    threads = []
    try:
        for server in servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
        while True:
            if not all(thread.is_alive() for thread in threads):
                # Docker restart policies act on process exit, not merely on
                # an unhealthy check. Do not leave a dead listener stranded.
                raise RuntimeError("DNS proxy listener stopped unexpectedly")
            threading.Event().wait(interval)
            try:
                manager.refresh()
            except Exception as exc:
                LOG.warning("Route maintenance failed: %s", exc)
    finally:
        for index, server in enumerate(servers):
            if index < len(threads) and threads[index].is_alive():
                server.shutdown()
            server.server_close()
        manager.close()


if __name__ == "__main__":
    main()
