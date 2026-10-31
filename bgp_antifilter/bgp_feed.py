"""Outbound, loopback-only IPv4 iBGP feed (RFC 4271 / 6793 / 4724).

This peer advertises locally produced routes only. It deliberately offers no
route-refresh or inbound route service. BIRD owns the external MikroTik session.
"""
import ipaddress
from itertools import islice
import logging
import os
import select
import socket
import struct
import threading
import time


LOG = logging.getLogger("dns-bgp")
MARKER = b"\xff" * 16


def bird_route_source():
    if os.environ.get("DNS_PROXY_ENABLED", "0") != "1":
        return 'protocol static static_antifilter {\n    ipv4;\n    include "/etc/bird/generated/routes.conf";\n}'
    port = int(os.environ.get("DNS_BGP_PORT", "1179"))
    if not 1024 <= port <= 65535:
        raise ValueError("DNS_BGP_PORT must be between 1024 and 65535")
    return f'''protocol bgp dns_live {{
    local 127.0.0.1 port {port} as MY_AS;
    neighbor 127.0.0.2 as MY_AS;
    passive on;
    strict bind on;
    multihop;
    graceful restart on;
    ipv4 {{
        import filter {{ dest = RTD_BLACKHOLE; accept; }};
        export none;
    }};
}}'''


def message(kind, payload=b""):
    length = 19 + len(payload)
    if not 19 <= length <= 4096:
        raise ValueError("BGP message exceeds the negotiated standard size")
    return MARKER + struct.pack("!HB", length, kind) + payload


def open_message(asn, router_id, hold=30):
    asn2 = asn if asn <= 65535 else 23456
    caps = b"\x41\x04" + struct.pack("!I", asn)
    # Restart time 120s, IPv4 unicast, forwarding state preserved. BIRD may
    # retain the old feed during a short restart until the replay's End-of-RIB.
    caps += b"\x40\x06" + struct.pack("!H", 120) + b"\x00\x01\x01\x80"
    option = b"\x02" + bytes([len(caps)]) + caps
    return message(1, struct.pack("!BHH4sB", 4, asn2, hold, socket.inet_aton(router_id), len(option)) + option)


def parse_open(payload, expected_asn, router_id):
    if len(payload) < 10:
        raise RuntimeError("Short BGP OPEN")
    version, asn, hold, peer_id, length = struct.unpack("!BHH4sB", payload[:10])
    if version != 4 or (hold and hold < 3) or len(payload) != 10 + length:
        raise RuntimeError("Invalid BGP OPEN")
    offset = 10
    asn4 = None
    while offset < len(payload):
        if offset + 2 > len(payload):
            raise RuntimeError("Truncated BGP OPEN option")
        kind, size = payload[offset:offset + 2]
        offset += 2
        end = offset + size
        if kind != 2 or end > len(payload):
            raise RuntimeError("Unsupported BGP OPEN option")
        while offset < end:
            if offset + 2 > end:
                raise RuntimeError("Truncated BGP capability")
            code, size = payload[offset:offset + 2]
            offset += 2
            if offset + size > end:
                raise RuntimeError("Truncated BGP capability value")
            if code == 65:
                if size != 4:
                    raise RuntimeError("Invalid AS4 capability")
                asn4 = struct.unpack("!I", payload[offset:offset + 4])[0]
            offset += size
    if (asn4 if asn4 is not None else asn) != expected_asn:
        raise RuntimeError("Unexpected local-feed peer ASN")
    if peer_id == b"\0" * 4 or peer_id == socket.inet_aton(router_id):
        raise RuntimeError("Invalid local-feed peer router ID")
    return min(30, hold) if hold else 0


def encode_prefix(value):
    network = ipaddress.IPv4Network(value)
    return bytes([network.prefixlen]) + network.network_address.packed[:(network.prefixlen + 7) // 8]


def updates(prefixes, next_hop, withdraw=False):
    attrs = b"" if withdraw else (
        b"\x40\x01\x01\x00"  # ORIGIN IGP
        b"\x40\x02\x00"      # empty AS_PATH: locally originated iBGP
        b"\x40\x03\x04" + socket.inet_aton(next_hop)
        + b"\x40\x05\x04" + struct.pack("!I", 100)  # LOCAL_PREF
    )
    chunk = bytearray()
    limit = 4096 - 19 - 4 - len(attrs)
    for value in prefixes:
        prefix = encode_prefix(value)
        if len(chunk) + len(prefix) > limit:
            payload = struct.pack("!H", len(chunk)) + chunk + b"\0\0" if withdraw else b"\0\0" + struct.pack("!H", len(attrs)) + attrs + chunk
            yield message(2, payload)
            chunk.clear()
        chunk.extend(prefix)
    if chunk:
        payload = struct.pack("!H", len(chunk)) + chunk + b"\0\0" if withdraw else b"\0\0" + struct.pack("!H", len(attrs)) + attrs + chunk
        yield message(2, payload)


def receive_exact(connection, length):
    parts = bytearray()
    while len(parts) < length:
        part = connection.recv(length - len(parts))
        if not part:
            raise ConnectionError("BIRD closed the local BGP feed")
        parts.extend(part)
    return bytes(parts)


def receive_message(connection):
    header = receive_exact(connection, 19)
    length, kind = struct.unpack("!HB", header[16:])
    if header[:16] != MARKER or not 19 <= length <= 4096:
        raise RuntimeError("Invalid BGP message header")
    payload = receive_exact(connection, length - 19)
    if kind == 3:
        raise RuntimeError(f"BIRD BGP notification: {payload.hex()}")
    return kind, payload


class BGPFeed:
    def __init__(self, asn, host="127.0.0.1", port=1179, source="127.0.0.2", router_id="127.0.0.2"):
        if not ipaddress.ip_address(host).is_loopback or not ipaddress.ip_address(source).is_loopback:
            raise ValueError("The DNS BGP feed must stay on loopback")
        if not 1024 <= port <= 65535 or not 1 <= asn <= 4294967295:
            raise ValueError("Invalid local BGP port or ASN")
        self.asn, self.host, self.port = asn, host, port
        self.source, self.router_id = source, router_id
        self.routes = set()
        self.pending = {}
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.connected = False
        self.sending = False
        self.error = "BGP feed has not connected"
        self.thread = threading.Thread(target=self._run, name="dns-bgp", daemon=True)
        self.thread.start()

    def update(self, added, removed):
        with self.lock:
            for route in removed:
                self.routes.discard(route)
                self.pending[route] = False
            for route in added:
                self.routes.add(route)
                self.pending[route] = True

    def ready(self):
        with self.lock:
            return self.connected and not self.pending and not self.sending

    def _session(self, connection):
        connection.sendall(open_message(self.asn, self.router_id))
        kind, payload = receive_message(connection)
        if kind != 1:
            raise RuntimeError("Expected BIRD OPEN")
        hold = parse_open(payload, self.asn, self.router_id)
        connection.sendall(message(4))
        kind, payload = receive_message(connection)
        if kind != 4 or payload:
            raise RuntimeError("Expected BIRD KEEPALIVE")
        with self.lock:
            snapshot = list(self.routes)
            self.pending.clear()
        for packet in updates(snapshot, self.source):
            connection.sendall(packet)
        connection.sendall(message(2, b"\0\0\0\0"))  # IPv4 End-of-RIB
        self.connected = True
        self.error = ""
        last_receive = last_keepalive = time.monotonic()
        while not self.stop.is_set():
            now = time.monotonic()
            if hold and now - last_receive > hold:
                raise TimeoutError("Local BGP hold timer expired")
            if hold and now - last_keepalive >= hold / 3:
                connection.sendall(message(4))
                last_keepalive = now
            # Coalesce all changes to each prefix before sending a small batch.
            with self.lock:
                batch = list(islice(self.pending.items(), 512))
                self.sending = bool(batch)
                for route, _ in batch:
                    del self.pending[route]
            for state in (True, False):
                for packet in updates((route for route, present in batch if present == state), self.source, withdraw=not state):
                    connection.sendall(packet)
            self.sending = False
            readable, _, _ = select.select([connection], [], [], 0.01)
            if readable:
                kind, payload = receive_message(connection)
                if kind not in (2, 4) or (kind == 4 and payload):
                    raise RuntimeError("Unexpected BIRD message on outbound-only feed")
                last_receive = time.monotonic()

    def _run(self):
        while not self.stop.is_set():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                    connection.settimeout(2)
                    connection.bind((self.source, 0))
                    connection.connect((self.host, self.port))
                    self._session(connection)
            except Exception as exc:
                self.error = str(exc)
                LOG.warning("Local BGP feed disconnected: %s", exc)
            finally:
                self.connected = False
            self.stop.wait(1)

    def close(self):
        self.stop.set()
        self.thread.join(timeout=3)
