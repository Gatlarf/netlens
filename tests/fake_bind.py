"""A tiny DNS server (TCP only) that behaves like BIND 9.20 for the calls the BIND plugin makes (checked against a real BIND on 2026-10-16):
AXFR and RFC 2136 UPDATE, both TSIG-signed with HMAC-SHA256. It verifies the TSIG of every request itself, with its own few lines."""

import hashlib
import hmac
import ipaddress
import socketserver
import struct
import threading

CLASS_IN, CLASS_NONE, CLASS_ANY = 1, 254, 255
TYPE = {1: "A", 5: "CNAME", 6: "SOA", 12: "PTR", 28: "AAAA", 250: "TSIG", 252: "AXFR", 255: "ANY"}


def name_at(buf, off):
    labels, end, jumped = [], off, False
    while True:
        n = buf[off]
        if n & 0xC0 == 0xC0:
            if not jumped:
                end = off + 2
            off, jumped = ((n & 0x3F) << 8) | buf[off + 1], True
            continue
        off += 1
        if n == 0:
            return ".".join(labels).lower(), (end if jumped else off)
        labels.append(buf[off:off + n].decode())
        off += n


def wire_name(name):
    return b"".join(bytes([len(label)]) + label.encode() for label in name.strip(".").split(".") if label) + b"\0"


def read_rrs(buf, off, count):
    out = []
    for _ in range(count):
        start = off
        name, off = name_at(buf, off)
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
        rdoff = off + 10
        out.append({"name": name, "type": TYPE.get(rtype, rtype), "class": rclass, "ttl": ttl, "rdata": buf[rdoff:rdoff + rdlen], "rdoff": rdoff, "start": start})
        off = rdoff + rdlen
    return out, off


def rdata_text(rec, buf):
    if rec["type"] == "A":
        return ".".join(str(b) for b in rec["rdata"])
    if rec["type"] == "AAAA":
        return str(ipaddress.IPv6Address(rec["rdata"]))
    if rec["type"] in ("CNAME", "PTR"):
        return name_at(buf, rec["rdoff"])[0]
    return rec["rdata"].hex()


def rdata_wire(rtype, value):
    if rtype == "A":
        return bytes(int(x) for x in value.split("."))
    if rtype == "AAAA":
        return ipaddress.IPv6Address(value).packed
    return wire_name(value)


class FakeBind:
    def __init__(self, key_name="netlens-key", secret=b"secret-for-tests-0123456789abcdef", zones=None, deny_update=False):
        self.key_name, self.secret, self.deny_update = key_name, secret, deny_update
        self.zones = zones or {}          # {"home.lan": [(name, type, value, ttl)]}
        self.updates = 0
        outer = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                length = struct.unpack(">H", self.rfile.read(2))[0]
                request = self.rfile.read(length)
                for response in outer.respond(request):
                    self.wfile.write(struct.pack(">H", len(response)) + response)

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self.server = Server(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.address = f"127.0.0.1:{self.port}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    # ------------------------------------------------------------------ protocol
    def verify(self, buf, an_end, ar_count):
        """True when the last additional record is a TSIG signed with our key."""
        records, _ = read_rrs(buf, an_end, ar_count)
        tsig = records[-1]
        if tsig["type"] != "TSIG" or tsig["name"] != self.key_name:
            return False
        alg, off = name_at(buf, tsig["rdoff"])
        signed_hi, signed_lo, fudge, mac_len = struct.unpack(">HIHH", buf[off:off + 10])
        mac = buf[off + 10:off + 10 + mac_len]
        stripped = bytearray(buf[:tsig["start"]])
        stripped[10:12] = struct.pack(">H", ar_count - 1)
        variables = wire_name(self.key_name) + struct.pack(">HI", CLASS_ANY, 0) + wire_name(alg) + struct.pack(">HIH", signed_hi, signed_lo, fudge) + struct.pack(">HH", 0, 0)
        return hmac.compare_digest(mac, hmac.new(self.secret, bytes(stripped) + variables, hashlib.sha256).digest())

    def header(self, request, rcode, an=0, qd=0, opcode=0):
        mid = request[:2]
        return mid + struct.pack(">HHHHHH", 0x8000 | (opcode << 11) | rcode, qd, an, 0, 0, 0)

    def respond(self, request):
        _, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", request[:12])
        opcode = (flags >> 11) & 0xF
        zone_name, off = name_at(request, 12)
        qtype, qclass = struct.unpack(">HH", request[off:off + 4])
        off += 4
        if opcode == 5:
            pre, off = read_rrs(request, off, an)
            upd, off = read_rrs(request, off, ns)
            if not self.verify(request, off, ar):
                return [self.header(request, 9, opcode=5)]
            if self.deny_update:
                return [self.header(request, 5, opcode=5)]
            if zone_name not in self.zones:
                return [self.header(request, 10, opcode=5)]
            return [self.header(request, self.do_update(zone_name, request, pre, upd), opcode=5)]
        if qtype == 252:
            if not self.verify(request, off, ar):
                return [self.header(request, 9)]
            if zone_name not in self.zones:
                return [self.header(request, 9)]
            soa = wire_name(zone_name) + struct.pack(">HHIH", 6, 1, 3600, 0)
            body = soa + b"".join(self.rr_wire(zone_name, r) for r in self.zones[zone_name]) + soa
            count = 2 + len(self.zones[zone_name])
            return [self.header(request, 0, an=count, qd=1)[:12] + wire_name(zone_name) + struct.pack(">HH", 252, 1) + body]
        return [self.header(request, 4)]

    @staticmethod
    def rr_wire(zone, rec):
        name, rtype, value, ttl = rec
        code = {v: k for k, v in TYPE.items()}[rtype]
        rdata = rdata_wire(rtype, value)
        return wire_name(name) + struct.pack(">HHIH", code, 1, ttl, len(rdata)) + rdata

    def do_update(self, zone, request, pre, upd):
        records = self.zones[zone]
        for p in pre:
            value = rdata_text(p, request) if p["class"] == CLASS_IN and p["rdata"] else None
            here = [r for r in records if r[0] == p["name"]]
            if p["class"] == CLASS_NONE and p["type"] == "ANY" and here:
                return 6                                                      # YXDOMAIN: the name is in use
            if p["class"] == CLASS_ANY and p["type"] == "SOA":
                continue
            if p["class"] == CLASS_IN and p["rdata"] and not any(r[1] == p["type"] and r[2] == value for r in here):
                return 8                                                      # NXRRSET: this record does not exist
        for u in upd:
            if u["class"] == CLASS_NONE:
                value = rdata_text(u, request)
                records[:] = [r for r in records if not (r[0] == u["name"] and r[1] == u["type"] and r[2] == value)]
            elif u["class"] == CLASS_IN:
                records.append((u["name"], u["type"], rdata_text(u, request), u["ttl"]))
        self.updates += 1
        return 0
