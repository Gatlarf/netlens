"""BIND 9 plugin (kind "dns"): register devices through RFC 2136 dynamic updates, read zones by AXFR, both signed with TSIG (RFC 8945).

DNS has no API, so this file speaks the DNS wire format itself (standard library only):

    AXFR  (TCP)   the whole zone: A, AAAA, CNAME, PTR records (needs `allow-transfer { key <name>; }`)
    UPDATE (TCP)  zone section + prerequisites + update section + TSIG (needs `allow-update { key <name>; }`)

Every write carries a prerequisite, so the server itself decides atomically whether it is still safe:
    add     prerequisite "name is not in use"                           (YXDOMAIN: someone was faster)
    update  prerequisite "this exact record exists", then delete it and add the new one   (NXRRSET: it changed meanwhile)
    delete  prerequisite "this exact record exists", then delete it                       (NXRRSET: already gone, which is success)
DNS records have no comment field, so nothing is `managed` on the server: Netlens relies on the list of records it remembers writing, and never
changes or removes any other record. Reverse zones cannot be listed, so they come from the setting `reverse_zones`. The server's answers are
checked for the response code only (their TSIG signature is not verified); the request signature is what protects the server.
"""

import base64
import hashlib
import hmac
import ipaddress
import random
import re
import socket
import struct
import time

TYPES = {"A": 1, "CNAME": 5, "SOA": 6, "PTR": 12, "AAAA": 28, "TSIG": 250, "AXFR": 252, "ANY": 255}
TYPE_NAMES = {v: k for k, v in TYPES.items()}
CLASS_IN, CLASS_NONE, CLASS_ANY = 1, 254, 255
OPCODE_UPDATE = 5
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE"}
ALGORITHMS = {"hmac-sha256": ("hmac-sha256.", hashlib.sha256), "hmac-sha384": ("hmac-sha384.", hashlib.sha384), "hmac-sha512": ("hmac-sha512.", hashlib.sha512),
              "hmac-sha1": ("hmac-sha1.", hashlib.sha1)}
REVERSE_SUFFIXES = (".in-addr.arpa", ".ip6.arpa")
MAX_RECORDS = 20000


class BindError(Exception):
    pass


class AuthRefused(BindError):
    auth_failed = True


class Rcode(BindError):
    def __init__(self, code, message=None):
        super().__init__(message or RCODES.get(code, str(code)))
        self.code = code


def _name(value):
    return str(value or "").strip().rstrip(".").lower()


# ----------------------------------------------------------------------------- DNS wire format
def encode_name(name):
    out = b""
    for label in _name(name).split(".") if _name(name) else []:
        raw = label.encode("idna") if not label.isascii() else label.encode()
        if not raw or len(raw) > 63:
            raise BindError(f"{name!r} is not a valid DNS name")
        out += bytes([len(raw)]) + raw
    return out + b"\0"


def read_name(buf, offset):
    labels, jumped, end, hops = [], False, offset, 0
    while True:
        if offset >= len(buf):
            raise BindError("a DNS answer ended in the middle of a name")
        length = buf[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(buf):
                raise BindError("a DNS answer ended in the middle of a name")
            pointer = ((length & 0x3F) << 8) | buf[offset + 1]
            if not jumped:
                end = offset + 2
            offset, jumped, hops = pointer, True, hops + 1
            if hops > 50:
                raise BindError("a DNS answer has a name that points to itself")
            continue
        offset += 1
        if length == 0:
            return ".".join(labels).lower(), (end if jumped else offset)
        labels.append(buf[offset:offset + length].decode("ascii", "replace"))
        offset += length


def rr(name, rtype, rclass, ttl, rdata=b""):
    return encode_name(name) + struct.pack(">HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def rdata_for(rtype, value):
    if rtype == "A":
        return ipaddress.IPv4Address(value).packed
    if rtype == "AAAA":
        return ipaddress.IPv6Address(value).packed
    if rtype in ("CNAME", "PTR"):
        return encode_name(value)
    raise BindError(f"{rtype} records are not handled by this plugin")


def value_of(rtype, rdata, buf, offset):
    if rtype == "A" and len(rdata) == 4:
        return str(ipaddress.IPv4Address(rdata))
    if rtype == "AAAA" and len(rdata) == 16:
        return str(ipaddress.IPv6Address(rdata))
    if rtype in ("CNAME", "PTR"):
        return read_name(buf, offset)[0]
    return None


class Key:
    def __init__(self, name, secret, algorithm="hmac-sha256"):
        algorithm = (algorithm or "hmac-sha256").strip().lower().rstrip(".")
        if algorithm not in ALGORITHMS:
            raise BindError(f"the algorithm must be one of {', '.join(ALGORITHMS)}")
        try:
            self.secret = base64.b64decode(str(secret).strip(), validate=True)
        except ValueError:
            raise BindError("the TSIG secret is not base64 text (copy it from the key file)")
        self.name = _name(name)
        self.algorithm_name, self.digest = ALGORITHMS[algorithm]

    def sign(self, message, message_id):
        """The message with a TSIG record added at the end (arcount + 1)."""
        signed_at = int(time.time())
        fudge = 300
        time_fudge = struct.pack(">HIH", signed_at >> 32, signed_at & 0xFFFFFFFF, fudge)
        variables = encode_name(self.name) + struct.pack(">HI", CLASS_ANY, 0) + encode_name(self.algorithm_name) + time_fudge + struct.pack(">HH", 0, 0)
        mac = hmac.new(self.secret, message + variables, self.digest).digest()
        rdata = encode_name(self.algorithm_name) + time_fudge + struct.pack(">H", len(mac)) + mac + struct.pack(">HHH", message_id, 0, 0)
        record = rr(self.name, TYPES["TSIG"], CLASS_ANY, 0, rdata)
        header = bytearray(message[:12])
        arcount = struct.unpack(">H", header[10:12])[0] + 1
        header[10:12] = struct.pack(">H", arcount)
        return bytes(header) + message[12:] + record


def build_query(zone, key):
    message_id = random.randint(1, 65535)
    message = struct.pack(">HHHHHH", message_id, 0, 1, 0, 0, 0) + encode_name(zone) + struct.pack(">HH", TYPES["AXFR"], CLASS_IN)
    return key.sign(message, message_id) if key else message


def build_update(zone, prerequisites, updates, key):
    message_id = random.randint(1, 65535)
    message = struct.pack(">HHHHHH", message_id, OPCODE_UPDATE << 11, 1, len(prerequisites), len(updates), 0)
    message += encode_name(zone) + struct.pack(">HH", TYPES["SOA"], CLASS_IN) + b"".join(prerequisites) + b"".join(updates)
    return key.sign(message, message_id), message_id


def parse_records(buf, offset, count):
    records = []
    for _ in range(count):
        name, offset = read_name(buf, offset)
        if offset + 10 > len(buf):
            raise BindError("a DNS answer was cut off")
        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", buf[offset:offset + 10])
        offset += 10
        rdata = buf[offset:offset + rdlength]
        records.append((name, TYPE_NAMES.get(rtype, rtype), rclass, ttl, rdata, offset))
        offset += rdlength
    return records, offset


# ----------------------------------------------------------------------------- connection
class Server:
    def __init__(self, host, key, timeout=10):
        host = str(host).strip()
        port = 53
        m = re.fullmatch(r"\[?([^\]\s]+?)\]?(?::(\d{1,5}))?", host)
        if not m or not m.group(1):
            raise BindError(f"{host!r} is not an address like 192.168.0.2 or 192.168.0.2:5353")
        self.host, self.port = m.group(1), int(m.group(2) or 53)
        if ":" in self.host and not m.group(2):
            self.host = host.strip("[]")
        self.key, self.timeout, self.id = key, float(timeout), f"{self.host}:{self.port}"

    def _exchange(self, request, messages):
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                sock.sendall(struct.pack(">H", len(request)) + request)
                out = []
                for _ in range(messages):
                    head = self._read(sock, 2)
                    out.append(self._read(sock, struct.unpack(">H", head)[0]))
                    if messages > 1 and self._last_message(out[-1]):
                        break
                return out
        except socket.timeout:
            raise BindError(f"{self.id} did not answer in time")
        except OSError as exc:
            raise BindError(f"cannot reach {self.id}: {exc}")

    @staticmethod
    def _read(sock, n):
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise BindError("the server closed the connection too early")
            data += chunk
        return data

    @staticmethod
    def _last_message(buf):
        return False

    def _check(self, rcode, what, zone):
        if rcode == 0:
            return
        if rcode in (5, 9):
            raise AuthRefused(f"{self.id} refused {what} for {zone} ({RCODES[rcode]}): check the key name and secret, allow-transfer / allow-update and that the zone exists")
        if rcode == 10:
            raise BindError(f"{self.id} is not authoritative for {zone} (NOTZONE)")
        raise Rcode(rcode, f"{self.id} answered {RCODES.get(rcode, rcode)} for {what} of {zone}")

    def axfr(self, zone):
        """[(name, type, value, ttl)] of the A, AAAA, CNAME and PTR records of a zone."""
        request = build_query(zone, self.key)
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                sock.sendall(struct.pack(">H", len(request)) + request)
                records, soa_seen = [], 0
                while soa_seen < 2:
                    length = struct.unpack(">H", self._read(sock, 2))[0]
                    buf = self._read(sock, length)
                    if len(buf) < 12:
                        raise BindError("a DNS answer was too short")
                    _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", buf[:12])
                    self._check(flags & 0xF, "the zone transfer", zone)
                    offset = 12
                    for _ in range(qd):
                        _, offset = read_name(buf, offset)
                        offset += 4
                    found, _ = parse_records(buf, offset, an)
                    for name, rtype, rclass, ttl, rdata, rdoff in found:
                        if rtype == "SOA":
                            soa_seen += 1
                        elif rtype in ("A", "AAAA", "CNAME", "PTR") and rclass == CLASS_IN:
                            value = value_of(rtype, rdata, buf, rdoff)
                            if value is not None:
                                records.append((name, rtype, value, ttl))
                    if len(records) > MAX_RECORDS:
                        raise BindError(f"{zone} has more than {MAX_RECORDS} records")
                return records
        except socket.timeout:
            raise BindError(f"{self.id} did not answer in time")
        except OSError as exc:
            raise BindError(f"cannot reach {self.id}: {exc}")

    def update(self, zone, prerequisites, updates):
        """Send a dynamic update; returns the response code."""
        request, _ = build_update(zone, prerequisites, updates, self.key)
        (buf,) = self._exchange(request, 1)
        if len(buf) < 12:
            raise BindError("a DNS answer was too short")
        return struct.unpack(">H", buf[2:4])[0] & 0xF

    def writable(self, zone):
        """A no-op update (only the prerequisite 'the zone has an SOA'): NOERROR means the key may update it, REFUSED that it may not."""
        prerequisite = rr(zone, TYPES["SOA"], CLASS_ANY, 0)
        code = self.update(zone, [prerequisite], [])
        if code == 0:
            return True
        if code in (5, 9):
            return False
        raise BindError(f"{self.id} answered {RCODES.get(code, code)} to a test update of {zone}")


def parse_servers(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "key_name", "key_secret"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one BIND server")
    out = []
    for i, r in enumerate(items, 1):
        host = str(r.get("host") or "").strip()
        if not host:
            raise ValueError(f"server {i}: enter its address")
        if not str(r.get("key_name") or "").strip() or not str(r.get("key_secret") or "").strip():
            raise ValueError(f"{host}: enter the TSIG key name and secret")
        out.append(Server(host, Key(r["key_name"], r["key_secret"], r.get("algorithm")), config.get("timeout") or 10))
    return out


def _zones(config):
    forward = [_name(z) for z in config.get("zones", [])]
    reverse = [_name(z) for z in re.split(r"[,;\s]+", str(config.get("reverse_zones") or "")) if z]
    return list(dict.fromkeys(forward + reverse))


def _is_reverse(zone):
    return zone.endswith(REVERSE_SUFFIXES)


def _gather(config):
    """{zone: (server, writable, records)} using the first server that answers for each zone."""
    servers, found, problems = parse_servers(config), {}, []
    for zone in _zones(config):
        last = None
        for server in servers:
            try:
                records = server.axfr(zone)
                found[zone] = (server, server.writable(zone), records)
                break
            except AuthRefused:
                raise
            except BindError as exc:
                last = str(exc)
        else:
            problems.append(f"{zone}: {last}")
    return servers, found, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    servers, found, problems = _gather(config)
    parts = [f"{len(servers)} server(s) configured"]
    for zone, (server, writable, records) in found.items():
        parts.append(f"zone {zone}: {len(records)} record(s), " + ("writable" if writable else "read-only for this key"))
    if not _zones(config):
        parts.append("no zone to check yet: enter the zones on the DNS registration page and the reverse zones here")
    if problems:
        parts.append("problems: " + "; ".join(problems))
        if not found:
            raise BindError("; ".join(problems))
    return {"message": ", ".join(parts)}


def fetch(config):
    servers, found, problems = _gather(config)
    if _zones(config) and not found:
        raise BindError("; ".join(problems))
    zones, records = [], []
    for zone, (server, writable, rows) in found.items():
        zones.append({"name": zone, "kind": "reverse" if _is_reverse(zone) else "forward", "writable": writable})
        for name, rtype, value, ttl in rows:
            records.append({"zone": zone, "name": name, "type": rtype, "value": value, "ttl": ttl, "managed": False, "comment": ""})
    return {"zones": zones, "records": records, "server": ", ".join(sorted({s.id for s, _, _ in found.values()}))[:100] or None}


def _apply_one(server, change, ttl):
    action, rtype, name, zone = change["action"], change["type"], change["name"], change["zone"]
    if rtype not in ("A", "AAAA", "CNAME", "PTR"):
        raise BindError(f"{rtype} records are not handled by this plugin")
    new = rr(name, TYPES[rtype], CLASS_IN, ttl, rdata_for(rtype, change["value"])) if action != "delete" else None
    if action == "add":
        code = server.update(zone, [rr(name, TYPES["ANY"], CLASS_NONE, 0)], [new])                      # prerequisite: the name is not in use
        if code == 6:
            raise BindError(f"{name} got a record in the meantime; nothing was written")
    elif action in ("update", "delete"):
        old_value = change["old_value"] if action == "update" else change["value"]
        exists = rr(name, TYPES[rtype], CLASS_IN, 0, rdata_for(rtype, old_value))                      # prerequisite: exactly this record exists
        gone = rr(name, TYPES[rtype], CLASS_NONE, 0, rdata_for(rtype, old_value))                      # delete exactly this record
        code = server.update(zone, [exists], [gone] + ([new] if action == "update" else []))
        if code == 8:
            if action == "delete":
                return                                                                                  # already gone
            raise BindError(f"{name} no longer points to {old_value}; nothing was changed")
    else:
        raise BindError(f"unknown action {action!r}")
    server._check(code, "the update", zone)
    if code != 0:
        raise BindError(f"{server.id} answered {RCODES.get(code, code)}")


def apply(config, changes):
    servers = parse_servers(config)
    ttl = int(config.get("ttl") or 3600)
    results, holders = [], {}
    for change in changes:
        zone = change["zone"]
        if zone not in holders:
            holders[zone] = None
            for server in servers:
                try:
                    if server.writable(zone):
                        holders[zone] = server
                        break
                except AuthRefused:
                    raise
                except BindError:
                    continue
        server = holders[zone]
        if server is None:
            results.append({"id": change["id"], "ok": False, "error": f"no server accepts updates for {zone} with this key"})
            continue
        try:
            _apply_one(server, change, ttl)
            results.append({"id": change["id"], "ok": True, "error": None})
        except AuthRefused:
            raise
        except BindError as exc:
            results.append({"id": change["id"], "ok": False, "error": str(exc)[:300]})
        except ValueError as exc:
            results.append({"id": change["id"], "ok": False, "error": f"not a valid value: {exc}"[:300]})
    return results


# ----------------------------------------------------------------------------- diagnostic (for the plugin's author)
def _problem(exc):
    return type(exc).__name__ + ": " + re.sub(r"\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b", "<server>", str(exc))[:300]


def diagnose(config):
    """What the servers answer, as counts and response codes (no names, addresses or keys)."""
    try:
        servers = parse_servers(config)
    except (ValueError, BindError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for server in servers:
        entry = {"zones": {}}
        report["servers"].append(entry)
        for index, zone in enumerate(_zones(config), 1):
            item = {"reverse": _is_reverse(zone)}
            entry["zones"][f"zone{index}"] = item
            try:
                rows = server.axfr(zone)
                item["transfer"] = {"ok": True, "records": len(rows), "types": {t: sum(1 for r in rows if r[1] == t) for t in sorted({r[1] for r in rows})}}
            except AuthRefused as exc:
                item["transfer"] = {"ok": False, "error": "refused (check the key and allow-transfer)"}
            except BindError as exc:
                item["transfer"] = {"ok": False, "error": _problem(exc)}
            try:
                item["update_allowed"] = server.writable(zone)
            except BindError as exc:
                item["update_allowed"] = {"error": _problem(exc)}
    return report
