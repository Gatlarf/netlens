"""Listen to what devices broadcast on their own: DHCP requests, mDNS announcements and SSDP notifications.

A device that asks for an address tells its name, its DHCP vendor class and the order of the options it wants;
that fingerprints the operating system even when the device uses a private (randomised) MAC address and has no
open ports. Nothing is sent: it only reads broadcasts that reach this machine (so only its own network segment).

The parsers are pure functions on bytes; `Listener` owns the raw socket (needs CAP_NET_RAW, like nmap) and
`apply()` writes what was learned to the database.
"""

from __future__ import annotations

import asyncio
import ctypes
import logging
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any

from app.scanner import fingerprint, names

log = logging.getLogger(__name__)

PORTS = (67, 68, 1900, 5353)
MAX_PENDING = 2000          # observations kept in memory for devices that are not in the database (yet)
PENDING_TTL = 3600          # seconds
FLUSH_EVERY = 10            # seconds between database writes


@dataclass
class Observation:
    mac: str
    ip: str | None = None
    names: dict[str, str] = field(default_factory=dict)       # name -> source ("dhcp", "mdns")
    hints: list[str] = field(default_factory=list)
    vendor_class: str | None = None
    seen: float = field(default_factory=time.time)

    def merge(self, other: "Observation") -> None:
        self.ip = other.ip or self.ip
        self.names.update(other.names)
        for hint in other.hints:
            if hint not in self.hints:
                self.hints.append(hint)
        self.vendor_class = other.vendor_class or self.vendor_class
        self.seen = other.seen


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def udp_payload(frame: bytes) -> tuple[bytes, str, str, int, int] | None:
    """(payload, source MAC, source IP, source port, destination port) of an Ethernet/IPv4/UDP frame, else None."""
    if len(frame) < 42 or frame[12:14] != b"\x08\x00":
        return None
    ihl = (frame[14] & 0x0F) * 4
    if frame[14] >> 4 != 4 or ihl < 20 or frame[23] != 17 or struct.unpack("!H", frame[20:22])[0] & 0x1FFF:
        return None  # not IPv4 UDP, or a fragment
    udp = 14 + ihl
    if len(frame) < udp + 8:
        return None
    sport, dport, length = struct.unpack("!HHH", frame[udp:udp + 6])
    payload = frame[udp + 8: udp + max(8, length)]
    return payload, _mac(frame[6:12]), socket.inet_ntoa(frame[26:30]), sport, dport


def parse_dhcp(payload: bytes) -> Observation | None:
    """A DHCP request from a client (DISCOVER / REQUEST / INFORM): its MAC, name, vendor class and OS fingerprint."""
    if len(payload) < 241 or payload[0] != 1 or payload[236:240] != b"\x63\x82\x53\x63":
        return None
    hlen = payload[2]
    if payload[1] != 1 or hlen != 6:
        return None
    mac = _mac(payload[28:34])
    options: dict[int, bytes] = {}
    i = 240
    while i < len(payload):
        code = payload[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(payload):
            break
        length = payload[i + 1]
        options[code] = payload[i + 2: i + 2 + length]
        i += 2 + length
    if options.get(53, b"\x00")[:1] not in (b"\x01", b"\x03", b"\x08"):  # discover, request, inform
        return None
    obs = Observation(mac=mac)
    ciaddr = socket.inet_ntoa(payload[12:16])
    wanted = options.get(50)
    ip = socket.inet_ntoa(wanted) if wanted and len(wanted) == 4 else ciaddr
    obs.ip = ip if ip != "0.0.0.0" else None
    hostname = options.get(12, b"").decode("utf-8", "replace").strip().strip("\x00")
    if hostname:
        obs.names[hostname[:80]] = "dhcp"
    vendor_class = options.get(60, b"").decode("utf-8", "replace").strip().strip("\x00")
    if vendor_class:
        obs.vendor_class = vendor_class[:100]
    os_name = fingerprint.os_from_dhcp_class(vendor_class) or fingerprint.os_from_dhcp_params(list(options.get(55, b"")))
    if os_name:
        obs.hints.append(f"os:{os_name}")
    return obs


def _dns_name(data: bytes, pos: int) -> tuple[str, int]:
    labels, end, jumps = [], None, 0
    while pos < len(data) and jumps < 20:
        n = data[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                break
            if end is None:
                end = pos + 2
            pos = ((n & 0x3F) << 8) | data[pos + 1]
            jumps += 1
            continue
        labels.append(data[pos + 1: pos + 1 + n].decode("utf-8", "replace"))
        pos += 1 + n
    return ".".join(labels), (end if end is not None else pos)


def parse_mdns(payload: bytes, mac: str, ip: str) -> Observation | None:
    """Names, service types and model strings from an mDNS response (a device announcing itself)."""
    if len(payload) < 12 or not payload[2] & 0x80:  # not a response
        return None
    qd, an, ns, ar = struct.unpack("!HHHH", payload[4:12])
    pos = 12
    try:
        for _ in range(qd):
            _, pos = _dns_name(payload, pos)
            pos += 4
        services: list[str] = []
        props: dict[str, str] = {}
        host_names: list[str] = []
        for _ in range(min(an + ns + ar, 60)):
            name, pos = _dns_name(payload, pos)
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", payload[pos:pos + 10])
            pos += 10
            rdata = payload[pos:pos + rdlen]
            if rtype == 1 and name.endswith(".local") and len(rdata) == 4 and socket.inet_ntoa(rdata) == ip:
                host_names.append(name[:-6])
            elif rtype == 12 and name.startswith("_"):
                services.append(name)
            elif rtype == 16:
                i = 0
                while i < len(rdata):
                    n = rdata[i]
                    item = rdata[i + 1: i + 1 + n].decode("utf-8", "replace")
                    if "=" in item:
                        k, v = item.split("=", 1)
                        props.setdefault(k.lower(), v)
                    i += 1 + n
            pos += rdlen
    except (struct.error, IndexError):
        pass
    obs = Observation(mac=mac, ip=ip)
    for service in services:
        hints, friendly = names.hints_from_mdns(service, props)
        obs.hints += [h for h in hints if h not in obs.hints]
        for friendly_name in friendly:
            obs.names[friendly_name] = "mdns"
    if not services and props:
        hints, friendly = names.hints_from_mdns("", props)
        obs.hints += hints
    for host in host_names:
        obs.names[host[:80]] = "mdns"
    return obs if (obs.names or obs.hints) else None


def parse_ssdp(payload: bytes, mac: str, ip: str) -> Observation | None:
    """A UPnP device announcing itself (NOTIFY ssdp:alive): the kind of device it is."""
    text = payload.decode("utf-8", "replace")
    if not text.startswith("NOTIFY"):
        return None
    headers = names.parse_ssdp_response(text)
    nt = headers.get("nt", "")
    if ":device:" not in nt:
        return None
    return Observation(mac=mac, ip=ip, hints=names.hints_from_upnp({"device_type": nt}))


def parse_frame(frame: bytes) -> Observation | None:
    parts = udp_payload(frame)
    if parts is None:
        return None
    payload, mac, ip, sport, dport = parts
    if dport == 67:
        return parse_dhcp(payload)
    if dport == 5353:
        return parse_mdns(payload, mac, ip)
    if dport == 1900:
        return parse_ssdp(payload, mac, ip)
    return None


def apply(conn: Any, obs: Observation, now: str | None = None) -> bool:
    """Write one observation to the device with that MAC (or, for mDNS / SSDP, that IP). False when no device matches yet."""
    from app.db import utcnow
    from app.plugins.enrich import device_lookup, refresh_hostname
    from app.scanner import store

    now = now or utcnow()
    by_mac, by_ip = device_lookup(conn)
    device_id = by_mac.get(obs.mac) or (by_ip.get(obs.ip) if obs.ip else None)
    if device_id is None:
        return False
    changed = store.add_hints(conn, device_id, obs.hints)
    for name, source in obs.names.items():
        conn.execute(
            """
            INSERT INTO device_names (device_id, name, source, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(device_id, name, source) DO UPDATE SET last_seen = excluded.last_seen
            """,
            (device_id, name, source, now, now),
        )
    if obs.names:
        refresh_hostname(conn, device_id)
    if obs.vendor_class and not fingerprint.os_from_dhcp_class(obs.vendor_class):
        # not an OS: some devices put their make in it ("Samsung Electronics"); only useful when we know nothing else
        row = conn.execute("SELECT vendor FROM devices WHERE id = ?", (device_id,)).fetchone()
        if row and not row["vendor"] and len(obs.vendor_class) > 3:
            conn.execute("UPDATE devices SET vendor = ? WHERE id = ?", (obs.vendor_class, device_id))
            changed = True
    store.reclassify_device(conn, device_id)
    conn.commit()
    return changed or bool(obs.names)


# ---- the raw socket -------------------------------------------------------------------------------

def _bpf_program() -> bytes:
    """Classic BPF: accept IPv4 UDP (not fragments) to ports 67, 68, 1900 or 5353; the kernel drops everything else."""
    ins = [
        (0x28, 0, 0, 12),                      # ldh [12]        ethertype
        (0x15, 0, 11, 0x0800),                 # jeq IPv4, else drop
        (0x30, 0, 0, 23),                      # ldb [23]        protocol
        (0x15, 0, 9, 17),                      # jeq UDP, else drop
        (0x28, 0, 0, 20),                      # ldh [20]        flags + fragment offset
        (0x45, 7, 0, 0x1FFF),                  # jset: fragment -> drop
        (0xB1, 0, 0, 14),                      # ldxb 4*([14]&0xf)  IP header length
        (0x48, 0, 0, 16),                      # ldh [x+16]      UDP destination port
        (0x15, 3, 0, 67),                      # jeq 67 -> accept
        (0x15, 2, 0, 68),
        (0x15, 1, 0, 1900),
        (0x15, 0, 1, 5353),                    # jeq 5353 -> accept, else drop
        (0x06, 0, 0, 0x00040000),              # ret accept
        (0x06, 0, 0, 0),                       # ret drop
    ]
    return b"".join(struct.pack("HBBI", *i) for i in ins)


def open_socket() -> socket.socket:
    """A raw packet socket that only receives DHCP / mDNS / SSDP datagrams. Raises PermissionError / OSError without NET_RAW."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    try:
        program = _bpf_program()
        buf = ctypes.create_string_buffer(program, len(program))
        fprog = struct.pack("HL", len(program) // 8, ctypes.addressof(buf))
        sock.setsockopt(socket.SOL_SOCKET, 26, fprog)   # SO_ATTACH_FILTER
        sock.setblocking(False)
        return sock
    except Exception:
        sock.close()
        raise


def join_multicast() -> list[socket.socket]:
    """Join the mDNS and SSDP groups so the network card passes those frames on (and IGMP snooping switches forward them)."""
    joined = []
    for group, port in (("224.0.0.251", 5353), ("239.255.255.250", 1900)):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("", port))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(group) + socket.inet_aton("0.0.0.0"))
            s.setblocking(False)
            joined.append(s)
        except OSError:
            continue
    return joined


class Listener:
    """Reads frames, remembers what each device announced, and writes it to the database every few seconds."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.pending: dict[str, Observation] = {}
        self.stats = {"running": False, "frames": 0, "applied": 0, "error": None}

    def feed(self, frame: bytes) -> None:
        obs = parse_frame(frame)
        if obs is None:
            return
        self.stats["frames"] += 1
        known = self.pending.get(obs.mac)
        if known is None:
            if len(self.pending) >= MAX_PENDING:
                oldest = min(self.pending, key=lambda m: self.pending[m].seen)
                del self.pending[oldest]
            self.pending[obs.mac] = obs
        else:
            known.merge(obs)

    def flush(self) -> int:
        """Write pending observations; keep those whose device is not known yet for a while."""
        from app.db import connect

        if not self.pending:
            return 0
        conn = connect(self.db_path)
        done = 0
        try:
            now = time.time()
            for mac, obs in list(self.pending.items()):
                try:
                    applied = apply(conn, obs)
                except Exception:
                    log.exception("could not store a passive observation")
                    applied = True
                if applied or now - obs.seen > PENDING_TTL:
                    del self.pending[mac]
                    done += 1 if applied else 0
        finally:
            conn.close()
        self.stats["applied"] += done
        return done

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            sock = open_socket()
        except (PermissionError, OSError) as exc:
            self.stats["error"] = "needs the NET_RAW capability" if isinstance(exc, PermissionError) else str(exc)
            log.info("passive listening is off: %s", self.stats["error"])
            return
        groups = join_multicast()

        def on_readable() -> None:
            for _ in range(200):
                try:
                    self.feed(sock.recv(2048))
                except BlockingIOError:
                    break
                except OSError:
                    break

        loop.add_reader(sock.fileno(), on_readable)
        self.stats["running"] = True
        try:
            while True:
                await asyncio.sleep(FLUSH_EVERY)
                await asyncio.to_thread(self.flush)
        finally:
            self.stats["running"] = False
            loop.remove_reader(sock.fileno())
            sock.close()
            for g in groups:
                g.close()


SETTING = "passive.enabled"


class Control:
    """Starts and stops the listener (the Settings page has a switch) and reports what it has seen."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.listener = Listener(db_path)
        self.task: asyncio.Task | None = None

    def enabled(self) -> bool:
        from app.db import connect, get_setting

        conn = connect(self.db_path)
        try:
            return get_setting(conn, SETTING) != "0"
        finally:
            conn.close()

    def set_enabled(self, value: bool) -> None:
        from app.db import connect, set_setting

        conn = connect(self.db_path)
        try:
            set_setting(conn, SETTING, "1" if value else "0")
            conn.commit()
        finally:
            conn.close()
        if value:
            self.start()
        else:
            self.stop()

    def start(self) -> None:
        if self.task is None or self.task.done():
            self.listener = Listener(self.db_path)
            self.task = asyncio.get_running_loop().create_task(self.listener.run())

    def stop(self) -> None:
        if self.task is not None:
            self.task.cancel()
            self.task = None
        self.listener.stats["running"] = False

    def status(self) -> dict:
        return {"enabled": self.enabled(), **self.listener.stats, "pending": len(self.listener.pending)}
