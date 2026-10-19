"""Messages that devices send on their own: SNMP traps and syslog.

A switch that loses a link, a UPS that goes on battery or a router that logs an error does not wait to be asked. Netlens can listen for those messages (UDP)
and turn them into events on the device they came from, so they show up on the device page, in the alert channels and in the log forwarding.

    SNMP traps   v1 and v2c (v2c informs are acknowledged); the community must be one of the listed ones. SNMPv3 traps are not supported.
    syslog       RFC 3164 and RFC 5424 over UDP; only messages at or above the chosen severity become events.

Both are off until switched on in Settings, and listen on high ports (1162 and 1514) because the standard ones (162 and 514) need extra privileges; point the
devices at those ports. The sender is matched to a device by its IP address. A sender is limited to 60 events a minute so a noisy or spoofed source cannot flood the log.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

from app.db import add_event, connect, get_setting, set_setting
from app.hostmetrics import snmp

log = logging.getLogger(__name__)
KEY = "inbound.policy"
RATE_PER_MINUTE = 60
MAX_DETAIL = 400

SEVERITIES = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"]
DEFAULTS = {
    "traps": {"enabled": False, "port": 1162, "communities": ["public"]},
    "syslog": {"enabled": False, "port": 1514, "min_severity": "warning"},
}

TRAP_V1, TRAP_V2, INFORM = 0xA4, 0xA7, 0xA6
SNMP_TRAP_OID = (1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0)
STD = "1.3.6.1.6.3.1.1.5."
KNOWN_TRAPS = {
    STD + "1": ("device_restarted", "restarted (cold start)"),
    STD + "2": ("device_restarted", "restarted (warm start)"),
    STD + "3": ("link_down", "link down"),
    STD + "4": ("link_up", "link up"),
    STD + "5": ("snmp_trap", "SNMP authentication failure (a wrong community was used)"),
    "1.3.6.1.2.1.17.0.1": ("snmp_trap", "spanning tree: new root bridge"),
    "1.3.6.1.2.1.17.0.2": ("snmp_trap", "spanning tree: topology changed"),
    "1.3.6.1.2.1.33.2.1": ("snmp_trap", "UPS is running on battery"),
    "1.3.6.1.2.1.33.2.2": ("snmp_trap", "UPS test completed"),
    "1.3.6.1.2.1.33.2.3": ("snmp_trap", "UPS alarm raised"),
    "1.3.6.1.2.1.33.2.4": ("snmp_trap", "UPS alarm cleared"),
}
V1_GENERIC = {0: STD + "1", 1: STD + "2", 2: STD + "3", 3: STD + "4", 4: STD + "5"}
IF_INDEX, IF_DESCR, IF_NAME = "1.3.6.1.2.1.2.2.1.1.", "1.3.6.1.2.1.2.2.1.2.", "1.3.6.1.2.1.31.1.1.1.1."


class InboundError(ValueError):
    pass


# ----------------------------------------------------------------------------------------------- policy
def _port(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise InboundError(f"{what}: the port must be a number from 1 to 65535")
    return value


def clean_policy(data: dict) -> dict:
    traps, syslog = data.get("traps") or {}, data.get("syslog") or {}
    communities = [str(c).strip() for c in (traps.get("communities") or DEFAULTS["traps"]["communities"]) if str(c).strip()]
    if not communities or len(communities) > 10 or any(len(c) > 64 for c in communities):
        raise InboundError("SNMP traps: give one to ten community names of at most 64 characters")
    severity = str(syslog.get("min_severity") or DEFAULTS["syslog"]["min_severity"]).lower()
    if severity not in SEVERITIES:
        raise InboundError("syslog: the lowest severity must be one of " + ", ".join(SEVERITIES))
    out = {
        "traps": {"enabled": bool(traps.get("enabled")), "port": _port(traps.get("port", 1162), "SNMP traps"), "communities": communities},
        "syslog": {"enabled": bool(syslog.get("enabled")), "port": _port(syslog.get("port", 1514), "syslog"), "min_severity": severity},
    }
    if out["traps"]["enabled"] and out["syslog"]["enabled"] and out["traps"]["port"] == out["syslog"]["port"]:
        raise InboundError("traps and syslog need different ports")
    return out


def get_policy(conn) -> dict:
    try:
        return clean_policy(json.loads(get_setting(conn, KEY) or "{}"))
    except (ValueError, InboundError):
        return clean_policy({})


def save_policy(conn, data: dict) -> dict:
    policy = clean_policy(data)
    set_setting(conn, KEY, json.dumps(policy))
    conn.commit()
    return policy


# ----------------------------------------------------------------------------------------------- SNMP traps
def _text(value: Any) -> str:
    if isinstance(value, bytes):
        try:
            text = value.decode("utf-8")
            if text.isprintable():
                return text
        except UnicodeDecodeError:
            pass
        return value.hex()
    if isinstance(value, tuple):
        return ".".join(str(n) for n in value)
    if value is None or isinstance(value, snmp.NoSuch):
        return ""
    return str(value)


def _dotted(oid: tuple) -> str:
    return ".".join(str(n) for n in oid)


def parse_trap(data: bytes) -> dict:
    """The parts of a v1 trap, v2c trap or v2c inform that Netlens uses. Raises SnmpError for anything else."""
    tag, start, end = snmp._read(data, 0)
    if tag != 0x30:
        raise snmp.SnmpError("this is not an SNMP message")
    pos = start
    _, a, b = snmp._read(data, pos)
    version = snmp._decode_int(data[a:b])
    pos = b
    _, a, b = snmp._read(data, pos)
    community = bytes(data[a:b]).decode("latin-1")
    pos = b
    pdu, ps, pe = snmp._read(data, pos)
    if version not in (0, 1) or pdu not in (TRAP_V1, TRAP_V2, INFORM):
        raise snmp.SnmpError("not a v1 or v2c trap")
    out: dict[str, Any] = {"version": version, "community": community, "pdu": pdu, "request_id": 0, "agent": None, "generic": None, "specific": None, "enterprise": ""}
    pos = ps
    if pdu == TRAP_V1:
        t, a, b = snmp._read(data, pos)
        out["enterprise"] = _dotted(snmp._decode_oid(data[a:b]))
        pos = b
        t, a, b = snmp._read(data, pos)
        out["agent"] = ".".join(str(x) for x in data[a:b]) if b - a == 4 else None
        pos = b
        for key in ("generic", "specific"):
            t, a, b = snmp._read(data, pos)
            out[key] = snmp._decode_int(data[a:b])
            pos = b
        t, a, b = snmp._read(data, pos)                      # time stamp
        pos = b
    else:
        for i in range(3):                                   # request id, error status, error index
            t, a, b = snmp._read(data, pos)
            if i == 0:
                out["request_id"] = snmp._decode_int(data[a:b])
            pos = b
    t, a, b = snmp._read(data, pos)
    out["raw_binds"] = bytes(data[a:b])
    binds, pos = [], a
    while pos < b and len(binds) < 64:
        _, vs, ve = snmp._read(data, pos)
        _, os_, oe = snmp._read(data, vs)
        vtag, vs2, ve2 = snmp._read(data, oe)
        binds.append((snmp._decode_oid(data[os_:oe]), snmp._decode_value(vtag, data[vs2:ve2])))
        pos = ve
    out["binds"] = binds
    return out


def ack_inform(trap: dict) -> bytes:
    """The response a v2c inform wants, so the sender stops repeating it."""
    pdu = snmp._tlv(snmp.RESPONSE, snmp._int(trap["request_id"]) + snmp._int(0) + snmp._int(0) + snmp._tlv(0x30, trap["raw_binds"]))
    return snmp._tlv(0x30, snmp._int(trap["version"]) + snmp._tlv(0x04, trap["community"].encode("latin-1")) + pdu)


def classify_trap(trap: dict) -> tuple[str, str]:
    """(event kind, readable text) of a parsed trap."""
    if trap["pdu"] == TRAP_V1:
        generic = trap["generic"]
        trap_oid = V1_GENERIC.get(generic) or f"{trap['enterprise']}.0.{trap['specific']}"
    else:
        trap_oid = ""
        for oid, value in trap["binds"]:
            if oid == SNMP_TRAP_OID:
                trap_oid = _text(value)
                break
    kind, text = KNOWN_TRAPS.get(trap_oid, ("snmp_trap", f"trap {trap_oid or 'without an identifier'}"))
    interface = ""
    for oid, value in trap["binds"]:
        name = _dotted(oid)
        if name.startswith(IF_NAME) or name.startswith(IF_DESCR):
            interface = _text(value)
            break
        if name.startswith(IF_INDEX) and not interface:
            interface = f"interface {_text(value)}"
    if kind in ("link_down", "link_up") and interface:
        text = f"{text}: {interface}"
    if kind == "snmp_trap" and trap_oid not in KNOWN_TRAPS:
        extra = "; ".join(f"{_dotted(o)} = {_text(v)}" for o, v in trap["binds"] if o != SNMP_TRAP_OID and _dotted(o) != "1.3.6.1.2.1.1.3.0" and _text(v))
        text = f"{text}" + (f" ({extra})" if extra else "")
    return kind, text[:MAX_DETAIL]


# ----------------------------------------------------------------------------------------------- syslog
_PRI = re.compile(r"^<(\d{1,3})>")
_RFC5424 = re.compile(r"^(\d) (\S+) (\S+) (\S+) (\S+) (\S+) (?:-|(?:\[.*?\])+) ?(.*)$", re.S)
_RFC3164 = re.compile(r"^(?:[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+) (\S+) (?:([^\s:\[]+)(?:\[\d+\])?: ?)?(.*)$", re.S)


def parse_syslog(raw: bytes) -> dict | None:
    text = raw.decode("utf-8", "replace").strip("\x00\r\n ")
    m = _PRI.match(text)
    if not m or int(m.group(1)) > 191:
        return None
    pri = int(m.group(1))
    rest = text[m.end():]
    host = app = ""
    body = rest
    m5 = _RFC5424.match(rest)
    if m5:
        host, app, body = m5.group(3), m5.group(4), m5.group(7)
    else:
        m3 = _RFC3164.match(rest)
        if m3:
            host, app, body = m3.group(1), m3.group(2) or "", m3.group(3)
    clean = lambda s: "" if s in ("-", "") else s  # noqa: E731
    return {"facility": pri >> 3, "severity": pri & 7, "host": clean(host), "app": clean(app), "message": " ".join(body.split())[:MAX_DETAIL]}


# ----------------------------------------------------------------------------------------------- events
def device_for(conn, ip: str, host: str = "") -> int | None:
    row = conn.execute("SELECT id FROM devices WHERE primary_ip = ? ORDER BY online DESC LIMIT 1", (ip,)).fetchone()
    if row is None:
        row = conn.execute("SELECT device_id AS id FROM device_ips WHERE ip = ? ORDER BY last_seen DESC LIMIT 1", (ip,)).fetchone()
    if row is None and host:
        row = conn.execute("SELECT id FROM devices WHERE lower(hostname) = lower(?) OR lower(custom_name) = lower(?) LIMIT 1", (host, host)).fetchone()
    return row["id"] if row else None


class Limiter:
    """At most RATE_PER_MINUTE events per sender and minute."""

    def __init__(self, clock=time.monotonic) -> None:
        self.clock, self.windows = clock, {}

    def allow(self, sender: str) -> bool:
        now = self.clock()
        start, count = self.windows.get(sender, (now, 0))
        if now - start >= 60:
            start, count = now, 0
        self.windows[sender] = (start, count + 1)
        if len(self.windows) > 2000:
            self.windows = {k: v for k, v in self.windows.items() if now - v[0] < 60}
        return count < RATE_PER_MINUTE


def record_trap(conn, trap: dict, sender: str, now: str | None = None) -> int:
    kind, text = classify_trap(trap)
    device = device_for(conn, trap["agent"] or sender) if trap["pdu"] == TRAP_V1 and trap["agent"] and trap["agent"] != "0.0.0.0" else device_for(conn, sender)
    detail = text if device is not None else f"{sender}: {text}"
    return add_event(conn, kind, detail, device, now)


def record_syslog(conn, message: dict, sender: str, min_severity: str, now: str | None = None) -> int | None:
    if message["severity"] > SEVERITIES.index(min_severity):
        return None
    device = device_for(conn, sender, message["host"])
    if device is None:
        return None                                       # an unknown sender: syslog is too chatty to keep what we cannot place
    label = SEVERITIES[message["severity"]]
    source = f"{message['app']}: " if message["app"] else ""
    return add_event(conn, "device_log", f"[{label}] {source}{message['message']}"[:MAX_DETAIL], device, now)


# ----------------------------------------------------------------------------------------------- the listeners
class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, receiver: "Receiver", which: str) -> None:
        self.receiver, self.which, self.transport = receiver, which, None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            self.receiver.handle(self.which, data, addr[0], self.transport, addr)
        except Exception:  # noqa: BLE001 - a bad datagram must never stop the listener
            log.exception("could not handle a %s message from %s", self.which, addr[0])


class Receiver:
    """Owns the two UDP listeners; `apply()` makes them match the saved policy."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.limiter = Limiter()
        self.transports: dict[str, Any] = {}
        self.ports: dict[str, int] = {}
        self.errors: dict[str, str] = {}
        self.stats = {"traps": {"received": 0, "last": None}, "syslog": {"received": 0, "kept": 0, "last": None}, "dropped": 0, "ignored": 0}

    def handle(self, which: str, data: bytes, sender: str, transport, addr) -> None:
        conn = connect(self.db_path)
        try:
            policy = get_policy(conn)
            if which == "traps":
                try:
                    trap = parse_trap(data)
                except snmp.SnmpError:
                    self.stats["ignored"] += 1
                    return
                if trap["community"] not in policy["traps"]["communities"]:
                    self.stats["ignored"] += 1
                    return
                if trap["pdu"] == INFORM and transport is not None:
                    transport.sendto(ack_inform(trap), addr)
                if not self.limiter.allow(sender):
                    self.stats["dropped"] += 1
                    return
                record_trap(conn, trap, sender)
                self.stats["traps"]["received"] += 1
                self.stats["traps"]["last"] = _now()
            else:
                message = parse_syslog(data)
                if message is None:
                    self.stats["ignored"] += 1
                    return
                self.stats["syslog"]["received"] += 1
                self.stats["syslog"]["last"] = _now()
                if message["severity"] > SEVERITIES.index(policy["syslog"]["min_severity"]):
                    return
                if not self.limiter.allow(sender):
                    self.stats["dropped"] += 1
                    return
                if record_syslog(conn, message, sender, policy["syslog"]["min_severity"]) is not None:
                    self.stats["syslog"]["kept"] += 1
        finally:
            conn.close()

    async def apply(self) -> None:
        conn = connect(self.db_path)
        try:
            policy = get_policy(conn)
        finally:
            conn.close()
        loop = asyncio.get_running_loop()
        for which in ("traps", "syslog"):
            wanted = policy[which]["port"] if policy[which]["enabled"] else None
            if which in self.transports and self.ports.get(which) != wanted:
                self.transports.pop(which).close()
                self.ports.pop(which, None)
            if wanted is None:
                self.errors.pop(which, None)
                continue
            if which in self.transports:
                continue
            try:
                transport, _ = await loop.create_datagram_endpoint(lambda w=which: _Protocol(self, w), local_addr=("0.0.0.0", wanted))
            except OSError as exc:
                self.errors[which] = f"cannot listen on UDP port {wanted}: {exc.strerror or exc}"
                log.warning("inbound %s: %s", which, self.errors[which])
                continue
            self.transports[which], self.ports[which] = transport, wanted
            self.errors.pop(which, None)

    def stop(self) -> None:
        for transport in self.transports.values():
            transport.close()
        self.transports.clear()
        self.ports.clear()

    def status(self, conn) -> dict:
        policy = get_policy(conn)
        return {
            "policy": policy,
            "severities": SEVERITIES,
            "traps": {**self.stats["traps"], "listening": "traps" in self.transports, "error": self.errors.get("traps")},
            "syslog": {**self.stats["syslog"], "listening": "syslog" in self.transports, "error": self.errors.get("syslog")},
            "dropped": self.stats["dropped"],
            "ignored": self.stats["ignored"],
        }


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
