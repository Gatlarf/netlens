"""A small SNMP v1 / v2c client (standard library only; the protocol is encoded by hand) and the health readings built on it.

Netlens asks a device for what it is willing to tell about itself: processor load, memory, disks, network traffic,
temperatures, UPS battery and printer supplies. Only read requests are sent.
"""

from __future__ import annotations

import ipaddress
import os
import socket

MAX_ROWS = 20000          # a table longer than this is cut off instead of walked forever


class SnmpError(Exception):
    pass


class Timeout(SnmpError):
    pass


class NoSuch:
    """noSuchObject / noSuchInstance / endOfMibView in an answer."""

    def __init__(self, kind):
        self.kind = kind

    def __repr__(self):
        return f"<{self.kind}>"


# ----------------------------------------------------------------------------- BER encoding (just what SNMP needs)
def _length(n):
    if n < 128:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag, content):
    return bytes([tag]) + _length(len(content)) + content


def _int(value):
    size = max(1, (value.bit_length() + 8) // 8) if value >= 0 else max(1, ((-value - 1).bit_length() + 8) // 8)
    return _tlv(0x02, value.to_bytes(size, "big", signed=True))


def _oid(oid):
    first = 40 * oid[0] + oid[1]
    out = bytearray()
    for number in (first,) + tuple(oid[2:]):
        chunk = [number & 0x7F]
        number >>= 7
        while number:
            chunk.append(0x80 | (number & 0x7F))
            number >>= 7
        out += bytes(reversed(chunk))
    return _tlv(0x06, bytes(out))


GET, GETNEXT, RESPONSE, GETBULK = 0xA0, 0xA1, 0xA2, 0xA5


def build_request(pdu_type, version, community, request_id, oids, max_repetitions=20):
    """version 0 = SNMPv1, 1 = SNMPv2c. GETBULK (v2c only) asks for `max_repetitions` rows after each OID."""
    binds = b"".join(_tlv(0x30, _oid(oid) + _tlv(0x05, b"")) for oid in oids)
    if pdu_type == GETBULK:
        head = _int(request_id) + _int(0) + _int(max_repetitions)
    else:
        head = _int(request_id) + _int(0) + _int(0)
    pdu = _tlv(pdu_type, head + _tlv(0x30, binds))
    return _tlv(0x30, _int(version) + _tlv(0x04, community.encode("utf-8")) + pdu)


def _read(data, pos):
    """(tag, content start, content end) of the element at `pos`."""
    if pos + 2 > len(data):
        raise SnmpError("the answer is cut off")
    tag, first = data[pos], data[pos + 1]
    pos += 2
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            raise SnmpError("the answer has a bad length")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    else:
        length = first
    if pos + length > len(data):
        raise SnmpError("the answer is cut off")
    return tag, pos, pos + length


def _decode_int(raw, signed=True):
    return int.from_bytes(raw, "big", signed=signed) if raw else 0


def _decode_oid(raw):
    if not raw:
        raise SnmpError("empty object identifier")
    numbers, value = [], 0
    for byte in raw:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            numbers.append(value)
            value = 0
    first = numbers[0]
    head = (first // 40, first % 40) if first < 80 else (2, first - 80)
    return head + tuple(numbers[1:])


def _decode_value(tag, raw):
    if tag == 0x02:
        return _decode_int(raw)
    if tag == 0x04:
        return bytes(raw)
    if tag == 0x05:
        return None
    if tag == 0x06:
        return _decode_oid(raw)
    if tag == 0x40:
        return ".".join(str(b) for b in raw)
    if tag in (0x41, 0x42, 0x43, 0x46):
        return _decode_int(raw, signed=False)
    if tag == 0x80:
        return NoSuch("noSuchObject")
    if tag == 0x81:
        return NoSuch("noSuchInstance")
    if tag == 0x82:
        return NoSuch("endOfMibView")
    return bytes(raw)


def parse_response(data):
    """(request id, error status, [(oid, value), ...]) of an SNMP answer."""
    tag, start, end = _read(data, 0)
    if tag != 0x30:
        raise SnmpError("this is not an SNMP answer")
    pos = start
    tag, s, e = _read(data, pos)                  # version
    pos = e
    tag, s, e = _read(data, pos)                  # community
    pos = e
    tag, s, e = _read(data, pos)                  # PDU
    if tag != RESPONSE:
        raise SnmpError(f"unexpected SNMP message type 0x{tag:02x}")
    pos = s
    ids = []
    for _ in range(3):                            # request id, error status, error index
        tag, a, b = _read(data, pos)
        ids.append(_decode_int(data[a:b]))
        pos = b
    tag, a, b = _read(data, pos)                  # variable bindings
    binds, pos = [], a
    while pos < b:
        tag, vs, ve = _read(data, pos)
        inner = vs
        otag, os_, oe = _read(data, inner)
        vtag, vs2, ve2 = _read(data, oe)
        binds.append((_decode_oid(data[os_:oe]), _decode_value(vtag, data[vs2:ve2])))
        pos = ve
    return ids[0], ids[1], binds


# ----------------------------------------------------------------------------- UDP
def udp_send(address, payload, timeout):
    """Send one datagram and return the next datagram that comes back (tests replace this function)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(payload, address)
        while True:
            try:
                data, source = sock.recvfrom(65535)
            except socket.timeout:
                raise Timeout(f"no answer from {address[0]} within {timeout:g} s (check the address, the community string and that SNMP is switched on)")
            except OSError as exc:
                raise SnmpError(f"cannot reach {address[0]}: {exc}")
            if source[0] == address[0]:
                return data


SEND = udp_send


class Agent:
    """One switch: GET, GETNEXT / GETBULK and table walks."""

    def __init__(self, host, community, version="2c", timeout=3.0, retries=2):
        host = host.strip()
        port = 161
        if ":" in host:
            host, _, text = host.rpartition(":")
            port = int(text)
        self.host = host
        self.address = (_resolve(host), port)
        self.community = community
        self.v1 = str(version) == "1"
        self.timeout = float(timeout)
        self.retries = int(retries)
        self._next_id = int.from_bytes(os.urandom(3), "big")

    def _ask(self, pdu_type, oids, max_repetitions=20):
        last = None
        for _ in range(self.retries + 1):
            self._next_id = (self._next_id + 1) % 0x7FFFFFFF
            payload = build_request(pdu_type, 0 if self.v1 else 1, self.community, self._next_id, oids, max_repetitions)
            try:
                raw = SEND(self.address, payload, self.timeout)
                request_id, status, binds = parse_response(raw)
            except Timeout as exc:
                last = exc
                continue
            if request_id != self._next_id:
                continue  # an answer to an earlier, repeated request
            if status == 2 and self.v1:
                return []  # v1: noSuchName means "no next object", the end of the table
            if status:
                raise SnmpError(f"{self.host} answered with SNMP error {status}")
            return binds
        raise last or Timeout(f"no answer from {self.host}")

    def get(self, *oids):
        """{oid: value} for the OIDs that exist (a missing one is left out)."""
        if self.v1:  # v1 refuses the whole request when one OID is missing: ask one by one
            out = {}
            for oid in oids:
                for found, value in self._ask(GET, [oid]):
                    if not isinstance(value, NoSuch):
                        out[found] = value
            return out
        return {oid: value for oid, value in self._ask(GET, oids) if not isinstance(value, NoSuch)}

    def walk(self, base):
        """[(oid suffix after `base`, value)] for the whole subtree below `base`."""
        rows, cursor = [], base
        while len(rows) < MAX_ROWS:
            binds = self._ask(GETNEXT if self.v1 else GETBULK, [cursor])
            if not binds:
                break
            progressed = False
            for oid, value in binds:
                if isinstance(value, NoSuch) or oid[:len(base)] != base:
                    return rows
                if oid <= cursor:
                    return rows  # an agent that goes backwards would loop us forever
                rows.append((oid[len(base):], value))
                cursor, progressed = oid, True
            if not progressed:
                break
        return rows


def _resolve(host):
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        try:
            return socket.gethostbyname(host)
        except OSError as exc:
            raise SnmpError(f"cannot resolve {host}: {exc}")




# ----------------------------------------------------------------------------- health readings
SYS_DESCR = (1, 3, 6, 1, 2, 1, 1, 1, 0)
SYS_UPTIME = (1, 3, 6, 1, 2, 1, 1, 3, 0)                 # TimeTicks (1/100 s)
HR_UPTIME = (1, 3, 6, 1, 2, 1, 25, 1, 1, 0)
HR_PROC_LOAD = (1, 3, 6, 1, 2, 1, 25, 3, 3, 1, 2)         # one row per processor core, percent
UCD_CPU_IDLE = (1, 3, 6, 1, 4, 1, 2021, 11, 11, 0)
UCD_LOAD_INT = (1, 3, 6, 1, 4, 1, 2021, 10, 1, 5)         # .1 .2 .3: load average * 100
HR_STORAGE_TYPE = (1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 2)
HR_STORAGE_DESCR = (1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 3)
HR_STORAGE_UNITS = (1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 4)
HR_STORAGE_SIZE = (1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 5)
HR_STORAGE_USED = (1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 6)
ST_OTHER, ST_VIRTUAL, ST_FIXED, ST_RAM = ((1, 3, 6, 1, 2, 1, 25, 2, 1, n) for n in (1, 3, 4, 2))
IF_NAME = (1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1)
IF_DESCR = (1, 3, 6, 1, 2, 1, 2, 2, 1, 2)
IF_OPER = (1, 3, 6, 1, 2, 1, 2, 2, 1, 8)
IF_HC_IN, IF_HC_OUT = (1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6), (1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 10)
IF_IN, IF_OUT = (1, 3, 6, 1, 2, 1, 2, 2, 1, 10), (1, 3, 6, 1, 2, 1, 2, 2, 1, 16)
LM_TEMP_DESCR = (1, 3, 6, 1, 4, 1, 2021, 13, 16, 2, 1, 2)
LM_TEMP_VALUE = (1, 3, 6, 1, 4, 1, 2021, 13, 16, 2, 1, 3)  # milli degrees Celsius
PRT_SUPPLY_DESCR = (1, 3, 6, 1, 2, 1, 43, 11, 1, 1, 6)
PRT_SUPPLY_MAX = (1, 3, 6, 1, 2, 1, 43, 11, 1, 1, 8)
PRT_SUPPLY_LEVEL = (1, 3, 6, 1, 2, 1, 43, 11, 1, 1, 9)
UPS_OUTPUT_SOURCE = (1, 3, 6, 1, 2, 1, 33, 1, 4, 1, 0)    # 3 normal, 5 on battery
UPS_MINUTES = (1, 3, 6, 1, 2, 1, 33, 1, 2, 3, 0)
UPS_CHARGE = (1, 3, 6, 1, 2, 1, 33, 1, 2, 4, 0)

HR_SW_RUN_NAME = (1, 3, 6, 1, 2, 1, 25, 4, 2, 1, 2)       # the programs that run, one row each
GROUPS = ("uptime", "cpu", "memory", "disk", "network", "temperature", "supplies", "ups")
GROUP_TITLES = {"uptime": "Time since start", "cpu": "Processor", "memory": "Memory", "disk": "Disks", "network": "Network traffic",
                "temperature": "Temperatures", "supplies": "Printer supplies", "ups": "UPS battery"}
SKIP_MOUNTS = ("/dev", "/sys", "/proc", "/run", "/snap", "/var/lib/docker", "/var/lib/containers", "/boot/efi", "/var/lib/kubelet")
MAX_INTERFACES = 24


def _text(raw, limit=60):
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).decode("utf-8", "replace").replace("\x00", "").strip()[:limit]
    return "" if raw is None else str(raw)[:limit]


def _num(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _table(agent, base):
    """{row index (the OID tail) -> value}"""
    return {tuple(suffix): value for suffix, value in agent.walk(base)}


def _mount_label(descr):
    text = _text(descr, 120)
    if " Label:" in text:                                  # Windows: "C:\ Label:System  Serial Number 1234"
        text = text.split(" Label:")[0].strip()
    return text[:40] or "disk"


def _safe(agent, fn, *args):
    try:
        return fn(*args)
    except Timeout:
        raise
    except SnmpError:
        return None


def read_uptime(agent):
    got = agent.get(HR_UPTIME, SYS_UPTIME)
    ticks = _num(got.get(HR_UPTIME)) or _num(got.get(SYS_UPTIME))
    return [("uptime_s", "", ticks / 100.0, "s")] if ticks else []


def read_cpu(agent):
    rows = [v for v in _table(agent, HR_PROC_LOAD).values() if _num(v) is not None and 0 <= v <= 100]
    out = []
    if rows:
        out.append(("cpu_pct", "", sum(rows) / len(rows), "%"))
    else:
        idle = _num(agent.get(UCD_CPU_IDLE).get(UCD_CPU_IDLE))
        if idle is not None and 0 <= idle <= 100:
            out.append(("cpu_pct", "", 100.0 - idle, "%"))
    load = _num(agent.get(UCD_LOAD_INT + (1,)).get(UCD_LOAD_INT + (1,)))
    if load is not None:
        out.append(("load1", "", load / 100.0, ""))
    return out


def _storage(agent):
    types, descr, units = _table(agent, HR_STORAGE_TYPE), _table(agent, HR_STORAGE_DESCR), _table(agent, HR_STORAGE_UNITS)
    size, used = _table(agent, HR_STORAGE_SIZE), _table(agent, HR_STORAGE_USED)
    rows = []
    for key, kind in types.items():
        u, s, d = _num(units.get(key)), _num(size.get(key)), _num(used.get(key))
        if u is None or s is None or d is None or s <= 0:
            continue
        rows.append({"type": tuple(kind) if isinstance(kind, tuple) else None, "descr": _text(descr.get(key), 120), "total": s * u, "used": d * u})
    return rows


def read_memory(agent, rows=None):
    rows = rows if rows is not None else _storage(agent)
    out = []
    ram = next((r for r in rows if r["type"] == ST_RAM), None)
    if ram:
        used = ram["used"]
        for r in rows:       # net-snmp counts cached memory and buffers as used; what a program could still get is what matters
            if r["type"] == ST_OTHER and r["descr"].lower() in ("cached memory", "memory buffers"):
                used -= r["used"]
        out.append(("mem_pct", "", max(0.0, min(100.0, used / ram["total"] * 100)), "%"))
    swap = next((r for r in rows if "swap" in r["descr"].lower() and r["type"] in (ST_VIRTUAL, ST_OTHER)), None)
    if swap:
        out.append(("swap_pct", "", swap["used"] / swap["total"] * 100, "%"))
    return out


def read_disk(agent, rows=None):
    rows = rows if rows is not None else _storage(agent)
    out, seen = [], set()
    for r in rows:
        if r["type"] != ST_FIXED:
            continue
        label = _mount_label(r["descr"])
        if label.startswith(SKIP_MOUNTS) or label in seen or r["total"] < 64 * 1024 * 1024:
            continue
        seen.add(label)
        out.append(("disk_pct", label, min(100.0, r["used"] / r["total"] * 100), "%"))
        out.append(("disk_free_b", label, max(0.0, r["total"] - r["used"]), "B"))
    return out[:40]


def _delta(now_value, before, bits):
    """Bytes counted since the last round; None when the counter was reset (a restart) instead of wrapping."""
    if now_value >= before:
        return now_value - before
    wrap = 1 << bits
    return now_value + wrap - before if before > wrap * 0.75 else None


def read_network(agent, state, now):
    """(points, seen): traffic per interface that is up, in bits per second since the previous round. The first round only
    learns the counters, so it has no points but `seen` says the interfaces are there."""
    names = _table(agent, IF_NAME) or _table(agent, IF_DESCR)
    oper = _table(agent, IF_OPER)
    rx, tx, bits = _table(agent, IF_HC_IN), _table(agent, IF_HC_OUT), 64
    if not rx:
        rx, tx, bits = _table(agent, IF_IN), _table(agent, IF_OUT), 32
    out, seen = [], False
    for key, name in names.items():
        label = _text(name, 40)
        low = label.lower()
        if not label or low == "lo" or low.startswith(("loopback", "software loopback")) or _num(oper.get(key)) != 1:
            continue
        a, b = _num(rx.get(key)), _num(tx.get(key))
        if a is None or b is None:
            continue
        seen = True
        mark = state.get(("if", key))
        state[("if", key)] = (now, a, b)
        if mark is None or now - mark[0] <= 0:
            continue
        da, db = _delta(a, mark[1], bits), _delta(b, mark[2], bits)
        if da is None or db is None:
            continue
        dt = now - mark[0]
        out.append(("net_rx_bps", label, da * 8 / dt, "bps"))
        out.append(("net_tx_bps", label, db * 8 / dt, "bps"))
        if len(out) >= MAX_INTERFACES * 2:
            break
    return out, seen


def read_temperature(agent):
    names, values = _table(agent, LM_TEMP_DESCR), _table(agent, LM_TEMP_VALUE)
    out = []
    for key, value in values.items():
        v = _num(value)
        if v is None:
            continue
        out.append(("temp_c", _text(names.get(key), 40) or f"sensor {key[-1]}", v / 1000.0, "\u00b0C"))
    return out[:12]


def read_supplies(agent):
    names, levels, maxes = _table(agent, PRT_SUPPLY_DESCR), _table(agent, PRT_SUPPLY_LEVEL), _table(agent, PRT_SUPPLY_MAX)
    out = []
    for key, level in levels.items():
        lv, mx = _num(level), _num(maxes.get(key))
        if lv is None or mx is None or mx <= 0 or lv < 0:       # -1 other, -2 unknown, -3 some remaining
            continue
        out.append(("supply_pct", _text(names.get(key), 40) or f"supply {key[-1]}", max(0.0, min(100.0, lv / mx * 100)), "%"))
    return out[:12]


def read_ups(agent):
    got = agent.get(UPS_OUTPUT_SOURCE, UPS_MINUTES, UPS_CHARGE)
    out = []
    charge, minutes, source = _num(got.get(UPS_CHARGE)), _num(got.get(UPS_MINUTES)), _num(got.get(UPS_OUTPUT_SOURCE))
    if charge is not None:
        out.append(("battery_pct", "", float(charge), "%"))
    if minutes is not None:
        out.append(("battery_minutes", "", float(minutes), "min"))
    if source is not None:
        out.append(("on_battery", "", 1.0 if source == 5 else 0.0, "state"))
    return out


def collect(agent, groups=None, state=None, now=None):
    """Read the requested groups (all by default). Returns (points, found) where points are (metric, label, value, unit)
    and found lists the groups that answered. `state` keeps the traffic counters between rounds."""
    import time

    state = state if state is not None else {}
    now = now if now is not None else time.time()
    wanted = [g for g in GROUPS if groups is None or g in groups]
    points, found = [], []
    storage = None
    for group in wanted:
        if group in ("memory", "disk") and storage is None:
            storage = _safe(agent, _storage, agent) or []
        if group == "uptime":
            got = _safe(agent, read_uptime, agent)
        elif group == "cpu":
            got = _safe(agent, read_cpu, agent)
        elif group == "memory":
            got = read_memory(agent, storage)
        elif group == "disk":
            got = read_disk(agent, storage)
        elif group == "network":
            result = _safe(agent, read_network, agent, state, now)
            got, seen = result if result else ([], False)
            if seen and not got:
                found.append(group)       # the first round only learns the counters; the group is there
                continue
        elif group == "temperature":
            got = _safe(agent, read_temperature, agent)
        elif group == "supplies":
            got = _safe(agent, read_supplies, agent)
        elif group == "ups":
            got = _safe(agent, read_ups, agent)
        else:
            got = []
        if got:
            found.append(group)
            points.extend(got)
    return points, found
