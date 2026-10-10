"""SNMP switch plugin (kind "topology"): which device is plugged into which switch port, read from managed switches.

Read-only SNMP v1 / v2c over UDP (standard library only, the protocol is encoded by hand below). Per switch:

    SNMPv2-MIB      sysDescr, sysName                                          what it is
    BRIDGE-MIB      dot1dBaseBridgeAddress, dot1dBasePortIfIndex               its own MAC, bridge port -> interface
    IF-MIB          ifName / ifDescr, ifPhysAddress                            port names and the MACs the switch itself uses
    Q-BRIDGE-MIB    dot1qTpFdbPort (else BRIDGE-MIB dot1dTpFdbPort)            the MAC address table: which MAC was learned on which port
    LLDP-MIB        lldpRemChassisId, lldpRemPortId, lldpRemSysName            what is plugged into each port (other switches in particular)

Netlens turns that into: every polled switch is a node, switches hang below each other following LLDP (from the core switch),
and every MAC found on an ordinary port is a wired client of that switch, with the port name. A MAC that was learned on a
port that leads to another switch (an uplink) is ignored there, so a device is attributed to the switch it is really plugged
into, not to every switch above it.
"""

import ipaddress
import os
import re
import socket
import struct
from collections import Counter, defaultdict

# ----------------------------------------------------------------------------- OIDs
SYS_DESCR = (1, 3, 6, 1, 2, 1, 1, 1, 0)
SYS_NAME = (1, 3, 6, 1, 2, 1, 1, 5, 0)
BRIDGE_ADDRESS = (1, 3, 6, 1, 2, 1, 17, 1, 1, 0)
BASE_PORT_IFINDEX = (1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 2)
IF_NAME = (1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1)
IF_DESCR = (1, 3, 6, 1, 2, 1, 2, 2, 1, 2)
IF_PHYS = (1, 3, 6, 1, 2, 1, 2, 2, 1, 6)
QBRIDGE_FDB_PORT = (1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2)    # .<vlan>.<mac, 6 numbers>
QBRIDGE_FDB_STATUS = (1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 3)
BRIDGE_FDB_PORT = (1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2)           # .<mac, 6 numbers>
BRIDGE_FDB_STATUS = (1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 3)
LLDP = (1, 0, 8802, 1, 1, 2, 1, 4, 1, 1)                       # lldpRemEntry; column .<timeMark>.<localPort>.<index>
LLDP_CHASSIS_SUBTYPE, LLDP_CHASSIS_ID, LLDP_PORT_SUBTYPE, LLDP_PORT_ID, LLDP_SYS_NAME = (LLDP + (c,) for c in (4, 5, 6, 7, 9))
LLDP_LOCAL_PORT = (1, 0, 8802, 1, 1, 2, 1, 3, 7, 1)            # lldpLocPortEntry; columns .2 subtype, .3 id

FDB_LEARNED = 3          # dot1qTpFdbStatus / dot1dTpFdbStatus: learned (self = 4 and mgmt = 5 are the switch's own addresses)
MAX_ROWS = 40000         # a table longer than this is cut off instead of walked forever
SAMPLES = 3


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


# ----------------------------------------------------------------------------- reading one switch
def _mac(raw):
    """"aa:bb:..." for a 6-byte value; all-zero and broadcast addresses are not real ones."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 6 or set(raw) in ({0}, {255}):
        return None
    return ":".join(f"{b:02x}" for b in raw)


def _text(raw, limit=100):
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).decode("utf-8", "replace").replace("\x00", "").strip()[:limit]
    return ""


class Switch:
    """What one switch tells: identity, ports, the MAC address table and its LLDP neighbours."""

    def __init__(self, agent):
        self.agent = agent
        self.host = agent.host
        self.descr = self.name = ""
        self.mac = None
        self.macs = set()
        self.ports = {}            # ifIndex -> name
        self.bridge_port = {}      # bridge port number -> ifIndex
        self.fdb = {}              # mac -> ifIndex (learned addresses only)
        self.neighbours = {}       # ifIndex -> {"mac": chassis MAC or None, "name": system name, "port": remote port}
        self.fdb_source = None
        self.lldp_ok = False

    def read(self):
        got = self.agent.get(SYS_DESCR, SYS_NAME, BRIDGE_ADDRESS)
        self.descr, self.name = _text(got.get(SYS_DESCR), 200), _text(got.get(SYS_NAME), 100)
        self.mac = _mac(got.get(BRIDGE_ADDRESS))
        self.ports = {suffix[0]: _text(value, 60) for suffix, value in self.agent.walk(IF_NAME) if suffix and _text(value, 60)}
        for suffix, value in self.agent.walk(IF_DESCR):
            self.ports.setdefault(suffix[0], _text(value, 60))
        for suffix, value in self.agent.walk(IF_PHYS):
            if _mac(value):
                self.macs.add(_mac(value))
        if self.mac:
            self.macs.add(self.mac)
        self.bridge_port = {suffix[0]: value for suffix, value in self.agent.walk(BASE_PORT_IFINDEX) if suffix and isinstance(value, int)}
        self._read_fdb()
        self._read_lldp()
        return self

    def _if_of(self, bridge_port):
        return self.bridge_port.get(bridge_port, bridge_port)  # without the mapping table the numbers are usually the same

    def _read_fdb(self):
        rows = [((s[-6:], v)) for s, v in self.agent.walk(QBRIDGE_FDB_PORT) if len(s) == 7 and isinstance(v, int)]
        status = {tuple(s[-6:]): v for s, v in self.agent.walk(QBRIDGE_FDB_STATUS) if len(s) == 7}
        self.fdb_source = "Q-BRIDGE-MIB"
        if not rows:
            rows = [(s[-6:], v) for s, v in self.agent.walk(BRIDGE_FDB_PORT) if len(s) == 6 and isinstance(v, int)]
            status = {tuple(s[-6:]): v for s, v in self.agent.walk(BRIDGE_FDB_STATUS) if len(s) == 6}
            self.fdb_source = "BRIDGE-MIB"
        for octets, port in rows:
            mac = _mac(bytes(octets))
            if not mac or port <= 0 or status.get(tuple(octets), FDB_LEARNED) != FDB_LEARNED:
                continue
            self.fdb.setdefault(mac, self._if_of(port))

    def _read_lldp(self):
        chassis = {s[1:]: v for s, v in self.agent.walk(LLDP_CHASSIS_ID) if len(s) >= 3}
        if not chassis:
            return
        self.lldp_ok = True
        subtype = {s[1:]: v for s, v in self.agent.walk(LLDP_CHASSIS_SUBTYPE) if len(s) >= 3}
        remote_port = {s[1:]: _text(v, 60) for s, v in self.agent.walk(LLDP_PORT_ID) if len(s) >= 3}
        names = {s[1:]: _text(v, 60) for s, v in self.agent.walk(LLDP_SYS_NAME) if len(s) >= 3}
        # lldpLocPortId says which interface a local LLDP port number is; fall back to "the same number"
        local = {s[0]: _text(v, 60) for s, v in self.agent.walk(LLDP_LOCAL_PORT + (3,)) if len(s) >= 1}
        by_name = {name: index for index, name in self.ports.items()}
        for key, raw in chassis.items():
            port_number = key[0]
            index = by_name.get(local.get(port_number, ""), port_number)
            mac = _mac(raw) if subtype.get(key) in (4, None) else None
            self.neighbours[index] = {"mac": mac, "name": names.get(key, ""), "port": remote_port.get(key, "")}

    def port_name(self, index):
        return self.ports.get(index) or f"port {index}"


# ----------------------------------------------------------------------------- turning several switches into a topology
def parse_hosts(config):
    """[(switch address, read community)]: the rows of the server list (a row without its own community uses the default one),
    or the list of addresses of an older Netlens."""
    default = str(config.get("community") or "")
    rows = config.get("servers")
    if isinstance(rows, list):
        return [(str(r["host"]).strip(), str(r.get("community") or "") or default) for r in rows if isinstance(r, dict) and str(r.get("host") or "").strip()]
    return [(h, default) for h in re.split(r"[,;\s]+", str(config.get("hosts") or "").strip()) if h]


def read_switches(config):
    hosts = parse_hosts(config)
    if not hosts:
        raise ValueError("enter the address of at least one switch")
    for host, community in hosts:
        if not community:
            raise ValueError(f"{host}: enter the read community (on the switch's line or as the default one)")
    timeout = config.get("timeout") or 3
    switches, problems = [], []
    for host, community in hosts:
        try:
            switches.append(Switch(Agent(host, community, config.get("version") or "2c", timeout)).read())
        except (SnmpError, ValueError) as exc:
            problems.append(f"{host}: {exc}")
    if not switches:
        raise SnmpError("; ".join(problems) or "no switch answered")
    return switches, problems


def to_topology(switches, root_host=None):
    nodes, owner, switch_of = [], {}, {}
    for sw in switches:
        mac = sw.mac or next(iter(sorted(sw.macs)), None)
        if not mac:
            continue
        node = {"mac": mac, "macs": sorted(sw.macs | {mac}), "ip": sw.agent.address[0], "name": sw.name or sw.host, "model": sw.descr[:100] or None, "role": "switch", "parent_mac": None}
        nodes.append(node)
        switch_of[id(node)] = sw
        for m in node["macs"]:
            owner.setdefault(m, node)

    # which switches face each other (LLDP), and which ports are those uplinks / downlinks
    links = defaultdict(set)      # node mac -> {neighbour node mac}
    trunk = defaultdict(set)      # node mac -> {ifIndex that leads to another polled switch}
    for node in nodes:
        sw = switch_of[id(node)]
        for index, neighbour in sw.neighbours.items():
            other = owner.get(neighbour["mac"]) if neighbour["mac"] else None
            if other is not None and other is not node:
                links[node["mac"]].add(other["mac"])
                trunk[node["mac"]].add(index)

    # the tree: from the core switch (configured, else the one with most neighbours), breadth first over the LLDP links
    by_mac = {n["mac"]: n for n in nodes}
    root = None
    if root_host:
        root = next((n for n in nodes if switch_of[id(n)].host == root_host or n["ip"] == root_host), None)
    if root is None and nodes:
        root = max(nodes, key=lambda n: (len(links[n["mac"]]), -nodes.index(n)))
    seen = {root["mac"]} if root else set()
    queue = [root["mac"]] if root else []
    while queue:
        current = queue.pop(0)
        for other in sorted(links[current]):
            if other not in seen:
                seen.add(other)
                by_mac[other]["parent_mac"] = current
                queue.append(other)

    # clients: a MAC on a port that is not an uplink; seen on several switches, the port with the fewest MACs is the real one
    node_macs = set(owner)
    seen_on = defaultdict(list)       # mac -> [(node, ifIndex, MACs on that port)]
    for node in nodes:
        sw = switch_of[id(node)]
        per_port = Counter(index for mac, index in sw.fdb.items() if index not in trunk[node["mac"]])
        for mac, index in sw.fdb.items():
            if index in trunk[node["mac"]] or mac in node_macs or int(mac[:2], 16) & 1:
                continue
            seen_on[mac].append((node, index, per_port[index], sw))
    clients = []
    for mac in sorted(seen_on):
        node, index, _, sw = min(seen_on[mac], key=lambda c: (c[2], nodes.index(c[0])))
        clients.append({"mac": mac, "node_mac": node["mac"], "medium": "wired", "port": sw.port_name(index)})
    return {"nodes": nodes, "clients": clients}


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    switches, problems = read_switches(config)
    macs = sum(len(s.fdb) for s in switches)
    text = f"Connected to {len(switches)} switch(es), {macs} learned MAC address(es)"
    if any(not s.fdb for s in switches):
        text += "; one switch has an empty address table"
    if problems:
        text += ". Not reachable: " + "; ".join(problems)
    return {"message": text}


def fetch(config):
    switches, problems = read_switches(config)
    if problems and len(problems) == len(parse_hosts(config)):
        raise SnmpError("; ".join(problems))
    return to_topology(switches, (config.get("root") or "").strip() or None)


# ----------------------------------------------------------------------------- diagnostic (for the plugin's author)
def _problem(exc):
    return type(exc).__name__ + ": " + re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", "<ip>", str(exc))[:300]


def diagnose(config):
    """What each switch answers, counted and typed; names, MAC addresses and IP addresses are left out."""
    report = {"switches": []}
    hosts = parse_hosts(config)
    report["host_count"] = len(hosts)
    switches = []
    for host, community in hosts:
        entry = {"steps": {}}
        report["switches"].append(entry)
        try:
            agent = Agent(host, community, config.get("version") or "2c", config.get("timeout") or 3)
        except (SnmpError, ValueError) as exc:
            entry["error"] = _problem(exc)
            continue

        def step(name, call):
            try:
                entry["steps"][name] = {"ok": True, "result": call()}
            except Exception as exc:  # noqa: BLE001 - the point is to record what failed
                entry["steps"][name] = {"ok": False, "error": _problem(exc)}

        step("system", lambda: (lambda got: {"sysDescr": SYS_DESCR in got, "sysName": SYS_NAME in got, "bridge_mac": BRIDGE_ADDRESS in got})(agent.get(SYS_DESCR, SYS_NAME, BRIDGE_ADDRESS)))
        step("sysDescr", lambda: re.sub(r"[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}", "<mac>", _text(agent.get(SYS_DESCR).get(SYS_DESCR), 120)))
        for name, base in (("ifName", IF_NAME), ("ifDescr", IF_DESCR), ("ifPhysAddress", IF_PHYS), ("dot1dBasePortIfIndex", BASE_PORT_IFINDEX),
                           ("dot1qTpFdbPort", QBRIDGE_FDB_PORT), ("dot1qTpFdbStatus", QBRIDGE_FDB_STATUS), ("dot1dTpFdbPort", BRIDGE_FDB_PORT),
                           ("lldpRemChassisId", LLDP_CHASSIS_ID), ("lldpRemSysName", LLDP_SYS_NAME), ("lldpLocPortId", LLDP_LOCAL_PORT + (3,))):
            step(name, lambda base=base: {"rows": len(agent.walk(base))})
        try:
            sw = Switch(agent).read()
            switches.append(sw)
            entry["summary"] = {
                "ports": len(sw.ports), "learned_macs": len(sw.fdb), "fdb_source": sw.fdb_source, "own_macs": len(sw.macs),
                "lldp": sw.lldp_ok, "lldp_neighbours": len(sw.neighbours), "macs_per_port_max": max(Counter(sw.fdb.values()).values(), default=0),
            }
        except Exception as exc:  # noqa: BLE001
            entry["error"] = _problem(exc)
    if switches:
        out = to_topology(switches, (config.get("root") or "").strip() or None)
        report["result"] = {
            "nodes": len(out["nodes"]), "nodes_with_parent": sum(1 for n in out["nodes"] if n["parent_mac"]),
            "clients": len(out["clients"]), "ports_named": sum(1 for c in out["clients"] if not c["port"].startswith("port ")),
        }
    return report
