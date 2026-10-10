"""The SNMP plugin against simulated switches: the BER codec (checked against a real SNMPv1 packet), table walks with
GETBULK / GETNEXT, the MAC address tables, LLDP, and the topology built from them."""

import importlib.util
import json
import re
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from app.plugins.matching import topology_links

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "snmp"
spec = importlib.util.spec_from_file_location("snmp_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)


def mac_bytes(text):
    return bytes(int(x, 16) for x in text.split(":"))


def octets(text):
    return tuple(int(x, 16) for x in text.split(":"))


# ---------------------------------------------------------------- a simulated agent
def encode_value(value):
    if value is None:
        return bytes([0x05, 0])
    if isinstance(value, int):
        return plugin._int(value)
    if isinstance(value, bytes):
        return plugin._tlv(0x04, value)
    if isinstance(value, plugin.NoSuch):
        return bytes([0x82, 0])
    raise TypeError(value)


def encode_response(version, community, request_id, status, binds):
    body = b"".join(plugin._tlv(0x30, plugin._oid(oid) + encode_value(value)) for oid, value in binds)
    pdu = plugin._tlv(plugin.RESPONSE, plugin._int(request_id) + plugin._int(status) + plugin._int(0) + plugin._tlv(0x30, body))
    return plugin._tlv(0x30, plugin._int(version) + plugin._tlv(0x04, community.encode()) + pdu)


def decode_request(data):
    _, start, _ = plugin._read(data, 0)
    pos = start
    out = []
    for _ in range(2):  # version, community
        _, a, b = plugin._read(data, pos)
        out.append(data[a:b])
        pos = b
    version, community = plugin._decode_int(out[0]), out[1].decode()
    tag, a, b = plugin._read(data, pos)
    pos = a
    numbers = []
    for _ in range(3):
        _, x, y = plugin._read(data, pos)
        numbers.append(plugin._decode_int(data[x:y]))
        pos = y
    _, x, y = plugin._read(data, pos)
    oids, pos = [], x
    while pos < y:
        _, vs, ve = plugin._read(data, pos)
        _, os_, oe = plugin._read(data, vs)
        oids.append(plugin._decode_oid(data[os_:oe]))
        pos = ve
    return tag, version, community, numbers, oids


class Mib:
    """One switch: the OIDs it knows, answering GET, GETNEXT and GETBULK like a real agent."""

    def __init__(self, community="public"):
        self.values = {}
        self.community = community
        self.requests = []

    def set(self, oid, value):
        self.values[oid] = value

    def handle(self, payload):
        tag, version, community, numbers, oids = decode_request(payload)
        self.requests.append((tag, version))
        if community != self.community:
            raise plugin.Timeout("wrong community: agents do not answer")
        request_id = numbers[0]
        keys = sorted(self.values)
        if tag == plugin.GET:
            binds = [(o, self.values.get(o, plugin.NoSuch("noSuchInstance"))) for o in oids]
            if version == 0 and any(isinstance(v, plugin.NoSuch) for _, v in binds):
                return encode_response(version, community, request_id, 2, binds)
            return encode_response(version, community, request_id, 0, binds)
        if tag == plugin.GETBULK and version == 0:
            raise AssertionError("GETBULK is not part of SNMPv1")
        binds = []
        for oid in oids:
            following = [k for k in keys if k > oid]
            rows = following[: (numbers[2] if tag == plugin.GETBULK else 1)]
            if not rows:
                if version == 0:
                    return encode_response(version, community, request_id, 2, [(oid, None)])
                binds.append((oid, plugin.NoSuch("endOfMibView")))
            binds += [(k, self.values[k]) for k in rows]
        return encode_response(version, community, request_id, 0, binds)


def switch_mib(name, descr, mac, ports, fdb, lldp=(), qbridge=True, community="public"):
    """ports {ifIndex: name}; fdb [(mac, ifIndex)]; lldp [(local port, neighbour chassis mac, neighbour name)]."""
    m = Mib(community)
    m.set(plugin.SYS_DESCR, descr.encode())
    m.set(plugin.SYS_NAME, name.encode())
    m.set(plugin.BRIDGE_ADDRESS, mac_bytes(mac))
    for index, port in ports.items():
        m.set(plugin.IF_NAME + (index,), port.encode())
        m.set(plugin.IF_PHYS + (index,), mac_bytes(mac))
        m.set(plugin.BASE_PORT_IFINDEX + (index - 1000,), index)       # bridge port numbers differ from ifIndexes
    for client, index in fdb:
        key = octets(client)
        if qbridge:
            m.set(plugin.QBRIDGE_FDB_PORT + (1,) + key, index - 1000)
            m.set(plugin.QBRIDGE_FDB_STATUS + (1,) + key, 3)
        else:
            m.set(plugin.BRIDGE_FDB_PORT + key, index - 1000)
            m.set(plugin.BRIDGE_FDB_STATUS + key, 3)
    m.set(plugin.QBRIDGE_FDB_STATUS + (1,) + octets(mac), 4) if qbridge else None   # the switch's own address: not a client
    for n, (local, chassis, remote_name) in enumerate(lldp, start=1):
        m.set(plugin.LLDP_CHASSIS_SUBTYPE + (0, local, n), 4)
        m.set(plugin.LLDP_CHASSIS_ID + (0, local, n), mac_bytes(chassis))
        m.set(plugin.LLDP_PORT_ID + (0, local, n), b"gi1/0/1")
        m.set(plugin.LLDP_SYS_NAME + (0, local, n), remote_name.encode())
    return m


CORE_MAC, GARDEN_MAC = "c0:00:00:00:00:01", "c0:00:00:00:00:02"
TV, CAM, NAS, AP_CLIENT, PHONE = "02:22:33:00:00:01", "02:22:33:00:00:02", "02:22:33:00:00:03", "02:22:33:00:00:04", "02:22:33:00:00:05"
ROUTER_MAC = "aa:aa:aa:00:00:01"


@pytest.fixture
def network(monkeypatch):
    core = switch_mib(
        "SW_CORE", "JetStream 24-Port Gigabit Smart Switch", CORE_MAC,
        {1001: "gi1/0/1", 1002: "gi1/0/2", 1003: "gi1/0/3", 1004: "gi1/0/4"},
        # port 1: the router (and everything beyond it), port 2: uplink to the garden switch (it also carries the TV and camera), 3: a NAS, 4: an access point with two clients behind it
        [(ROUTER_MAC, 1001), (TV, 1002), (CAM, 1002), (GARDEN_MAC, 1002), (NAS, 1003), (AP_CLIENT, 1004), (PHONE, 1004)],
        lldp=[(1002, GARDEN_MAC, "SW_GARDEN")],
    )
    garden = switch_mib(
        "SW_GARDEN", "JetStream 8-Port Gigabit Smart Switch", GARDEN_MAC,
        {1001: "gi1/0/1", 1005: "gi1/0/5", 1006: "gi1/0/6"},
        [(CORE_MAC, 1001), (NAS, 1001), (AP_CLIENT, 1001), (PHONE, 1001), (ROUTER_MAC, 1001), (TV, 1005), (CAM, 1006)],
        lldp=[(1001, CORE_MAC, "SW_CORE")],
    )
    agents = {"10.0.0.2": core, "10.0.0.3": garden}

    def send(address, payload, timeout):
        if address[0] not in agents:
            raise plugin.Timeout(f"no answer from {address[0]}")
        return agents[address[0]].handle(payload)

    monkeypatch.setattr(plugin, "SEND", send)
    return agents


CONFIG = {"hosts": "10.0.0.2, 10.0.0.3", "community": "public", "version": "2c", "timeout": 1}


# ---------------------------------------------------------------- the codec
def test_a_real_snmpv1_get_request_is_encoded_byte_for_byte():
    expected = "302602010004067075626c6963a019020101020100020100300e300c06082b060102010101000500"
    assert plugin.build_request(plugin.GET, 0, "public", 1, [plugin.SYS_DESCR]).hex() == expected


@pytest.mark.parametrize("value,hexed", [(0, "020100"), (127, "02017f"), (128, "02020080"), (-1, "0201ff"), (300, "0202012c"), (-129, "0202ff7f")])
def test_integers(value, hexed):
    assert plugin._int(value).hex() == hexed


def test_long_oids_and_lengths_round_trip():
    oid = (1, 3, 6, 1, 4, 1, 8802, 1, 1, 2, 1, 4, 1, 1, 5, 0, 12, 3)
    assert plugin._decode_oid(plugin._oid(oid)[2:]) == oid
    big = plugin.build_request(plugin.GET, 1, "x" * 200, 70000, [oid] * 10)
    tag, version, community, numbers, oids = decode_request(big)
    assert (version, len(community), numbers[0], oids[0]) == (1, 200, 70000, oid)


def test_responses_are_parsed_including_counters_and_end_of_mib():
    binds = [((1, 3, 6, 1, 2, 1, 1, 5, 0), b"name"), ((1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 7), 7), ((1, 3, 6, 2), plugin.NoSuch("endOfMibView"))]
    request_id, status, parsed = plugin.parse_response(encode_response(1, "public", 99, 0, binds))
    assert (request_id, status) == (99, 0) and parsed[0][1] == b"name" and parsed[1][1] == 7 and isinstance(parsed[2][1], plugin.NoSuch)
    with pytest.raises(plugin.SnmpError):
        plugin.parse_response(b"\x30\x05\x02")
    with pytest.raises(plugin.SnmpError):
        plugin.parse_response(b"garbage")


# ---------------------------------------------------------------- reading and the topology
def test_manifest_is_valid():
    manifest = validate_manifest(json.loads((ROOT / "plugin.json").read_text()))
    assert manifest["id"] == "snmp" and manifest["kind"] == "topology" and manifest["diagnose"] is True


def test_connection_test_reports_what_it_found(network):
    message = plugin.test(CONFIG)["message"]
    assert message.startswith("Connected to 2 switch(es), ") and "learned MAC address(es)" in message


def test_topology_attributes_each_device_to_the_switch_it_is_plugged_into(network):
    out = validate_output("topology", plugin.fetch(CONFIG))
    nodes = {n["name"]: n for n in out["nodes"]}
    assert set(nodes) == {"SW_CORE", "SW_GARDEN"} and all(n["role"] == "switch" for n in out["nodes"])
    assert nodes["SW_GARDEN"]["parent_mac"] == CORE_MAC and nodes["SW_CORE"]["parent_mac"] is None   # from LLDP
    where = {c["mac"]: (c["node_mac"], c["port"]) for c in out["clients"]}
    assert where[TV] == (GARDEN_MAC, "gi1/0/5") and where[CAM] == (GARDEN_MAC, "gi1/0/6")      # not the core switch they are visible on too
    assert where[NAS] == (CORE_MAC, "gi1/0/3") and where[PHONE] == (CORE_MAC, "gi1/0/4")
    assert ROUTER_MAC not in where or where[ROUTER_MAC][0] == CORE_MAC
    assert CORE_MAC not in where and GARDEN_MAC not in where        # the switches themselves are nodes, not clients
    assert all(c["medium"] == "wired" for c in out["clients"])


def test_the_core_switch_can_be_chosen(network):
    out = plugin.fetch({**CONFIG, "root": "10.0.0.3"})
    nodes = {n["name"]: n for n in out["nodes"]}
    assert nodes["SW_GARDEN"]["parent_mac"] is None and nodes["SW_CORE"]["parent_mac"] == GARDEN_MAC


def test_links_in_netlens_hierarchy(network):
    out = validate_output("topology", plugin.fetch(CONFIG))
    by_mac = {CORE_MAC: 1, GARDEN_MAC: 2, TV: 3, NAS: 4}
    links = {(c, p, how) for c, p, how in topology_links(out, by_mac, {})}
    assert (2, 1, "node") in links and (3, 2, "wired") in links and (4, 1, "wired") in links


def test_without_lldp_the_port_with_the_fewest_addresses_wins(monkeypatch):
    a = switch_mib("A", "x", "c0:00:00:00:00:0a", {1001: "p1", 1002: "p2"}, [(TV, 1001), (CAM, 1001), (NAS, 1002)])       # TV is on a busy port: an uplink
    b = switch_mib("B", "x", "c0:00:00:00:00:0b", {1001: "p1"}, [(TV, 1001)])                                              # alone on its port: the edge
    agents = {"10.0.1.1": a, "10.0.1.2": b}
    monkeypatch.setattr(plugin, "SEND", lambda address, payload, timeout: agents[address[0]].handle(payload))
    out = plugin.fetch({"hosts": "10.0.1.1 10.0.1.2", "community": "public"})
    where = {c["mac"]: c["node_mac"] for c in out["clients"]}
    assert where[TV] == "c0:00:00:00:00:0b" and where[NAS] == "c0:00:00:00:00:0a"
    assert all(n["parent_mac"] is None for n in out["nodes"])      # nothing says how they are connected


def test_old_switches_old_tables_and_v1(monkeypatch):
    m = switch_mib("OLD", "legacy", "c0:00:00:00:00:0c", {1001: "1", 1002: "2"}, [(TV, 1002), (CAM, 1001)], qbridge=False)
    monkeypatch.setattr(plugin, "SEND", lambda address, payload, timeout: m.handle(payload))
    out = plugin.fetch({"hosts": "10.0.2.1", "community": "public", "version": "1"})
    assert {c["mac"]: c["port"] for c in out["clients"]} == {TV: "2", CAM: "1"}
    assert {version for _, version in m.requests} == {0}                    # SNMPv1 only
    assert all(tag != plugin.GETBULK for tag, _ in m.requests)


def test_multicast_zero_and_learning_status_are_ignored(monkeypatch):
    m = switch_mib("S", "x", "c0:00:00:00:00:0d", {1001: "p1"}, [("01:00:5e:00:00:01", 1001), (TV, 1001)])
    m.set(plugin.QBRIDGE_FDB_PORT + (1,) + octets(CAM), 1)
    m.set(plugin.QBRIDGE_FDB_STATUS + (1,) + octets(CAM), 5)               # mgmt entry: the switch's own
    monkeypatch.setattr(plugin, "SEND", lambda address, payload, timeout: m.handle(payload))
    out = plugin.fetch({"hosts": "10.0.3.1", "community": "public"})
    assert [c["mac"] for c in out["clients"]] == [TV]


def test_an_unreachable_switch_is_reported_but_does_not_stop_the_others(network):
    config = {**CONFIG, "hosts": "10.0.0.2, 10.0.0.77"}
    message = plugin.test(config)["message"]
    assert "1 switch(es)" in message and "10.0.0.77" in message
    assert len(plugin.fetch(config)["nodes"]) == 1
    with pytest.raises(plugin.SnmpError):
        plugin.fetch({**CONFIG, "hosts": "10.0.0.77"})


def test_wrong_community_and_bad_settings_give_clear_errors(network):
    with pytest.raises(plugin.SnmpError, match="no answer|10.0.0.2"):
        plugin.test({**CONFIG, "community": "secret"})
    with pytest.raises(ValueError, match="at least one switch"):
        plugin.test({"community": "x"})
    with pytest.raises(ValueError, match="community"):
        plugin.test({"hosts": "10.0.0.2"})


def test_the_diagnostic_reports_counts_and_leaks_nothing(network):
    report = plugin.diagnose(CONFIG)
    text = json.dumps(report)
    assert report["host_count"] == 2 and report["result"]["nodes"] == 2 and report["result"]["clients"] >= 4
    summary = report["switches"][0]["summary"]
    assert summary["fdb_source"] == "Q-BRIDGE-MIB" and summary["lldp"] is True and summary["ports"] == 4
    assert report["switches"][0]["steps"]["dot1qTpFdbPort"]["result"]["rows"] > 0
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text) and not re.search(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", text, re.I)
    assert "SW_CORE" not in text and "SW_GARDEN" not in text and "public" not in text


def test_the_diagnostic_survives_a_dead_switch(network):
    report = plugin.diagnose({**CONFIG, "hosts": "10.0.0.77"})
    assert report["switches"][0]["steps"]["system"]["ok"] is False and "result" not in report


def test_hosts_with_ports_and_separators():
    assert plugin.parse_hosts("10.0.0.2:1161, 10.0.0.3;10.0.0.4\n10.0.0.5") == ["10.0.0.2:1161", "10.0.0.3", "10.0.0.4", "10.0.0.5"]
    assert plugin.Agent("10.0.0.2:1161", "x").address == ("10.0.0.2", 1161)


def test_the_real_udp_path_against_a_local_agent():
    """No fake transport: real sockets, a thread answering on localhost, including a datagram from a stranger and a timeout."""
    import socket
    import threading

    mib = switch_mib("UDP", "real socket", "c0:00:00:00:00:0e", {1001: "p1"}, [(TV, 1001)])
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(5)
    port = server.getsockname()[1]
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                data, source = server.recvfrom(65535)
            except OSError:
                return
            try:
                server.sendto(mib.handle(data), source)
            except plugin.Timeout:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        out = plugin.fetch({"hosts": f"127.0.0.1:{port}", "community": "public", "timeout": 1})
        assert [c["mac"] for c in out["clients"]] == [TV] and out["clients"][0]["port"] == "p1"
        with pytest.raises(plugin.SnmpError, match="no answer"):
            plugin.fetch({"hosts": f"127.0.0.1:{port}", "community": "wrong", "timeout": 1})
    finally:
        stop.set()
        server.close()
