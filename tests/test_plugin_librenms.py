"""The LibreNMS plugin against canned answers (shapes recorded from LibreNMS 26.9.1 on 2026-10-16; the links and FDB rows were inserted by hand)."""

import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.plugin_http_fixture import Canned

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "librenms"
spec = importlib.util.spec_from_file_location("librenms_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

TOKEN = "1|secret"


def dev(i, host, typ, name=None, disabled=0):
    return {"device_id": i, "hostname": host, "ip": host, "sysName": name or host, "type": typ, "os": "linux", "hardware": "Box", "disabled": disabled}


def port(pid, d, name, mac):
    return {"port_id": pid, "device_id": d, "ifName": name, "ifPhysAddress": mac}


DEVICES = [dev(1, "192.168.0.1", "firewall", "fw"), dev(2, "192.168.0.2", "network", "sw1"), dev(3, "192.168.0.3", "wireless", "ap1"), dev(4, "192.168.0.50", "server", "nas"),
           dev(5, "192.168.0.60", "server", "nomac"), dev(6, "192.168.0.9", "network", "off", disabled=1), dev(7, "192.168.0.70", "firewall", "fw2")]
PORTS = [port(1, 1, "lan", "aa0000000101"), port(2, 2, "uplink", "aa0000000201"), port(3, 2, "p2", "aa0000000202"), port(4, 2, "p3", "aa0000000203"), port(5, 3, "eth0", "aa0000000301"),
         port(6, 4, "eth0", "aa0000000401"), port(7, 1, "lo", None), port(8, 5, "eth0", "000000000000"), port(9, 7, "wan", "aa0000000701"), port(10, 2, "mc", "01005e000001"), port(11, 2, "p4", "aa0000000204")]
LINKS = [{"id": 1, "local_port_id": 1, "local_device_id": 1, "remote_port_id": 2, "protocol": "lldp", "remote_hostname": "sw1", "remote_device_id": 2, "remote_port": "uplink"},
         {"id": 2, "local_port_id": 4, "local_device_id": 2, "remote_port_id": 5, "protocol": "lldp", "remote_hostname": "ap1", "remote_device_id": 3, "remote_port": "eth0"},
         {"id": 3, "local_port_id": 3, "local_device_id": 2, "remote_port_id": 6, "protocol": "cdp", "remote_hostname": "nas", "remote_device_id": 4, "remote_port": "eth0"}]
FDB = [{"ports_fdb_id": 1, "port_id": 11, "mac_address": "ba0000000001", "vlan_id": 1, "device_id": 2}, {"ports_fdb_id": 2, "port_id": 2, "mac_address": "ba0000000002", "vlan_id": 1, "device_id": 2},
       {"ports_fdb_id": 3, "port_id": 3, "mac_address": "aa0000000401", "vlan_id": 1, "device_id": 2}, {"ports_fdb_id": 4, "port_id": 3, "mac_address": "ffffffffffff", "vlan_id": 1, "device_id": 2}]
ARP = [{"id": 1, "port_id": 1, "device_id": 1, "mac_address": "ba0000000001", "ipv4_address": "192.168.0.80"}]


def routes():
    return {"/api/v0/system": {"status": "ok", "system": [{"local_ver": "26.9.1"}], "count": 1}, "/api/v0/devices": {"status": "ok", "devices": DEVICES, "count": 7},
            "/api/v0/ports": {"status": "ok", "ports": PORTS}, "/api/v0/resources/links": {"status": "ok", "links": LINKS, "count": 3},
            "/api/v0/resources/fdb": {"status": "ok", "ports_fdb": FDB}, "/api/v0/resources/ip/arp/all": {"status": "ok", "arp": ARP}}


@pytest.fixture
def librenms():
    with Canned(routes(), auth=None) as s:
        yield s


def config(s, token=TOKEN, **extra):
    return {"servers": [{"host": s.url, "token": token}], "timeout": 5, **extra}


def test_manifest_and_tree_follow_the_contract(librenms):
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "topology"
    out = validate_output("topology", plugin.fetch(config(librenms)))
    nodes = {n["name"]: n for n in out["nodes"]}
    assert sorted(nodes) == ["ap1", "fw", "fw2", "sw1"]                       # disabled and MAC-less devices are left out
    assert nodes["fw"]["role"] == "gateway" and nodes["fw"]["parent_mac"] is None
    assert nodes["fw2"]["role"] == "node"                                      # only one gateway
    assert nodes["sw1"]["parent_mac"] == "aa:00:00:00:01:01" and nodes["ap1"]["parent_mac"] == "aa:00:00:00:02:01"
    assert nodes["sw1"]["role"] == "switch" and nodes["ap1"]["role"] == "ap"
    assert nodes["sw1"]["macs"] == ["aa:00:00:00:02:01", "aa:00:00:00:02:02", "aa:00:00:00:02:03", "aa:00:00:00:02:04"]      # multicast addresses are not MACs of the device


def test_clients_get_switch_and_port(librenms):
    out = validate_output("topology", plugin.fetch(config(librenms)))
    clients = {c["mac"]: c for c in out["clients"]}
    nas = clients["aa:00:00:00:04:01"]
    assert nas["node_mac"] == "aa:00:00:00:02:01" and nas["name"] == "nas" and nas["port"] == "p2"       # attached through the link
    assert nas["os"] == "linux"
    learned = clients["ba:00:00:00:00:01"]
    assert learned["node_mac"] == "aa:00:00:00:02:01" and learned["port"] == "p4" and learned["ip"] == "192.168.0.80"      # from the FDB and the ARP table
    assert "ba:00:00:00:00:02" not in clients                                  # learned on an uplink: it sits further away
    assert "ff:ff:ff:ff:ff:ff" not in clients


def test_fdb_can_be_left_out(librenms):
    out = plugin.fetch(config(librenms, fdb_clients=False))
    assert [c["mac"] for c in out["clients"]] == ["aa:00:00:00:04:01"]
    assert "/api/v0/resources/fdb" not in librenms.seen


def test_empty_lists_are_not_errors():
    r = routes()
    r["/api/v0/resources/links"] = 404
    r["/api/v0/resources/fdb"] = 404
    with Canned(r) as s:
        out = plugin.fetch(config(s))
    assert len(out["nodes"]) == 4 and all("parent_mac" not in n for n in out["nodes"])


def test_message_and_auth(librenms):
    assert "LibreNMS 26.9.1" in plugin.test(config(librenms))["message"] and "1 device(s) have no MAC" in plugin.test(config(librenms))["message"]
    with Canned(routes(), auth="X") as s:
        with pytest.raises(plugin.AuthRefused) as exc:
            plugin.fetch(config(s))
        assert exc.value.auth_failed


def test_settings_are_checked():
    with pytest.raises(ValueError):
        plugin.parse_servers({"servers": []})
    with pytest.raises(ValueError):
        plugin.parse_servers({"servers": [{"host": "x"}]})


def test_diagnose_has_only_counts(librenms):
    report = plugin.diagnose(config(librenms))
    text = json.dumps(report)
    steps = report["servers"][0]["steps"]
    assert steps["devices"]["count"] == 7 and steps["links"]["protocols"] == ["cdp", "lldp"] and steps["fdb"]["count"] == 4 and steps["ports"]["with_mac"] == 8
    for secret in ("192.168", "aa:00", "aa0000", "sw1", "nas", "127.0.0.1"):
        assert secret not in text
