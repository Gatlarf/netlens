"""The NetBox plugin against canned answers (shapes recorded from NetBox 4.7.3 on 2026-10-16)."""

import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.plugin_http_fixture import Canned

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "netbox"
spec = importlib.util.spec_from_file_location("netbox_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

AUTH = "Bearer nbt_key.secret"


def device(i, name, role, ip=None, status="active"):
    return {"id": i, "name": name, "status": {"value": status}, "role": {"slug": role}, "device_type": {"model": "Generic"}, "primary_ip4": {"address": f"{ip}/24"} if ip else None}


def iface(i, dev, name, mac, peer=None):
    return {"id": i, "device": {"id": dev, "name": f"d{dev}"}, "name": name, "mac_address": mac, "primary_mac_address": {"mac_address": mac} if mac else None,
            "link_peers": [{"device": {"id": peer[0]}, "name": peer[1]}] if peer else []}


DEVICES = [device(1, "router1", "router", "192.168.0.1"), device(2, "switch1", "switch", "192.168.0.2"), device(3, "ap1", "access-point", "192.168.0.3"),
           device(4, "server1", "server", "192.168.0.50"), device(5, "nomac", "server", "192.168.0.60"), device(6, "switch2", "switch", "192.168.0.4"),
           device(7, "cam1", "camera", "192.168.0.70")]
INTERFACES = [iface(1, 1, "eth0", "AA:00:00:00:01:01"), iface(2, 1, "eth1", "AA:00:00:00:01:02", (2, "port1")), iface(3, 2, "port1", "AA:00:00:00:02:01", (1, "eth1")),
              iface(4, 2, "port2", "AA:00:00:00:02:02", (3, "eth0")), iface(5, 3, "eth0", "AA:00:00:00:03:01", (2, "port2")),
              iface(6, 2, "port3", "AA:00:00:00:02:03", (4, "eth0")), iface(7, 4, "eth0", "AA:00:00:00:04:01", (2, "port3")),
              iface(8, 5, "eth0", None), iface(9, 6, "port1", "AA:00:00:00:06:01", (3, "eth1")), iface(10, 3, "eth1", "AA:00:00:00:03:02", (6, "port1")),
              iface(11, 7, "eth0", "AA:00:00:00:07:01", (6, "port2")), iface(12, 6, "port2", "AA:00:00:00:06:02", (7, "eth0"))]


def routes(url):
    return {"/api/status/": {"netbox-version": "4.7.3"}, "/api/dcim/devices/": {"count": 7, "next": f"{url}/api/dcim/devices/page2", "results": DEVICES[:4]},
            "/api/dcim/devices/page2": {"count": 7, "next": None, "results": DEVICES[4:]}, "/api/dcim/interfaces/": {"count": 12, "next": None, "results": INTERFACES}}


@pytest.fixture
def netbox():
    with Canned({}, auth=AUTH) as s:
        s.routes.update(routes(s.url))
        yield s


def config(s, token="nbt_key.secret", **extra):
    return {"servers": [{"host": s.url, "token": token}], "timeout": 5, **extra}


def test_manifest_and_tree_follow_the_contract(netbox):
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "topology"
    out = validate_output("topology", plugin.fetch(config(netbox)))
    nodes = {n["name"]: n for n in out["nodes"]}
    assert sorted(nodes) == ["ap1", "router1", "switch1", "switch2"]                                  # the second page of devices is read too
    assert nodes["router1"]["role"] == "gateway" and nodes["router1"]["parent_mac"] is None
    assert nodes["switch1"]["role"] == "switch" and nodes["switch1"]["parent_mac"] == "aa:00:00:00:01:01"
    assert nodes["ap1"]["role"] == "ap" and nodes["ap1"]["parent_mac"] == "aa:00:00:00:02:01"          # ap1 hangs below switch1 although it is also cabled to switch2
    assert nodes["switch2"]["parent_mac"] == "aa:00:00:00:03:01" and nodes["switch2"]["ip"] == "192.168.0.4"
    clients = {c["name"]: c for c in out["clients"]}
    assert sorted(clients) == ["cam1", "server1"]                                                      # "nomac" cannot be matched and is skipped
    assert (clients["server1"]["node_mac"], clients["server1"]["port"], clients["server1"]["ip"]) == ("aa:00:00:00:02:01", "port3", "192.168.0.50")
    assert (clients["cam1"]["node_mac"], clients["cam1"]["port"]) == ("aa:00:00:00:06:01", "port2")


def test_token_styles_message_and_diagnose(netbox):
    assert "Connected to NetBox 4.7.3: 4 network device(s), 2 other device(s). 1 device(s) have no MAC address" in plugin.test(config(netbox))["message"]
    with pytest.raises(plugin.AuthRefused) as caught:
        plugin.test(config(netbox, token="nbt_key.wrong"))
    assert caught.value.auth_failed is True
    assert plugin.Server("http://x", "abc123").auth == "Token abc123" and plugin.Server("http://x", "nbt_k.t").auth == "Bearer nbt_k.t"
    text = json.dumps(plugin.diagnose(config(netbox)))
    assert "192.168" not in text and "router1" not in text and '"cabled": 10' in text and '"count": 7' in text
    out = plugin.fetch(config(netbox, network_roles="router, switch"))
    assert sorted(n["name"] for n in out["nodes"]) == ["router1", "switch1", "switch2"]
