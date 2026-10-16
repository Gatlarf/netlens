"""The OPNsense plugin against canned answers (recorded from OPNsense 26.7 under QEMU on 2026-10-16; the DHCP lease rows follow the
OPNsense documentation because the lab firewall had no leases)."""

import base64
import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.plugin_http_fixture import Canned

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "opnsense"
spec = importlib.util.spec_from_file_location("opnsense_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

AUTH = "Basic " + base64.b64encode(b"key1:secret1").decode()


def arp(mac, ip, intf="vtnet0", desc="LAN", hostname="", manufacturer="", expired=False):
    return {"mac": mac, "ip": ip, "intf": intf, "expired": expired, "expires": 1100, "permanent": False, "type": "ethernet", "manufacturer": manufacturer, "hostname": hostname, "intf_description": desc}


IFACES = {"total": 4, "rowCount": 4, "current": 1, "rows": [
    {"device": "vtnet0", "description": "LAN", "identifier": "lan", "macaddr": "52:54:00:12:34:56", "macaddr_hw": "52:54:00:12:34:56", "addr4": "192.168.1.1/24"},
    {"device": "vtnet1", "description": "WAN", "identifier": "wan", "macaddr": "52:54:00:12:34:57", "macaddr_hw": "52:54:00:12:34:57", "addr4": "203.0.113.5/24"},
    {"device": "vtnet2", "description": "IOT", "identifier": "opt1", "macaddr": "52:54:00:12:34:58", "macaddr_hw": "52:54:00:12:34:58", "addr4": "192.168.20.1/24"},
    {"device": "lo0", "description": "Loopback", "identifier": "lo0", "macaddr": "00:00:00:00:00:00", "addr4": "127.0.0.1/8"}]}
ARP = {"total": 6, "rowCount": 6, "current": 1, "rows": [
    arp("52:54:00:12:34:56", "192.168.1.1"),
    arp("52:55:c0:a8:01:02", "192.168.1.2", hostname="nas.lan", manufacturer="Synology"),
    arp("02:11:22:33:44:55", "192.168.1.20"),
    arp("02:11:22:33:44:66", "192.168.1.21", expired=True),
    arp("02:aa:00:00:00:01", "192.168.20.5", "vtnet2", "IOT", manufacturer="Espressif"),
    arp("02:bb:00:00:00:01", "203.0.113.1", "vtnet1", "WAN")]}
ROUTES = {
    "/api/diagnostics/system/system_information": {"name": "fw.internal", "versions": ["OPNsense 26.7-amd64", "FreeBSD 15.1-RELEASE-p1"], "updates": "x"},
    "/api/interfaces/overview/interfacesInfo": IFACES,
    "/api/diagnostics/interface/search_arp": ARP,
    "/api/dnsmasq/leases/search": {"total": 1, "rowCount": 1, "current": 1, "rows": [{"hwaddr": "02:11:22:33:44:55", "address": "192.168.1.20", "hostname": "laptop", "expire": 1}]},
    "/api/kea/leases4/search": {"total": 0, "rowCount": 0, "current": 1, "rows": []},
}


def config(url, key="key1", secret="secret1", **extra):
    return {"servers": [{"host": url, "api_key": key, "api_secret": secret}], "timeout": 5, **extra}


def test_manifest_and_output_follow_the_contract():
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "topology"
    with Canned(ROUTES, auth=AUTH) as s:
        out = validate_output("topology", plugin.fetch(config(s.url)))
    gw = out["nodes"][0]
    assert (gw["mac"], gw["ip"], gw["name"], gw["role"]) == ("52:54:00:12:34:56", "192.168.1.1", "fw.internal", "gateway")
    assert set(gw["macs"]) - {gw["mac"]} == {"52:54:00:12:34:57", "52:54:00:12:34:58"}
    clients = {c["mac"]: c for c in out["clients"]}
    assert set(clients) == {"52:55:c0:a8:01:02", "02:11:22:33:44:55", "02:aa:00:00:00:01"}               # not the firewall itself, not an expired entry, not the WAN
    assert clients["52:55:c0:a8:01:02"]["name"] == "nas.lan" and clients["52:55:c0:a8:01:02"]["vendor"] == "Synology"
    assert clients["02:11:22:33:44:55"]["name"] == "laptop" and clients["02:11:22:33:44:55"]["medium"] == "unknown"    # the name comes from the lease
    assert all(c["node_mac"] == "52:54:00:12:34:56" for c in out["clients"])


def test_interface_filter_and_second_firewall():
    with Canned(ROUTES, auth=AUTH) as s:
        out = plugin.fetch(config(s.url, interfaces="IOT"))
        assert [c["mac"] for c in out["clients"]] == ["02:aa:00:00:00:01"]
    with Canned(ROUTES, auth=AUTH) as a, Canned(ROUTES, auth=AUTH) as b:
        out = validate_output("topology", plugin.fetch({"servers": [{"host": a.url, "api_key": "key1", "api_secret": "secret1"}, {"host": b.url, "api_key": "key1", "api_secret": "secret1"}], "timeout": 5}))
    assert len(out["nodes"]) == 1                                  # the same firewall listed twice is one node (same MAC)


def test_search_asks_again_when_the_first_answer_is_cut_off():
    cut = dict(ARP, total=10)
    full = dict(ARP, total=10, rowCount=10, rows=ARP["rows"] + [arp(f"02:cc:00:00:00:{i:02x}", f"192.168.1.{100 + i}") for i in range(4)])
    with Canned({**ROUTES, "/api/diagnostics/interface/search_arp": cut, ("POST", "/api/diagnostics/interface/search_arp"): full}, auth=AUTH) as s:
        out = plugin.fetch(config(s.url))
    assert len(out["clients"]) == 3 + 4


def test_message_login_rights_and_diagnose():
    with Canned(ROUTES, auth=AUTH) as s:
        assert "Connected to 1 OPNsense (OPNsense 26.7-amd64): 3 client(s) in the ARP table, DHCP leases: dnsmasq 1, kea 0" in plugin.test(config(s.url))["message"]
        with pytest.raises(plugin.AuthRefused) as caught:
            plugin.test(config(s.url, secret="wrong"))
        assert caught.value.auth_failed is True
        text = json.dumps(plugin.diagnose(config(s.url)))
    assert "192.168" not in text and "nas.lan" not in text and "52:54" not in text and '"with_hostname": 1' in text
    with Canned({**ROUTES, "/api/diagnostics/interface/search_arp": 403}, auth=AUTH) as s, pytest.raises(plugin.AuthRefused) as caught:
        plugin.test(config(s.url))
    assert "ARP" not in str(caught.value) and "search_arp" in str(caught.value)
