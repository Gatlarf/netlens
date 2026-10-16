"""The MikroTik plugin against canned REST answers (recorded from a RouterOS 7.12.1 CHR on 2026-10-16; the Wi-Fi registration tables and neighbour
list follow the RouterOS documentation because the lab router has no radio and no neighbours)."""

import base64
import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.plugin_http_fixture import Canned

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "mikrotik"
spec = importlib.util.spec_from_file_location("mikrotik_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

AUTH = "Basic " + base64.b64encode(b"netlens:pw").decode()
NO_CMD = 400


def routes(nat=True, wifi=True, name="rtr", own="AA:00:00:00:00:01", neighbors=True):
    r = {
        "/rest/system/identity": {"name": name},
        "/rest/system/resource": {"board-name": "hAP ax3", "version": "7.12.1 (stable)"},
        "/rest/interface": [{"name": "bridge-lan", "type": "bridge", "mac-address": own}, {"name": "ether1", "type": "ether", "mac-address": own.replace(":01", ":02")}, {"name": "wlan1", "type": "wlan", "mac-address": own.replace(":01", ":03")}],
        "/rest/ip/address": [{"address": "192.168.88.1/24", "interface": "bridge-lan", "disabled": "false", "invalid": "false"}],
        "/rest/ip/firewall/nat": [{"chain": "srcnat", "action": "masquerade", "disabled": "false"}] if nat else [],
        "/rest/ip/neighbor": [{"mac-address": "AA:00:00:00:00:77", "identity": "switch-garage", "address": "192.168.88.7", "platform": "MikroTik", "board": "CRS326"},
                              {"mac-address": "BB:00:00:00:00:99", "identity": "pc", "address": "192.168.88.99", "platform": ""}] if neighbors else [],
        "/rest/interface/bridge/host": [
            {"mac-address": own, "local": "true", "on-interface": "bridge-lan", "interface": "bridge-lan"},
            {"mac-address": "02:11:22:33:44:55", "local": "false", "on-interface": "ether3", "interface": "ether3"},
            {"mac-address": "02:11:22:33:44:66", "local": "false", "on-interface": "wlan1", "interface": "wlan1"}],
        "/rest/ip/arp": [{"address": "192.168.88.20", "mac-address": "02:11:22:33:44:55", "complete": "true", "invalid": "false", "disabled": "false"},
                         {"address": "192.168.88.21", "mac-address": "02:11:22:33:44:66", "complete": "true", "invalid": "false", "disabled": "false"},
                         {"address": "192.168.88.30", "complete": "false", "invalid": "false", "disabled": "false"}],
        "/rest/ip/dhcp-server/lease": [{"address": "192.168.88.20", "mac-address": "02:11:22:33:44:55", "host-name": "laptop", "status": "bound", "disabled": "false"},
                                       {"address": "192.168.88.50", "mac-address": "02:99:99:99:99:99", "comment": "offline tv", "status": "waiting", "disabled": "false"}],
        "/rest/interface/wireless/registration-table": NO_CMD if not wifi else [],
        "/rest/interface/wifi/registration-table": [{"mac-address": "02:11:22:33:44:66", "interface": "wifi1", "signal": "-58", "tx-rate": "866.7Mbps-80MHz/2S", "rx-rate": "780Mbps-80MHz/2S", "band": "5ghz-ax"}] if wifi else NO_CMD,
    }
    return r


class Ros(Canned):
    def __init__(self, routes, **kw):
        # RouterOS answers 400 "no such command" for a menu that does not exist
        super().__init__(routes, auth=AUTH)
        self.routes = {k: ({"error": 400, "message": "Bad Request", "detail": "no such command or directory (wifi)"} if v == NO_CMD else v) for k, v in routes.items()}


def config(*rows, password="pw"):
    return {"servers": [{"username": "netlens", "password": password, **row} for row in rows], "timeout": 5}


def test_manifest_and_output_follow_the_contract():
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "topology"
    with Ros(routes()) as s:
        out = validate_output("topology", plugin.fetch(config({"host": s.url})))
    nodes = {n["name"]: n for n in out["nodes"]}
    assert nodes["rtr"]["mac"] == "aa:00:00:00:00:01" and nodes["rtr"]["role"] == "gateway" and nodes["rtr"]["model"] == "hAP ax3"
    assert nodes["switch-garage"]["parent_mac"] == "aa:00:00:00:00:01" and "pc" not in nodes                      # only MikroTik neighbours become nodes
    clients = {c["mac"]: c for c in out["clients"]}
    assert set(clients) == {"02:11:22:33:44:55", "02:11:22:33:44:66"}                                              # own MAC, offline lease and incomplete ARP are not clients
    laptop, phone = clients["02:11:22:33:44:55"], clients["02:11:22:33:44:66"]
    assert (laptop["medium"], laptop["port"], laptop["ip"], laptop["name"]) == ("wired", "ether3", "192.168.88.20", "laptop")
    assert (phone["medium"], phone["band"], phone["rssi"], phone["tx_mbps"], phone["rx_mbps"]) == ("wifi", "5 GHz", -58, 866.7, 780.0) and phone.get("port") is None


def test_legacy_wireless_table_and_rate_parsing():
    r = routes(wifi=False)
    r["/rest/interface/wireless/registration-table"] = [{"mac-address": "02:11:22:33:44:66", "interface": "wlan1", "signal-strength": "-61@5GHz", "tx-rate": "130Mbps-20MHz/2S", "rx-rate": "6.5Mbps"}]
    with Ros(r) as s:
        phone = next(c for c in plugin.fetch(config({"host": s.url}))["clients"] if c["mac"] == "02:11:22:33:44:66")
    assert (phone["medium"], phone["band"], phone["rssi"], phone["tx_mbps"], phone["rx_mbps"]) == ("wifi", "5 GHz", -61, 130.0, 6.5)
    assert plugin._rate("1.2Gbps") == 1200.0 and plugin._rate("") is None and plugin._rate("0bps") is None


def test_switch_role_uplink_and_two_devices():
    with Ros(routes()) as gw, Ros(routes(nat=False, name="sw", own="AA:00:00:00:00:77", neighbors=False)) as sw:
        out = validate_output("topology", plugin.fetch(config({"host": gw.url.replace("127.0.0.1", "localhost")}, {"host": sw.url, "uplink": "192.168.88.1"})))
    nodes = {n["name"]: n for n in out["nodes"]}
    assert nodes["sw"]["role"] == "switch" and nodes["sw"]["mac"] == "aa:00:00:00:00:77" and len([n for n in out["nodes"] if n["mac"] == "aa:00:00:00:00:77"]) == 1   # the listed switch is not added twice as a neighbour
    assert nodes["sw"]["parent_mac"] == "aa:00:00:00:00:01"                                                       # the uplink 192.168.88.1 is the gateway's own address (its host is a name, so the address comes from /ip/address)
    assert len({c["mac"] for c in out["clients"]}) == len(out["clients"])


def test_message_login_and_diagnose():
    with Ros(routes()) as s:
        assert "2 client(s), 1 on Wi-Fi, 1 MikroTik neighbour(s)" in plugin.test(config({"host": s.url}))["message"]
        with pytest.raises(plugin.AuthRefused) as caught:
            plugin.test(config({"host": s.url}, password="wrong"))
        assert caught.value.auth_failed is True
        text = json.dumps(plugin.diagnose(config({"host": s.url})))
    assert '"wifi_stations": {"ok": true' in text and "192.168" not in text and "aa:00" not in text.lower() and "laptop" not in text
