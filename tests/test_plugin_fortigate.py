"""The FortiGate plugin against a simulated firewall. The answers follow the FortiOS REST API as documented; no real FortiGate has answered yet."""

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from app.plugins.contract import validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "fortigate"
spec = importlib.util.spec_from_file_location("fortigate_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

TOKEN = "tok"
EXPIRES = 1893456000      # 2030-01-01
PAGES = {
    "/api/v2/monitor/system/status": {"results": {"model_name": "FortiGate", "model_number": "60F", "hostname": "FGT-HQ"}, "serial": "FGT60F0000000001", "version": "v7.2.5"},
    "/api/v2/cmdb/system/interface": {"results": [
        {"name": "wan1", "macaddr": "00:09:0f:aa:00:01", "ip": "203.0.113.2 255.255.255.248", "type": "physical", "status": "up", "snmp-index": 3},
        {"name": "lan", "macaddr": "00:09:0f:aa:00:02", "ip": "192.168.1.99 255.255.255.0", "role": "lan", "type": "physical", "status": "up", "snmp-index": 4},
        {"name": "dmz", "macaddr": "00:09:0f:aa:00:03", "ip": "0.0.0.0 0.0.0.0", "type": "physical", "status": "down", "snmp-index": 5},
        {"name": "ssl.root", "type": "tunnel", "ip": "0.0.0.0 0.0.0.0"}]},
    "/api/v2/monitor/system/interface": {"results": {"wan1": {"link": True, "speed": 1000.0, "tx_packets": 100, "rx_packets": 200, "tx_errors": 0, "rx_errors": 1},
                                                       "lan": {"link": True, "speed": 1000.0, "tx_packets": 5000, "rx_packets": 6000, "tx_errors": 0, "rx_errors": 0},
                                                       "dmz": {"link": False, "speed": 0}}},
    "/api/v2/monitor/system/dhcp": {"results": [{"ip": "192.168.1.50", "mac": "AA:BB:CC:00:00:50", "hostname": "laptop", "interface": "lan"},
                                                  {"ip": "192.168.1.60", "mac": "aa:bb:cc:00:00:60", "hostname": "", "interface": "lan"}]},
    "/api/v2/monitor/user/device/query": {"results": [{"mac": "aa:bb:cc:00:00:60", "ipv4_address": "192.168.1.60", "hostname": "hp-printer", "hardware_vendor": "HP", "hardware_type": "Printer",
                                                         "os_name": "Linux", "is_online": True, "interface": "lan"},
                                                        {"mac": "aa:bb:cc:00:00:70", "ipv4_address": "192.168.1.70", "os_name": "iOS", "os_version": "17", "is_online": True},
                                                        {"mac": "aa:bb:cc:00:00:71", "ipv4_address": "192.168.1.71", "is_online": False}]},
    "/api/v2/monitor/network/arp": {"results": [{"ip": "192.168.1.80", "mac": "aa:bb:cc:00:00:80", "interface": "lan"}, {"ip": "192.168.1.99", "mac": "00:09:0f:aa:00:02", "interface": "lan"}]},
    "/api/v2/cmdb/system/ha": {"results": {"mode": "a-p", "group-name": "hq"}},
    "/api/v2/monitor/system/ha-peer": {"results": [{"serial_no": "FGT60F0000000001", "primary": True}, {"serial_no": "FGT60F0000000002", "primary": False}]},
    "/api/v2/monitor/vpn/ipsec": {"results": [{"name": "to-branch", "rgwy": "198.51.100.7", "proxyid": [{"status": "up"}, {"status": "down"}]}, {"name": "to-lab", "proxyid": [{"status": "down"}]}]},
    "/api/v2/monitor/license/status": {"results": {"forticare": {"status": "registered", "support": {"enhanced": {"type": "enhanced", "expires": EXPIRES, "status": "licensed"}, "hardware": {"expires": 0}}},
                                                     "fortiguard": {"antivirus": {"expires": EXPIRES + 86400 * 30}}}},
}


class Fake:
    def __init__(self, pages=None, missing=()):
        self.pages, self.missing, self.seen = pages or PAGES, set(missing), []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                url = urlsplit(self.path)
                outer.seen.append((url.path, parse_qs(url.query), self.headers.get("Authorization")))
                if self.headers.get("Authorization") != "Bearer " + TOKEN:
                    self.send_response(401); self.end_headers(); return
                if url.path in outer.missing or url.path not in outer.pages:
                    self.send_response(404); self.end_headers(); return
                raw = json.dumps(outer.pages[url.path]).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


@pytest.fixture
def fake():
    f = Fake()
    yield f
    f.close()


def cfg(f, **extra):
    return {"servers": [{"host": f.url, "token": TOKEN, **extra}], "verify_tls": True, "timeout": 5}


def test_the_manifest_is_valid():
    validate_manifest(json.loads((ROOT / "plugin.json").read_text()))


def test_fetch_gives_a_valid_topology_with_clients_interfaces_and_health(fake):
    out = validate_output("topology", plugin.fetch(cfg(fake)))
    node = out["nodes"][0]
    assert node["role"] == "gateway" and node["mac"] == "00:09:0f:aa:00:02" and node["name"] == "FGT-HQ" and node["model"] == "FortiGate 60F"
    assert sorted((p["port"], p["name"], p["up"], p["enabled"]) for p in node["ports"]) == [(3, "wan1", True, True), (4, "lan", True, True), (5, "dmz", False, False)]
    fw = node["firewall"]
    assert fw["version"] == "v7.2.5" and fw["serial"] == "FGT60F0000000001"
    assert fw["ha"] == {"mode": "active-passive", "state": "primary", "peer_state": "secondary", "in_sync": None}
    assert {t["name"]: t["up"] for t in fw["tunnels"]} == {"to-branch": True, "to-lab": False}
    assert [l["expires"] for l in fw["licences"]] == ["2030-01-01", "2030-01-31"]
    by_mac = {c["mac"]: c for c in out["clients"]}
    assert set(by_mac) == {"aa:bb:cc:00:00:50", "aa:bb:cc:00:00:60", "aa:bb:cc:00:00:70", "aa:bb:cc:00:00:80"}       # the firewall's own MAC and the offline entry are left out
    printer = by_mac["aa:bb:cc:00:00:60"]
    assert (printer["name"], printer["vendor"], printer["device_type"], printer["ip"], printer["port"]) == ("hp-printer", "HP", "printer", "192.168.1.60", "lan")
    assert by_mac["aa:bb:cc:00:00:70"]["device_type"] == "phone" and by_mac["aa:bb:cc:00:00:70"]["os"] == "iOS 17"
    assert by_mac["aa:bb:cc:00:00:50"]["name"] == "laptop" and all(c["node_mac"] == node["mac"] for c in out["clients"])


def test_only_get_requests_with_the_token_and_the_vdom(fake):
    plugin.fetch(cfg(fake, vdom="customer1"))
    assert fake.seen and all(a == "Bearer " + TOKEN and q.get("vdom") == ["customer1"] for _, q, a in fake.seen)


def test_a_wrong_token_stops_retries(fake):
    c = cfg(fake)
    c["servers"][0]["token"] = "nope"
    with pytest.raises(plugin.AuthRefused) as err:
        plugin.fetch(c)
    assert err.value.auth_failed and "trusted hosts" in str(err.value)


def test_endpoints_this_version_lacks_are_skipped():
    f = Fake(missing=("/api/v2/monitor/user/device/query", "/api/v2/monitor/network/arp", "/api/v2/monitor/license/status", "/api/v2/monitor/vpn/ipsec"))
    try:
        out = validate_output("topology", plugin.fetch(cfg(f)))
        assert {c["mac"] for c in out["clients"]} == {"aa:bb:cc:00:00:50", "aa:bb:cc:00:00:60"}
        assert out["nodes"][0]["firewall"]["version"] == "v7.2.5" and out["nodes"][0]["firewall"]["tunnels"] == []
    finally:
        f.close()


def test_a_standalone_unit_has_no_ha_part():
    pages = dict(PAGES)
    pages["/api/v2/cmdb/system/ha"] = {"results": {"mode": "standalone"}}
    f = Fake(pages)
    try:
        assert "ha" not in plugin.fetch(cfg(f))["nodes"][0]["firewall"]
    finally:
        f.close()


def test_two_firewalls_the_second_hangs_below_the_first(fake):
    other = dict(PAGES)
    other["/api/v2/monitor/system/status"] = {"results": {"hostname": "FGT-BRANCH"}, "serial": "X", "version": "v7.0.1"}
    other["/api/v2/cmdb/system/interface"] = {"results": [{"name": "lan", "macaddr": "00:09:0f:bb:00:02", "ip": "10.9.0.1 255.255.255.0", "role": "lan", "type": "physical"}]}
    second = Fake(other)
    try:
        config = {"servers": [{"host": fake.url, "token": TOKEN}, {"host": second.url, "token": TOKEN}], "verify_tls": True}
        out = validate_output("topology", plugin.fetch(config))
        roles = {n["name"]: (n["role"], n.get("parent_mac")) for n in out["nodes"]}
        assert roles == {"FGT-HQ": ("gateway", None), "FGT-BRANCH": ("node", "00:09:0f:aa:00:02")}
        assert sum(1 for c in out["clients"] if c["mac"] == "aa:bb:cc:00:00:50") == 1               # a device both firewalls know is listed once
    finally:
        second.close()


def test_test_and_diagnose(fake):
    assert "1 FortiGate" in plugin.test(cfg(fake))["message"] and "v7.2.5" in plugin.test(cfg(fake))["message"]
    report = plugin.diagnose(cfg(fake))
    steps = report["firewalls"][0]["steps"]
    assert steps["dhcp"]["count"] == 2 and "hostname" in steps["dhcp"]["fields"] and steps["licences"]["licence_entries_found"] == 2
    assert "127.0.0.1" not in json.dumps(report) and "FGT60F" not in json.dumps(report)
    assert plugin.diagnose({"servers": []})["error"]
