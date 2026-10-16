"""The OpenWrt plugin against a simulated ubus (shapes recorded from OpenWrt 25.12.5 under QEMU on 2026-10-16; the Wi-Fi answers follow
the iwinfo documentation because the lab router has no radio)."""

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "openwrt"
spec = importlib.util.spec_from_file_location("openwrt_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

SID = "abcdef0123456789abcdef0123456789"


def router(wan=True, wifi=True, denied=()):
    """Return the ubus answers of one simulated router."""
    interfaces = [{"interface": "loopback", "device": "lo", "ipv4-address": [{"address": "127.0.0.1", "mask": 8}]},
                  {"interface": "lan", "device": "br-lan", "ipv4-address": [{"address": "192.168.1.1" if wan else "192.168.1.2", "mask": 24}],
                   "route": [] if wan else [{"target": "0.0.0.0", "mask": 0, "nexthop": "192.168.1.1"}]}]
    if wan:
        interfaces.append({"interface": "wan", "device": "eth1", "proto": "dhcp", "ipv4-address": [{"address": "203.0.113.5", "mask": 24}], "route": [{"target": "0.0.0.0", "mask": 0}]})
    answers = {
        ("system", "board"): {"hostname": "gw" if wan else "ap1", "model": "Test Router", "release": {"description": "OpenWrt 25.12.5"}},
        ("network.interface", "dump"): {"interface": interfaces},
        ("network.device", "status"): {"macaddr": "aa:aa:aa:00:00:01" if wan else "aa:aa:aa:00:00:02"},
        ("luci-rpc", "getDHCPLeases"): {"dhcp_leases": [{"expires": 3600, "hostname": "laptop", "macaddr": "02:11:22:33:44:55", "ipaddr": "192.168.1.120"},
                                                          {"expires": 3600, "macaddr": "AA:BB:CC:00:00:07", "ipaddr": "192.168.1.121"}], "dhcp6_leases": []},
        ("luci-rpc", "getHostHints"): {"02:11:22:33:44:55": {"ipaddrs": ["192.168.1.120"], "ip6addrs": [], "name": "laptop"},
                                       "AA:AA:AA:00:00:01": {"ipaddrs": ["192.168.1.1"], "ip6addrs": []}, "00:00:00:00:00:00": {"ipaddrs": ["1.1.1.1"], "ip6addrs": []},
                                       "DE:AD:00:00:00:09": {"ipaddrs": [], "ip6addrs": ["fe80::1"]}},
    }
    if wifi:
        answers[("luci-rpc", "getWirelessDevices")] = {"radio0": {"interfaces": [{"section": "default_radio0", "ifname": "phy0-ap0"}]}, "radio1": {"interfaces": [{"ifname": "phy1-ap0"}]}}
        answers[("iwinfo", "info", "phy0-ap0")] = {"frequency": 2437}
        answers[("iwinfo", "info", "phy1-ap0")] = {"frequency": 5180}
        answers[("iwinfo", "assoclist", "phy0-ap0")] = {"results": [{"mac": "AA:BB:CC:00:00:07", "signal": -61, "rx": {"rate": 72200}, "tx": {"rate": 65000}}]}
        answers[("iwinfo", "assoclist", "phy1-ap0")] = {"results": [{"mac": "02:11:22:33:44:55", "signal": -48, "rx": {"rate": 866700}, "tx": {"rate": 780000}}]}
    return answers, denied


class Ubus:
    def __init__(self, routers, users=None):
        self.users = users or {"netlens": "pw"}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
                sid, obj, method, args = body["params"]
                answers, denied = outer.current
                if (obj, method) == ("session", "login"):
                    result = [0, {"ubus_rpc_session": SID}] if outer.users.get(args.get("username")) == args.get("password") else [6]
                elif (obj, method) == ("session", "destroy"):
                    result = [0]
                elif sid != SID:
                    reply = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32002, "message": "Access denied"}}
                    return self.send(reply)
                elif obj in denied:
                    result = [6]
                else:
                    key = (obj, method, args.get("device")) if obj == "iwinfo" else (obj, method)
                    result = [0, answers[key]] if key in answers else [4]
                self.send({"jsonrpc": "2.0", "id": 1, "result": result})

            def send(self, payload):
                raw = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.current = routers
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def config(*rows, password="pw"):
    return {"servers": [{"username": "netlens", "password": password, **row} for row in rows], "timeout": 5}


def test_manifest_and_gateway_output_follow_the_contract():
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "topology"
    with Ubus(router()) as s:
        out = validate_output("topology", plugin.fetch(config({"host": s.url})))
    assert [(n["mac"], n["ip"], n["name"], n["model"], n["role"], n["parent_mac"]) for n in out["nodes"]] == [("aa:aa:aa:00:00:01", "192.168.1.1", "gw", "Test Router", "gateway", None)]
    clients = {c["mac"]: c for c in out["clients"]}
    assert set(clients) == {"02:11:22:33:44:55", "aa:bb:cc:00:00:07"}                                    # own MAC, 00:.. and address-less hints are dropped
    laptop = clients["02:11:22:33:44:55"]
    assert (laptop["medium"], laptop["band"], laptop["rssi"], laptop["tx_mbps"], laptop["rx_mbps"], laptop["name"]) == ("wifi", "5 GHz", -48, 780.0, 866.7, "laptop")
    assert clients["aa:bb:cc:00:00:07"]["band"] == "2.4 GHz" and clients["aa:bb:cc:00:00:07"]["node_mac"] == "aa:aa:aa:00:00:01"


def test_wired_when_there_is_no_radio_and_an_access_point_gets_its_uplink():
    with Ubus(router(wan=False, wifi=False)) as ap:
        out = validate_output("topology", plugin.fetch(config({"host": ap.url, "uplink": "192.168.1.1"})))
        assert out["nodes"][0]["role"] == "ap" and all(c["medium"] == "wired" for c in out["clients"])
    with Ubus(router()) as gw, Ubus(router(wan=False)) as ap:
        out = validate_output("topology", plugin.fetch(config({"host": gw.url}, {"host": ap.url, "uplink": "192.168.1.1", "role": "ap"})))
    nodes = {n["name"]: n for n in out["nodes"]}
    assert nodes["ap1"]["parent_mac"] == "aa:aa:aa:00:00:01" and nodes["gw"]["role"] == "gateway"
    assert len({c["mac"] for c in out["clients"]}) == len(out["clients"])                                  # a device is reported once


def test_messages_login_and_the_missing_rights():
    with Ubus(router()) as s:
        assert "2 client(s), 2 on Wi-Fi" in plugin.test(config({"host": s.url}))["message"]
        with pytest.raises(plugin.AuthRefused) as caught:
            plugin.test(config({"host": s.url}, password="wrong"))
        assert caught.value.auth_failed is True
    with Ubus(router(denied=("system",))) as s, pytest.raises(plugin.AuthRefused) as caught:
        plugin.test(config({"host": s.url}))
    assert "system board" in str(caught.value)


def test_diagnose_has_counts_only():
    with Ubus(router()) as s:
        text = json.dumps(plugin.diagnose(config({"host": s.url})))
    assert '"leases": {"ok": true, "count": 2' in text and '"wifi_stations": 2' in text
    assert "192.168" not in text and "aa:bb" not in text.lower() and "laptop" not in text
