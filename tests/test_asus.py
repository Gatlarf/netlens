import json

import pytest

from app.plugins.builtin.asus.client import AsusAuthError, AsusClient, AsusError, build_snapshot, parse_onboarding
from app.plugins.builtin.asus.config import AsusConfig, normalize_url
from app.plugins.builtin.asus.plugin import to_topology

AUTH = {"Authorization": "Bearer secret"}
MAIN, N1, N2 = "aa:00:00:00:00:10", "aa:00:00:00:00:20", "aa:00:00:00:00:30"

NODES = [
    {"alias": "Main", "model_name": "RT-AX92U", "ip": "10.0.0.1", "mac": MAIN.upper(), "re_path": "0", "ap2g": MAIN.upper(),
     "wired_mac": [N1.upper()]},
    {"alias": "Garden", "model_name": "RT-AX92U", "ip": "10.0.0.50", "mac": N1.upper(), "re_path": "1", "wired_mac": []},
    {"alias": "Attic", "model_name": "RT-AX92U", "ip": "10.0.0.60", "mac": N2.upper(), "re_path": "1", "wired_mac": []},
]
ONBOARDING = "﻿get_onboardinglist = [{}][0];\nget_cfg_clientlist = [" + json.dumps(NODES) + "];\nnext = 1;"


def _client_entry(mac, ip, wl="0", node="", online="1", name=""):
    return {"mac": mac.upper(), "ip": ip, "isWL": wl, "amesh_papMac": node.upper(), "isOnline": online, "name": name}


CLIENTS = {"get_clientlist": {
    "maclist": ["x"],
    "ClientAPILevel": "1",
    "02:00:00:00:00:01": _client_entry("02:00:00:00:00:01", "10.0.0.11", "0", "", name="wired on main"),
    "02:00:00:00:00:02": _client_entry("02:00:00:00:00:02", "10.0.0.12", "2", N1, name="wifi on garden"),
    "02:00:00:00:00:03": _client_entry("02:00:00:00:00:03", "10.0.0.13", "0", N1),
    "02:00:00:00:00:04": _client_entry("02:00:00:00:00:04", "10.0.0.14", "1", N2, online="0"),
}}


class FakeTransport:
    def __init__(self, login=None, fail_on=None):
        self.calls = []
        self.login = login if login is not None else {"asus_token": "TOK"}
        self.fail_on = fail_on

    def __call__(self, method, url, headers, data):
        path = url.split("8443", 1)[-1]
        self.calls.append((method, path, headers.get("Cookie")))
        if self.fail_on and self.fail_on in path:
            raise AsusError("boom")
        if path == "/login.cgi":
            return 200, json.dumps(self.login).encode()
        if path.startswith("/appGet.cgi"):
            return 200, json.dumps(CLIENTS).encode()
        if path == "/ajax_onboarding.asp":
            return 200, ONBOARDING.encode()
        if path == "/Logout.asp":
            return 200, b""
        return 404, b""


CFG = AsusConfig(enabled=True, url="10.0.0.1", username="u", password="pw")


def test_normalize_url():
    assert normalize_url("192.168.0.1") == "https://192.168.0.1:8443"
    assert normalize_url("https://r.lan:9443/") == "https://r.lan:9443"
    assert normalize_url("http://192.168.0.1") == "http://192.168.0.1"
    assert normalize_url("") == ""
    for bad in ("ftp://x", "https://x/admin"):
        with pytest.raises(ValueError):
            normalize_url(bad)


def test_parse_onboarding_and_snapshot():
    nodes = parse_onboarding(ONBOARDING)
    assert [n["alias"] for n in nodes] == ["Main", "Garden", "Attic"]
    snap = build_snapshot(CLIENTS, nodes)
    assert [n["main"] for n in snap["nodes"]] == [True, False, False]
    assert snap["nodes"][0]["wired_macs"] == [N1]
    assert {c["mac"] for c in snap["clients"]} == {"02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03"}  # offline one dropped
    wifi = next(c for c in snap["clients"] if c["mac"].endswith(":02"))
    assert wifi == {"mac": "02:00:00:00:00:02", "ip": "10.0.0.12", "name": "wifi on garden", "wired": False, "band": "5 GHz", "node_mac": N1}
    assert next(c for c in snap["clients"] if c["mac"].endswith(":01"))["node_mac"] is None
    with pytest.raises(AsusError):
        parse_onboarding("nothing here")


def test_client_logs_in_reads_and_always_logs_out():
    t = FakeTransport()
    snap = AsusClient(CFG, transport=t).snapshot()
    assert len(snap["nodes"]) == 3
    assert [c[1] for c in t.calls] == ["/login.cgi", "/appGet.cgi?hook=get_clientlist()", "/ajax_onboarding.asp", "/Logout.asp"]
    assert t.calls[1][2] == "asus_token=TOK" and t.calls[0][2] is None

    t = FakeTransport(fail_on="ajax_onboarding")
    with pytest.raises(AsusError):
        AsusClient(CFG, transport=t).snapshot()
    assert t.calls[-1][1] == "/Logout.asp"  # no session left open after an error


def test_refused_login_is_one_attempt_and_no_logout():
    t = FakeTransport(login={"error_status": "3"})
    with pytest.raises(AsusAuthError) as exc:
        AsusClient(CFG, transport=t).snapshot()
    assert "username and password" in str(exc.value)
    assert [c[1] for c in t.calls] == ["/login.cgi"]

    t = FakeTransport(login={"error_status": "7"})
    with pytest.raises(AsusAuthError) as exc:
        AsusClient(CFG, transport=t).snapshot()
    assert "blocked" in str(exc.value)


def test_to_topology_follows_the_plugin_contract():
    from app.plugins.contract import validate_output

    topo = to_topology(build_snapshot(CLIENTS, parse_onboarding(ONBOARDING)))
    out = validate_output("topology", topo)  # what the router plugin returns must pass the validator
    roles = {n["name"]: (n["role"], n["parent_mac"]) for n in out["nodes"]}
    assert roles == {"Main": ("gateway", None), "Garden": ("node", MAIN), "Attic": ("node", MAIN)}
    by_mac = {c["mac"]: c for c in out["clients"]}
    assert by_mac["02:00:00:00:00:01"]["node_mac"] == MAIN and by_mac["02:00:00:00:00:01"]["medium"] == "wired"  # no node = the router
    assert by_mac["02:00:00:00:00:02"]["node_mac"] == N1 and by_mac["02:00:00:00:00:02"]["band"] == "5 GHz"
    assert "02:00:00:00:00:04" not in by_mac  # offline clients are left out


def test_a_node_wired_to_another_node_hangs_below_it():
    nodes = [dict(n) for n in NODES]
    nodes[1]["wired_mac"] = [N2.upper()]  # Garden is wired to... Attic is wired to Garden
    topo = to_topology(build_snapshot(CLIENTS, parse_onboarding("get_cfg_clientlist = [" + json.dumps(nodes) + "];")))
    assert {n["name"]: n["parent_mac"] for n in topo["nodes"]}["Attic"] == N1


def test_auth_error_is_flagged_for_the_core():
    assert AsusAuthError.auth_failed is True
