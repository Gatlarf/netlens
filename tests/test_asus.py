import json

import pytest

from tests.plugin_modules import load

_asus = load("asus")
AsusAuthError, AsusClient, AsusError, build_snapshot, parse_onboarding = _asus.AsusAuthError, _asus.AsusClient, _asus.AsusError, _asus.build_snapshot, _asus.parse_onboarding
AsusConfig, normalize_url, to_topology = _asus.AsusConfig, _asus.normalize_url, _asus.to_topology

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
    entry = {"mac": mac.upper(), "ip": ip, "isWL": wl, "amesh_papMac": node.upper(), "isOnline": online, "name": name}
    if wl != "0":
        entry.update(rssi="-61", curTx="72.2", curRx="1")
    return entry


CLIENTS = {"get_clientlist": {
    "maclist": ["x"],
    "ClientAPILevel": "1",
    "02:00:00:00:00:01": _client_entry("02:00:00:00:00:01", "10.0.0.11", "0", "", name="wired on main"),
    "02:00:00:00:00:02": _client_entry("02:00:00:00:00:02", "10.0.0.12", "2", N1, name="wifi on garden"),
    "02:00:00:00:00:03": _client_entry("02:00:00:00:00:03", "10.0.0.13", "0", N1),
    "02:00:00:00:00:04": _client_entry("02:00:00:00:00:04", "10.0.0.14", "1", N2, online="0"),
}}


NETDEV = {"netdev": {"BRIDGE_rx": "0x2094588f9", "BRIDGE_tx": "0x16b900fbbe", "INTERNET_rx": "0x168c4afc2e", "INTERNET_tx": "0x203cf8d7d", "WIRED_rx": "0x23dfe321d", "WIRED_tx": "0x16ec0cfaa8",
                    "WIRELESS0_rx": "0x56a36a2", "WIRELESS0_tx": "0xa7cccf2", "WIRELESS1_rx": "0x0", "WIRELESS1_tx": "0x7776f07", "WIRELESS2_rx": "0xb8a836", "WIRELESS2_tx": "0x92fb135"}}


HOOKS = {
    "/appGet.cgi?hook=cpu_usage(appobj)": {"cpu_usage": {"cpu1_total": "1000", "cpu1_usage": "100", "cpu2_total": "1000", "cpu2_usage": "300"}},
    "/appGet.cgi?hook=memory_usage(appobj)": {"memory_usage": {"mem_total": "524288", "mem_free": "131072", "mem_used": "393216"}},
    "/appGet.cgi?hook=get_cpu_temperature()": {"get_cpu_temperature": "61.589"},
    "/appGet.cgi?hook=get_wan_lan_status()": {"get_wan_lan_status": {"portSpeed": {"WAN 0": "G", "LAN 1": "X", "LAN 2": "M", "LAN 3": "G", "LAN 4": "X"}, "portCount": {"wanCount": 1, "lanCount": 4}}},
}


class FakeTransport:
    def __init__(self, login=None, fail_on=None):
        self.calls = []
        self.login = login if login is not None else {"asus_token": "TOK"}
        self.fail_on = fail_on
        self.apps = self.devices = None
        self.netdev = True

    def __call__(self, method, url, headers, data):
        path = url.split("8443", 1)[-1]
        self.calls.append((method, path, headers.get("Cookie")))
        if self.fail_on and self.fail_on in path:
            raise AsusError("boom")
        if path == "/login.cgi":
            return 200, json.dumps(self.login).encode()
        if path == "/appGet.cgi?hook=uptime()":
            return 200, json.dumps({"uptime": "Thu, 22 Oct 2026 23:50:00 +0200(1 secs since boot)"}).encode()
        if path.startswith("/getWanTraffic.asp") and "mode=detail" in path:
            return (200, self.apps) if self.apps else (404, b"")
        if path.startswith("/getAppTraffic.asp"):
            return (200, self.devices) if self.devices else (404, b"")
        if path == "/appGet.cgi?hook=netdev(appobj)":
            return (200, json.dumps(NETDEV).encode()) if self.netdev else (404, b"")
        if path in HOOKS and self.netdev:
            return 200, json.dumps(HOOKS[path]).encode()
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
    assert wifi == {"mac": "02:00:00:00:00:02", "ip": "10.0.0.12", "name": "wifi on garden", "wired": False, "band": "5 GHz", "node_mac": N1,
                    "rssi": -61, "tx_mbps": 72.2, "rx_mbps": 1.0, "vendor": None, "printer": False}
    assert next(c for c in snap["clients"] if c["mac"].endswith(":01"))["rssi"] is None  # wired: no signal
    assert next(c for c in snap["clients"] if c["mac"].endswith(":01"))["node_mac"] is None
    with pytest.raises(AsusError):
        parse_onboarding("nothing here")


def test_client_logs_in_reads_and_always_logs_out():
    t = FakeTransport()
    snap = AsusClient(AsusConfig(url=CFG.url, username=CFG.username, password=CFG.password, traffic=False), transport=t).snapshot()
    assert len(snap["nodes"]) == 3
    paths = [c[1] for c in t.calls]
    assert paths[:3] == ["/login.cgi", "/appGet.cgi?hook=get_clientlist()", "/ajax_onboarding.asp"] and paths[-1] == "/Logout.asp"
    assert paths.count("/login.cgi") == 3 and paths.count("/Logout.asp") == 3                       # the router and the two nodes that are online
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


def _answer(rows):
    return ("\ufeffvar array_statistics = new Array();\narray_statistics = " + json.dumps(rows) + ";\n").encode()


def test_traffic_analyzer_gives_usage_per_application_and_device():
    from datetime import datetime, timezone

    t = FakeTransport()
    t.apps = _answer([["Netflix", 100, 5000], ["DNS", 0, 0], ["Claude", 20, 30]])
    t.devices = _answer([["02:00:00:00:00:01".upper(), 10, 900], ["bad", 1, 1]])
    snap = AsusClient(CFG, transport=t).snapshot()
    days = [u["day"] for u in snap["usage"]]
    assert days == ["2026-10-22", "2026-10-21"]                       # the router's own date, today first
    today = snap["usage"][0]
    assert today["applications"] == [{"name": "Netflix", "tx_bytes": 100, "rx_bytes": 5000}, {"name": "Claude", "tx_bytes": 20, "rx_bytes": 30}]
    # today's applications per device: one read per device, with the device's address as the router wrote it
    assert today["clients"] == [{"mac": "02:00:00:00:00:01", "tx_bytes": 10, "rx_bytes": 900,
                                 "applications": [{"name": "Netflix", "tx_bytes": 100, "rx_bytes": 5000}, {"name": "Claude", "tx_bytes": 20, "rx_bytes": 30}]}]
    assert any("getWanTraffic.asp?client=02:00:00:00:00:01&" in c[1] for c in t.calls)
    assert "applications" not in snap["usage"][1]["clients"][0] if snap["usage"][1]["clients"] else True      # only today is read per device
    end = [c[1] for c in t.calls if c[1].startswith("/getWanTraffic")][0]
    # the day that ends at the router's midnight (+02:00): 2026-10-23 00:00 +02:00
    assert f"date={int(datetime(2026, 10, 22, 22, 0, tzinfo=timezone.utc).timestamp())}" in end
    from app.plugins.contract import validate_output
    out = validate_output("topology", to_topology(snap))
    assert out["usage"][0]["applications"][0] == {"name": "Netflix", "rx_bytes": 5000, "tx_bytes": 100}


def test_a_router_without_traffic_analyzer_still_syncs():
    t = FakeTransport()          # both pages answer 404
    snap = AsusClient(CFG, transport=t).snapshot()
    assert snap["usage"] == [] and len(snap["nodes"]) == 3


def test_netlens_switch_for_application_statistics_has_the_last_word(monkeypatch):
    t = FakeTransport()
    t.apps = _answer([["Netflix", 100, 5000]])
    t.devices = _answer([["02:00:00:00:00:01", 10, 900]])
    monkeypatch.setattr(_asus, "CLIENT_FACTORY", lambda cfg: AsusClient(cfg, transport=t))
    base = {"url": "10.0.0.1", "username": "u", "password": "pw", "traffic": True}
    assert _asus.fetch({**base, "collect_usage": True})["usage"] != []
    t.calls.clear()
    assert _asus.fetch({**base, "collect_usage": False})["usage"] == []
    assert not [c for c in t.calls if "Traffic" in c[1]]          # nothing was even asked
    assert _asus.fetch(base)["usage"] != []                      # an older Netlens does not send the flag: unchanged


def test_the_router_and_every_node_report_their_health_and_ports():
    from app.plugins.contract import validate_output

    snap = AsusClient(CFG, transport=FakeTransport()).snapshot()
    out = validate_output("topology", to_topology(snap))
    by_name = {n["name"]: n for n in out["nodes"]}
    gateway = by_name["Main"]
    assert [m["metric"] for m in gateway["metrics"]] == ["cpu_pct", "mem_pct", "temp_c", "uptime_s"]
    cpu = gateway["metrics"][0]
    assert cpu["used"] == 400 and cpu["total"] == 2000 and gateway["metrics"][1]["value"] == 75.0 and gateway["metrics"][2]["value"] == 61.6
    ports = {p["name"]: p for p in gateway["ports"]}
    assert ports["WAN"]["rx_bytes"] == 0x168C4AFC2E and ports["WAN"]["port"] == 1 and ports["LAN"]["tx_bytes"] == 0x16EC0CFAA8
    assert ports["LAN 1"]["up"] is False and ports["LAN 2"]["speed_mbps"] == 100 and ports["LAN 3"]["speed_mbps"] == 1000 and ports["WAN port"]["up"] is True
    for name in ("Garden", "Attic"):                                                                    # the nodes were asked too
        assert [m["metric"] for m in by_name[name]["metrics"]][0] == "cpu_pct" and any(p["name"] == "LAN 3" for p in by_name[name]["ports"])


def test_the_firmware_of_a_node_and_the_update_waiting():
    nodes = [dict(n, fwver="3.0.0.4.388_1", newfwver="3.0.0.4.388_2") if i == 0 else dict(n, fwver="3.0.0.4.388_1") for i, n in enumerate(NODES)]
    snap = build_snapshot(CLIENTS, parse_onboarding("get_cfg_clientlist = [" + json.dumps(nodes) + "];"))
    from app.plugins.contract import validate_output

    checked = validate_output("topology", to_topology(snap))["nodes"]
    assert checked[0]["firmware"]["latest"] == "3.0.0.4.388_2" and checked[1]["firmware"]["latest"] is None             # the same version is no update


def test_a_node_that_refuses_the_login_is_skipped_and_the_others_still_count():
    class Picky(FakeTransport):
        def __call__(self, method, url, headers, data):
            if "10.0.0.50" in url:
                return 200, json.dumps({"error_status": "2"}).encode()                     # wrong password on the node
            return super().__call__(method, url, headers, data)

    snap = AsusClient(CFG, transport=Picky()).snapshot()
    nodes = {n["name"]: n for n in snap["nodes"]}
    assert not nodes["Garden"].get("metrics") and nodes["Attic"]["metrics"] and nodes["Main"]["metrics"]
    assert list(snap["node_errors"].values()) == ["login refused"]


def test_a_router_that_does_not_say_still_syncs_and_the_switches_turn_it_off():
    transport = FakeTransport()
    transport.netdev = False
    snap = AsusClient(CFG, transport=transport).snapshot()
    assert not snap["nodes"][0].get("ports") and "ports" not in to_topology(snap)["nodes"][0]
    for kwargs in ({"interfaces": False}, {"nodes": False}):
        quiet = FakeTransport()
        snap = AsusClient(AsusConfig(enabled=True, url="10.0.0.1", username="u", password="pw", **kwargs), transport=quiet).snapshot()
        logins = [c for c in quiet.calls if c[1] == "/login.cgi"]
        assert len(logins) == 1                                                                   # only the main router
        assert bool(snap["nodes"][0].get("metrics")) == ("interfaces" not in kwargs)
