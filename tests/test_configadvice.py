import json

import pytest

from app import configadvice as ca
from app import configchange as cc
from app.db import connect, get_or_create_device, init_db

# The real settings of an ASUS router (a live read, 2026-11-11): the secondary DNS server has a mistyped first number.
LIVE = {
    "wan.proto": "static", "wan.dns_auto": "0", "wan.dns1": "192.168.0.181", "wan.dns2": "102.168.0.200", "wan.nat": "1", "lan.ip": "192.168.0.1", "lan.dhcp": "1",
    "lan.dhcp_dns1": "192.168.0.181", "lan.dhcp_dns2": "", "wifi.2g.ssid": "home", "wifi.2g.auth": "psk2", "wifi.5g.ssid": "home", "wifi.5g.auth": "psk2", "wifi.wps": "1",
    "admin.http": "2", "admin.wan_access": "0", "admin.ssh": "0", "admin.ssh_wan": "", "admin.telnet": "0", "nat.upnp": "1", "nat.dmz": "", "security.firewall": "1",
}


def ids(items, plugin="asus", known=None):
    return {f["id"]: f for f in ca.evaluate(plugin, items, known)[0]}


def test_the_live_router_gets_the_typo_the_upnp_and_the_wps_findings_and_nothing_loud_besides():
    got = ids(LIVE, known={"192.168.0.181": "pihole"})
    assert got["dns-typo:102.168.0.200"]["status"] == "risk" and "192.168.0.200" in got["dns-typo:102.168.0.200"]["evidence"]
    assert {"upnp", "wps", "http-admin", "dns-single:lan.dhcp_dns1"} <= set(got)
    assert "pihole" in got["dns-single:lan.dhcp_dns1"]["evidence"]
    assert not {"remote-admin", "telnet", "firewall-off", "dmz"} & set(got)


def test_titles_carry_no_address_or_name_because_the_dashboard_shows_them_to_everybody():
    for f in ids(LIVE).values():
        assert "102.168" not in f["title"] and "192.168" not in f["title"]


@pytest.mark.parametrize("change,finding", [
    ({"admin.wan_access": "1"}, "remote-admin"), ({"admin.telnet": "1"}, "telnet"), ({"admin.ssh": "1", "admin.ssh_wan": "1"}, "ssh-wan"),
    ({"security.firewall": "0"}, "firewall-off"), ({"nat.dmz": "192.168.0.50"}, "dmz"), ({"admin.http": "0"}, "http-admin"),
    ({"wifi.2g.auth": "open"}, "wifi-open:2.4 GHz (home)"), ({"wifi.5g.auth": "shared"}, "wifi-old:5 GHz (home)"), ({"wifi.5g.auth": "pskpsk2"}, "wifi-legacy:5 GHz (home)"),
    ({"portforward.RDP": "3389 192.168.0.9 3389 TCP"}, "forward-risky:RDP"),
])
def test_each_rule_fires(change, finding):
    assert finding in ids({**LIVE, **change})


def test_a_clean_configuration_has_no_loud_findings():
    clean = {**LIVE, "wan.dns2": "192.168.0.200", "lan.dhcp_dns2": "192.168.0.200", "nat.upnp": "0", "wifi.wps": "0", "admin.http": "1"}
    assert ids(clean) == {}


def test_a_public_resolver_next_to_a_local_one_is_a_warning_not_a_typo():
    got = ids({**LIVE, "wan.dns2": "1.1.1.1"})
    assert got["dns-mixed:1.1.1.1"]["status"] == "warn" and not any(k.startswith("dns-typo") for k in got)


def test_a_setting_the_plugin_does_not_report_never_fires():
    assert ids({"wan.proto": "dhcp"}) == {}


def test_the_typo_helper():
    assert ca.typo_of_private("102.168.0.200") == "192.168.0.200" and ca.typo_of_private("8.8.8.8") is None and ca.typo_of_private("192.168.0.1") is None


def test_unifi_and_omada_wifi_and_rules():
    unifi = {"wifi.Guest.security": "open", "wifi.Home.security": "wpapsk", "wifi.Home.wpa_mode": "wpa2", "wifi.Home.wpa_enc": "tkip", "wifi.Off.security": "open", "wifi.Off.enabled": "false",
             "portforward.NAS": "tcp 445 -> 192.168.1.5:445 enabled=true", "portforward.Web": "tcp 443 -> 192.168.1.5:443 enabled=true", "firewall.LAN_IN.allow all": "accept all from any to any enabled=true"}
    got = ids(unifi, "unifi")
    assert {"wifi-open:Guest", "wifi-legacy:Home", "forward-risky:NAS", "rule-any:LAN_IN.allow all"} <= set(got) and "wifi-open:Off" not in got and "forward-risky:Web" not in got
    assert {"wifi-open:Cafe", "wifi-old:Old"} <= set(ids({"wifi.Cafe.security": "0", "wifi.Old.security": "1", "wifi.Ok.security": "3"}, "omada"))


def test_a_plugin_without_rules_gets_none():
    assert not ca.supported("snmp")


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    get_or_create_device(c, "aa:bb:cc:00:00:01", "192.168.0.1")
    yield c
    c.close()


def data(items):
    return {"nodes": [{"mac": "aa:bb:cc:00:00:01", "macs": ["aa:bb:cc:00:00:01"], "ip": "192.168.0.1", "name": "Router", "config": [{"key": k, "value": v} for k, v in items.items()]}], "clients": []}


def advice_events(conn):
    return [r["detail"] for r in conn.execute("SELECT detail FROM events WHERE kind = 'config_advice' ORDER BY id")]


def test_events_only_for_what_is_new_and_the_first_evaluation_only_reports_risks(conn):
    cc.record(conn, "asus", data(LIVE), "2026-11-11T10:00:00Z", version="1.6.3")
    assert len(advice_events(conn)) == 1 and "typing mistake" in advice_events(conn)[0]          # warns (UPnP, WPS ...) wait for the second look
    cc.record(conn, "asus", data(LIVE), "2026-11-11T11:00:00Z", version="1.6.3")
    assert len(advice_events(conn)) == 1
    cc.record(conn, "asus", data({**LIVE, "admin.telnet": "1"}), "2026-11-11T12:00:00Z", version="1.6.3")
    assert len(advice_events(conn)) == 2 and "Telnet" in advice_events(conn)[1]


def test_accepting_a_finding_keeps_it_out_of_the_problem_list_but_visible(conn):
    cc.record(conn, "asus", data(LIVE), "2026-11-11T10:00:00Z", version="1.6.3")
    assert any(a["id"] == "upnp" for a in ca.attention(conn))
    ca.accept(conn, 1, "upnp", "game console", "bert")
    advice = ca.for_device(conn, 1)
    assert not any(a["id"] == "upnp" for a in ca.attention(conn)) and any(x["id"] == "upnp" and x["accepted"]["reason"] == "game console" for x in advice["accepted"])
    assert ca.unaccept(conn, 1, "upnp") and any(a["id"] == "upnp" for a in ca.attention(conn))


def test_a_plugin_upgrade_that_reads_more_settings_is_not_a_configuration_change(conn):
    few = {k: LIVE[k] for k in ("wan.proto", "wifi.2g.ssid", "security.firewall")}
    cc.record(conn, "asus", data(few), "2026-11-11T09:00:00Z", version="1.6.1")
    cc.record(conn, "asus", data(LIVE), "2026-11-11T10:00:00Z", version="1.6.2")
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'config_changed'").fetchone()[0] == 0
    cc.record(conn, "asus", data({**LIVE, "nat.upnp": "0"}), "2026-11-11T11:00:00Z", version="1.6.2")
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'config_changed'").fetchone()[0] == 1       # a real change at the same version still is one


def test_review_keeps_only_findings_that_cite_a_real_setting(conn):
    cc.record(conn, "asus", data(LIVE), "2026-11-11T10:00:00Z", version="1.6.3")
    seen = []

    def ask(messages):
        seen.append(messages)
        return 'Sure: [{"key": "nat.upnp", "title": "UPnP", "why": "w", "fix": "f", "severity": "high"}, {"key": "made.up", "title": "Invented", "why": "x", "fix": "y", "severity": "high"}]'

    out = ca.review(conn, 1, ask=ask)
    assert [x["key"] for x in out["items"]] == ["nat.upnp"] and not out["cached"]
    assert "UPnP is switched on" in seen[0][1]["content"] and "nat.upnp = 1" in seen[0][1]["content"]       # known findings and the settings go to the model
    assert ca.review(conn, 1, ask=ask)["cached"] and len(seen) == 1                                          # unchanged settings are not sent again
    cc.record(conn, "asus", data({**LIVE, "nat.upnp": "0"}), "2026-11-11T11:00:00Z", version="1.6.3")
    assert ca.last_review(conn, 1)["outdated"]


def test_review_without_a_model_is_refused(conn):
    cc.record(conn, "asus", data(LIVE), "2026-11-11T10:00:00Z", version="1.6.3")
    with pytest.raises(PermissionError):
        ca.review(conn, 1)
    assert json.dumps(ca.for_device(conn, 1))


@pytest.fixture
def client(tmp_path):
    from fastapi.testclient import TestClient
    from app.config import load_settings
    from app.main import create_app

    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as c:
        c.app_ = app
        yield c


def test_api_advice_accept_and_review(client):
    from fastapi.testclient import TestClient

    conn = connect(client.app_.state.db_path)
    init_db(conn)
    dev = get_or_create_device(conn, "aa:bb:cc:00:00:01", "192.168.0.1")
    cc.record(conn, "asus", data(LIVE), "2026-11-11T10:00:00Z", version="1.6.3")
    dev = conn.execute("SELECT id FROM devices").fetchone()[0]
    conn.close()
    a = client.get(f"/api/devices/{dev}/config/advice").json()
    assert a["rules"] and any(f["id"] == "upnp" for f in a["findings"]) and a["review"] is None and a["review_available"] is False
    assert client.put(f"/api/devices/{dev}/config/advice/upnp", json={"reason": ""}).status_code == 422
    assert client.put(f"/api/devices/{dev}/config/advice/nope", json={"reason": "x"}).status_code == 404
    done = client.put(f"/api/devices/{dev}/config/advice/upnp", json={"reason": "game console"}).json()
    assert [x["id"] for x in done["accepted"]] == ["upnp"]
    assert "upnp" not in {x["id"] for x in client.get("/api/config-advice").json()["findings"]}
    assert client.get(f"/api/devices/{dev}/config/advice").json()["accepted"][0]["accepted"]["who"]
    assert client.delete(f"/api/devices/{dev}/config/advice/upnp").status_code == 200
    assert client.post(f"/api/devices/{dev}/config/review").status_code == 409              # no model set up
    assert client.get("/api/devices/9999/config/advice").status_code == 404
    anon = TestClient(client.app_)
    client.post("/api/users", json={"username": "vera", "password": "longenough1", "role": "viewer"})
    anon.post("/api/login", json={"username": "vera", "password": "longenough1"})
    assert anon.get(f"/api/devices/{dev}/config/advice").status_code == 403 and anon.put(f"/api/devices/{dev}/config/advice/upnp", json={"reason": "x"}).status_code == 403
    assert anon.post(f"/api/devices/{dev}/config/review").status_code == 403


def test_recommendations_reach_the_dashboard_ask_and_mcp(conn):
    from app import ask_more, dashboard, mcp

    cc.record(conn, "asus", data(LIVE), "2026-11-11T10:00:00Z", version="1.6.3")
    items = dashboard._config_attention(conn)
    assert items and items[0]["level"] == "bad" and items[0]["href"] == "#/device/1" and "typing mistake" in items[0]["text"]
    r = ask_more.t_security(conn, {})
    assert any("typing mistake" in c["problem"] for c in r["config_recommendations"]) and "typing mistake" in ask_more.r_security(r)
    assert "get_config_advice" in mcp.TOOLS
