import json

import pytest

from app import configchange as cc
from app.db import connect, get_or_create_device, init_db
from app.plugins import contract


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    get_or_create_device(c, "aa:bb:cc:00:00:01", "192.168.0.1")
    yield c
    c.close()


def data(items, failed=None):
    node = {"mac": "aa:bb:cc:00:00:01", "macs": ["aa:bb:cc:00:00:01"], "ip": "192.168.0.1", "name": "Router", "config": [{"key": k, "value": v} for k, v in items.items()]}
    if failed:
        node["config_failed"] = failed
    return {"nodes": [node], "clients": []}


def events(conn):
    return [r["detail"] for r in conn.execute("SELECT detail FROM events WHERE kind = 'config_changed' ORDER BY id")]


def test_diff():
    d = cc.diff({"a": "1", "b": "2", "c": "3"}, {"a": "1", "b": "9", "d": "4"})
    assert d == {"added": [{"key": "d", "value": "4"}], "removed": [{"key": "c", "value": "3"}], "changed": [{"key": "b", "before": "2", "after": "9"}]}


def test_first_set_is_a_baseline_and_a_change_raises_one_event(conn):
    cc.record(conn, "asus", data({"wan.proto": "dhcp", "upnp": "1"}), "2026-11-10T10:00:00Z")
    assert events(conn) == []
    cc.record(conn, "asus", data({"wan.proto": "dhcp", "upnp": "1"}), "2026-11-10T11:00:00Z")
    assert events(conn) == []                                                   # same: nothing
    out = cc.record(conn, "asus", data({"wan.proto": "dhcp", "upnp": "0", "ssh": "1"}), "2026-11-10T12:00:00Z")
    assert out["changed"] == 1 and len(events(conn)) == 1 and "1 changed, 1 added" in events(conn)[0] and "upnp" in events(conn)[0]
    info = cc.for_device(conn, 1)
    assert info["items"] == 3 and info["changes"][0]["changed"] == [{"key": "upnp", "before": "1", "after": "0"}]


def test_a_section_that_could_not_be_read_is_not_a_change(conn):
    cc.record(conn, "unifi", data({"firewall.1": "allow", "firewall.2": "deny", "wifi.ssid": "Home"}), "2026-11-10T10:00:00Z")
    cc.record(conn, "unifi", data({"wifi.ssid": "Home"}, failed=["firewall"]), "2026-11-10T11:00:00Z")
    assert events(conn) == [] and cc.for_device(conn, 1)["items"] == 3
    cc.record(conn, "unifi", data({"wifi.ssid": "Home"}), "2026-11-10T12:00:00Z")      # not failed this time: the rules really are gone
    assert len(events(conn)) == 1 and "2 removed" in events(conn)[0]


def test_unknown_device_and_retention(conn):
    d = data({"a": "1"})
    d["nodes"][0].update(macs=["aa:bb:cc:99:99:99"], ip="10.9.9.9")
    assert cc.record(conn, "x", d)["devices"] == 0
    for i in range(cc.KEEP_CHANGES + 5):
        cc.record(conn, "x", data({"a": str(i)}), f"2026-11-10T10:{i // 60:02d}:{i % 60:02d}Z")
    assert conn.execute("SELECT COUNT(*) FROM config_changes").fetchone()[0] == cc.KEEP_CHANGES


def test_contract_drops_secret_looking_keys_and_clamps():
    out = contract.validate_output("topology", {"nodes": [{"mac": "aa:bb:cc:00:00:01", "config": [
        {"key": "wifi.ssid", "value": "Home"}, {"key": "wifi.password", "value": "hunter2"}, {"key": "wl0_wpa_psk", "value": "x"},
        {"key": "snmp.community", "value": "public"}, {"key": "api_key", "value": "k"}, {"key": "upnp", "value": True}, {"key": "wifi.ssid", "value": "dup"},
        {"key": "long", "value": "x" * 1000}]}], "clients": []})
    cfg = {i["key"]: i["value"] for i in out["nodes"][0]["config"]}
    assert set(cfg) == {"wifi.ssid", "upnp", "long"} and cfg["upnp"] == "true" and cfg["wifi.ssid"] == "Home" and len(cfg["long"]) == 300


def test_a_node_without_config_is_unchanged_by_the_contract():
    out = contract.validate_output("topology", {"nodes": [{"mac": "aa:bb:cc:00:00:01"}], "clients": []})
    assert "config" not in out["nodes"][0]


def test_api_admin_only_and_empty(tmp_path):
    from fastapi.testclient import TestClient
    from app.config import load_settings
    from app.main import create_app

    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    c0 = connect(tmp_path / "t.db")
    init_db(c0)
    get_or_create_device(c0, "aa:bb:cc:00:00:01", "192.168.0.1")
    cc.record(c0, "asus", data({"a": "1"}), "2026-11-10T10:00:00Z")
    cc.record(c0, "asus", data({"a": "2"}), "2026-11-10T11:00:00Z")
    c0.close()
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as c:
        r = c.get("/api/devices/1/config").json()
        assert r["items"] == 1 and r["changes"][0]["changed"][0]["after"] == "2"
        assert c.get("/api/devices/999/config").status_code == 404
        assert len(c.get("/api/config-changes").json()["changes"]) >= 0
        anon = TestClient(app)
        c.post("/api/users", json={"username": "vera", "password": "longenough1", "role": "viewer"})
        anon.post("/api/login", json={"username": "vera", "password": "longenough1"})
        assert anon.get("/api/devices/1/config").status_code == 403 and anon.get("/api/config-changes").status_code == 403
