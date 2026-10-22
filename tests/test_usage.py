"""Traffic per application and per device as a router reports it: contract, storage, Statistics, and port byte counters."""

import sqlite3

import pytest

from app.db import init_db
from app.plugins.contract import ContractError, validate_output
from app.plugins.enrich import record_switch_ports, record_usage
from app import usagecfg
from app.stats import compute_stats

NOW = "2026-10-22T12:00:00Z"


@pytest.fixture
def conn(tmp_path):
    c = sqlite3.connect(tmp_path / "t.db")
    c.row_factory = sqlite3.Row
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, custom_name, online, first_seen, last_seen) VALUES (1, '02:00:00:00:00:01', '10.0.0.5', 'laptop', 1, 'x', 'x')")
    c.commit()
    return c


def data(day="2026-10-22", apps=(("Netflix", 100, 5000),), clients=(("02:00:00:00:00:01", 10, 900), ("02:00:00:00:00:99", 1, 1))):
    return validate_output("topology", {"nodes": [], "clients": [], "usage": [{
        "day": day, "applications": [{"name": n, "tx_bytes": t, "rx_bytes": r} for n, t, r in apps],
        "clients": [{"mac": m, "tx_bytes": t, "rx_bytes": r} for m, t, r in clients]}]})


def test_the_contract_checks_the_usage_part():
    assert data()["usage"][0]["clients"][0] == {"mac": "02:00:00:00:00:01", "rx_bytes": 900, "tx_bytes": 10, "applications": []}
    with pytest.raises(ContractError):
        validate_output("topology", {"nodes": [], "clients": [], "usage": [{"day": "yesterday"}]})
    assert validate_output("topology", {"nodes": [], "clients": []})["usage"] == []


def test_the_latest_figure_of_a_day_replaces_the_earlier_one(conn):
    record_usage(conn, "asus", data(), NOW)
    record_usage(conn, "asus", data(apps=(("Netflix", 300, 9000), ("Claude", 1, 2))), NOW)
    rows = {r["name"]: (r["rx_bytes"], r["tx_bytes"]) for r in conn.execute("SELECT * FROM app_usage")}
    assert rows == {"Netflix": (9000, 300), "Claude": (2, 1)}
    # only devices Netlens knows are kept
    assert [(r["device_id"], r["rx_bytes"]) for r in conn.execute("SELECT * FROM client_usage")] == [(1, 900)]


def test_statistics_add_up_the_days_in_the_range(conn):
    usagecfg.set_enabled(conn, True)
    assert compute_stats(conn, "7d", NOW)["applications"] == {"available": False, "enabled": True}
    record_usage(conn, "asus", data(day="2026-10-22"), NOW)
    record_usage(conn, "asus", data(day="2026-10-21", apps=(("Netflix", 50, 1000), ("Steam", 5, 50))), NOW)
    record_usage(conn, "asus", data(day="2026-10-01", apps=(("Old", 9, 9),)), NOW)
    a = compute_stats(conn, "7d", NOW)["applications"]
    assert a["available"] and a["days"] == 2 and a["rx"] == 6050 and a["tx"] == 155
    assert [x["name"] for x in a["applications"]] == ["Netflix", "Steam"]
    assert a["applications"][0]["rx"] == 6000 and a["clients"][0]["name"] == "laptop"
    today = compute_stats(conn, "24h", NOW)["applications"]
    assert today["days"] == 1 and today["rx"] == 5000


def test_port_byte_counters_become_bits_per_second(conn, tmp_path, monkeypatch):
    from app import tsdb

    points = []

    class Store:
        def latest(self, *a):
            return None

        def record(self, pts, ts=None):
            points.extend(pts)

    monkeypatch.setattr(tsdb, "for_conn", lambda c: Store())
    node = lambda tx, rx: {"nodes": [{"macs": ["02:00:00:00:00:01"], "name": "sw", "mac": "02:00:00:00:00:01", "ports": [
        {"port": 3, "name": None, "enabled": True, "up": True, "speed_mbps": 1000, "duplex": "full", "tx_bytes": tx, "rx_bytes": rx}]}]}
    record_switch_ports(conn, "omada", node(1000, 2000), "2026-10-22T12:00:00Z")
    record_switch_ports(conn, "omada", node(11000, 4000), "2026-10-22T12:00:10Z")
    got = {p[2]: p[3] for p in points if p[2].startswith("net_")}
    assert got == {"net_tx_bps": 8000.0, "net_rx_bps": 1600.0}


def with_apps(day="2026-10-22"):
    return validate_output("topology", {"nodes": [], "clients": [], "usage": [{
        "day": day, "applications": [{"name": "Netflix", "tx_bytes": 100, "rx_bytes": 5000}],
        "clients": [{"mac": "02:00:00:00:00:01", "tx_bytes": 10, "rx_bytes": 900,
                     "applications": [{"name": "Netflix", "tx_bytes": 7, "rx_bytes": 800}, {"name": "Steam", "tx_bytes": 3, "rx_bytes": 100}, {"name": "Netflix", "tx_bytes": 1, "rx_bytes": 1}]}]}]})


def test_applications_per_device_replace_the_day_and_keep_the_biggest_first(conn):
    out = with_apps()["usage"][0]["clients"][0]["applications"]
    assert [a["name"] for a in out] == ["Netflix", "Steam"]            # a repeated name is ignored
    record_usage(conn, "asus", with_apps(), NOW)
    record_usage(conn, "asus", validate_output("topology", {"nodes": [], "clients": [], "usage": [{
        "day": "2026-10-22", "applications": [], "clients": [{"mac": "02:00:00:00:00:01", "tx_bytes": 1, "rx_bytes": 2, "applications": [{"name": "Steam", "tx_bytes": 5, "rx_bytes": 6}]}]}]}), NOW)
    assert [(r["name"], r["rx_bytes"]) for r in conn.execute("SELECT * FROM client_app_usage")] == [("Steam", 6)]       # Netflix is gone from today's list


def test_a_device_without_an_application_list_keeps_what_it_had(conn):
    record_usage(conn, "asus", with_apps(), NOW)
    record_usage(conn, "asus", data(), NOW)                           # a sync that could not read the list
    assert conn.execute("SELECT COUNT(*) FROM client_app_usage").fetchone()[0] == 2


def test_nothing_is_kept_while_collecting_is_off_and_switching_off_removes_it(conn):
    assert usagecfg.enabled(conn) is False                            # off until an administrator turns it on
    record_usage(conn, "asus", with_apps(), NOW)
    assert usagecfg.stored_rows(conn) > 0
    before = usagecfg.stored_rows(conn)
    assert usagecfg.set_enabled(conn, False) == before
    assert usagecfg.stored_rows(conn) == 0 and compute_stats(conn, "7d", NOW)["applications"] == {"available": False, "enabled": False}


def test_api_switch_and_device_applications(tmp_path):
    from datetime import datetime, timezone

    from fastapi.testclient import TestClient

    from app.config import load_settings
    from app.db import connect, get_or_create_device
    from app.main import create_app

    path = tmp_path / "a.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as c:
        conn = connect(path)
        device = get_or_create_device(conn, "02:00:00:00:00:01", "10.0.0.5")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert c.get("/api/usage").json() == {"enabled": False, "stored_rows": 0}
        assert c.get(f"/api/devices/{device}/applications").json() == {"enabled": False, "available": False}
        assert c.put("/api/usage", json={"enabled": True}).json()["enabled"] is True
        assert c.get(f"/api/devices/{device}/applications").json() == {"enabled": True, "available": False}
        record_usage(conn, "asus", with_apps(today), now)
        body = c.get(f"/api/devices/{device}/applications?days=7").json()
        assert body["available"] and body["rx"] == 900 and [a["name"] for a in body["applications"]] == ["Netflix", "Steam"]
        assert body["applications"][0]["share"] == round(100 * 807 / 910, 1) or body["applications"][0]["share"] > 0
        assert c.get("/api/stats?range=7d").json()["applications"]["available"] is True
        assert c.get("/api/devices/9999/applications").status_code == 404
        removed = c.put("/api/usage", json={"enabled": False}).json()["removed_rows"]
        assert removed >= 4 and c.get("/api/usage").json() == {"enabled": False, "stored_rows": 0}
        assert c.get("/api/stats?range=7d").json()["applications"]["available"] is False
        # a viewer may not read or change the switch
        assert c.get("/api/usage", headers={"Authorization": "Bearer nope"}).status_code in (401, 403)
