"""Traffic per application and per device as a router reports it: contract, storage, Statistics, and port byte counters."""

import sqlite3

import pytest

from app.db import init_db
from app.plugins.contract import ContractError, validate_output
from app.plugins.enrich import record_switch_ports, record_usage
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
    assert data()["usage"][0]["clients"][0] == {"mac": "02:00:00:00:00:01", "rx_bytes": 900, "tx_bytes": 10}
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
    assert compute_stats(conn, "7d", NOW)["applications"] == {"available": False}
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
