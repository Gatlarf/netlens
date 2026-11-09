"""Advice to lock a device that does not move to the access point that served it best."""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app import wifipin
from app.db import init_db

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
STAMP = "%Y-%m-%dT%H:%M:%SZ"


@pytest.fixture
def conn(tmp_path):
    c = sqlite3.connect(tmp_path / "t.db")
    c.row_factory = sqlite3.Row
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, custom_name, online, device_type, first_seen, last_seen) VALUES (1, '02:00:00:00:00:01', '10.0.0.5', 'p1', 1, 'server', 'x', 'x')")
    c.commit()
    return c


def fill(conn, plan, roams=3, outages_on=()):
    t = NOW - timedelta(days=3)
    for node, rssi, n in plan:
        for _ in range(n):
            t += timedelta(minutes=10)
            conn.execute("INSERT INTO wifi_samples (device_id, ts, node, band, rssi) VALUES (1, ?, ?, '2.4 GHz', ?)", (t.strftime(STAMP), node, rssi))
    for i in range(roams):
        conn.execute("INSERT INTO events (ts, device_id, kind, detail) VALUES (?, 1, 'wifi_roamed', 'Basement -> Office (2.4 GHz)')", ((NOW - timedelta(days=2, hours=i)).strftime(STAMP),))
    conn.commit()


def test_a_fixed_device_hopping_between_access_points_is_told_to_lock_to_the_best(conn):
    fill(conn, [("Office", -75, 30), ("Basement", -55, 60)])
    out = wifipin.advice(conn, 1, now=NOW)
    assert out["best"] == "Basement" and "locking it to Basement" in out["suggestion"] and "-55" in out["suggestion"]
    assert out["access_points"][0]["node"] == "Basement"


def test_no_advice_when_the_signals_are_alike_or_the_device_may_move(conn):
    fill(conn, [("Office", -60, 30), ("Basement", -58, 30)])
    assert wifipin.advice(conn, 1, now=NOW)["suggestion"] is None
    conn.execute("UPDATE devices SET device_type = 'phone'")
    conn.execute("DELETE FROM wifi_samples")
    conn.commit()
    fill(conn, [("Office", -80, 30), ("Basement", -50, 30)])
    assert wifipin.advice(conn, 1, now=NOW)["suggestion"] is None


def test_nothing_for_one_access_point_or_a_device_that_never_roamed(conn):
    fill(conn, [("Basement", -55, 40)], roams=0)
    assert wifipin.advice(conn, 1, now=NOW) is None
    assert wifipin.advice(conn, 99, now=NOW) is None


def test_ask_names_the_advice(conn):
    from app import ask

    fill(conn, [("Office", -75, 30), ("Basement", -55, 60)])
    out = ask.t_device(conn, {"name": "p1"}, NOW)
    assert out["wifi"]["best"] == "Basement"
    assert "Consider locking it to Basement" in ask.render("device", out)
