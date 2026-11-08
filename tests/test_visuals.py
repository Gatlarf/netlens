from datetime import datetime, timedelta, timezone

import pytest

from app import stats, visuals
from app.db import connect, init_db

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)


def stamp(minutes_ago):
    return (NOW - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "c.db")
    init_db(c)
    for i, name in enumerate(["switch", "nas", "camera"], 1):
        c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (?, ?, ?, ?, 1, 'x', 'x')", (i, f"aa:00:00:00:00:0{i}", f"10.0.0.{i}", name))
    c.execute("UPDATE devices SET parent_mode='none' WHERE id=1")
    c.execute("UPDATE devices SET parent_mode='device', parent_device_id=1 WHERE id=2")
    c.execute("UPDATE devices SET parent_mode='device', parent_device_id=2 WHERE id=3")
    c.commit()
    yield c
    c.close()


def test_the_calendar_has_a_percentage_per_day_outages_and_marks(conn):
    for hour, n, up in (("2026-11-06T10", 60, 60), ("2026-11-06T11", 60, 30), ("2026-11-07T10", 60, 60), ("2026-01-01T10", 60, 0)):
        conn.execute("INSERT INTO checks_hourly (device_id, hour, n, up) VALUES (2, ?, ?, ?)", (hour, n, up))
    conn.execute("INSERT INTO events (ts, device_id, kind, detail) VALUES ('2026-11-06T10:30:00Z', 2, 'device_offline', 'x')")
    conn.execute("INSERT INTO events (ts, device_id, kind, detail) VALUES ('2026-11-05T10:30:00Z', 2, 'firmware_update', 'firmware 2')")
    conn.commit()
    out = visuals.calendar(conn, 2, 30, now=NOW)
    assert out["days"] == [{"d": "2026-11-06", "pct": 75.0, "outages": 1}, {"d": "2026-11-07", "pct": 100.0, "outages": 0}]
    assert out["marks"] == [{"d": "2026-11-05", "kind": "firmware_update", "text": "firmware 2"}]
    assert len(visuals.calendar(conn, 2, 365, now=NOW)["days"]) == 3
    assert visuals.calendar(conn, 99, 30, now=NOW) is None


def test_a_cascade_orders_the_steps_and_keeps_what_the_devices_hang_below(conn):
    rows = [(60, 2, "device_offline", "nas offline"), (58, 3, "device_offline", "camera offline"), (50, 3, "device_online", "camera back"), (45, 2, "device_online", "nas back")]
    for minutes, dev, kind, detail in rows:
        conn.execute("INSERT INTO events (ts, device_id, kind, detail) VALUES (?, ?, ?, ?)", (stamp(minutes), dev, kind, detail))
    conn.commit()
    first = conn.execute("SELECT MIN(id) FROM events").fetchone()[0]
    out = visuals.cascade(conn, first, now=NOW)
    assert [(s["id"], s["state"]) for s in out["steps"]] == [(2, "down"), (3, "down"), (3, "up"), (2, "up")]
    assert out["steps"][1]["t"] == 120 and out["duration"] == 900
    assert {n["id"]: n["parent_id"] for n in out["nodes"]} == {1: None, 2: 1, 3: 2} and [n["id"] for n in out["nodes"] if not n["affected"]] == [1]
    assert visuals.cascade(conn, 999999, now=NOW) is None


def test_roams_are_counted_per_pair_of_access_points(conn):
    for minutes, detail in ((10, "Basement -> Guest Room (2.4 GHz)"), (20, "Basement -> Guest Room (5 GHz)"), (30, "Guest Room -> Basement"), (40, "odd text"), (5000, "Basement -> Attic")):
        conn.execute("INSERT INTO events (ts, device_id, kind, detail) VALUES (?, 1, 'wifi_roamed', ?)", (stamp(minutes), detail))
    conn.commit()
    now = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert stats._roam_flows(conn, now, 2) == [{"from": "Basement", "to": "Guest Room", "count": 2}, {"from": "Guest Room", "to": "Basement", "count": 1}]
    assert stats._wifi(conn, now, 2)["roam_flows"][0]["count"] == 2
