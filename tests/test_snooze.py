from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import snooze, tsdb
from app.config import load_settings
from app.db import add_event, connect, init_db
from app.hostmetrics import service as hm
from app.main import create_app

AUTH = {"Authorization": "Bearer secret"}
NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
STAMP = "%Y-%m-%dT%H:%M:%SZ"


@pytest.fixture
def conn(tmp_path):
    tsdb.forget_all()
    c = connect(tmp_path / "t.db")
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'nas', 0, 'x', 'x')")
    c.execute("INSERT INTO host_monitors (id, device_id, method, address, port, credential, interval_s, groups, alerts, enabled, created) VALUES (1,1,'snmp','10.0.0.5',161,'',60,'[]',1,1,'x')")
    c.commit()
    yield c
    c.close()
    tsdb.forget_all()


def held(conn, kind):
    return [r["maintenance"] for r in conn.execute("SELECT maintenance FROM events WHERE kind = ? ORDER BY id", (kind,))]


def test_subjects_are_checked(conn):
    for bad in ("", "device:x", "metric:1:cpu_pct", "service:1; drop", "device:1\nx", "metric:1:Cpu:/"):
        with pytest.raises(ValueError):
            snooze.snooze(conn, bad, 60, now=NOW)
    for bad in (1, 0, 60 * 24 * 31, True):
        with pytest.raises(ValueError):
            snooze.snooze(conn, "device:1", bad, now=NOW)


def test_events_about_a_snoozed_subject_are_held_back_and_a_recovery_ends_it(conn):
    snooze.snooze(conn, "device:1", 60)
    add_event(conn, "device_offline", "nas", device_id=1)
    assert held(conn, "device_offline") == ["Snoozed"]
    add_event(conn, "device_offline", "other", device_id=2 if False else None)         # an event with no subject is never held
    assert held(conn, "device_offline")[-1] is None
    add_event(conn, "device_online", None, device_id=1)                                  # back: held back too, and the snooze is over
    assert held(conn, "device_online") == ["Snoozed"] and "device:1" not in snooze.active(conn)
    add_event(conn, "device_offline", "nas", device_id=1)
    assert held(conn, "device_offline")[-1] is None                                      # a new outage is announced


def test_a_health_reading_snooze_also_covers_the_disk_forecast(conn):
    snooze.snooze(conn, "metric:1:disk_pct:/data", 60)
    hm.evaluate(conn, 1, 1, "nas", [("disk_pct", "/data", 97.0, "%")], "2026-03-10T12:00:00Z")
    assert held(conn, "metric_critical") == ["Snoozed"]
    from app import forecast

    add_event(conn, "capacity_warning", "x", device_id=1, subject="metric:1:disk_pct:/data")
    assert held(conn, "capacity_warning") == ["Snoozed"]


def test_problems_carry_the_snooze(conn):
    hm.evaluate(conn, 1, 1, "nas", [("disk_pct", "/data", 97.0, "%")], "2026-03-10T12:00:00Z")
    p = hm.problems(conn)[0]
    assert p["snooze"] == "metric:1:disk_pct:/data" and p["snoozed_until"] is None
    snooze.snooze(conn, p["snooze"], 60)
    assert hm.problems(conn)[0]["snoozed_until"] and hm.problems(conn, include_snoozed=False) == []


def test_an_ended_snooze_announces_what_is_still_wrong(conn):
    hm.evaluate(conn, 1, 1, "nas", [("disk_pct", "/data", 97.0, "%")], "2026-03-10T12:00:00Z")
    snooze.snooze(conn, "device:1", 5, now=NOW - timedelta(hours=1))
    snooze.snooze(conn, "metric:1:disk_pct:/data", 5, now=NOW - timedelta(hours=1))
    before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    raised = snooze.expire(conn, NOW)
    assert sorted(raised) == ["device_offline", "metric_critical"]
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == before + 2
    assert snooze.expire(conn, NOW) == []                                                # nothing left to end


def test_an_ended_snooze_of_a_recovered_problem_is_silent(conn):
    conn.execute("UPDATE devices SET online = 1")
    conn.commit()
    snooze.snooze(conn, "device:1", 5, now=NOW - timedelta(hours=1))
    assert snooze.expire(conn, NOW) == []


def test_the_api_and_the_dashboard(tmp_path):
    tsdb.forget_all()
    p = tmp_path / "t.db"
    c = connect(p)
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, always_on, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'nas', 0, 1, 'x', 'x')")
    c.commit()
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=p)
    with TestClient(app, headers=AUTH) as tc:
        before = tc.get("/api/dashboard").json()
        item = next(a for a in before["attention"] if a.get("snooze") == "device:1")
        assert "should always be online" in item["text"]
        assert tc.post("/api/snoozes", json={"subject": "device:1", "minutes": 60}).status_code == 201
        after = tc.get("/api/dashboard").json()
        assert not [a for a in after["attention"] if a.get("snooze") == "device:1"]
        assert after["snoozed"][0]["snooze"] == "device:1" and after["snoozed"][0]["until"]
        assert tc.get("/api/snoozes").json()["snoozes"][0]["key"] == "device:1"
        assert tc.post("/api/snoozes", json={"subject": "oops", "minutes": 60}).status_code == 422
        assert tc.delete("/api/snoozes?subject=device:1").status_code == 200
        assert tc.delete("/api/snoozes?subject=device:1").status_code == 404
        assert [a for a in tc.get("/api/dashboard").json()["attention"] if a.get("snooze") == "device:1"]
    tsdb.forget_all()
