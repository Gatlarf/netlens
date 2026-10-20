import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import dbmaint, tsdb
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app

AUTH = {"Authorization": "Bearer secret"}
NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)


def ago(days):
    return (NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def conn(tmp_path):
    tsdb.forget_all()
    c = connect(tmp_path / "t.db")
    init_db(c)
    yield c
    c.close()
    tsdb.forget_all()


def test_retention_defaults_and_checks(conn):
    assert dbmaint.retention(conn)["events_days"] == 730
    assert dbmaint.save_retention(conn, {"events_days": 0, "audit_days": 90})["events_days"] == 0
    assert dbmaint.retention(conn)["audit_days"] == 90
    for bad in ({"events_days": 5}, {"checks_days": 0}, {"nonsense": 1}, {"scans_days": True}, {"audit_days": 99999}):
        with pytest.raises(dbmaint.MaintError):
            dbmaint.save_retention(conn, bad)


def test_purge_removes_only_what_is_old_and_can_preview(conn):
    for d in (1, 800, 900):
        conn.execute("INSERT INTO events (ts, kind, detail) VALUES (?, 'x', 'y')", (ago(d),))
    conn.execute("INSERT INTO scans (kind, status, started) VALUES ('quick', 'done', ?)", (ago(500),))
    conn.execute("INSERT INTO scans (kind, status, started) VALUES ('quick', 'running', ?)", (ago(500),))
    conn.commit()
    assert dbmaint.purge(conn, dry_run=True, now=NOW)["events"] == 2 and conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 3
    out = dbmaint.purge(conn, now=NOW)
    assert out["events"] == 2 and out["scans"] == 1
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1 and conn.execute("SELECT status FROM scans").fetchone()[0] == "running"
    dbmaint.save_retention(conn, {"events_days": 0})
    conn.execute("INSERT INTO events (ts, kind) VALUES (?, 'x')", (ago(2000),))
    assert dbmaint.purge(conn, now=NOW)["events"] == 0                      # 0 keeps everything


def test_leftovers_of_a_removed_thing_are_found_and_removed(conn):
    store = tsdb.for_conn(conn)
    conn.execute("INSERT INTO probes (name, token_hash, created) VALUES ('s', 'h', 'x')")
    conn.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'a', 1, 'x', 'x')")
    now = int(time.time())
    store.record_bulk([(now, "device", 1, "up", 1.0, "", ""), (now, "device", 77, "up", 1.0, "", ""), (now, "remote", 5, "up", 1.0, "", ""), (now, "plugin", 3, "up", 1.0, "", "")])
    conn.execute("INSERT INTO settings (key, value) VALUES ('probe.config.1', '{}'), ('probe.config.9', '{}'), ('probe.commands.9', '[]')")
    conn.commit()
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("INSERT INTO service_results (check_id, ts, up) VALUES (99, 'x', 1)")
    conn.commit()
    found = dbmaint.orphans(conn, dry_run=True)
    assert found["service_results"] == 1 and found["settings"] == 2 and found["graph_series"] == 2
    assert dbmaint.orphans(conn)["graph_series"] == 2
    assert sorted(store.series_owners()) == [("device", 1), ("plugin", 3)]       # plugin graphs have no table to check against: they stay
    assert conn.execute("SELECT COUNT(*) FROM service_results").fetchone()[0] == 0
    assert [r[0] for r in conn.execute("SELECT key FROM settings WHERE key LIKE 'probe.%'")] == ["probe.config.1"]
    assert dbmaint.orphans(conn, dry_run=True) == {k: 0 for k in found}


def test_upkeep_tools_run(conn):
    for i in range(300):
        conn.execute("INSERT INTO events (ts, kind, detail) VALUES (?, 'x', ?)", (ago(900), "d" * 200))
    conn.commit()
    dbmaint.purge(conn, now=NOW)
    assert dbmaint.optimize(conn)["seconds"] >= 0 and dbmaint.reindex(conn)["seconds"] >= 0 and dbmaint.checkpoint(conn)["busy"] in (True, False)
    out = dbmaint.compact(conn)
    assert out["after_bytes"] <= out["before_bytes"]
    assert dbmaint.integrity(conn)["ok"]
    info = dbmaint.overview(conn)
    assert info["main"]["bytes"] > 0 and any(t["name"] == "events" for t in info["tables"]) and info["retention"]["scans_days"] == 365


def test_weekly_run_is_due_once_on_sunday_night(conn):
    sunday = datetime(2026, 10, 25, 3, 40, tzinfo=timezone.utc)
    assert sunday.weekday() == 6
    assert dbmaint.due(conn, datetime(2026, 10, 22, 10, 0, tzinfo=timezone.utc)) is False
    assert dbmaint.due(conn, sunday) is True
    dbmaint._remember(conn, "tidy", {"summary": {}})
    conn.execute("UPDATE settings SET value = replace(value, substr(value, instr(value, '\"ts\": \"') + 7, 20), ?) WHERE key = ?", (sunday.strftime("%Y-%m-%dT%H:%M:%SZ"), dbmaint.LAST_KEY))
    assert dbmaint.due(conn, sunday + timedelta(minutes=10)) is False


def test_the_api(tmp_path):
    tsdb.forget_all()
    p = tmp_path / "t.db"
    c = connect(p)
    init_db(c)
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=p)
    with TestClient(app, headers=AUTH) as tc:
        j = tc.get("/api/database").json()
        assert j["main"]["bytes"] > 0 and j["retention"]["events_days"] == 730 and j["tables"]
        assert tc.put("/api/database/retention", json={"events_days": 365}).json()["retention"]["events_days"] == 365
        assert tc.put("/api/database/retention", json={"events_days": 3}).status_code == 422
        assert tc.post("/api/database/purge", json={"dry_run": True}).json()["dry_run"] is True
        assert tc.post("/api/database/orphans", json={}).status_code == 200
        for step in ("optimize", "reindex", "integrity", "compact", "tidy"):
            assert tc.post(f"/api/database/{step}").status_code == 200, step
        assert tc.get("/api/database").json()["last"]["tidy"]["ts"]
    tsdb.forget_all()


def test_a_viewer_cannot_use_it(tmp_path):
    tsdb.forget_all()
    p = tmp_path / "t.db"
    c = connect(p)
    init_db(c)
    from app import users

    users.create_user(c, "vera", "a-long-enough-password", "viewer")
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=p)
    with TestClient(app) as tc:
        assert tc.post("/api/login", json={"username": "vera", "password": "a-long-enough-password"}).status_code == 200
        assert tc.get("/api/database").status_code == 403
        assert tc.post("/api/database/compact").status_code == 403
    tsdb.forget_all()
