from datetime import datetime, timedelta, timezone

import pytest

from app import changes
from app.db import connect, init_db

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)


def stamp(hours_ago):
    return (NOW - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "c.db")
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'nas', 1, 'x', 'x')")
    rows = [(stamp(1), 1, "device_new", "New device nas"), (stamp(2), 1, "metric_warning", "nas: disk full"), (stamp(30), 1, "device_offline", "nas went offline"),
            (stamp(3), None, "wake_sent", "magic packet"), (stamp(4), 1, "port_unexpected", "port 23 opened")]
    for ts, dev, kind, detail in rows:
        c.execute("INSERT INTO events (ts, device_id, kind, detail) VALUES (?,?,?,?)", (ts, dev, kind, detail))
    c.execute("INSERT INTO audit_log (ts, user, role, ip, method, path, status, action) VALUES (?, 'bert', 'admin', '1.2.3.4', 'PATCH', '/api/devices/1', 200, 'Changed the settings of nas')", (stamp(5),))
    c.execute("INSERT INTO audit_log (ts, user, role, ip, method, path, status, action) VALUES (?, 'bert', 'admin', '1.2.3.4', 'POST', '/api/login', 200, 'Signed in')", (stamp(5),))
    c.commit()
    yield c
    c.close()


def test_timeline_merges_and_groups(conn):
    doc = changes.timeline(conn, "24h", include_audit=True, now=NOW)
    kinds = [i["kind"] for i in doc["items"]]
    assert kinds == ["device_new", "metric_warning", "port_unexpected", "change"]            # newest first, quiet kinds and sign-ins left out
    assert doc["counts"] == {"devices": 1, "health": 1, "security": 1, "settings": 1}
    assert doc["items"][-1]["who"] == "bert" and doc["items"][0]["device"] == "nas"


def test_viewers_do_not_see_changes_made(conn):
    doc = changes.timeline(conn, "24h", include_audit=False, now=NOW)
    assert "change" not in [i["kind"] for i in doc["items"]] and "settings" not in doc["categories"]


def test_period_and_category(conn):
    assert len(changes.timeline(conn, "7d", now=NOW)["items"]) == 4                      # the offline event 30 h ago is inside seven days
    only = changes.timeline(conn, "7d", category="availability", now=NOW)
    assert [i["kind"] for i in only["items"]] == ["device_offline"] and only["counts"]["devices"] == 1


def test_api_needs_login_and_returns_the_timeline(tmp_path):
    from fastapi.testclient import TestClient

    from app.config import load_settings
    from app.main import create_app

    settings = load_settings({"NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.1.0/24", "NETLENS_SNMP_COMMUNITY": "public"})
    with TestClient(create_app(settings, db_path=tmp_path / "t.db")) as client:
        assert client.get("/api/changes").status_code == 401
        body = client.get("/api/changes?period=7d", headers={"Authorization": "Bearer secret"}).json()
        assert body["period"] == "7d" and "items" in body and "settings" in body["categories"]


def test_only_always_on_devices_leaves_out_the_others(conn):
    conn.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, always_on, first_seen, last_seen) VALUES (2, 'aa:00:00:00:00:02', '10.0.0.6', 'iphone', 1, 0, 'x', 'x')")
    conn.execute("UPDATE devices SET always_on = 1 WHERE id = 1")
    conn.execute("INSERT INTO events (ts, device_id, kind, detail) VALUES (?, 2, 'device_new', 'New device iphone')", (stamp(1),))
    conn.commit()
    everything = changes.timeline(conn, "24h", include_audit=True, now=NOW)
    core = changes.timeline(conn, "24h", include_audit=True, now=NOW, only={1})
    assert any(i["device"] == "iphone" for i in everything["items"]) and not any(i["device"] == "iphone" for i in core["items"])
    assert any(i["kind"] == "change" for i in core["items"]) and any(i["device"] == "nas" for i in core["items"])      # changes made by people and the nas stay
