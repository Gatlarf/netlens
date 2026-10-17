import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import escalation, licence, tsdb
from app.config import load_settings
from app.db import add_event, connect, init_db, set_setting
from app.main import create_app

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


def stamp(minutes_ago):
    return (NOW - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def conn(tmp_path, monkeypatch):
    tsdb.forget_all()
    c = connect(tmp_path / "e.db")
    init_db(c)
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    c.execute("INSERT INTO devices (id, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, '192.168.1.20', 'nas', 1, '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z')")
    channels = [{"id": "c1", "type": "webhook", "name": "Bert", "enabled": True, "events": [], "settings": {"url": "http://x/y"}},
                {"id": "c2", "type": "webhook", "name": "Team", "enabled": True, "events": [], "settings": {"url": "http://x/z"}}]
    set_setting(c, "notify.channels", json.dumps(channels))
    c.commit()
    yield c
    c.close()
    tsdb.forget_all()


def policy(conn, **kw):
    data = {"enabled": True, "levels": [{"after_min": 15, "channels": ["c1"]}, {"after_min": 45, "channels": ["c2"]}]}
    data.update(kw)
    return escalation.save_policy(conn, data)


def test_policy_is_validated(conn):
    with pytest.raises(escalation.PolicyError):
        policy(conn, levels=[])
    with pytest.raises(escalation.PolicyError):
        policy(conn, levels=[{"after_min": 15, "channels": ["nope"]}])
    with pytest.raises(escalation.PolicyError):
        policy(conn, levels=[{"after_min": 30, "channels": []}, {"after_min": 10, "channels": []}])
    with pytest.raises(escalation.PolicyError):
        policy(conn, kinds=["nonsense"])
    assert policy(conn)["levels"][1]["after_min"] == 45


def test_levels_fire_in_time_and_only_once(conn):
    policy(conn)
    add_event(conn, "service_down", "smb down", device_id=1, now=stamp(20))
    assert [(l, c) for _, l, c in escalation.due(conn, NOW)] == [(1, ["c1"])]
    sent = []

    def poster(url, data, headers, timeout=15.0):
        sent.append(url)
        return 200, "ok"

    assert asyncio.run(escalation.process(str(conn.execute("PRAGMA database_list").fetchone()[2]), now=NOW, poster=poster)) == 1
    assert sent == ["http://x/y"] and escalation.due(conn, NOW) == []
    later = NOW + timedelta(minutes=30)
    assert [(l, c) for _, l, c in escalation.due(conn, later)] == [(2, ["c2"])]


def test_a_late_event_jumps_straight_to_the_right_level(conn):
    policy(conn)
    add_event(conn, "service_down", "x", device_id=1, now=stamp(60))
    assert [l for _, l, _ in escalation.due(conn, NOW)] == [1, 2]


def test_acknowledged_resolved_and_quiet_events_do_not_escalate(conn):
    policy(conn)
    a = add_event(conn, "service_down", "acked", device_id=1, now=stamp(30))
    escalation.acknowledge(conn, a, "bert", NOW)
    assert escalation.due(conn, NOW) == []
    add_event(conn, "device_offline", "not a serious kind", device_id=1, now=stamp(30))
    assert escalation.due(conn, NOW) == []
    b = add_event(conn, "metric_critical", "hot", device_id=1, now=stamp(30))
    assert [i["id"] for i, _, _ in escalation.due(conn, NOW)] == [b]
    add_event(conn, "metric_ok", "cool again", device_id=1, now=stamp(10))
    assert escalation.due(conn, NOW) == []
    conn.execute("INSERT INTO events (ts, device_id, kind, detail, maintenance) VALUES (?, 1, 'service_down', 'held', 'window')", (stamp(30),))
    conn.commit()
    assert escalation.due(conn, NOW) == []


def test_disabled_or_unlicensed_does_nothing(conn, monkeypatch):
    policy(conn, enabled=False)
    add_event(conn, "service_down", "x", device_id=1, now=stamp(30))
    assert escalation.due(conn, NOW) == []
    policy(conn)
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: False)
    assert escalation.due(conn, NOW) == []


def test_api(tmp_path):
    tsdb.forget_all()
    settings = load_settings({"NETLENS_DATA_DIR": str(tmp_path), "NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.250.0/30"})
    with TestClient(create_app(settings)) as client:
        h = {"Authorization": "Bearer secret"}
        view = client.get("/api/escalation", headers=h).json()
        assert view["allowed"] is False and view["policy"]["enabled"] is False
        assert client.put("/api/escalation", json={"enabled": True, "levels": [{"after_min": 10, "channels": []}]}, headers=h).status_code == 402
        assert client.post("/api/licence/trial", headers=h).status_code == 200
        done = client.put("/api/escalation", json={"enabled": True, "levels": [{"after_min": 10, "channels": []}]}, headers=h)
        assert done.status_code == 200 and done.json()["policy"]["enabled"] is True
        assert client.put("/api/escalation", json={"levels": []}, headers=h).status_code == 422
        assert client.post("/api/escalation/999/ack", headers=h).status_code == 404
    tsdb.forget_all()
