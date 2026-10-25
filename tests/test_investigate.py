"""Investigating an incident: the full-disk case (a slow climb, a sudden jump after a restart loop, and nobody subscribed to the alert)."""

from datetime import datetime, timedelta, timezone

import pytest

from app import investigate, licence, tsdb
from app.db import add_event, connect, init_db
from app.notify import channels as ch

NOW = datetime(2026, 10, 25, 9, 0, tzinfo=timezone.utc)
JUMP = datetime(2026, 10, 24, 16, 5, tzinfo=timezone.utc)


@pytest.fixture
def conn(tmp_path, monkeypatch):
    tsdb.forget_all()
    c = connect(tmp_path / "i.db")
    init_db(c)
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:bb:cc:dd:ee:01', '192.168.1.81', 'lxc-docker1', 1, 'x', 'x')")
    c.execute("INSERT INTO host_monitors (id, device_id, method, address, port, created) VALUES (1, 1, 'ssh', '192.168.1.81', 22, 'x')")
    c.execute("INSERT INTO metric_state (monitor_id, metric, label, level, since, value) VALUES (1, 'disk_pct', '/', 'critical', '2026-10-24T16:24:22Z', 100)")
    store = tsdb.for_conn(c)
    t = int((JUMP - timedelta(days=2)).timestamp())
    while t < int(NOW.timestamp()):
        when = datetime.fromtimestamp(t, timezone.utc)
        if when < JUMP:
            value = 80 + 4 * (when - (JUMP - timedelta(days=2))).total_seconds() / (2 * 86400)          # about 2 points a day
        else:
            value = min(100.0, 84 + (when - JUMP).total_seconds() / 60 * 1.2)                              # +15 points in about 13 minutes
        store.record([("device", 1, "disk_pct", value, "/", "%")], ts=t)
        t += 300
    c.commit()
    yield c
    c.close()
    tsdb.forget_all()


def ev(conn, kind, when, detail):
    return add_event(conn, kind, detail, device_id=1, now=when.strftime("%Y-%m-%dT%H:%M:%SZ"))


def make_incident(conn):
    for n in range(5):
        ev(conn, "container_restarting", JUMP - timedelta(minutes=50 - 10 * n), "whoiswho-frontend on lxc-docker1 keeps restarting (160%d restarts)" % n)
    ev(conn, "metric_warning", JUMP + timedelta(minutes=6), "lxc-docker1: disk full on / is 86% (limit 85%)")
    return ev(conn, "metric_critical", JUMP + timedelta(minutes=19), "lxc-docker1: disk full on / is 96% (limit 95%)")


def test_the_shape_of_a_reading_is_a_step_or_a_climb():
    steady = [[i * 300, 50.0, 50, 50] for i in range(50)]
    assert investigate.shape(steady)["kind"] == "steady"
    climb = [[i * 3600, 50.0 + i * 0.5, 0, 0] for i in range(48)]
    assert investigate.shape(climb)["kind"] == "climb"
    step = [[i * 300, 80.0 if i < 100 else 98.0, 0, 0] for i in range(120)]
    s = investigate.shape(step)
    assert s["kind"] == "step" and (s["from_value"], s["to_value"]) == (80.0, 98.0)


def test_a_full_disk_is_a_jump_after_a_restart_loop_and_nobody_was_told(conn):
    make_incident(conn)
    ch.save_channels(conn, [{"id": "a", "type": "email", "name": "E-mail", "enabled": True, "events": ["device_new", "service_down"],
                             "filters": {"min_severity": "info", "min_tier": "any", "devices": [], "groups": []}, "settings": {}}])
    from app import incidents

    found = incidents.incidents(conn, 7, NOW)
    assert found
    report = investigate.investigate(conn, found[0]["id"], now=NOW)
    text = " ".join(f["text"] for f in report["findings"])
    assert "did not creep up, it jumped: from" in text
    assert "points a day" in text and "disk forecast did not warn" in text
    assert "Probable source: whoiswho-frontend" in text and "5 alerts" in text
    assert "Nobody was told" in text and "no channel includes it" in text
    assert "still critical" in text
    assert report["findings"][0]["level"] == "cause"
    assert report["devices"][0]["timeline"][0]["count"] == 5                    # the restarts are one line with a count


def test_quiet_hours_and_a_working_channel(conn):
    make_incident(conn)
    ch.save_channels(conn, [{"id": "a", "type": "email", "name": "E-mail", "enabled": True, "events": ["metric_warning", "metric_critical", "container_restarting"],
                             "filters": {"min_severity": "info", "min_tier": "any", "devices": [], "groups": []}, "settings": {}}])
    from app import incidents

    report = investigate.investigate(conn, incidents.incidents(conn, 7, NOW)[0]["id"], now=NOW)
    assert not any("Nobody was told" in f["text"] for f in report["findings"])
    assert {n["kind"]: n["channels"] for n in report["notifications"]}["metric_critical"] == ["E-mail"]


def test_unknown_incident_and_words(conn):
    assert investigate.investigate(conn, 999999, now=NOW) is None
    make_incident(conn)
    from app import incidents

    report = investigate.investigate(conn, incidents.incidents(conn, 7, NOW)[0]["id"], now=NOW)
    assert investigate.narrate(conn, report, ask=lambda messages: "It jumped.") == "It jumped."
    assert "lxc-docker1" in messages_user(report)


def messages_user(report):
    import json

    return json.dumps(report["facts"])
