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
    assert "jumped from" in text and "to 100.0%" in text
    assert "points a day" in text and "disk forecast did not warn" in text
    assert "Probable cause: whoiswho-frontend" in text and "5 alerts" in text
    assert "reached nobody" in text and "Settings → Notifications" in text
    assert "still critical" in text
    assert report["findings"][0]["level"] == "cause"
    assert report["findings"][-1]["level"] in ("notify", "warn")                   # the notification remark comes last
    assert report["devices"][0]["timeline"][0]["count"] == 5                    # the restarts are one line with a count


def test_quiet_hours_and_a_working_channel(conn):
    make_incident(conn)
    ch.save_channels(conn, [{"id": "a", "type": "email", "name": "E-mail", "enabled": True, "events": ["metric_warning", "metric_critical", "container_restarting"],
                             "filters": {"min_severity": "info", "min_tier": "any", "devices": [], "groups": []}, "settings": {}}])
    from app import incidents

    report = investigate.investigate(conn, incidents.incidents(conn, 7, NOW)[0]["id"], now=NOW)
    assert not any(f["level"] == "notify" and "reached nobody" in f["text"] for f in report["findings"])
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


def test_a_scan_on_the_host_is_the_cause_the_host_follows_and_flapping_devices_are_left_out(conn):
    import json

    onset = datetime(2026, 10, 25, 2, 49, tzinfo=timezone.utc)
    store = tsdb.for_conn(conn)
    for i, (name, ip) in enumerate([("nuc", "192.168.1.10"), ("lxc-dockerdev", "192.168.1.89"), ("hp-laserjet", "192.168.1.39")], 10):
        conn.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (?, ?, ?, ?, 1, 'x', 'x')", (i, f"aa:bb:cc:dd:ee:{i}", ip, name))
    conn.execute("INSERT INTO hypervisor_guests (plugin_id, guest_id, name, kind, status, device_id, host_device_id, updated, details) VALUES ('proxmox', 'g1', 'lxc-dockerdev', 'lxc', 'running', 11, 10, 'x', '{}')")
    conn.execute("INSERT INTO hypervisor_guests (plugin_id, guest_id, name, kind, status, device_id, host_device_id, updated, details) VALUES ('docker', 'c1', 'greenbone-gvmd-1', 'container', 'running', NULL, 11, 'x', ?)", (json.dumps({"started": "2026-10-18T13:38:40Z"}),))
    conn.execute("INSERT INTO vuln_servers (plugin_id, server_id, name, updated) VALUES ('greenbone', '127.0.0.1:9390', 'Greenbone', 'x')")
    for n in range(5):
        conn.execute("INSERT INTO vuln_findings (plugin_id, finding_id, server_id, host_ip, title, severity, last_seen, updated) VALUES ('greenbone', ?, '127.0.0.1:9390', ?, 't', 'medium', ?, 'x')",
                     (f"f{n}", f"192.168.1.{n}", f"2026-10-25T03:{12 + n * 8}:00Z"))
    t = int((onset - timedelta(hours=8)).timestamp())
    while t < int(NOW.timestamp()):
        when = datetime.fromtimestamp(t, timezone.utc)
        store.record([("device", 11, "cpu_pct", 18.0 if when < onset else 100.0, "", "%"), ("device", 10, "cpu_pct", 15.0 if when < onset + timedelta(minutes=30) else 58.0, "", "%")], ts=t)
        t += 300
    detail = lambda d: d
    add_event(conn, "metric_critical", "lxc-dockerdev: processor busy is 100% (limit 98%)", device_id=11, now="2026-10-25T03:06:48Z")
    add_event(conn, "anomaly", "Processor busy of nuc is 58.23%, unusual for this time of day", device_id=10, now="2026-10-25T03:14:23Z")
    for minute, kind in ((8, "device_offline"), (16, "device_online"), (24, "device_offline")):
        add_event(conn, kind, "192.168.1.39 still offline after maintenance 'AImesh nightly reboot'", device_id=12, now=f"2026-10-25T03:{minute:02d}:00Z")
    add_event(conn, "service_down", "Biekes.be is down: timed out", now="2026-10-25T03:08:36Z")
    from app import incidents

    found = [i for i in incidents.incidents(conn, 7, NOW) if i["start"] >= "2026-10-25"]
    report = investigate.investigate(conn, found[0]["id"], now=NOW)
    text = " ".join(f["text"] for f in report["findings"])
    assert [d["name"] for d in report["devices"]] == ["nuc", "lxc-dockerdev"] or {d["name"] for d in report["devices"]} == {"nuc", "lxc-dockerdev"}
    assert [u["name"] for u in report["unrelated"]] == ["hp-laserjet"] and "AImesh nightly reboot" in report["unrelated"][0]["why"]
    assert "Probable cause: Greenbone (a vulnerability scanner)" in text and "runs on the affected machine" in text
    assert "the host of lxc-dockerdev" in text and "starting 25 Oct 02:" in text
    assert "Biekes.be is down" in text and "result of the overload" in text
    assert "lxc-dockerdev" in report["title"] and "processor use" in report["title"]
    assert report["findings"][0]["level"] == "cause"


def test_the_storage_snapshots_name_what_filled_the_disk_and_the_model_does_not_get_the_names(conn):
    import json

    from app import incidents
    from app.hostprobe import service as probes
    from tests.test_hostprobe import snapshot

    probes.store(conn, 1, True, "locked", None, snapshot(0), now=(JUMP - timedelta(hours=4)).timestamp())
    probes.store(conn, 1, True, "locked", None, snapshot(16, with_big=True), now=(JUMP + timedelta(hours=2)).timestamp())
    make_incident(conn)
    report = investigate.investigate(conn, incidents.incidents(conn, 7, NOW)[0]["id"], now=NOW)
    text = " ".join(f["text"] for f in report["findings"])
    assert "Probable cause: on lxc-docker1, the directory /media/torrents/transmission/incomplete grew by 16.0 GB" in text
    asked = json.dumps(report["facts"])
    assert "transmission" not in asked and "names withheld" in asked and "16.0 GB" in asked
    probes.save_settings(conn, {"names_to_llm": True})
    again = investigate.investigate(conn, incidents.incidents(conn, 7, NOW)[0]["id"], now=NOW)
    assert "transmission/incomplete" in json.dumps(again["facts"])
