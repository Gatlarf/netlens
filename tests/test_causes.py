from datetime import datetime, timedelta, timezone

import pytest

from app import causes
from app.db import connect, init_db

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)


def stamp(minutes_ago):
    return (NOW - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "c.db")
    init_db(c)
    # switch (1) -> nas (2) -> camera (3); printer (4) is separate
    for i, name in enumerate(["switch", "nas", "camera", "printer"], 1):
        c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, always_on, first_seen, last_seen) VALUES (?, ?, ?, ?, 1, ?, 'x', 'x')", (i, f"aa:00:00:00:00:0{i}", f"10.0.0.{i}", name, 1 if i == 3 else 0))
    c.execute("UPDATE devices SET parent_mode='device', parent_device_id=1 WHERE id=2")
    c.execute("UPDATE devices SET parent_mode='device', parent_device_id=2 WHERE id=3")
    c.execute("UPDATE devices SET parent_mode='none' WHERE id IN (1, 4)")
    c.commit()
    yield c
    c.close()


def event(c, minutes_ago, device, kind, detail="x"):
    c.execute("INSERT INTO events (ts, device_id, kind, detail) VALUES (?,?,?,?)", (stamp(minutes_ago), device, kind, detail))
    c.commit()


def test_changes_before_an_outage_are_ranked_by_closeness_and_relation(conn):
    event(conn, 5, 3, "device_offline", "camera is offline")                      # the outage itself: never a suspect
    event(conn, 20, 3, "port_opened", "tcp/23 telnet")                            # on the device, close
    event(conn, 400, 3, "firmware_update", "firmware 2")                          # on the device, far
    event(conn, 30, 1, "device_offline", "switch")                                # the device two levels up went away
    event(conn, 40, 4, "port_opened", "tcp/80")                                   # an unrelated device: left out
    event(conn, 3, 3, "port_opened", "tcp/99")                                    # after the outage: left out
    out = causes.before(conn, 3, now=NOW)
    assert out["at"] == stamp(5) and out["basis"] == "the latest outage"
    texts = [s["text"] for s in out["suspects"]]
    assert "tcp/23 telnet" in texts and "switch went offline" in texts and "firmware 2" not in texts
    assert "tcp/80" not in texts and "tcp/99" not in texts and not any("camera is offline" in t for t in texts)
    assert out["suspects"][0]["text"] == "tcp/23 telnet" and out["suspects"][0]["relation"] == "this device"
    wide = causes.before(conn, 3, hours=24, now=NOW)
    assert any(s["text"] == "firmware 2" for s in wide["suspects"])


def test_settings_people_changed_count_and_repeats_are_merged(conn):
    event(conn, 5, 2, "device_offline")
    for minutes in (20, 25, 26):
        event(conn, minutes, 2, "port_opened", "tcp/8080")
    for path, action in (("/api/devices/2", "Changed the settings of nas"), ("/api/devices/4", "Changed printer"), ("/api/devices/2/hostprobe/run", "Ran a probe"), ("/api/config/general", "Changed the scan interval")):
        conn.execute("INSERT INTO audit_log (ts, user, role, ip, method, path, status, action) VALUES (?, 'bert', 'admin', '1.2.3.4', 'PUT', ?, 200, ?)", (stamp(10), path, action))
    conn.commit()
    out = causes.before(conn, 2, now=NOW)
    by_text = {s["text"]: s for s in out["suspects"]}
    assert by_text["tcp/8080"]["times"] == 3
    assert by_text["Changed the settings of nas"]["who"] == "bert"
    assert "Changed printer" not in by_text and "Ran a probe" not in by_text and "Changed the scan interval" in by_text
    assert out["suspects"][0]["text"] == "Changed the settings of nas"


def test_an_outage_can_be_chosen_and_an_unknown_device_is_none(conn):
    event(conn, 200, 3, "device_offline")
    event(conn, 5, 3, "device_offline")
    event(conn, 210, 3, "guest_stopped", "container stopped")
    out = causes.before(conn, 3, at=stamp(200), now=NOW)
    assert out["basis"] == "the outage you chose" and [s["text"] for s in out["suspects"]] == ["container stopped"] and len(out["outages"]) == 2
    assert causes.before(conn, 99, now=NOW) is None
    quiet = causes.before(conn, 4, now=NOW)
    assert quiet["suspects"] == [] and "not gone offline" in quiet["basis"]


def test_impact_lists_everything_below_a_device_level_by_level(conn):
    conn.execute("INSERT INTO service_checks (device_id, name, kind, host, enabled, last_up, created) VALUES (3, 'camera web', 'http', '10.0.0.3', 1, 1, 'x')")
    conn.execute("INSERT INTO hypervisor_guests (plugin_id, guest_id, name, kind, status, host_device_id, updated) VALUES ('docker', 'a', 'frigate', 'container', 'running', 2, 'x')")
    conn.execute("UPDATE devices SET online = 0 WHERE id = 3")
    conn.commit()
    out = causes.impact(conn, 1)
    assert out["total"] == 2 and out["depth"] == 2 and [d["name"] for d in out["levels"][0]] == ["nas"] and [d["name"] for d in out["levels"][1]] == ["camera"]
    assert [g["name"] for g in out["guests"]] == ["frigate"] and [s["name"] for s in out["services"]] == ["camera web"]
    assert out["always_on_count"] == 1 and out["already_offline"] == 1 and out["risk"] == "medium"
    assert "2 devices in 2 levels" in out["summary"] and "1 of the devices is marked always-on" in out["summary"]
    leaf = causes.impact(conn, 4)
    assert leaf["total"] == 0 and leaf["risk"] == "none" and "Nothing is known to depend" in leaf["summary"]
    assert causes.impact(conn, 99) is None


def test_ask_understands_both_questions(conn):
    from app import ask, ask_more

    event(conn, 5, 3, "device_offline")
    event(conn, 20, 3, "port_opened", "tcp/23 telnet")
    names = ["switch", "nas", "camera", "printer"]
    assert ask.route("what changed before the camera went offline?", names, conn)[0] == "causes"
    assert ask.route("what would break if I reboot the switch?", names, conn) == ("impact", {"device": "switch"})
    assert ask.route("is it safe to restart nas", names, conn)[0] == "impact"
    tool, args = ask.route("what changed before camera broke", names, conn)
    answer = ask_more.RENDERERS["causes"](ask_more.TOOLS["causes"][0](conn, args))
    assert "tcp/23 telnet" in answer and "suspects, not proof" in answer
    assert "2 devices" in ask_more.RENDERERS["impact"](ask_more.TOOLS["impact"][0](conn, {"device": "switch"}))
    assert ask_more.TOOLS["causes"][0](conn, {"device": "nothing-like-this"}).get("error")
