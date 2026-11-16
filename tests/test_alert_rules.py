"""Alert rules: muting, muting while another device is down, and muting repeats; the preview; and that a muted event is recorded but not sent."""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import alertrules, tsdb
from app.config import load_settings
from app.db import add_event, connect, init_db
from app.main import create_app
from app.notify import channels

NOW = datetime(2026, 11, 17, 12, 0, 0, tzinfo=timezone.utc)      # a Tuesday


def stamp(minutes_ago=0, base=NOW):
    return (base - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def conn(tmp_path):
    alertrules.invalidate()
    c = connect(tmp_path / "netlens.db")
    init_db(c)
    c.execute("INSERT INTO device_groups (id, name, color) VALUES (1, 'Garden', '#2a9d8f')") if c.execute("SELECT 1 FROM sqlite_master WHERE name = 'device_groups'").fetchone() else None
    for i, (name, online, group, kind, tier) in enumerate((("Garden AP", 1, 1, "ap", "normal"), ("Garden cam", 1, 1, "camera", "normal"), ("Office NAS", 1, None, "nas", "critical"), ("Printer", 1, None, "printer", "low")), 1):
        c.execute("INSERT INTO devices (id, primary_ip, hostname, online, group_id, device_type, tier, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                  (i, f"10.0.0.{i}", name, online, group, kind, tier))
    c.commit()
    yield c
    c.close()
    alertrules.invalidate()


def rule(conn, **kw):
    base = {"name": "Test", "type": "mute", "kinds": ["device_offline"], "scope": {"type": "all"}}
    return alertrules.upsert(conn, {**base, **kw})


def events(conn):
    return [(r["kind"], r["device_id"], r["maintenance"]) for r in conn.execute("SELECT kind, device_id, maintenance FROM events ORDER BY id")]


def test_a_rule_is_checked_and_stored_cleanly(conn):
    saved = rule(conn, name="  Garden   at night ", kinds=["device_offline", "device_offline", "service_down"], scope={"type": "group", "ids": [1, 1]}, when={"days": [4, 5], "from": "22:00", "to": "07:00"})
    assert saved["name"] == "Garden at night" and saved["kinds"] == ["device_offline", "service_down"] and saved["scope"] == {"type": "group", "ids": [1]} and saved["keep_critical"] is True
    for bad in ({"name": ""}, {"type": "x"}, {"kinds": []}, {"kinds": ["nonsense"]}, {"kinds": ["audit_tampered"]}, {"scope": {"type": "group", "ids": []}}, {"scope": {"type": "below"}},
                {"when": {"days": [], "from": "22:00", "to": "07:00"}}, {"when": {"days": [1], "from": "25:00", "to": "07:00"}}, {"type": "while_down"}, {"type": "repeat", "count": 1, "minutes": 5}):
        with pytest.raises(alertrules.RuleError):
            rule(conn, **bad)
    assert len(alertrules.load(conn)) == 1
    assert alertrules.remove(conn, saved["id"]) and alertrules.load(conn) == [] and not alertrules.remove(conn, "nope")


def test_a_mute_rule_records_the_event_with_a_tag_and_leaves_the_others_alone(conn):
    rule(conn, name="Garden", scope={"type": "group", "ids": [1]})
    add_event(conn, "device_offline", "Garden AP offline", device_id=1, now=stamp())
    add_event(conn, "device_offline", "NAS offline", device_id=3, now=stamp())              # not in the group
    add_event(conn, "service_down", "x", device_id=1, now=stamp())                           # not one of the events
    assert events(conn) == [("device_offline", 1, "Rule: Garden"), ("device_offline", 3, None), ("service_down", 1, None)]
    assert alertrules.muted_counts(conn) == {"Garden": 1}


def test_recoveries_follow_their_problem_and_critical_events_are_kept_unless_the_rule_says_otherwise(conn):
    rule(conn, name="R", kinds=["device_offline", "service_down"])
    add_event(conn, "device_online", "back", device_id=1, now=stamp())                       # the recovery of a muted problem
    add_event(conn, "service_up", "up", device_id=1, now=stamp())
    add_event(conn, "service_down", "down", device_id=1, now=stamp())                        # service_down is critical: kept while "never mute critical" is on
    assert [e[2] for e in events(conn)] == ["Rule: R", "Rule: R", None]
    rule(conn, name="R", id=alertrules.load(conn)[0]["id"], kinds=["device_offline", "service_down"], keep_critical=False)
    add_event(conn, "service_down", "down again", device_id=1, now=stamp())
    assert events(conn)[-1][2] == "Rule: R"
    alertrules.remove(conn, alertrules.load(conn)[0]["id"])
    other = rule(conn, name="No recoveries", kinds=["device_offline"], recoveries=False, scope={"type": "devices", "ids": [4]})
    add_event(conn, "device_online", "back", device_id=4, now=stamp())
    assert events(conn)[-1][2] is None and other["recoveries"] is False


def test_an_event_that_is_never_muted_cannot_be_muted(conn):
    rule(conn, name="All", kinds=["*"], keep_critical=False)
    add_event(conn, "audit_tampered", "x", now=stamp())
    add_event(conn, "device_offline", "x", device_id=1, now=stamp())
    assert [e[2] for e in events(conn)] == [None, "Rule: All"]


def test_the_scopes(conn):
    cases = [({"type": "devices", "ids": [2, 4]}, [2, 4]), ({"type": "tier", "value": "critical"}, [3]), ({"type": "tier", "value": "low"}, [4]), ({"type": "type", "value": "ap"}, [1]), ({"type": "all"}, [1, 2, 3, 4])]
    for scope, expected in cases:
        conn.execute("DELETE FROM events")
        conn.commit()
        for r in alertrules.load(conn):
            alertrules.remove(conn, r["id"])
        rule(conn, scope=scope)
        for d in (1, 2, 3, 4):
            add_event(conn, "device_offline", "x", device_id=d, now=stamp())
        assert [e[1] for e in events(conn) if e[2]] == expected, scope


def test_everything_behind_a_device_is_found_through_the_hierarchy(conn):
    conn.execute("UPDATE devices SET parent_mode = 'device', parent_device_id = 1 WHERE id = 2")           # the camera is set to hang below the AP
    conn.commit()
    from app.hierarchy import descendants, load_hierarchy

    _d, h = load_hierarchy(conn)
    behind = descendants(h, 1)
    rule(conn, scope={"type": "below", "device_id": 1})
    for d in (1, 2, 3):
        add_event(conn, "device_offline", "x", device_id=d, now=stamp())
    assert behind == {2} and {e[1] for e in events(conn) if e[2]} == {2}                  # the camera hangs below the AP; the AP itself and the NAS are not behind it


def test_times_a_window_across_midnight_belongs_to_the_day_it_started():
    quiet = {"tz": "UTC", "offset_min": 0}
    when = {"days": [4], "from": "22:00", "to": "07:00"}                      # Fridays 22:00 to 07:00
    at = lambda d, hhmm: datetime.strptime(f"2026-11-{d} {hhmm}", "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
    assert alertrules.in_window(when, at(20, "23:00"), quiet)                  # Friday night
    assert alertrules.in_window(when, at(21, "03:00"), quiet)                  # Saturday small hours: still the Friday window
    assert not alertrules.in_window(when, at(21, "23:00"), quiet)              # Saturday night is another day
    assert not alertrules.in_window(when, at(20, "12:00"), quiet) and not alertrules.in_window(when, at(20, "03:00"), quiet)
    assert alertrules.in_window({"days": [0, 1], "from": "08:00", "to": "08:00"}, at(16, "14:00"), quiet)       # the same time twice is the whole day
    assert alertrules.in_window(None, at(16, "14:00"), quiet)


def test_while_a_device_is_down(conn):
    rule(conn, name="NVR", type="while_down", device_id=3, kinds=["device_offline"], scope={"type": "devices", "ids": [2, 3]})
    add_event(conn, "device_offline", "cam", device_id=2, now=stamp())                         # the NAS is up: announced
    conn.execute("UPDATE devices SET online = 0 WHERE id = 3")
    conn.commit()
    add_event(conn, "device_offline", "cam", device_id=2, now=stamp())                         # the NAS is down: muted
    add_event(conn, "device_offline", "NAS", device_id=3, now=stamp())                         # what is said about the NAS itself is never held back by its own rule
    assert [e[2] for e in events(conn)] == [None, "Rule: NVR", None]


def test_repeats_are_muted_after_the_limit_and_announced_once(conn):
    rule(conn, name="Flapping", type="repeat", kinds=["device_offline"], count=3, minutes=10)
    for minutes_ago in (9, 8, 7, 6, 5, 4):
        add_event(conn, "device_offline", f"flap {minutes_ago}", device_id=1, now=stamp(minutes_ago))
    add_event(conn, "device_offline", "other device", device_id=2, now=stamp(3))               # another device has its own count
    got = events(conn)
    assert [g[2] for g in got if g[0] == "device_offline"] == [None, None, None, "Rule: Flapping", "Rule: Flapping", "Rule: Flapping", None]
    summaries = [g for g in got if g[0] == "alerts_muted"]
    assert len(summaries) == 1                                                                   # one message when the limit is passed, not one per muted event
    text = conn.execute("SELECT detail FROM events WHERE kind = 'alerts_muted'").fetchone()[0]
    assert "Garden AP" in text and "3" in text and "Flapping" in text
    add_event(conn, "device_offline", "much later", device_id=1, now=stamp(-30))              # quiet for longer than the window: announced again
    assert events(conn)[-1][2] is None


def test_repeats_can_be_counted_for_all_the_devices_together(conn):
    rule(conn, name="Storm", type="repeat", kinds=["device_offline"], count=2, minutes=5, per="scope", scope={"type": "group", "ids": [1]})
    for d in (1, 2, 1):
        add_event(conn, "device_offline", "x", device_id=d, now=stamp(1))
    assert [e[2] for e in events(conn) if e[0] == "device_offline"] == [None, None, "Rule: Storm"]


def test_the_preview_replays_the_last_days_without_changing_anything(conn):
    base = datetime.now(timezone.utc)
    for minutes_ago, d in ((300, 1), (200, 1), (100, 2), (50, 3)):
        add_event(conn, "device_offline", f"d{d}", device_id=d, now=stamp(minutes_ago, base))
    add_event(conn, "device_online", "back", device_id=1, now=stamp(40, base))
    before = events(conn)
    out = alertrules.preview(conn, {"name": "Preview", "type": "mute", "kinds": ["device_offline"], "scope": {"type": "group", "ids": [1]}}, days=7)
    assert out["events"] == 5 and out["muted"] == 4 and out["by_kind"] == {"device_offline": 3, "device_online": 1} and len(out["examples"]) == 4    # two for the AP, one for the camera and the AP's recovery
    assert events(conn) == before
    repeat = alertrules.preview(conn, {"name": "R", "type": "repeat", "kinds": ["device_offline"], "count": 2, "minutes": 600, "per": "device"}, days=7)
    assert repeat["muted"] == 0                                                                    # no device went offline three times
    with pytest.raises(alertrules.RuleError):
        alertrules.preview(conn, {"name": "x", "type": "mute", "kinds": []})


class Poster:
    def __init__(self):
        self.calls = []

    def __call__(self, url, data, headers, timeout):
        self.calls.append(data.decode())
        return 200, "ok"


async def test_a_muted_event_is_recorded_but_not_sent_and_the_summary_is(conn, tmp_path):
    channels.save_channels(conn, [{"id": "a", "type": "discord", "name": "a", "enabled": True, "events": ["device_offline", "alerts_muted"], "settings": {"webhook_url": "https://a.example/hook"}, "last_event_id": 0}])
    rule(conn, name="Flapping", type="repeat", kinds=["device_offline"], count=2, minutes=10)
    add_event(conn, "device_offline", "Garden AP offline", device_id=1, now=stamp(4))            # the first two are announced
    add_event(conn, "device_offline", "Garden AP offline second", device_id=1, now=stamp(3))
    add_event(conn, "device_offline", "Garden AP offline again", device_id=1, now=stamp(2))      # the third is muted, and one summary says so
    add_event(conn, "device_offline", "once more", device_id=1, now=stamp(1))                    # muted, no second summary
    poster = Poster()
    assert (await channels.process_channels(str(tmp_path / "netlens.db"), poster=poster))["sent"] == 1
    text = " ".join(poster.calls)
    assert "2 offline" in text and text.count("Offline: Garden AP") == 2 and "Muted" in text and "Flapping" in text          # two offline events and the one summary; the muted ones are not in it
    assert [e[0] for e in events(conn)] == ["device_offline", "device_offline", "alerts_muted", "device_offline", "device_offline"]       # all of it is on record


def test_the_api(tmp_path):
    tsdb.forget_all()
    app = create_app(load_settings({"NETLENS_TOKEN": "t", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=tmp_path / "netlens.db")
    with TestClient(app) as c:
        c.headers["Authorization"] = "Bearer t"
        meta = c.get("/api/alert-rules").json()
        assert meta["rules"] == [] and any(k["kind"] == "device_offline" and k["problem"] for k in meta["kinds"]) and all(k["kind"] != "audit_tampered" for k in meta["kinds"])
        made = c.post("/api/alert-rules", json={"name": "Night", "type": "mute", "kinds": ["device_offline"], "scope": {"type": "all"}, "when": {"days": [0, 1, 2, 3, 4], "from": "22:00", "to": "07:00"}})
        assert made.status_code == 201
        rid = made.json()["id"]
        assert c.post("/api/alert-rules", json={"name": "", "type": "mute", "kinds": ["device_offline"]}).status_code == 422
        assert c.put(f"/api/alert-rules/{rid}", json={"name": "Night 2", "type": "mute", "kinds": ["device_offline"], "scope": {"type": "all"}}).json()["name"] == "Night 2"
        assert c.put(f"/api/alert-rules/{rid}/enabled", json={"enabled": False}).json()["enabled"] is False
        assert c.put("/api/alert-rules/zzzz/enabled", json={"enabled": True}).status_code == 404
        pv = c.post("/api/alert-rules/preview", json={"rule": {"name": "p", "type": "mute", "kinds": ["device_offline"], "scope": {"type": "all"}}}).json()
        assert pv["events"] == 0 and pv["muted"] == 0
        assert c.get("/api/events?held=true").status_code == 200 and c.get("/api/events?held=false").status_code == 200
        assert c.delete(f"/api/alert-rules/{rid}").status_code == 204 and c.delete(f"/api/alert-rules/{rid}").status_code == 404
    tsdb.forget_all()


def test_ask_can_say_why_nobody_was_told(conn):
    from app import ask_extra

    rule(conn, name="Garden", scope={"type": "group", "ids": [1]})
    add_event(conn, "device_offline", "Garden AP offline", device_id=1, now=stamp())
    add_event(conn, "device_offline", "NAS offline", device_id=3, now=stamp())
    out = ask_extra.t_muted(conn, {"days": 3}, NOW + timedelta(hours=1))
    assert out["held_back"] == 1 and out["by_reason"] == [{"reason": "Rule: Garden", "events": 1}] and out["rules"][0]["name"] == "Garden"
    text = ask_extra.r_muted(out)
    assert "1 event(s) were recorded but not sent" in text and "Rule: Garden" in text and "Garden AP" in text
    assert ask_extra.t_muted(conn, {"device": "NAS", "days": 3}, NOW + timedelta(hours=1))["held_back"] == 0
    import re

    routed = {t for t, rx in ask_extra.RULES if re.search(rx, "why didn't I get an alert for the garden camera", re.I)}
    assert "muted" in routed and "muted" in ask_extra.TOOLS and "muted" in ask_extra.RENDERERS
