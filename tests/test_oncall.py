import asyncio
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app import escalation, licence, oncall
from app.config import load_settings
from app.db import add_event, connect, get_or_create_device, init_db
from app.main import create_app
from app.notify import channels as ch

ADMIN = {"Authorization": "Bearer secret"}


def utc(text):
    return datetime.strptime(text, "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def licensed(monkeypatch):
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    ch.save_channels(c, [
        {"id": "c-ann", "type": "ntfy", "name": "Ann phone", "enabled": True, "events": ["service_down"], "settings": {"server": "https://ntfy.example", "topic": "ann"}, "last_event_id": 0},
        {"id": "c-bob", "type": "ntfy", "name": "Bob phone", "enabled": True, "events": ["service_down"], "settings": {"server": "https://ntfy.example", "topic": "bob"}, "last_event_id": 0},
        {"id": "c-cy", "type": "ntfy", "name": "Cy phone", "enabled": True, "events": ["service_down"], "settings": {"server": "https://ntfy.example", "topic": "cy"}, "last_event_id": 0},
    ])
    yield c
    c.close()


SCHEDULE = {
    "enabled": True, "tz": "UTC",
    "people": [{"id": "ann", "name": "Ann", "channels": ["c-ann"]}, {"id": "bob", "name": "Bob", "channels": ["c-bob"]}, {"id": "cy", "name": "Cy", "channels": ["c-cy"]}],
    "shifts": [
        {"name": "Days", "days": [0, 1, 2, 3, 4], "start": "08:00", "end": "18:00", "people": ["ann", "bob"], "rotate": "weekly"},
        {"name": "Nights", "days": [0, 1, 2, 3, 4, 5, 6], "start": "22:00", "end": "06:00", "people": ["cy"], "rotate": "none"},
    ],
    "overrides": [], "fallback": ["bob"],
}


def who(conn, when):
    r = oncall.on_call(conn, utc(when))
    return [p["id"] for p in r["people"]], r["source"], r["until"]


def test_a_shift_and_a_night_shift_past_midnight(conn):
    oncall.save_policy(conn, SCHEDULE)
    assert who(conn, "2026-10-20 09:00")[1] == "Days"                     # a Tuesday morning
    assert who(conn, "2026-10-20 23:30") == (["cy"], "Nights", "2026-10-21T06:00:00Z")
    assert who(conn, "2026-10-21 02:00") == (["cy"], "Nights", "2026-10-21T06:00:00Z")   # still the night that began the evening before
    assert who(conn, "2026-10-20 19:00") == (["bob"], "fallback", None)   # nothing covers 19:00: the fallback


def test_weekly_rotation_switches_on_monday_and_daily_every_day(conn):
    oncall.save_policy(conn, SCHEDULE)
    week = [who(conn, f"2026-10-{d} 10:00")[0] for d in (19, 20, 23)]       # Mon, Tue, Fri of one week
    assert week[0] == week[1] == week[2] and len(week[0]) == 1
    nextweek = who(conn, "2026-10-26 10:00")[0]
    assert nextweek != week[0]
    daily = {**SCHEDULE, "shifts": [{**SCHEDULE["shifts"][0], "rotate": "daily"}]}
    oncall.save_policy(conn, daily)
    assert who(conn, "2026-10-20 10:00")[0] != who(conn, "2026-10-21 10:00")[0]


def test_override_beats_the_shifts_and_ends(conn):
    oncall.save_policy(conn, {**SCHEDULE, "overrides": [{"person": "cy", "from": "2026-10-20T08:00", "to": "2026-10-21T08:00", "note": "swap"}]})
    assert who(conn, "2026-10-20 10:00") == (["cy"], "override", "2026-10-21T08:00:00Z")
    assert who(conn, "2026-10-21 10:00")[1] == "Days"


def test_time_zone_is_respected(conn):
    oncall.save_policy(conn, {**SCHEDULE, "tz": "Europe/Brussels"})
    assert who(conn, "2026-10-20 06:30")[1] == "Days"                      # 08:30 in Brussels (summer time, UTC+2)
    assert who(conn, "2026-10-20 03:30")[1] == "Nights"                    # 05:30 local is still the night shift
    assert who(conn, "2026-10-20 05:30")[1] == "fallback"                  # 07:30 local: the night is over and the day shift has not begun


def test_nobody_on_call_without_a_fallback(conn):
    oncall.save_policy(conn, {**SCHEDULE, "fallback": []})
    assert who(conn, "2026-10-20 19:00") == ([], None, None)


def test_channels_now_and_the_switch(conn):
    oncall.save_policy(conn, {**SCHEDULE, "enabled": False})
    assert oncall.channels_now(conn, utc("2026-10-20 23:30")) == []
    oncall.save_policy(conn, SCHEDULE)
    assert oncall.channels_now(conn, utc("2026-10-20 23:30")) == ["c-cy"]


def test_validation(conn):
    bad = [
        {"people": [{"name": ""}]},
        {"people": [{"name": "A", "channels": ["nope"]}]},
        {"people": [{"name": "A"}, {"name": "A"}]},
        {"people": [{"id": "a", "name": "A"}], "shifts": [{"days": [], "start": "08:00", "end": "09:00", "people": ["a"]}]},
        {"people": [{"id": "a", "name": "A"}], "shifts": [{"days": [1], "start": "8:00", "end": "09:00", "people": ["a"]}]},
        {"people": [{"id": "a", "name": "A"}], "shifts": [{"days": [1], "start": "08:00", "end": "08:00", "people": ["a"]}]},
        {"people": [{"id": "a", "name": "A"}], "shifts": [{"days": [1], "start": "08:00", "end": "09:00", "people": ["zz"]}]},
        {"people": [{"id": "a", "name": "A"}], "overrides": [{"person": "a", "from": "2026-10-20T10:00", "to": "2026-10-20T09:00"}]},
        {"people": [{"id": "a", "name": "A"}], "fallback": ["zz"]},
        {"tz": "not a zone!"},
    ]
    for data in bad:
        with pytest.raises(oncall.OnCallError):
            oncall.clean_policy(conn, data)


def test_timeline_lists_coming_shifts_and_overrides(conn):
    oncall.save_policy(conn, {**SCHEDULE, "overrides": [{"person": "cy", "from": "2026-10-21T08:00", "to": "2026-10-21T12:00", "note": "swap"}]})
    rows = oncall.timeline(conn, utc("2026-10-20 12:00"), days=2)
    assert any(r["kind"] == "override" and r["name"] == "swap" for r in rows)
    assert [r["from"] for r in rows] == sorted(r["from"] for r in rows)
    assert any(r["name"] == "Days" and r["people"] for r in rows)


def test_escalation_reaches_whoever_is_on_call(conn):
    oncall.save_policy(conn, SCHEDULE)
    d = get_or_create_device(conn, "aa:bb:cc:00:00:01", "10.0.0.1")
    eid = add_event(conn, "service_down", "web down", d, now="2026-10-20T23:00:00Z")
    escalation.save_policy(conn, {"enabled": True, "kinds": ["service_down"], "levels": [{"after_min": 5, "channels": ["@oncall"]}]})
    sent = []

    def poster(url, data, headers, timeout=15.0):
        sent.append(url)
        return 200, "ok"

    conn.commit()
    path = conn.execute("PRAGMA database_list").fetchone()[2]
    n = asyncio.run(escalation.process(path, now=utc("2026-10-20 23:30"), poster=poster))
    assert n == 1 and sent and sent[0].endswith("/cy")                      # Cy has the night shift
    assert eid


def post(sent):
    def poster(url, data, headers, timeout=15.0):
        sent.append(url)
        return 200, "ok"

    return poster


def test_escalation_waits_when_nobody_is_on_call(conn):
    oncall.save_policy(conn, {**SCHEDULE, "fallback": []})
    d = get_or_create_device(conn, "aa:bb:cc:00:00:01", "10.0.0.1")
    add_event(conn, "service_down", "web down", d, now="2026-10-20T18:30:00Z")
    escalation.save_policy(conn, {"enabled": True, "kinds": ["service_down"], "levels": [{"after_min": 5, "channels": ["@oncall"]}]})
    conn.commit()
    path = conn.execute("PRAGMA database_list").fetchone()[2]
    sent = []
    assert asyncio.run(escalation.process(path, now=utc("2026-10-20 19:00"), poster=post(sent))) == 0 and not sent
    assert conn.execute("SELECT COUNT(*) FROM escalation_state WHERE level > 0").fetchone()[0] == 0          # still open: the next round looks again
    assert asyncio.run(escalation.process(path, now=utc("2026-10-20 22:30"), poster=post(sent))) == 1


def test_api_roundtrip(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app) as c:
        r = c.get("/api/oncall", headers=ADMIN)
        assert r.status_code == 200 and r.json()["policy"]["enabled"] is False and r.json()["now"]["people"] == []
        bad = c.put("/api/oncall", json={"people": [{"name": ""}]}, headers=ADMIN)
        assert bad.status_code == 422
        ok = c.put("/api/oncall", json={"enabled": True, "tz": "UTC", "people": [{"id": "a", "name": "Ann"}], "shifts": [{"name": "All", "days": [0, 1, 2, 3, 4, 5, 6], "start": "00:00", "end": "23:59", "people": ["a"]}], "fallback": []}, headers=ADMIN)
        assert ok.status_code == 200 and ok.json()["now"]["people"][0]["name"] == "Ann"
        assert c.get("/api/oncall").status_code == 401
        esc = c.get("/api/escalation", headers=ADMIN).json()
        assert esc["channels"][0]["id"] == "@oncall"


def test_a_channel_with_its_own_quiet_hours(conn):
    q = ch.clean_channel_quiet({"enabled": True, "start": "23:00", "end": "07:00", "bypass_critical": False, "tz": "UTC", "offset_min": 0})
    assert q == {"enabled": True, "start": "23:00", "end": "07:00", "bypass_critical": False, "tz": "UTC", "offset_min": 0}
    assert ch.clean_channel_quiet({"enabled": False}) is None and ch.clean_channel_quiet(None) is None
    with pytest.raises(ValueError):
        ch.clean_channel_quiet({"enabled": True, "start": "late", "end": "07:00"})
