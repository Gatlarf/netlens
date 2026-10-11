import asyncio
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import maintenance as m
from app.config import load_settings
from app.db import add_event, connect, get_or_create_device, init_db
from app.main import create_app
from app.notify import channels as ch
from app.notify.config import NotifyConfig
from app.notify.digest import collect_events

AUTH = {"Authorization": "Bearer t"}


def at(day, h, mi=0):
    """A UTC moment; 2026-10-12 is a Monday."""
    return datetime(2026, 10, day, h, mi, tzinfo=timezone.utc)


def weekly(days=(0, 2), start="03:00", end="04:00", **extra):
    return m.clean_window({"name": "AiMesh", "scope": {"devices": [1]}, "schedule": {"type": "weekly", "days": list(days), "start": start, "end": end}, **extra})


# ------------------------------------------------------------------ validation
@pytest.mark.parametrize("data, message", [
    ({"name": "", "scope": {"all": True}, "schedule": {"type": "weekly", "days": [0], "start": "03:00", "end": "04:00"}}, "name"),
    ({"name": "x", "scope": {}, "schedule": {"type": "weekly", "days": [0], "start": "03:00", "end": "04:00"}}, "covers"),
    ({"name": "x", "scope": {"all": True}, "schedule": {"type": "weekly", "days": [], "start": "03:00", "end": "04:00"}}, "day"),
    ({"name": "x", "scope": {"all": True}, "schedule": {"type": "weekly", "days": [7], "start": "03:00", "end": "04:00"}}, "day"),
    ({"name": "x", "scope": {"all": True}, "schedule": {"type": "weekly", "days": [0], "start": "3am", "end": "04:00"}}, "03:00"),
    ({"name": "x", "scope": {"all": True}, "schedule": {"type": "weekly", "days": [0], "start": "03:00", "end": "03:00"}}, "differ"),
    ({"name": "x", "scope": {"all": True}, "schedule": {"type": "once", "start": "2026-10-12T05:00:00Z", "end": "2026-10-12T04:00:00Z"}}, "after"),
    ({"name": "x", "scope": {"all": True}, "schedule": {"type": "sometimes"}}, "weekly or once"),
    ({"name": "x", "scope": {"all": True}, "schedule": {"type": "once", "start": "now", "end": "later"}}, "start"),
])
def test_bad_windows_are_refused(data, message):
    with pytest.raises(ValueError, match=message):
        m.clean_window(data)


# ------------------------------------------------------------------ the schedule
def test_weekly_window_is_active_on_its_days_only():
    w = weekly()                                  # Monday and Wednesday, 03:00-04:00 UTC
    assert m.is_active(w, at(12, 3, 30)) and m.is_active(w, at(14, 3, 0))
    assert not m.is_active(w, at(12, 4, 0)) and not m.is_active(w, at(12, 2, 59)) and not m.is_active(w, at(13, 3, 30))
    assert m.next_start(w, at(12, 3, 30)) == at(14, 3, 0)
    assert m.current_end(w, at(12, 3, 30)) == at(12, 4, 0) and m.current_end(w, at(13, 3, 30)) is None


def test_a_window_may_run_past_midnight():
    w = weekly(days=(5,), start="23:00", end="02:00")        # Saturday night into Sunday
    assert m.is_active(w, at(17, 23, 30)) and m.is_active(w, at(18, 1, 0))
    assert not m.is_active(w, at(18, 2, 0)) and not m.is_active(w, at(16, 23, 30))


def test_the_time_zone_decides_the_local_time():
    w = weekly(days=(0,), start="03:00", end="04:00", tz="Europe/Brussels", offset_min=120)      # CEST, UTC+2
    assert m.is_active(w, at(12, 1, 30)) and not m.is_active(w, at(12, 3, 30))
    off = weekly(days=(0,), start="03:00", end="04:00", tz="No/Such_Zone", offset_min=60)         # unknown name: the browser's offset
    assert m.is_active(off, at(12, 2, 30)) and not m.is_active(off, at(12, 3, 30))


def test_one_off_and_disabled_windows():
    once = m.clean_window({"name": "x", "scope": {"all": True}, "schedule": {"type": "once", "start": "2026-10-12T10:00:00Z", "end": "2026-10-12T12:00:00Z"}})
    assert m.is_active(once, at(12, 11)) and not m.is_active(once, at(12, 12)) and m.next_start(once, at(12, 9)) == at(12, 10) and m.next_start(once, at(12, 11)) is None
    assert not m.is_active({**once, "enabled": False}, at(12, 11))


# ------------------------------------------------------------------ events
class Conn(sqlite3.Connection):
    """A connection that can carry the database path and device ids for the tests."""


@pytest.fixture
def db(tmp_path):
    conn = sqlite3.connect(tmp_path / "t.db", factory=Conn)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_db(conn)
    ids = [get_or_create_device(conn, f"aa:00:00:00:00:0{i}", f"10.0.0.{i}") for i in (1, 2, 3)]
    conn.execute("UPDATE devices SET hostname = 'mesh' WHERE id = ?", (ids[0],))
    conn.execute("INSERT INTO device_groups (id, name, color) VALUES (1, 'attic', '#000000')")
    conn.execute("UPDATE devices SET group_id = 1 WHERE id = ?", (ids[2],))
    conn.commit()
    conn.path = tmp_path / "t.db"
    conn.ids = ids
    return conn


def put_window(conn, **scope):
    w = m.clean_window({"name": "Reboot", "scope": scope, "schedule": {"type": "once", "start": "2026-10-12T02:00:00Z", "end": "2026-10-12T05:00:00Z"}})
    m.save_windows(conn, m.load_windows(conn) + [w])
    return w


def test_scope_all_groups_devices_and_the_devices_behind(db):
    a, b, c = db.ids
    db.execute("UPDATE devices SET parent_mode = 'device', parent_device_id = ? WHERE id = ?", (a, b))
    db.commit()
    assert m.device_ids(db, put_window(db, devices=[a])) == {a}
    assert m.device_ids(db, m.clean_window({"name": "x", "scope": {"devices": [a], "behind": True}, "schedule": {"type": "weekly", "days": [0], "start": "01:00", "end": "02:00"}})) == {a, b}
    assert m.device_ids(db, m.clean_window({"name": "x", "scope": {"groups": [1]}, "schedule": {"type": "weekly", "days": [0], "start": "01:00", "end": "02:00"}})) == {c}
    assert m.device_ids(db, m.clean_window({"name": "x", "scope": {"all": True}, "schedule": {"type": "weekly", "days": [0], "start": "01:00", "end": "02:00"}})) == {a, b, c}


def test_events_in_a_window_are_tagged_and_not_sent(db):
    a, b, _ = db.ids
    put_window(db, devices=[a])
    add_event(db, "device_offline", "10.0.0.1", device_id=a, now="2026-10-12T03:00:00Z")
    add_event(db, "device_offline", "10.0.0.2", device_id=b, now="2026-10-12T03:00:00Z")         # not covered
    add_event(db, "device_offline", "10.0.0.1", device_id=a, now="2026-10-12T06:00:00Z")         # after the window
    add_event(db, "port_opened", "22", device_id=a, now="2026-10-12T03:00:00Z")                  # not an alarm kind
    tags = [(r["device_id"], r["kind"], r["maintenance"]) for r in db.execute("SELECT * FROM events ORDER BY id")]
    assert tags == [(a, "device_offline", "Reboot"), (b, "device_offline", None), (a, "device_offline", None), (a, "port_opened", None)]
    # the e-mail digest leaves the held-back one out
    cfg = NotifyConfig(notify_offline=True)
    db.execute("UPDATE devices SET notify_offline = 1")
    db.commit()
    kept, _ = collect_events(db, 0, cfg)
    assert [(e["device_id"]) for e in kept] == [b, a]
    # and so do the channels
    pending = ch._pending_events(db, 0)
    assert [e["maintenance"] for e in pending] == ["Reboot", None, None, None]


def test_channels_do_not_send_held_back_events(db):
    a = db.ids[0]
    put_window(db, devices=[a])
    channel = {"id": "c1", "type": "webhook", "name": "w", "enabled": True, "events": ["device_offline"], "settings": {"url": "http://x", "secret": ""}, "last_event_id": 0}
    ch.save_channels(db, [channel])
    sent = []
    add_event(db, "device_offline", "10.0.0.1", device_id=a, now="2026-10-12T03:00:00Z")
    result = asyncio.run(ch.process_channels(str(db.path), poster=lambda *args: (sent.append(args) or 200, "ok")))
    assert result["sent"] == 0 and not sent
    assert ch.load_channels(connect(db.path))[0]["last_event_id"] == 1          # and it moved on, so the event is not retried


def test_still_offline_after_the_window_is_announced_once(db):
    a = db.ids[0]
    put_window(db, devices=[a])
    db.execute("UPDATE devices SET online = 0 WHERE id = ?", (a,))
    add_event(db, "device_offline", "10.0.0.1", device_id=a, now="2026-10-12T03:00:00Z")
    assert m.announce_still_down(db, at(12, 4, 0)) == 0               # window still running
    assert m.announce_still_down(db, at(12, 5, 1)) == 1
    assert m.announce_still_down(db, at(12, 5, 2)) == 0               # once only
    last = db.execute("SELECT detail, maintenance FROM events ORDER BY id DESC LIMIT 1").fetchone()
    assert last["maintenance"] is None and "still offline after maintenance 'Reboot'" in last["detail"]


def test_a_device_that_came_back_is_not_announced(db):
    a = db.ids[0]
    put_window(db, devices=[a])
    add_event(db, "device_offline", "10.0.0.1", device_id=a, now="2026-10-12T03:00:00Z")
    add_event(db, "device_online", None, device_id=a, now="2026-10-12T03:20:00Z")
    db.execute("UPDATE devices SET online = 0 WHERE id = ?", (a,))
    assert m.announce_still_down(db, at(12, 6)) == 0


# ------------------------------------------------------------------ the API
@pytest.fixture
def client(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "t", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=tmp_path / "t.db")
    with TestClient(app, headers=AUTH) as c:
        conn = connect(tmp_path / "t.db")
        c.device = get_or_create_device(conn, "aa:00:00:00:00:01", "10.0.0.1")
        conn.close()
        yield c


def body(**extra):
    return {"name": "AiMesh reboot", "scope": {"devices": [], "behind": True}, "schedule": {"type": "weekly", "days": [0, 2, 5, 6], "start": "03:00", "end": "04:00"}, "tz": "UTC", **extra}


def test_create_change_and_delete_a_window(client):
    assert client.get("/api/maintenance").json()["windows"] == []
    assert client.post("/api/maintenance", json=body()).status_code == 422                      # covers nothing
    made = client.post("/api/maintenance", json=body(scope={"devices": [client.device]})).json()["windows"]
    assert len(made) == 1 and made[0]["summary"] == "Mon, Wed, Sat, Sun 03:00–04:00" and made[0]["devices_covered"] == 1 and made[0]["next"]
    wid = made[0]["id"]
    changed = client.put(f"/api/maintenance/{wid}", json=body(name="Renamed", enabled=False, scope={"all": True})).json()["windows"][0]
    assert changed["name"] == "Renamed" and changed["enabled"] is False and changed["next"] is None and changed["id"] == wid
    assert client.put("/api/maintenance/nope", json=body(scope={"all": True})).status_code == 404
    assert client.delete(f"/api/maintenance/{wid}").json()["windows"] == []
    assert client.delete(f"/api/maintenance/{wid}").status_code == 404


def test_start_now_marks_the_device_and_ends_when_deleted(client):
    r = client.post("/api/maintenance/now", json={"device_ids": [client.device], "minutes": 60})
    assert r.status_code == 201
    window = r.json()["windows"][0]
    assert window["active"] and window["manual"] and window["name"].startswith("Manual:")
    assert client.get(f"/api/devices/{client.device}").json()["maintenance"] == window["name"]
    assert next(n for n in client.get("/api/map").json()["nodes"] if n["id"] == client.device)["maintenance"] == window["name"]
    assert client.post("/api/maintenance/now", json={"device_ids": [999], "minutes": 60}).status_code == 404
    assert client.post("/api/maintenance/now", json={"device_ids": [client.device], "minutes": 1}).status_code == 422
    client.delete(f"/api/maintenance/{window['id']}")
    assert client.get(f"/api/devices/{client.device}").json()["maintenance"] is None


def test_events_api_shows_the_window(client):
    client.post("/api/maintenance/now", json={"device_ids": [client.device], "minutes": 30})
    from app.db import add_event

    conn = connect(client.app.state.db_path)
    add_event(conn, "device_offline", "10.0.0.1", device_id=client.device)
    conn.close()
    event = client.get("/api/events").json()[0]
    assert event["kind"] == "device_offline" and event["maintenance"].startswith("Manual:")
