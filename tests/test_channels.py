import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import add_event, connect, init_db
from app.main import create_app
from app.notify import channels as ch
from app.notify.channels import ChannelError, build_digest, clean_quiet, clean_settings, in_quiet_hours, process_channels, send_channel

AUTH = {"Authorization": "Bearer secret"}


def utc(h, m=0):
    return datetime(2026, 3, 10, h, m, tzinfo=timezone.utc)


class Poster:
    def __init__(self, status=200):
        self.calls, self.status = [], status

    def __call__(self, url, data, headers, timeout):
        self.calls.append((url, data, headers))
        return self.status, "ok"


def channel(kind, **settings):
    return {"id": "c1", "type": kind, "name": kind, "enabled": True, "events": ch.DEFAULT_EVENTS, "settings": settings}


# ------------------------------------------------------------------ settings
def test_clean_settings_defaults_required_and_secrets():
    s = clean_settings("ntfy", {"topic": "my-topic"})
    assert s == {"server": "https://ntfy.sh", "topic": "my-topic", "token": "", "priority": "default"}
    assert clean_settings("ntfy", {"topic": "t2"}, {"token": "SECRET", "topic": "t1"})["token"] == "SECRET"  # a blank secret keeps the saved one
    for kind, bad, message in [
        ("ntfy", {}, "Topic is required"), ("ntfy", {"topic": "bad topic!"}, "topic may only"), ("ntfy", {"topic": "t", "priority": "urgent"}, "priority"),
        ("ntfy", {"topic": "t", "server": "ftp://x"}, "http"), ("telegram", {"bot_token": "x"}, "Chat ID"), ("discord", {"webhook_url": "nope"}, "http"),
        ("webhook", {"url": ""}, "URL is required"), ("pushover", {"app_token": "a"}, "User key"),
    ]:
        with pytest.raises(ValueError, match=message):
            clean_settings(kind, bad)


def test_clean_events():
    assert ch.clean_events(["service_up", "device_new"]) == ["device_new", "service_up"]
    for bad in ("x", ["device_new", "nope"]):
        with pytest.raises(ValueError):
            ch.clean_events(bad)


# ------------------------------------------------------------------ sending
def test_each_service_gets_the_right_request():
    p = Poster()
    send_channel(channel("ntfy", server="https://ntfy.example/", topic="t", token="TOK", priority="high"), "Title é", "body", [], poster=p)
    url, data, headers = p.calls[-1]
    assert url == "https://ntfy.example/t" and data == b"body" and headers["Authorization"] == "Bearer TOK" and headers["Priority"] == "high" and "Title" in headers

    send_channel(channel("telegram", bot_token="123:ABC", chat_id="42"), "T", "B", [], poster=p)
    url, data, _ = p.calls[-1]
    assert url == "https://api.telegram.org/bot123:ABC/sendMessage" and json.loads(data) == {"chat_id": "42", "text": "T\nB"}

    send_channel(channel("discord", webhook_url="https://discord.example/hook"), "T", "B", [], poster=p)
    assert p.calls[-1][0] == "https://discord.example/hook" and json.loads(p.calls[-1][1]) == {"content": "**T**\nB"}

    send_channel(channel("pushover", app_token="a", user_key="u"), "T", "B", [], poster=p)
    assert p.calls[-1][0] == "https://api.pushover.net/1/messages.json" and b"token=a" in p.calls[-1][1] and b"user=u" in p.calls[-1][1]

    events = [{"id": 5, "ts": "t", "kind": "device_new", "name": "N", "ip": "10.0.0.1", "mac": "m", "detail": "d", "device_id": 3, "secretish": "x"}]
    send_channel(channel("webhook", url="https://hook.example/x", secret="S"), "T", "B", events, poster=p)
    body = json.loads(p.calls[-1][1])
    assert body["source"] == "netlens" and body["events"][0] == {"id": 5, "ts": "t", "kind": "device_new", "name": "N", "ip": "10.0.0.1", "mac": "m", "detail": "d", "device_id": 3}
    assert p.calls[-1][2]["Authorization"] == "Bearer S"


@pytest.mark.parametrize("status,hint", [(401, "token"), (404, "address"), (429, "rate"), (500, "HTTP 500")])
def test_errors_are_clear_and_never_leak_the_token(status, hint):
    with pytest.raises(ChannelError, match=hint) as exc:
        send_channel(channel("telegram", bot_token="123:SECRETTOKEN", chat_id="1"), "T", "B", [], poster=Poster(status))
    assert "SECRETTOKEN" not in str(exc.value)

    def unreachable(url, data, headers, timeout):
        raise ChannelError("cannot reach the server (timed out)")

    with pytest.raises(ChannelError, match="cannot reach"):
        send_channel(channel("discord", webhook_url="https://x"), "T", "B", [], poster=unreachable)


def test_digest_text():
    events = [
        {"kind": "device_new", "name": "Phone", "ip": "10.0.0.7", "vendor": "Apple", "trusted": 0, "detail": ""},
        {"kind": "device_offline", "name": "NAS", "ip": "10.0.0.2", "trusted": 1, "detail": ""},
        {"kind": "service_down", "name": "x", "ip": "", "detail": "Web (10.0.0.2:80) is down: refused"},
    ]
    title, body = build_digest(events)
    assert title == "[Netlens] 1 new device, 1 offline, 1 service down"
    assert body.splitlines() == ["New device: Phone (10.0.0.7), Apple [unknown device]", "Offline: NAS (10.0.0.2)", "Web (10.0.0.2:80) is down: refused"]
    many = [{"kind": "device_offline", "name": f"d{i}", "ip": "", "detail": ""} for i in range(50)]
    assert build_digest(many)[1].splitlines()[-1] == "... and 10 more"


# ------------------------------------------------------------------ quiet hours
@pytest.mark.parametrize("quiet,hour,expected", [
    ({"enabled": True, "start": "23:00", "end": "07:00"}, 23, True), ({"enabled": True, "start": "23:00", "end": "07:00"}, 3, True),
    ({"enabled": True, "start": "23:00", "end": "07:00"}, 7, False), ({"enabled": True, "start": "23:00", "end": "07:00"}, 12, False),
    ({"enabled": True, "start": "13:00", "end": "15:00"}, 14, True), ({"enabled": True, "start": "13:00", "end": "15:00"}, 15, False),
    ({"enabled": False, "start": "00:00", "end": "23:59"}, 3, False), ({"enabled": True, "start": "08:00", "end": "08:00"}, 8, False),
])
def test_quiet_hours(quiet, hour, expected):
    assert in_quiet_hours(utc(hour), {"tz": "UTC", "offset_min": 0, "bypass_critical": True, **quiet}) is expected


def test_quiet_hours_use_the_users_time_zone_or_offset():
    q = {"enabled": True, "start": "23:00", "end": "07:00", "bypass_critical": True}
    assert in_quiet_hours(utc(22, 30), {**q, "tz": "Europe/Brussels", "offset_min": 60}) is True  # 23:30 local (CET)
    assert in_quiet_hours(utc(22, 30), {**q, "tz": "Not/AZone", "offset_min": 60}) is True  # unknown name: the offset from the browser
    assert in_quiet_hours(utc(22, 30), {**q, "tz": "UTC", "offset_min": 0}) is False
    assert clean_quiet({"enabled": True, "start": "22:00", "end": "06:30", "tz": "Europe/Brussels", "offset_min": 60})["end"] == "06:30"
    for bad in ({"start": "25:00", "end": "07:00"}, {"start": "22:00", "end": "7"}, {"start": "22:00", "end": "07:00", "tz": "x y"}, {"start": "22:00", "end": "07:00", "offset_min": 9999}):
        with pytest.raises(ValueError):
            clean_quiet({"enabled": True, **bad})


# ------------------------------------------------------------------ processing
@pytest.fixture
def db(tmp_path):
    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    conn.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen, trusted) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.1', 'phone', 1, 'x', 'x', 0)")
    conn.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen, trusted, notify_offline) VALUES (2, 'aa:00:00:00:00:02', '10.0.0.2', 'tv', 1, 'x', 'x', 1, 0)")
    conn.commit()
    return path, conn


def add_channels(conn, *chs):
    ch.save_channels(conn, list(chs))


def chan(id, kind="discord", events=None, last=0, **extra):
    return {"id": id, "type": kind, "name": id, "enabled": True, "events": events or ["device_new", "device_offline", "service_down"],
            "settings": {"webhook_url": f"https://{id}.example/hook"}, "last_event_id": last, **extra}


async def test_a_channel_only_hears_what_it_asked_for(db):
    path, conn = db
    add_channels(conn, chan("a", events=["device_new"]), chan("b", events=["device_offline", "service_down"]))
    add_event(conn, "device_new", "10.0.0.1", device_id=1)
    add_event(conn, "device_offline", "10.0.0.2", device_id=2)  # device 2 has its offline switch off
    add_event(conn, "device_offline", "10.0.0.1", device_id=1)
    add_event(conn, "port_opened", "tcp/22", device_id=1)  # nobody asked
    conn.commit()
    p = Poster()
    assert await process_channels(str(path), poster=p) == {"sent": 2, "failed": 0}
    by_url = {c[0]: json.loads(c[1])["content"] for c in p.calls}
    assert "New device: phone (10.0.0.1) [unknown device]" in by_url["https://a.example/hook"] and "Offline" not in by_url["https://a.example/hook"]
    assert by_url["https://b.example/hook"].count("Offline") == 1 and "tv" not in by_url["https://b.example/hook"]  # the muted device is skipped
    assert await process_channels(str(path), poster=p) == {"sent": 0, "failed": 0}  # nothing new
    assert len(p.calls) == 2


async def test_a_new_channel_starts_from_now_and_a_re_enabled_one_skips_the_gap(db):
    path, conn = db
    add_event(conn, "device_new", "10.0.0.1", device_id=1)
    add_channels(conn, {**chan("a"), "last_event_id": None})  # never ran
    conn.commit()
    p = Poster()
    await process_channels(str(path), poster=p)
    assert p.calls == []  # the history is not sent
    add_event(conn, "device_new", "10.0.0.9")
    conn.commit()
    assert (await process_channels(str(path), poster=p))["sent"] == 1


async def test_failure_keeps_the_events_for_the_next_try_without_hurting_other_channels(db):
    path, conn = db
    add_channels(conn, chan("bad"), chan("good"))
    add_event(conn, "device_new", "10.0.0.1", device_id=1)
    conn.commit()

    class Flaky(Poster):
        down = True

        def __call__(self, url, data, headers, timeout):
            if "bad" in url and self.down:
                raise ChannelError("cannot reach the server (timed out)")
            return super().__call__(url, data, headers, timeout)

    p = Flaky()
    r = await process_channels(str(path), poster=p)
    channels = {c["id"]: c for c in ch.load_channels(connect(path))}
    assert r == {"sent": 1, "failed": 1}
    assert channels["bad"]["status"]["ok"] is False and "cannot reach" in channels["bad"]["status"]["error"] and channels["bad"]["last_event_id"] == 0
    assert channels["good"]["status"]["ok"] is True and channels["good"]["last_event_id"] == 1  # the other channel was not held up
    p.down = False
    r = await process_channels(str(path), poster=p)
    channels = {c["id"]: c for c in ch.load_channels(connect(path))}
    assert r == {"sent": 1, "failed": 0}  # only the one that had missed it
    assert channels["bad"]["status"]["ok"] is True and channels["bad"]["last_event_id"] == 1  # caught up


async def test_quiet_hours_hold_events_back_until_morning(db):
    path, conn = db
    add_channels(conn, chan("a"))
    ch.set_setting(conn, ch.QUIET_KEY, json.dumps({"enabled": True, "start": "23:00", "end": "07:00", "tz": "UTC", "offset_min": 0, "bypass_critical": True}))
    add_event(conn, "device_new", "10.0.0.1", device_id=1)
    conn.commit()
    p = Poster()
    assert (await process_channels(str(path), now=utc(2), poster=p))["sent"] == 0 and p.calls == []
    add_event(conn, "device_offline", "10.0.0.1", device_id=1)
    conn.commit()
    assert (await process_channels(str(path), now=utc(8), poster=p))["sent"] == 1  # one digest with everything
    text = json.loads(p.calls[0][1])["content"]
    assert "New device" in text and "Offline" in text


async def test_a_service_going_down_breaks_through_quiet_hours(db):
    path, conn = db
    add_channels(conn, chan("a"))
    ch.set_setting(conn, ch.QUIET_KEY, json.dumps({"enabled": True, "start": "23:00", "end": "07:00", "tz": "UTC", "offset_min": 0, "bypass_critical": True}))
    add_event(conn, "device_new", "10.0.0.1", device_id=1)
    add_event(conn, "service_down", "Web (10.0.0.2:80) is down: refused", device_id=2)
    conn.commit()
    p = Poster()
    assert (await process_channels(str(path), now=utc(2), poster=p))["sent"] == 1
    assert "Web (10.0.0.2:80) is down" in json.loads(p.calls[0][1])["content"]
    ch.set_setting(conn, ch.QUIET_KEY, json.dumps({"enabled": True, "start": "23:00", "end": "07:00", "tz": "UTC", "offset_min": 0, "bypass_critical": False}))
    add_event(conn, "service_down", "again", device_id=2)
    conn.commit()
    assert (await process_channels(str(path), now=utc(2), poster=p))["sent"] == 0  # no bypass: held


async def test_disabled_channels_and_events_nobody_wants_advance_quietly(db):
    path, conn = db
    add_channels(conn, {**chan("off"), "enabled": False}, chan("a", events=["device_new"]))
    add_event(conn, "port_opened", "x", device_id=1)
    conn.commit()
    p = Poster()
    assert await process_channels(str(path), poster=p) == {"sent": 0, "failed": 0} and p.calls == []
    assert {c["id"]: c["last_event_id"] for c in ch.load_channels(connect(path))} == {"off": 0, "a": 1}  # a skipped past what it ignores


# ------------------------------------------------------------------ API
@pytest.fixture
def client(db):
    path, conn = db
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    app.state.channel_poster = Poster()
    with TestClient(app, headers=AUTH) as c:
        c.poster = app.state.channel_poster
        yield c


def test_api_crud_masks_secrets(client):
    r = client.post("/api/notify-channels", json={"type": "telegram", "name": "Me", "settings": {"bot_token": "123:SECRETTOKEN", "chat_id": "42"}})
    assert r.status_code == 201 and "SECRETTOKEN" not in r.text
    created = r.json()
    assert created["settings"] == {"chat_id": "42"} and created["secrets_set"] == {"bot_token": True} and created["events"] == ch.DEFAULT_EVENTS
    cid = created["id"]
    listing = client.get("/api/notify-channels").json()
    assert [c["id"] for c in listing["channels"]] == [cid] and "SECRETTOKEN" not in json.dumps(listing)
    assert set(listing["types"]) == {"ntfy", "telegram", "discord", "pushover", "webhook"} and listing["default_events"] == ch.DEFAULT_EVENTS
    assert listing["events"][0] == {"key": "device_new", "label": "A new (unknown) device appears"}

    updated = client.put(f"/api/notify-channels/{cid}", json={"settings": {"chat_id": "43", "bot_token": ""}, "events": ["service_down"], "name": "Renamed"}).json()
    assert updated["settings"]["chat_id"] == "43" and updated["events"] == ["service_down"] and updated["name"] == "Renamed" and updated["secrets_set"]["bot_token"] is True
    stored = ch.load_channels(connect(client.app.state.db_path))[0]
    assert stored["settings"]["bot_token"] == "123:SECRETTOKEN"  # kept

    off = client.put(f"/api/notify-channels/{cid}", json={"enabled": False}).json()
    assert off["enabled"] is False
    assert client.delete(f"/api/notify-channels/{cid}").json() == {"removed": cid}
    assert client.get("/api/notify-channels").json()["channels"] == []
    assert client.delete(f"/api/notify-channels/{cid}").status_code == 404


def test_api_validation_and_auth(client):
    assert client.post("/api/notify-channels", json={"type": "sms", "settings": {}}).status_code == 422
    assert client.post("/api/notify-channels", json={"type": "ntfy", "settings": {}}).status_code == 422
    assert client.post("/api/notify-channels", json={"type": "ntfy", "settings": {"topic": "t"}, "events": ["nope"]}).status_code == 422
    assert client.put("/api/notify-channels/zzz", json={"enabled": True}).status_code == 404
    bad = {"Authorization": "Bearer no"}
    for method, url in (("get", "/api/notify-channels"), ("post", "/api/notify-channels"), ("put", "/api/notify-quiet"), ("post", "/api/notify-channels/x/test")):
        assert getattr(client, method)(url, headers=bad).status_code == 401


def test_api_test_message_and_quiet_settings(client):
    cid = client.post("/api/notify-channels", json={"type": "ntfy", "settings": {"topic": "mytopic"}}).json()["id"]
    assert client.post(f"/api/notify-channels/{cid}/test").json() == {"ok": True}
    assert client.poster.calls[-1][0] == "https://ntfy.sh/mytopic"
    client.app.state.channel_poster = Poster(401)
    r = client.post(f"/api/notify-channels/{cid}/test")
    assert r.status_code == 502 and "token" in r.json()["detail"]
    q = client.put("/api/notify-quiet", json={"enabled": True, "start": "22:30", "end": "06:00", "tz": "Europe/Brussels", "offset_min": 60}).json()
    assert q["start"] == "22:30" and client.get("/api/notify-channels").json()["quiet"]["enabled"] is True
    assert client.put("/api/notify-quiet", json={"enabled": True, "start": "99:99"}).status_code == 422
