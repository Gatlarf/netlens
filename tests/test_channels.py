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
    assert body["source"] == "netlens" and body["events"][0] == {"id": 5, "ts": "t", "kind": "device_new", "name": "N", "ip": "10.0.0.1", "mac": "m", "detail": "d", "device_id": 3,
                                                                  "severity": "info", "label": ch.EVENT_LABELS["device_new"], "group": None}
    assert body["text"] == "T\nB"
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


async def test_a_channel_with_its_own_quiet_hours_ignores_the_general_ones(db):
    path, conn = db
    sleepy = {**chan("sleepy"), "quiet": {"enabled": True, "start": "22:00", "end": "09:00", "tz": "UTC", "offset_min": 0, "bypass_critical": True}}
    add_channels(conn, sleepy, chan("awake"))
    add_event(conn, "device_new", "10.0.0.1", device_id=1)
    conn.commit()
    p = Poster()
    r = await process_channels(str(path), now=utc(8), poster=p)               # 08:00: the general channel hears it, the sleepy person's own hours hold it
    assert r["sent"] == 1
    assert (await process_channels(str(path), now=utc(10), poster=p))["sent"] == 1           # after 09:00 it arrives


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
    assert set(listing["types"]) == {"email", "ntfy", "telegram", "discord", "pushover", "webhook"} and listing["default_events"] == ch.DEFAULT_EVENTS
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


# ------------------------------------------------------------------ e-mail as a channel
EMAIL = {"smtp_host": "smtp.example.com", "security": "starttls", "smtp_port": "", "username": "u", "password": "pw", "from_addr": "netlens@example.com", "to_addrs": "a@example.com, b@example.com"}


class Mailer:
    def __init__(self, error=None):
        self.sent, self.error = [], error

    def __call__(self, cfg, subject, body):
        from app.notify.mail import MailError

        if self.error:
            raise MailError(self.error)
        self.sent.append((cfg, subject, body))


def test_email_settings_are_validated_and_normalised():
    s = clean_settings("email", EMAIL)
    assert s["to_addrs"] == "a@example.com, b@example.com" and s["security"] == "starttls"
    for bad in ({"to_addrs": ""}, {"to_addrs": "nope"}, {"from_addr": "a@example.com, b@example.com"}, {"smtp_host": ""}, {"security": "tls13"}, {"smtp_port": "abc"}, {"smtp_port": "70000"}):
        with pytest.raises(ValueError):
            clean_settings("email", {**EMAIL, **bad})
    assert clean_settings("email", {**EMAIL, "password": ""}, {"password": "kept"})["password"] == "kept"


def test_email_channel_sends_through_the_mailer():
    m = Mailer()
    send_channel(channel("email", **clean_settings("email", EMAIL)), "[Netlens] 1 new device", "New device: x", [], mailer=m)
    cfg, subject, body = m.sent[0]
    assert (cfg.smtp_host, cfg.smtp_port, cfg.security, cfg.to_addrs) == ("smtp.example.com", 587, "starttls", ["a@example.com", "b@example.com"])
    assert subject == "[Netlens] 1 new device" and body.startswith("New device: x")
    ssl = clean_settings("email", {**EMAIL, "security": "ssl"})
    send_channel(channel("email", **ssl), "t", "b", [], mailer=m)
    assert m.sent[1][0].smtp_port == 465
    custom = clean_settings("email", {**EMAIL, "smtp_port": "2525"})
    send_channel(channel("email", **custom), "t", "b", [], mailer=m)
    assert m.sent[2][0].smtp_port == 2525
    with pytest.raises(ChannelError, match="authentication failed"):
        send_channel(channel("email", **ssl), "t", "b", [], mailer=Mailer("authentication failed (check username and password)"))


async def test_email_channel_takes_part_in_processing(db):
    path, conn = db
    add_channels(conn, {"id": "m", "type": "email", "name": "E-mail", "enabled": True, "events": ["device_new"], "settings": clean_settings("email", EMAIL), "last_event_id": 0})
    add_event(conn, "device_new", "10.0.0.1", device_id=1)
    conn.commit()
    m = Mailer()
    assert await process_channels(str(path), poster=Poster(), mailer=m) == {"sent": 1, "failed": 0}
    assert "new device" in m.sent[0][1]
    failing = Mailer("connection refused by SMTP server")
    ch.save_channels(conn, [{**ch.load_channels(conn)[0], "last_event_id": 0}])
    assert await process_channels(str(path), poster=Poster(), mailer=failing) == {"sent": 0, "failed": 1}
    assert "refused" in ch.load_channels(conn)[0]["status"]["error"]


def test_old_mail_setup_becomes_an_email_channel_once(tmp_path):
    from app.notify.config import NotifyConfig, save_config

    conn = connect(tmp_path / "t.db")
    init_db(conn)
    save_config(conn, NotifyConfig(enabled=True, smtp_host="smtp.example.com", smtp_port=465, security="ssl", username="u", password="pw",
                                   from_addr="n@example.com", to_addrs=["a@example.com"], notify_new=True, notify_offline=False, notify_services=True, last_event_id=7))
    ch.save_channels(conn, [chan("keep", kind="discord")])
    channels = ch.load_channels(conn)
    mail = next(c for c in channels if c["type"] == "email")
    assert mail["enabled"] is True and mail["last_event_id"] == 7 and mail["events"] == ["device_new", "service_down", "service_up"]
    assert mail["settings"]["smtp_port"] == "465" and mail["settings"]["password"] == "pw" and mail["settings"]["to_addrs"] == "a@example.com"
    assert [c["id"] for c in channels if c["type"] != "email"] == ["keep"]
    assert len(ch.load_channels(conn)) == 2          # not again
    ch.save_channels(conn, [])                       # deleted on purpose: it stays deleted
    assert ch.load_channels(conn) == []


def test_nothing_is_migrated_without_a_mail_setup(tmp_path):
    conn = connect(tmp_path / "t.db")
    init_db(conn)
    assert ch.load_channels(conn) == []


def test_email_through_the_api(client):
    r = client.post("/api/notify-channels", json={"type": "email", "name": "Home", "settings": EMAIL})
    assert r.status_code == 201 and "pw" not in r.text and r.json()["secrets_set"] == {"password": True}
    assert client.get("/api/notify-channels").json()["types"]["email"]["fields"][1]["kind"] == "select"
    client.app.state.mail_sender = Mailer()
    assert client.post(f"/api/notify-channels/{r.json()['id']}/test").json() == {"ok": True}
    assert client.app.state.mail_sender.sent[0][1] == "[Netlens] Test message"
    client.app.state.mail_sender = Mailer("authentication failed (check username and password)")
    bad = client.post(f"/api/notify-channels/{r.json()['id']}/test")
    assert bad.status_code == 502 and "authentication failed" in bad.json()["detail"]
    assert client.post("/api/notify-channels", json={"type": "email", "settings": {**EMAIL, "to_addrs": "x"}}).status_code == 422


def test_per_device_offline_switch_via_api(client):
    from app.db import get_or_create_device

    conn = connect(client.app.state.db_path)
    d = get_or_create_device(conn, "aa:bb:cc:00:00:01", "192.168.1.5")
    conn.close()
    assert client.get(f"/api/devices/{d}").json()["notify_offline"] is True
    assert client.patch(f"/api/devices/{d}", json={"notify_offline": False}).json()["notify_offline"] is False
    assert next(x for x in client.get("/api/devices").json() if x["id"] == d)["notify_offline"] is False


# ------------------------------------------------------------------ filters and one message per event
def test_filters_are_validated_and_applied():
    assert ch.clean_filters(None) == {"min_severity": "info", "min_tier": "any", "devices": [], "groups": []}
    assert ch.clean_filters({"min_severity": "warning", "devices": [3, 1, 3], "groups": [2]}) == {"min_severity": "warning", "min_tier": "any", "devices": [1, 3], "groups": [2]}
    for bad in ({"min_severity": "loud"}, {"devices": "1"}, {"groups": ["a"]}, {"devices": [True]}):
        with pytest.raises(ValueError):
            ch.clean_filters(bad)
    down, new = {"kind": "service_down", "device_id": 1, "group_id": 7}, {"kind": "device_new", "device_id": 2, "group_id": None}
    assert ch.severity_of("service_down") == "critical" and ch.severity_of("device_offline") == "warning" and ch.severity_of("device_new") == "info"
    assert ch.passes_filters(down, None) and ch.passes_filters(new, {"min_severity": "info"})
    assert ch.passes_filters(down, {"min_severity": "critical"}) and not ch.passes_filters(new, {"min_severity": "warning"})
    assert ch.passes_filters(down, {"devices": [1]}) and not ch.passes_filters(new, {"devices": [1]})
    assert ch.passes_filters(down, {"groups": [7]}) and not ch.passes_filters(new, {"groups": [7]})
    assert ch.passes_filters(new, {"devices": [1], "groups": [7]}) is False and ch.passes_filters(down, {"devices": [9], "groups": [7]})   # a device or a group


def test_webhook_settings_mode_and_header():
    s = clean_settings("webhook", {"url": "https://n8n.example/hook", "mode": "each", "header": "X-API-Key: abc"})
    assert s["mode"] == "each" and s["header"] == "X-API-Key: abc"
    assert clean_settings("webhook", {"url": "https://x.example"})["mode"] == "batch"
    for bad in ({"mode": "all"}, {"header": "no colon here"}, {"header": "X: a\nInjected: b"}):
        with pytest.raises(ValueError):
            clean_settings("webhook", {"url": "https://x.example", **bad})
    p = Poster()
    send_channel(channel("webhook", url="https://x.example", header="X-API-Key: abc", mode="each"), "T", "B", [{"id": 1, "kind": "service_down", "name": "N", "detail": "d"}], poster=p)
    sent = json.loads(p.calls[-1][1])
    assert p.calls[-1][2]["X-API-Key"] == "abc" and sent["event"]["severity"] == "critical" and "events" not in sent


async def test_a_channel_filters_by_severity_and_device(db):
    path, conn = db
    add_channels(conn, chan("crit", events=["service_down", "device_offline"], filters={"min_severity": "critical"}),
                 chan("dev2", events=["service_down", "device_offline"], filters={"devices": [2]}))
    add_event(conn, "device_offline", "10.0.0.1", device_id=1)
    add_event(conn, "service_down", "web", device_id=1)
    conn.commit()
    p = Poster()
    await process_channels(str(path), poster=p)
    by_url = {c[0]: json.loads(c[1])["content"] for c in p.calls}
    assert list(by_url) == ["https://crit.example/hook"] and "Offline" not in by_url["https://crit.example/hook"]   # dev2 heard nothing: both events are about device 1


async def test_each_mode_sends_one_message_per_event_and_resumes_after_a_failure(db):
    path, conn = db
    hook = {"url": "https://n8n.example/hook", "mode": "each"}
    add_channels(conn, {"id": "n", "type": "webhook", "name": "n8n", "enabled": True, "events": ["device_new", "service_down"], "settings": hook, "last_event_id": 0})
    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        add_event(conn, "device_new", ip, device_id=1)
    conn.commit()

    class Fails(Poster):
        failed = False

        def __call__(self, url, data, headers, timeout):
            if len(self.calls) == 1 and not self.failed:
                self.failed = True
                raise ChannelError("down")
            return super().__call__(url, data, headers, timeout)

    p = Fails()
    r = await process_channels(str(path), poster=p)
    assert r == {"sent": 1, "failed": 1} and ch.load_channels(connect(path))[0]["last_event_id"] == 1   # the second event is where it resumes
    r = await process_channels(str(path), poster=p)
    assert r == {"sent": 2, "failed": 0} and ch.load_channels(connect(path))[0]["last_event_id"] == 3
    assert [json.loads(c[1])["event"]["detail"] for c in p.calls] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_api_saves_filters_and_rejects_bad_ones(client):
    made = client.post("/api/notify-channels", json={"type": "webhook", "settings": {"url": "https://n8n.example/hook", "mode": "each"},
                                                     "filters": {"min_severity": "warning", "min_tier": "any", "devices": [4], "groups": [1]}})
    assert made.status_code == 201 and made.json()["filters"] == {"min_severity": "warning", "min_tier": "any", "devices": [4], "groups": [1]}
    cid = made.json()["id"]
    assert client.put(f"/api/notify-channels/{cid}", json={"filters": {"min_severity": "critical"}}).json()["filters"] == {"min_severity": "critical", "min_tier": "any", "devices": [], "groups": []}
    assert client.put(f"/api/notify-channels/{cid}", json={"filters": {"min_severity": "nope"}}).status_code == 422
    assert client.post("/api/notify-channels", json={"type": "ntfy", "settings": {"topic": "t"}}).json()["filters"]["min_severity"] == "info"


def test_openclaw_formats():
    s = clean_settings("webhook", {"url": "http://claw.lan:18789/hooks/wake", "format": "openclaw_wake"})
    assert s["format"] == "openclaw_wake" and s["agent_id"] == "main"
    for bad in ({"format": "xml"}, {"agent_id": "bad agent!"}):
        with pytest.raises(ValueError):
            clean_settings("webhook", {"url": "http://x.example", **bad})
    p = Poster()
    ev = [{"id": 1, "kind": "service_down", "name": "NAS", "detail": "NAS web is down"}]
    send_channel(channel("webhook", url="http://c/hooks/wake", format="openclaw_wake", agent_id="main", secret="T"), "[Netlens] Service down", "NAS web is down", ev, poster=p)
    assert json.loads(p.calls[-1][1]) == {"text": "[Netlens] Service down\nNAS web is down", "mode": "now", "agentId": "main"} and p.calls[-1][2]["Authorization"] == "Bearer T"
    send_channel(channel("webhook", url="http://c/hooks/agent", format="openclaw_agent", agent_id="ops"), "T", "B", ev, poster=p)
    assert json.loads(p.calls[-1][1]) == {"message": "T\nB", "name": "Netlens", "agentId": "ops", "deliver": True}


def test_a_channel_can_be_limited_to_critical_or_normal_importance():
    f_all, f_normal, f_critical = ({"min_tier": t} for t in ("any", "normal", "critical"))
    for tier, expect in (("critical", (True, True, True)), ("normal", (True, True, False)), ("low", (True, False, False))):
        e = {"kind": "device_offline", "tier": tier}
        assert tuple(ch.passes_filters(e, f) for f in (f_all, f_normal, f_critical)) == expect
    assert ch.clean_filters({"min_tier": "critical"})["min_tier"] == "critical"
    with pytest.raises(ValueError):
        ch.clean_filters({"min_tier": "loud"})
