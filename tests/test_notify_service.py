from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import add_event, connect, get_or_create_device, init_db
from app.main import create_app
from app.notify.config import NotifyConfig, load_config, save_config
from app.notify.mail import MailError
from app.notify.service import process_notifications
from app.scanner.orchestrator import ScanManager

AUTH = {"Authorization": "Bearer secret"}


def _cfg(**kw) -> NotifyConfig:
    base = dict(enabled=True, smtp_host="smtp.test", from_addr="nl@test.io", to_addrs=["me@test.io"])
    base.update(kw)
    return NotifyConfig(**base)


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    conn.close()
    return str(path)


def _conn(db):
    return connect(db)


class Sender:
    def __init__(self, fail=False):
        self.sent, self.fail = [], fail

    def __call__(self, cfg, subject, body):
        if self.fail:
            raise MailError("connection refused by SMTP server")
        self.sent.append((subject, body))


@pytest.mark.asyncio
async def test_disabled_does_nothing(db):
    sender = Sender()
    assert (await process_notifications(db, sender=sender))["reason"] == "disabled"
    assert sender.sent == []


@pytest.mark.asyncio
async def test_first_run_initialises_without_mailing_history(db):
    c = _conn(db)
    d = get_or_create_device(c, "aa:bb:cc:00:00:01", "192.168.1.5")
    add_event(c, "device_new", "192.168.1.5", device_id=d)
    save_config(c, _cfg())
    c.close()
    sender = Sender()
    assert (await process_notifications(db, sender=sender))["reason"] == "initialised"
    assert sender.sent == []
    c = _conn(db)
    assert load_config(c).last_event_id == 1
    c.close()


@pytest.mark.asyncio
async def test_new_and_offline_are_mailed_once_and_opt_out_is_respected(db):
    c = _conn(db)
    save_config(c, _cfg(last_event_id=0))
    a = get_or_create_device(c, "aa:bb:cc:00:00:01", "192.168.1.5")
    b = get_or_create_device(c, "aa:bb:cc:00:00:02", "192.168.1.6")
    c.execute("UPDATE devices SET notify_offline = 0 WHERE id = ?", (b,))
    c.commit()
    add_event(c, "device_new", "192.168.1.5 Acme", device_id=a)
    add_event(c, "device_offline", "192.168.1.5", device_id=a)
    add_event(c, "device_offline", "192.168.1.6", device_id=b)  # opted out
    c.close()

    sender = Sender()
    result = await process_notifications(db, sender=sender)
    assert result["sent"] == 2
    subject, body = sender.sent[0]
    assert subject == "[Netlens] 1 new device, 1 device offline"
    assert "192.168.1.5" in body and "192.168.1.6" not in body

    # nothing new -> nothing sent; the cursor advanced past the filtered event too
    assert (await process_notifications(db, sender=sender))["sent"] == 0
    assert len(sender.sent) == 1


@pytest.mark.asyncio
async def test_failed_send_is_retried_after_next_scan(db):
    c = _conn(db)
    save_config(c, _cfg(last_event_id=0))
    a = get_or_create_device(c, "aa:bb:cc:00:00:01", "192.168.1.5")
    add_event(c, "device_new", "192.168.1.5", device_id=a)
    c.close()

    result = await process_notifications(db, sender=Sender(fail=True))
    assert "refused" in result["error"]
    c = _conn(db)
    assert load_config(c).last_event_id == 0  # not advanced
    c.close()

    good = Sender()
    assert (await process_notifications(db, sender=good))["sent"] == 1


@pytest.mark.asyncio
async def test_scan_runs_after_scan_hooks_and_survives_hook_errors(db):
    calls = []

    async def good(path):
        calls.append(path)

    async def bad(path):
        raise RuntimeError("boom")

    async def runner(kind, targets, **kw):
        return '<?xml version="1.0"?><nmaprun></nmaprun>'

    async def names():
        return {}

    async def ranges():
        return ["192.168.1.0/24"]

    settings = load_settings({"NETLENS_TOKEN": "secret"})
    manager = ScanManager(db, settings, runner=runner, names_provider=names, ranges_provider=ranges, after_scan=[bad, good])
    await manager.start("quick")
    await manager.wait()
    assert calls == [db]
    c = _conn(db)
    assert c.execute("SELECT status FROM scans").fetchone()["status"] == "done"
    c.close()


def _client(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    app.state.sent = []

    def fake_sender(cfg, subject, body):
        app.state.sent.append((cfg.to_addrs, subject))

    app.state.mail_sender = fake_sender
    return app, TestClient(app, headers=AUTH)


def test_api_roundtrip_masks_password(tmp_path):
    app, c = _client(tmp_path)
    with c:
        r = c.put("/api/notifications", json={
            "smtp_host": "smtp.test", "smtp_port": 465, "security": "ssl", "username": "u", "password": "s3cret",
            "from_addr": "nl@test.io", "to_addrs": "a@test.io, b@test.io", "enabled": True,
        })
        assert r.status_code == 200
        body = r.json()
        assert body["to_addrs"] == ["a@test.io", "b@test.io"] and body["password_set"] is True
        assert "password" not in body and "s3cret" not in r.text
        # partial update keeps the password
        r = c.put("/api/notifications", json={"notify_new": False})
        assert r.json()["password_set"] is True and r.json()["notify_new"] is False
        # enabling initialised the cursor so history is not mailed
        conn = connect(tmp_path / "t.db")
        assert load_config(conn).last_event_id == 0 and load_config(conn).password == "s3cret"
        conn.close()


@pytest.mark.parametrize("payload", [
    {"security": "plain"},
    {"smtp_port": 0},
    {"to_addrs": "not-an-address"},
    {"from_addr": "a@x.io, b@x.io"},
    {"enabled": True},  # not configured yet
])
def test_api_validation(tmp_path, payload):
    _, c = _client(tmp_path)
    with c:
        assert c.put("/api/notifications", json=payload).status_code == 422


def test_api_test_mail(tmp_path):
    app, c = _client(tmp_path)
    with c:
        assert c.post("/api/notifications/test").status_code == 422  # nothing configured
        c.put("/api/notifications", json={"smtp_host": "h", "from_addr": "nl@test.io", "to_addrs": ["me@test.io"]})
        r = c.post("/api/notifications/test")
        assert r.json() == {"ok": True, "to": ["me@test.io"]}
        assert app.state.sent == [(["me@test.io"], "[Netlens] Test email")]

        def failing(cfg, subject, body):
            raise MailError("authentication failed (check username and password)")

        app.state.mail_sender = failing
        r = c.post("/api/notifications/test")
        assert r.status_code == 502 and "authentication failed" in r.json()["detail"]
        assert c.get("/api/notifications").json()["status"]["ok"] is False
        assert c.get("/api/notifications", headers={"Authorization": "Bearer x"}).status_code == 401


def test_per_device_offline_switch_via_api(tmp_path):
    app, c = _client(tmp_path)
    conn = connect(tmp_path / "t.db")
    init_db(conn)
    d = get_or_create_device(conn, "aa:bb:cc:00:00:01", "192.168.1.5")
    conn.close()
    with c:
        assert c.get(f"/api/devices/{d}").json()["notify_offline"] is True
        r = c.patch(f"/api/devices/{d}", json={"notify_offline": False})
        assert r.status_code == 200 and r.json()["notify_offline"] is False
        assert c.get("/api/devices").json()[0]["notify_offline"] is False
        c.patch(f"/api/devices/{d}", json={"notify_offline": True})
        assert c.get(f"/api/devices/{d}").json()["notify_offline"] is True
