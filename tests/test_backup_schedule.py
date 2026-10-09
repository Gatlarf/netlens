import os
import stat
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import backup_schedule as bs
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app

AUTH = {"Authorization": "Bearer secret"}
T0 = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "netlens.db"
    conn = connect(path)
    init_db(conn)
    yield conn, path
    conn.close()


def test_run_backup_makes_private_valid_file_and_records_it(db):
    conn, path = db
    result = bs.run_backup(conn, path, T0)
    assert result["ok"] and result["name"] == "netlens-20261009-120000.db"
    f = bs.backup_dir(path) / result["name"]
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert stat.S_IMODE(bs.backup_dir(path).stat().st_mode) == 0o700
    assert bs.get_last(conn)["ok"] is True


def test_prune_keeps_newest(db):
    conn, path = db
    bs.set_schedule(conn, {"keep": 2})
    for i in range(4):
        bs.run_backup(conn, path, T0 + timedelta(minutes=i))
    assert [b["name"] for b in bs.list_backups(path)] == ["netlens-20261009-120300.db", "netlens-20261009-120200.db"]


def test_due_logic(db):
    conn, path = db
    assert not bs.is_due(conn, T0)  # disabled
    bs.set_schedule(conn, {"enabled": True, "every_hours": 24})
    assert bs.is_due(conn, T0)  # never ran
    bs.run_backup(conn, path, T0)
    assert not bs.is_due(conn, T0 + timedelta(hours=23))
    assert bs.is_due(conn, T0 + timedelta(hours=24))


def test_failure_is_recorded_event_and_retried_after_an_hour(db, monkeypatch):
    conn, path = db
    bs.set_schedule(conn, {"enabled": True})
    monkeypatch.setattr(bs, "create_backup", lambda *a: (_ for _ in ()).throw(bs.BackupError("disk full")))
    result = bs.run_backup(conn, path, T0)
    assert not result["ok"] and "disk full" in result["error"]
    assert conn.execute("SELECT detail FROM events WHERE kind='backup_failed'").fetchone()[0] == "disk full"
    assert not bs.is_due(conn, T0 + timedelta(minutes=30))
    assert bs.is_due(conn, T0 + timedelta(hours=1))


@pytest.mark.parametrize("raw", [{"every_hours": 5}, {"keep": 0}, {"keep": 61}, {"keep": True}, {"keep": "7"}])
def test_bad_schedule_rejected(db, raw):
    with pytest.raises(ValueError):
        bs.clean_schedule(raw)


def test_backup_path_rejects_traversal(db):
    conn, path = db
    bs.run_backup(conn, path, T0)
    assert bs.backup_path(path, "../netlens.db") is None
    assert bs.backup_path(path, "netlens-20261009-120000.db") is not None


@pytest.fixture
def client(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app, headers=AUTH) as c:
        yield c


def test_api_roundtrip_download_restore_delete(client):
    assert client.get("/api/backups").json()["backups"] == []
    r = client.put("/api/backups/schedule", json={"enabled": True, "every_hours": 12, "keep": 3})
    assert r.json()["schedule"] == {"enabled": True, "every_hours": 12, "keep": 3}
    assert client.put("/api/backups/schedule", json={"every_hours": 5}).status_code == 422
    name = client.post("/api/backups/run").json()["result"]["name"]
    assert client.get(f"/api/backups/{name}").content.startswith(b"SQLite format 3")
    assert client.post(f"/api/backups/{name}/restore").json()["ok"] is True
    assert client.get("/api/backups/..%2Ft.db").status_code in (404, 422)
    assert client.get("/api/backups/nope.db").status_code == 404
    assert client.delete(f"/api/backups/{name}").json()["backups"] == []


def test_requires_auth(client):
    assert client.get("/api/backups", headers={"Authorization": "Bearer no"}).status_code == 401
    assert client.post("/api/backups/run", headers={"Authorization": "Bearer no"}).status_code == 401
