import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.backup import validate_backup
from app.config import load_settings
from app.db import SCHEMA_VERSION, connect, get_or_create_device, get_setting, init_db, set_setting
from app.main import create_app

AUTH = {"Authorization": "Bearer secret"}


@pytest.fixture
def env(tmp_path):
    db = tmp_path / "t.db"
    conn = connect(db)
    init_db(conn)
    get_or_create_device(conn, "aa:bb:cc:00:00:01", "192.168.1.5")
    set_setting(conn, "marker", "original")
    conn.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db)
    return app, TestClient(app, headers=AUTH), db


def _marker(db):
    conn = connect(db)
    try:
        return get_setting(conn, "marker"), conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    finally:
        conn.close()


def test_download_is_a_valid_snapshot(env, tmp_path):
    app, c, db = env
    with c:
        r = c.get("/api/backup")
        assert r.status_code == 200
        assert "netlens-backup-" in r.headers["content-disposition"] and r.headers["content-disposition"].endswith('.db"')
        out = tmp_path / "dl.db"
        out.write_bytes(r.content)
        assert validate_backup(out) == SCHEMA_VERSION
        assert c.get("/api/backup", headers={"Authorization": "Bearer no"}).status_code == 401


def test_restore_roundtrip(env):
    app, c, db = env
    with c:
        snapshot = c.get("/api/backup").content
        conn = connect(db)
        set_setting(conn, "marker", "changed")
        get_or_create_device(conn, "aa:bb:cc:00:00:02", "192.168.1.6")
        conn.close()
        assert _marker(db) == ("changed", 2)

        r = c.post("/api/restore", content=snapshot)
        assert r.status_code == 200 and r.json() == {"ok": True, "backup_schema_version": SCHEMA_VERSION, "devices": 1}
        assert _marker(db) == ("original", 1)
        # the API keeps working on the restored data
        assert len(c.get("/api/devices").json()) == 1


def test_restore_reapplies_saved_settings(env):
    app, c, db = env
    with c:
        c.put("/api/config/general", json={"quick_interval": 300})
        snapshot = c.get("/api/backup").content
        c.put("/api/config/general", json={"quick_interval": None})
        assert app.state.settings.quick_interval == 900
        assert c.post("/api/restore", content=snapshot).status_code == 200
        assert app.state.settings.quick_interval == 300


@pytest.mark.parametrize("payload, status, text", [
    (b"", 422, "empty"),
    (b"this is definitely not a database" * 10, 422, "not a Netlens"),
])
def test_bad_uploads_are_rejected_and_change_nothing(env, payload, status, text):
    app, c, db = env
    with c:
        r = c.post("/api/restore", content=payload)
        assert r.status_code == status and text in r.json()["detail"]
        assert _marker(db) == ("original", 1)


def test_non_netlens_sqlite_file_is_rejected(env, tmp_path):
    app, c, db = env
    other = tmp_path / "other.db"
    x = sqlite3.connect(other)
    x.execute("CREATE TABLE x (a)")
    x.commit()
    x.close()
    with c:
        r = c.post("/api/restore", content=other.read_bytes())
        assert r.status_code == 422 and "not a Netlens database" in r.json()["detail"]
        assert _marker(db) == ("original", 1)


def test_restore_refused_while_scanning(env):
    app, c, db = env
    app.state.scan_manager.is_running = lambda: True
    with c:
        r = c.post("/api/restore", content=b"x")
        assert r.status_code == 409
        assert c.post("/api/restore", content=b"x", headers={"Authorization": "Bearer no"}).status_code == 401
