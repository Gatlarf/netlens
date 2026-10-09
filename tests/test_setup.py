import sqlite3

import pytest
from fastapi.testclient import TestClient

from app import cli, users
from app.config import ConfigError, load_settings
from app.db import connect, init_db
from app.main import create_app


def make(tmp_path, token=None, ranges=("192.168.7.0/24",)):
    env = {"NETLENS_DATA_DIR": str(tmp_path)}
    if token:
        env["NETLENS_TOKEN"] = token
    app = create_app(load_settings(env), db_path=tmp_path / "t.db")

    async def detect():
        return list(ranges)

    app.state.scan_manager.ranges_provider = detect
    started = []

    async def fake_start(kind, target=None):
        started.append(kind)
        return 1

    app.state.scan_manager.start = fake_start
    app.state.started = started
    return app


def test_token_is_optional_in_the_configuration():
    assert load_settings({}).token == ""
    assert load_settings({"NETLENS_TOKEN": " abc "}).token == "abc"


def test_fresh_install_asks_for_setup_and_has_no_token_login(tmp_path):
    with TestClient(make(tmp_path)) as c:
        s = c.get("/api/session").json()
        assert s == {"authenticated": False, "setup_required": True, "token_login": False}
        info = c.get("/api/setup").json()
        assert info["required"] and info["detected_ranges"] == ["192.168.7.0/24"] and info["min_password"] == 8
        # protected things stay protected until the account exists, and an empty token never matches
        assert c.get("/api/devices").status_code == 401
        assert c.get("/api/devices", headers={"Authorization": "Bearer "}).status_code == 401
        assert c.post("/api/login", json={"token": ""}).status_code == 401
        assert c.post("/api/login", json={}).status_code == 401
        c.cookies.set("netlens_session", "")
        assert c.get("/api/devices").status_code == 401


def test_setup_creates_the_admin_signs_in_and_starts_the_scan(tmp_path):
    app = make(tmp_path)
    with TestClient(app) as c:
        r = c.post("/api/setup", json={"username": "Bert", "password": "longenough1", "ranges": ["192.168.7.0/24"]})
        assert r.status_code == 200 and r.json() == {"ok": True, "scan_started": True}
        assert app.state.started == ["quick"]
        s = c.get("/api/session").json()  # signed in already
        assert s["authenticated"] and s["user"] == {"username": "Bert", "role": "admin", "builtin": False}
        assert c.get("/api/config").json()["ranges"] == ["192.168.7.0/24"]
        assert c.get("/api/users").status_code == 200
        # done: closed for everybody
        anon = TestClient(app)
        assert anon.get("/api/setup").status_code == 404
        assert anon.post("/api/setup", json={"username": "evil", "password": "longenough1"}).status_code == 409
        assert anon.get("/api/session").json()["setup_required"] is False
        assert len(users.list_users(connect(tmp_path / "t.db"))) == 1


def test_setup_validation_and_optional_scan(tmp_path):
    app = make(tmp_path)
    with TestClient(app) as c:
        for body in ({"username": "", "password": "longenough1"}, {"username": "a b", "password": "longenough1"}, {"username": "ok", "password": "short"},
                     {"username": "ok", "password": "longenough1", "ranges": ["8.8.8.0/24"]}, {"username": "ok", "password": "longenough1", "ranges": ["nonsense"]}):
            assert c.post("/api/setup", json=body).status_code == 422, body
        assert not users.has_users(connect(tmp_path / "t.db"))  # nothing half-created
        r = c.post("/api/setup", json={"username": "ok", "password": "longenough1", "start_scan": False})
        assert r.json()["scan_started"] is False and app.state.started == []
        assert c.get("/api/config").json()["ranges"] != ["8.8.8.0/24"]  # no ranges given: auto-detect stays


def test_two_setups_at_once_only_one_wins(tmp_path):
    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    assert users.create_first_admin(conn, "first", "longenough1") is not None
    assert users.create_first_admin(conn, "second", "longenough1") is None
    assert [u["username"] for u in users.list_users(conn)] == ["first"]


def test_an_install_with_a_token_never_shows_the_wizard(tmp_path):
    """The upgrade path: NETLENS_TOKEN stays in the compose file, nothing changes for its owner."""
    app = make(tmp_path, token="secret")
    with TestClient(app) as c:
        assert c.get("/api/session").json() == {"authenticated": False, "setup_required": False, "token_login": True}
        assert c.get("/api/setup").status_code == 404
        assert c.post("/api/setup", json={"username": "evil", "password": "longenough1"}).status_code == 409
        assert c.post("/api/login", json={"token": "secret"}).status_code == 200
        assert c.get("/api/users").json()["token_configured"] is True
        assert c.get("/api/devices").status_code == 200


def test_upgrade_of_an_old_database_keeps_data_logins_and_skips_setup(tmp_path):
    """A schema-v7 database from before the user system: opens, migrates, keeps its device and the token login."""
    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    conn.execute("INSERT INTO devices (mac, primary_ip, first_seen, last_seen, online) VALUES ('aa:bb:cc:00:00:01', '10.0.0.1', 't', 't', 1)")
    for table in ("users", "sessions", "api_tokens", "share_links", "port_baselines"):
        conn.execute(f"DROP TABLE {table}")
    conn.execute("UPDATE schema_version SET version = 7")
    conn.commit()
    conn.close()
    app = make(tmp_path, token="secret")
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as c:
        assert [d["primary_ip"] for d in c.get("/api/devices").json()] == ["10.0.0.1"]
        assert c.get("/api/session").json()["user"]["builtin"] is True
        assert c.post("/api/users", json={"username": "bert", "password": "longenough1", "role": "admin"}).status_code == 201
    assert connect(path).execute("SELECT version FROM schema_version").fetchone()[0] >= 9


def test_removing_the_token_later_with_users_present_needs_no_wizard(tmp_path):
    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    users.create_user(conn, "bert", "longenough1", "admin")
    conn.close()
    with TestClient(make(tmp_path)) as c:
        assert c.get("/api/session").json() == {"authenticated": False, "setup_required": False, "token_login": False}
        assert c.post("/api/login", json={"username": "bert", "password": "longenough1"}).status_code == 200


# ---- recovery commands -------------------------------------------------------------------------------------
def test_cli_reset_and_create(tmp_path, capsys):
    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    users.create_user(conn, "bert", "oldpassword1", "viewer")
    sid = users.login(conn, "bert", "oldpassword1")
    conn.close()
    assert cli.run(["--db", str(path), "reset-password", "BERT", "--password", "brandnewpass1"]) == 0
    conn = connect(path)
    assert users.login(conn, "bert", "brandnewpass1") and users.login(conn, "bert", "oldpassword1") is None
    assert users.user_for_session(conn, sid) is None  # old logins ended
    conn.close()
    assert cli.run(["--db", str(path), "create-admin", "rescue", "--password", "rescuepass12"]) == 0
    assert cli.run(["--db", str(path), "create-admin", "bert", "--password", "promoted-pass1"]) == 0  # promotes and re-enables
    conn = connect(path)
    assert {u["username"]: u["role"] for u in users.list_users(conn)} == {"bert": "admin", "rescue": "admin"}
    conn.close()
    cli.run(["--db", str(path), "list-users"])
    assert "rescue" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        cli.run(["--db", str(path), "reset-password", "nobody", "--password", "x" * 9])
    with pytest.raises(SystemExit):
        cli.run(["--db", str(tmp_path / "missing.db"), "list-users"])
    with pytest.raises(SystemExit):
        cli.run(["--db", str(path), "reset-password", "bert", "--password", "short"])
