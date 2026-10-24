import pytest
from fastapi.testclient import TestClient

from app import audit
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app

ADMIN = {"Authorization": "Bearer secret"}


@pytest.fixture
def env(tmp_path):
    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, custom_name, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'nas', 'Kelder NAS', 1, 'x', 'x')")
    c.commit()
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app) as client:
        yield client, app, path


def lines(path):
    c = connect(path)
    try:
        return [dict(r) for r in c.execute("SELECT * FROM audit_log ORDER BY id")]
    finally:
        c.close()


def test_a_change_is_written_down_with_who_and_what(env):
    c, _, path = env
    assert c.patch("/api/devices/1", json={"custom_name": "Kelder NAS"}, headers=ADMIN).status_code == 200
    rows = lines(path)
    assert len(rows) == 1 and rows[0]["action"] == "Changed the settings of Kelder NAS" and rows[0]["user"] == "access token" and rows[0]["method"] == "PATCH"


def test_reads_and_failures_are_not_logged_and_bodies_never(env):
    c, _, path = env
    c.get("/api/devices", headers=ADMIN)
    c.patch("/api/devices/999", json={"custom_name": "x"}, headers=ADMIN)                          # 404
    c.post("/api/users", json={"username": "bob", "password": "very-secret-password", "role": "viewer"}, headers=ADMIN)
    rows = lines(path)
    assert len(rows) == 1 and rows[0]["action"] == "Added a user"
    assert "very-secret-password" not in str(rows)


def test_sign_ins_and_failures_are_recorded(env):
    c, app, path = env
    c.post("/api/users", json={"username": "alice", "password": "longenough1", "role": "admin"}, headers=ADMIN)
    other = TestClient(app)
    assert other.post("/api/login", json={"username": "alice", "password": "wrong-wrong"}).status_code == 401
    assert other.post("/api/login", json={"username": "alice", "password": "longenough1"}).status_code == 200
    assert other.post("/api/logout").status_code == 200
    actions = [r["action"] for r in lines(path)]
    assert any(a.startswith("Failed sign-in as 'alice'") for a in actions) and "Signed in" in actions and "Signed out" in actions
    signed = next(r for r in lines(path) if r["action"] == "Signed in")
    assert signed["user"] == "alice" and "longenough1" not in str(lines(path))


def test_the_api_is_for_administrators_only(env):
    c, app, path = env
    c.post("/api/users", json={"username": "vera", "password": "longenough1", "role": "viewer"}, headers=ADMIN)
    vera = TestClient(app)
    vera.post("/api/login", json={"username": "vera", "password": "longenough1"})
    assert vera.get("/api/audit").status_code == 403
    r = c.get("/api/audit?limit=5", headers=ADMIN).json()
    assert r["entries"] and "vera" in r["users"] or r["entries"]
    assert c.get("/api/audit?q=viewer", headers=ADMIN).status_code == 200
    csv = c.get("/api/audit.csv", headers=ADMIN)
    assert csv.headers["content-type"].startswith("text/csv") and "Added a user" in csv.text


def test_describe_falls_back_to_something_honest(env):
    _, _, path = env
    conn = connect(path)
    assert audit.describe(conn, "PUT", "/api/something/new") == "Changed something / new"
    assert audit.describe(conn, "DELETE", "/api/devices/1") == "Deleted the device Kelder NAS"
    conn.close()


def test_pruning_keeps_the_newest(env):
    _, _, path = env
    conn = connect(path)
    for i in range(5):
        audit.record(conn, "u", "admin", "1.2.3.4", "POST", "/api/x", 200, f"n{i}")
    conn.execute("UPDATE audit_log SET ts = '2020-01-01T00:00:00Z' WHERE action = 'n0'")
    conn.commit()
    audit.prune(conn)
    assert [r["action"] for r in conn.execute("SELECT action FROM audit_log ORDER BY id")] == ["n1", "n2", "n3", "n4"]
    conn.close()


def test_sentences_fill_in_what_was_changed():
    import sqlite3

    c = sqlite3.connect(":memory:")
    assert audit.describe(c, "PUT", "/api/plugins/truenas") == "Changed the settings of the plugin truenas"
    assert audit.describe(c, "POST", "/api/probes/3/command") == "Sent a command to remote site 3"
