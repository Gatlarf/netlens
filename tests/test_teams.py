import sqlite3

import pytest
from fastapi.testclient import TestClient

from app import db as dbmod, groups, licence, users
from app.config import load_settings
from app.db import add_event, connect, get_or_create_device, init_db
from app.main import create_app

ADMIN = {"Authorization": "Bearer secret"}

OLD_USERS = """CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
    disabled INTEGER NOT NULL DEFAULT 0,
    created TEXT NOT NULL,
    last_login TEXT,
    oidc_sub TEXT
)"""


def test_users_table_is_rebuilt_without_losing_anything(tmp_path):
    conn = sqlite3.connect(tmp_path / "old.db")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(OLD_USERS)
    conn.execute("CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, created TEXT, expires TEXT)")
    conn.execute("CREATE TABLE api_tokens (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT, token_hash TEXT)")
    conn.execute("INSERT INTO users (id, username, password_hash, role, created, oidc_sub) VALUES (7, 'ann', 'h', 'admin', 't', 'sub-1'), (9, 'bob', 'h', 'viewer', 't', NULL)")
    conn.execute("INSERT INTO sessions VALUES ('x', 9, 't', 't')")
    conn.execute("INSERT INTO api_tokens VALUES (1, 9, 'n', 'th')")
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO users (username, password_hash, role, created) VALUES ('op', 'h', 'operator', 't')")
    dbmod._allow_operator_role(conn)
    conn.execute("INSERT INTO users (username, password_hash, role, created) VALUES ('op', 'h', 'operator', 't')")
    assert [(r["id"], r["username"], r["role"], r["oidc_sub"]) for r in conn.execute("SELECT * FROM users WHERE id IN (7, 9) ORDER BY id")] == [(7, "ann", "admin", "sub-1"), (9, "bob", "viewer", None)]
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
    conn.execute("DELETE FROM users WHERE id = 9")                       # the foreign keys still point at the new table
    assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0 and conn.execute("SELECT COUNT(*) FROM api_tokens").fetchone()[0] == 0
    dbmod._allow_operator_role(conn)                                       # a second run changes nothing
    conn.close()


@pytest.fixture(autouse=True)
def licensed(monkeypatch):
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)


@pytest.fixture
def env(tmp_path):
    path = tmp_path / "t.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app) as c:
        conn = connect(path)
        a = groups.create(conn, "Customer A")
        b = groups.create(conn, "Customer B")
        ids = {}
        for name, ip, grp in (("a1", "10.0.0.1", a), ("a2", "10.0.0.2", a), ("b1", "10.0.1.1", b), ("loose", "10.0.2.1", None)):
            d = get_or_create_device(conn, f"aa:bb:cc:00:00:{len(ids) + 1:02d}", ip)
            conn.execute("UPDATE devices SET custom_name = ? WHERE id = ?", (name, d))
            ids[name] = d
        groups.assign(conn, [ids["a1"], ids["a2"]], a)
        groups.assign(conn, [ids["b1"]], b)
        for name in ids:
            add_event(conn, "device_offline", f"{name} down", ids[name])
        conn.commit()
        conn.close()
        yield c, app, path, {"a": a, "b": b, **ids}


def make(c, name, role, scope=None):
    r = c.post("/api/users", json={"username": name, "password": "longenough1", "role": role, "scope": scope}, headers=ADMIN)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def sign_in(app, name):
    c = TestClient(app)
    assert c.post("/api/login", json={"username": name, "password": "longenough1"}).status_code == 200
    return c


def test_operator_may_act_but_not_configure(env):
    c, app, _, _ = env
    make(c, "olga", "operator")
    olga = sign_in(app, "olga")
    assert olga.get("/api/session").json()["user"]["role"] == "operator"
    for path in ("/api/devices", "/api/stats/summary", "/api/maintenance", "/api/escalation"):
        assert olga.get(path).status_code == 200, path
    # allowed actions reach the handler (a bad body is a 422, not a refusal)
    assert olga.post("/api/snoozes", json={}).status_code == 422
    assert olga.post("/api/maintenance", json={}).status_code == 422
    assert olga.post("/api/devices/1/ping").status_code != 403
    assert olga.patch("/api/devices/1", json={"notes": "checked by Olga"}).status_code == 200
    # everything that configures or destroys is refused
    refused = [("get", "/api/users"), ("post", "/api/users"), ("delete", "/api/devices/1"), ("put", "/api/config/ranges"), ("post", "/api/backups/run"),
               ("put", "/api/channels"), ("post", "/api/restore"), ("get", "/api/vault/status"), ("post", "/api/devices/1/monitor/test"), ("put", "/api/siem")]
    for method, path in refused:
        r = getattr(olga, method)(path, **({"json": {}} if method in ("post", "put", "patch") else {}))
        assert r.status_code in (403, 404, 405), (method, path, r.status_code)
    assert olga.get("/api/users").status_code == 403


def test_viewer_still_cannot_act(env):
    c, app, _, _ = env
    make(c, "vera", "viewer")
    vera = sign_in(app, "vera")
    assert vera.post("/api/snoozes", json={}).status_code == 403
    assert vera.get("/api/maintenance").status_code == 403


def test_scoped_viewer_sees_only_its_groups(env):
    c, app, _, ids = env
    make(c, "carol", "viewer", [ids["a"]])
    carol = sign_in(app, "carol")
    assert carol.get("/api/session").json()["user"]["scoped"] is True
    assert carol.get("/api/session").json()["start_page"] == "#/devices"
    assert sorted(d["custom_name"] for d in carol.get("/api/devices").json()) == ["a1", "a2"]
    assert [g["name"] for g in carol.get("/api/groups").json()["groups"]] == ["Customer A"]
    assert carol.get(f"/api/devices/{ids['a1']}").status_code == 200
    assert carol.get(f"/api/devices/{ids['a1']}/uptime").status_code == 200
    for other in ("b1", "loose"):
        assert carol.get(f"/api/devices/{ids[other]}").status_code == 404
        assert carol.get(f"/api/devices/{ids[other]}/uptime").status_code == 404
    events = carol.get("/api/events").json()
    assert sorted(e["detail"] for e in events) == ["a1 down", "a2 down"]
    assert carol.get("/api/events", params={"device_id": ids["b1"]}).json() == []
    up = carol.get("/api/uptime").json()
    assert sorted(r["name"] for r in up) == ["a1", "a2"]


def test_scoped_viewer_reaches_nothing_else(env):
    c, app, _, ids = env
    make(c, "carol", "viewer", [ids["a"]])
    carol = sign_in(app, "carol")
    for path in ("/api/dashboard", "/api/map", "/api/stats", "/api/stats/summary", "/api/hierarchy", "/api/service-checks", "/api/scans", "/api/probes", "/metrics",
                 "/api/users", f"/api/timeseries/device/{ids['b1']}", "/api/reports/weekly", "/api/snoozes", "/api/changes"):
        assert carol.get(path).status_code in (403, 404), path
    assert carol.patch(f"/api/devices/{ids['a1']}", json={"notes": "x"}).status_code == 403
    assert carol.post("/api/scans", json={"kind": "quick"}).status_code == 403
    assert carol.get(f"/api/timeseries/device/{ids['a1']}").status_code != 403           # its own device's graph is fine


def test_a_scoped_token_keeps_the_limit(env):
    c, app, _, ids = env
    uid = make(c, "cust", "viewer", [ids["b"]])
    token = c.post(f"/api/users/{uid}/tokens", json={"name": "portal"}, headers=ADMIN).json()["token"]
    r = TestClient(app).get("/api/devices", headers={"Authorization": f"Bearer {token}"})
    assert [d["custom_name"] for d in r.json()] == ["b1"]


def test_scope_rules(env):
    c, app, path, ids = env
    r = c.post("/api/users", json={"username": "x1", "password": "longenough1", "role": "operator", "scope": [ids["a"]]}, headers=ADMIN)
    assert r.status_code == 422 and "viewer" in r.json()["detail"]
    assert c.post("/api/users", json={"username": "x2", "password": "longenough1", "role": "viewer", "scope": [999]}, headers=ADMIN).status_code == 422
    uid = make(c, "x3", "viewer", [ids["a"], ids["b"]])
    listed = {u["username"]: u for u in c.get("/api/users", headers=ADMIN).json()["users"]}
    assert listed["x3"]["scope"] == sorted([ids["a"], ids["b"]])
    assert c.patch(f"/api/users/{uid}", json={"scope": [ids["b"]]}, headers=ADMIN).status_code == 200
    assert c.patch(f"/api/users/{uid}", json={"password": "anotherlong1"}, headers=ADMIN).status_code == 200      # leaves the scope alone
    listed = {u["username"]: u for u in c.get("/api/users", headers=ADMIN).json()["users"]}
    assert listed["x3"]["scope"] == [ids["b"]]
    assert c.patch(f"/api/users/{uid}", json={"scope": None}, headers=ADMIN).status_code == 200
    assert {u["username"]: u for u in c.get("/api/users", headers=ADMIN).json()["users"]}["x3"]["scope"] is None
    c.patch(f"/api/users/{uid}", json={"scope": [ids["a"]]}, headers=ADMIN)
    c.patch(f"/api/users/{uid}", json={"role": "operator"}, headers=ADMIN)                                          # promoting ends the limit
    assert {u["username"]: u for u in c.get("/api/users", headers=ADMIN).json()["users"]}["x3"]["scope"] is None


def test_roles_listed(env):
    c, *_ = env
    assert c.get("/api/users", headers=ADMIN).json()["roles"] == ["admin", "operator", "viewer"]


def test_operators_and_customer_views_need_a_licence(env, monkeypatch):
    c, app, _, ids = env
    make(c, "olga", "operator")
    make(c, "carol", "viewer", [ids["a"]])
    olga = sign_in(app, "olga")
    assert olga.post("/api/snoozes", json={}).status_code == 422                      # licensed: reaches the handler
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: feature != "teams")
    assert c.get("/api/users", headers=ADMIN).json()["teams_allowed"] is False
    # creating or changing them is refused ...
    assert c.post("/api/users", json={"username": "o2", "password": "longenough1", "role": "operator"}, headers=ADMIN).status_code == 402
    assert c.post("/api/users", json={"username": "v2", "password": "longenough1", "role": "viewer", "scope": [ids["a"]]}, headers=ADMIN).status_code == 402
    uid = make(c, "plain", "viewer")
    assert c.patch(f"/api/users/{uid}", json={"role": "operator"}, headers=ADMIN).status_code == 402
    assert c.patch(f"/api/users/{uid}", json={"scope": [ids["a"]]}, headers=ADMIN).status_code == 402
    assert c.patch(f"/api/users/{uid}", json={"password": "anotherlong1"}, headers=ADMIN).status_code == 200      # other changes are fine
    assert make(c, "plain2", "admin") and make(c, "plain3", "viewer")                                                # free roles stay free
    # ... and what exists keeps working: an operator acts as a viewer, a customer view keeps its limit
    assert olga.post("/api/snoozes", json={}).status_code == 403
    assert olga.get("/api/devices").status_code == 200
    carol = sign_in(app, "carol")
    assert [d["custom_name"] for d in carol.get("/api/devices").json()] == ["a1", "a2"]
