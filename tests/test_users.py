import pytest
from fastapi.testclient import TestClient

from app import users
from app.config import load_settings
from app.db import connect, get_or_create_device, init_db
from app.main import create_app

ADMIN = {"Authorization": "Bearer secret"}


@pytest.fixture
def env(tmp_path):
    path = tmp_path / "t.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app) as c:
        conn = connect(path)
        get_or_create_device(conn, "aa:bb:cc:00:00:01", "10.0.0.1")
        conn.close()
        yield c, app, path


def make(c, name, role, password="longenough1"):
    r = c.post("/api/users", json={"username": name, "password": password, "role": role}, headers=ADMIN)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def sign_in(app, name, password="longenough1"):
    c = TestClient(app)
    r = c.post("/api/login", json={"username": name, "password": password})
    assert r.status_code == 200, r.text
    return c


# ---- passwords --------------------------------------------------------------------------------
def test_password_hash_roundtrip_and_unique_salts():
    a, b = users.hash_password("secret-pass"), users.hash_password("secret-pass")
    assert a != b and users.verify_password("secret-pass", a) and not users.verify_password("Secret-pass", a)
    assert not users.verify_password("x", "garbage") and not users.verify_password("x", "scrypt$1$2")


@pytest.mark.parametrize("name", ["", " ", "a b", "x" * 33, "-lead", "é"])
def test_bad_usernames(name):
    with pytest.raises(users.UserError):
        users.check_username(name)


def test_bad_passwords():
    for pw in ("short", "x" * 201, None):
        with pytest.raises(users.UserError):
            users.check_password(pw)


# ---- login / roles --------------------------------------------------------------------------------
def test_admin_user_can_do_everything_viewer_is_read_only(env):
    c, app, _ = env
    make(c, "alice", "admin")
    make(c, "vera", "viewer")
    alice, vera = sign_in(app, "alice"), sign_in(app, "vera")
    assert alice.get("/api/session").json()["user"] == {"username": "alice", "role": "admin", "builtin": False}
    assert alice.get("/api/users").status_code == 200
    # viewer: may read devices, the map, stats...
    for path in ("/api/devices", "/api/devices/1", "/api/map", "/api/stats/summary", "/api/stats?range=7d", "/api/events", "/api/hierarchy", "/api/scans/current", "/api/service-checks", "/api/update", "/api/map-settings"):
        assert vera.get(path).status_code == 200, path
    # ...but not secrets, settings, exports, backups or admin pages
    for path in ("/api/users", "/api/backup", "/api/backups", "/api/notifications", "/api/plugins", "/api/export/devices.json", "/api/notify-channels", "/api/config", "/api/ignored", "/api/plugin-index"):
        assert vera.get(path).status_code == 403, path
    # and changes nothing
    assert vera.post("/api/scans", json={"kind": "quick"}).status_code == 403
    assert vera.patch("/api/devices/1", json={"custom_name": "x"}).status_code == 403
    assert vera.delete("/api/devices/1").status_code == 403
    assert vera.post("/api/devices/1/wake").status_code == 403
    assert vera.put("/api/map-settings", json={"domain_suffix": "x.com"}).status_code == 403
    assert vera.post("/api/devices/baseline", json={}).status_code == 403
    assert vera.get("/api/devices/1").json()["id"] == 1


def test_wrong_credentials_and_disabled_user(env):
    c, app, _ = env
    uid = make(c, "bob", "viewer")
    anon = TestClient(app)
    assert anon.post("/api/login", json={"username": "bob", "password": "wrongwrong"}).status_code == 401
    assert anon.post("/api/login", json={"username": "nobody", "password": "wrongwrong"}).status_code == 401
    bob = sign_in(app, "bob")
    assert bob.get("/api/devices").status_code == 200
    c.patch(f"/api/users/{uid}", json={"disabled": True}, headers=ADMIN)
    assert bob.get("/api/devices").status_code == 401  # existing login ends
    assert anon.post("/api/login", json={"username": "bob", "password": "longenough1"}).status_code == 401


def test_unauthenticated_and_legacy_token_login(env):
    c, app, _ = env
    assert TestClient(app).get("/api/devices").status_code == 401
    legacy = TestClient(app)
    assert legacy.post("/api/login", json={"token": "secret"}).status_code == 200
    assert legacy.get("/api/users").status_code == 200
    assert TestClient(app).post("/api/login", json={"token": "nope"}).status_code == 401
    assert TestClient(app).post("/api/login", json={}).status_code == 401


def test_username_is_case_insensitive_and_unique(env):
    c, _, _ = env
    make(c, "Carol", "viewer")
    assert c.post("/api/users", json={"username": "carol", "password": "longenough1", "role": "viewer"}, headers=ADMIN).status_code == 409
    assert c.post("/api/users", json={"username": "x", "password": "short", "role": "viewer"}, headers=ADMIN).status_code == 422
    assert c.post("/api/users", json={"username": "x", "password": "longenough1", "role": "root"}, headers=ADMIN).status_code == 422


def test_password_change_ends_other_logins_and_keeps_this_one(env):
    c, app, _ = env
    make(c, "dan", "viewer")
    one, two = sign_in(app, "dan"), sign_in(app, "dan")
    assert one.post("/api/me/password", json={"current": "wrong-one", "new": "brandnewpass1"}).status_code == 403
    assert one.post("/api/me/password", json={"current": "longenough1", "new": "short"}).status_code == 422
    assert one.post("/api/me/password", json={"current": "longenough1", "new": "brandnewpass1"}).status_code == 200
    assert one.get("/api/devices").status_code == 200
    assert two.get("/api/devices").status_code == 401
    TestClient(app).post("/api/login", json={"username": "dan", "password": "brandnewpass1"}).raise_for_status()


def test_builtin_token_cannot_change_a_password(env):
    c, _, _ = env
    assert c.post("/api/me/password", json={"current": "a", "new": "b" * 9}, headers=ADMIN).status_code == 400


def test_logout_ends_the_session_on_the_server(env):
    c, app, path = env
    make(c, "eve", "viewer")
    eve = sign_in(app, "eve")
    stolen = eve.cookies.get("netlens_session")
    eve.post("/api/logout")
    assert TestClient(app, cookies={"netlens_session": stolen}).get("/api/devices").status_code == 401


def test_role_change_applies_at_once(env):
    c, app, _ = env
    uid = make(c, "fay", "viewer")
    fay = sign_in(app, "fay")
    assert fay.get("/api/users").status_code == 403
    c.patch(f"/api/users/{uid}", json={"role": "admin"}, headers=ADMIN)
    assert fay.get("/api/users").status_code == 200


def test_deleting_a_user_removes_sessions_and_tokens(env):
    c, app, path = env
    uid = make(c, "gus", "viewer")
    gus = sign_in(app, "gus")
    c.post(f"/api/users/{uid}/tokens", json={"name": "ha"}, headers=ADMIN)
    c.delete(f"/api/users/{uid}", headers=ADMIN)
    assert gus.get("/api/devices").status_code == 401
    conn = connect(path)
    assert conn.execute("SELECT (SELECT COUNT(*) FROM sessions) + (SELECT COUNT(*) FROM api_tokens)").fetchone()[0] == 0
    conn.close()
    assert c.delete(f"/api/users/{uid}", headers=ADMIN).status_code == 404


# ---- API tokens --------------------------------------------------------------------------------
def test_api_token_acts_with_the_users_role_and_shows_once(env):
    c, app, path = env
    uid = make(c, "hal", "viewer")
    r = c.post(f"/api/users/{uid}/tokens", json={"name": "Home Assistant"}, headers=ADMIN)
    token = r.json()["token"]
    assert token.startswith("nl_")
    assert token not in c.get("/api/users", headers=ADMIN).text
    conn = connect(path)
    assert token not in str(conn.execute("SELECT * FROM api_tokens").fetchall()[0][:])
    conn.close()
    bearer = {"Authorization": f"Bearer {token}"}
    anon = TestClient(app)
    assert anon.get("/api/stats/summary", headers=bearer).status_code == 200
    assert anon.get("/metrics", headers=bearer).status_code == 200
    assert anon.get("/api/users", headers=bearer).status_code == 403
    assert anon.post("/api/scans", json={"kind": "quick"}, headers=bearer).status_code == 403
    assert anon.get("/api/stats/summary", headers={"Authorization": "Bearer nl_wrong"}).status_code == 401
    tid = c.get("/api/users", headers=ADMIN).json()["users"][0]["tokens"][0]["id"]
    assert c.get("/api/users", headers=ADMIN).json()["users"][0]["tokens"][0]["last_used"]
    c.delete(f"/api/users/{uid}/tokens/{tid}", headers=ADMIN)
    assert anon.get("/api/stats/summary", headers=bearer).status_code == 401


def test_token_needs_a_name_and_a_user(env):
    c, _, _ = env
    uid = make(c, "ivy", "admin")
    assert c.post(f"/api/users/{uid}/tokens", json={"name": " "}, headers=ADMIN).status_code == 422
    assert c.post("/api/users/999/tokens", json={"name": "x"}, headers=ADMIN).status_code == 404


def test_login_rate_limit_per_username(env):
    c, app, _ = env
    make(c, "jo", "viewer")
    anon = TestClient(app)
    codes = [anon.post("/api/login", json={"username": "jo", "password": "nopenopenope"}).status_code for _ in range(7)]
    assert codes[:5] == [401] * 5 and codes[5:] == [429, 429]
    assert anon.post("/api/login", json={"username": "jo", "password": "longenough1"}).status_code == 429
