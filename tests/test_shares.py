import pytest
from fastapi.testclient import TestClient

from app import shares
from app.config import load_settings
from app.db import connect, get_or_create_device, init_db
from app.main import create_app

ADMIN = {"Authorization": "Bearer secret"}


@pytest.fixture
def env(tmp_path):
    shares._cache.clear()
    path = tmp_path / "t.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app) as c:
        conn = connect(path)
        a = get_or_create_device(conn, "aa:bb:cc:00:00:01", "10.0.0.1")
        b = get_or_create_device(conn, "aa:bb:cc:00:00:02", "10.0.0.2")
        conn.execute("UPDATE devices SET custom_name = 'Router', device_type = 'router' WHERE id = ?", (a,))
        conn.execute("UPDATE devices SET hostname = NULL, custom_name = NULL WHERE id = ?", (b,))
        conn.commit()
        conn.close()
        yield c, app, path


def new(c, **kw):
    body = {"name": "Family", "mode": "view", **kw}
    r = c.post("/api/shares", json=body, headers=ADMIN)
    assert r.status_code == 201, r.text
    return r.json()["links"][0]["token"]


def test_view_link_hides_addresses_by_default(env):
    c, app, _ = env
    token = new(c)
    anon = TestClient(app)
    data = anon.get(f"/share-api/{token}").json()
    assert data["mode"] == "view" and data["devices_total"] == 2
    text = str(data)
    assert "10.0.0." not in text and "aa:bb:cc" not in text
    assert {d["name"] for d in data["devices"]} == {"Router", "Device 2"}  # a name that is only an address is not shown


def test_view_link_with_ips_and_macs(env):
    c, app, _ = env
    token = new(c, show_ips=True, show_macs=True)
    data = TestClient(app).get(f"/share-api/{token}").json()
    assert {d["ip"] for d in data["devices"]} == {"10.0.0.1", "10.0.0.2"} and all(d["mac"] for d in data["devices"])
    assert "10.0.0.2" in {d["name"] for d in data["devices"]}


def test_status_link_has_no_devices(env):
    c, app, _ = env
    token = new(c, mode="status", show_ips=True)
    data = TestClient(app).get(f"/share-api/{token}").json()
    assert "devices" not in data and data["devices_total"] == 2 and "10.0.0" not in str(data)


def test_page_is_served_and_visits_are_counted_once(env):
    c, app, _ = env
    token = new(c)
    anon = TestClient(app)
    r = anon.get(f"/share/{token}")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"] and r.headers["x-robots-tag"].startswith("noindex")
    anon.get(f"/share-api/{token}")
    assert c.get("/api/shares", headers=ADMIN).json()["links"][0]["views"] == 1


@pytest.mark.parametrize("token", ["nope", "x" * 32, "../../etc/passwd", "a" * 200])
def test_unknown_tokens_are_404(env, token):
    _, app, _ = env
    anon = TestClient(app)
    assert anon.get(f"/share-api/{token}").status_code == 404
    assert anon.get(f"/share/{token}").status_code == 404


def test_delete_revokes_at_once(env):
    c, app, _ = env
    token = new(c)
    link_id = c.get("/api/shares", headers=ADMIN).json()["links"][0]["id"]
    assert c.delete(f"/api/shares/{link_id}", headers=ADMIN).status_code == 200
    assert TestClient(app).get(f"/share-api/{token}").status_code == 404
    assert c.delete(f"/api/shares/{link_id}", headers=ADMIN).status_code == 404


def test_expired_link(env):
    c, app, path = env
    token = new(c, expires_days=1)
    conn = connect(path)
    conn.execute("UPDATE share_links SET expires = '2020-01-01T00:00:00Z'")
    conn.commit()
    conn.close()
    assert TestClient(app).get(f"/share-api/{token}").status_code == 404
    assert c.get("/api/shares", headers=ADMIN).json()["links"][0]["expired"] is True


@pytest.mark.parametrize("body", [{"name": " "}, {"name": "x", "mode": "edit"}, {"name": "x", "expires_days": 0}, {"name": "x", "expires_days": 99999}])
def test_bad_links_rejected(env, body):
    c, _, _ = env
    assert c.post("/api/shares", json=body, headers=ADMIN).status_code == 422


def test_share_endpoints_do_not_open_the_rest(env):
    c, app, _ = env
    token = new(c)
    anon = TestClient(app)
    for path in ("/api/devices", "/api/shares", "/api/stats/summary", "/api/map"):
        assert anon.get(path).status_code == 401
    assert anon.get(f"/api/shares", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_only_administrators_manage_links(env):
    c, app, _ = env
    c.post("/api/users", json={"username": "vera", "password": "longenough1", "role": "viewer"}, headers=ADMIN)
    vera = TestClient(app)
    vera.post("/api/login", json={"username": "vera", "password": "longenough1"})
    assert vera.get("/api/shares").status_code == 403
    assert vera.post("/api/shares", json={"name": "x"}).status_code == 403


def test_scanner_is_rate_limited(env):
    _, app, _ = env
    anon = TestClient(app)
    codes = [anon.get("/share-api/" + "z" * 24).status_code for _ in range(32)]
    assert codes[:30] == [404] * 30 and codes[30:] == [429, 429]
