import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.main import create_app

ADMIN = {"Authorization": "Bearer secret"}


@pytest.fixture
def env(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app) as c:
        yield c, app


def make(c, name, role):
    assert c.post("/api/users", json={"username": name, "password": "longenough1", "role": role}, headers=ADMIN).status_code == 201


def sign_in(app, name):
    c = TestClient(app)
    assert c.post("/api/login", json={"username": name, "password": "longenough1"}).status_code == 200
    return c


def test_default_is_no_choice(env):
    c, _ = env
    r = c.get("/api/me/preferences", headers=ADMIN).json()
    assert r["start_page"] is None and {"value": "#/map", "label": "Map"} in r["start_pages"]
    assert c.get("/api/session", headers=ADMIN).json()["start_page"] is None


def test_choose_and_reset(env):
    c, _ = env
    assert c.put("/api/me/preferences", json={"start_page": "#/health"}, headers=ADMIN).json()["start_page"] == "#/health"
    assert c.get("/api/session", headers=ADMIN).json()["start_page"] == "#/health"
    assert c.put("/api/me/preferences", json={"start_page": None}, headers=ADMIN).json()["start_page"] is None


@pytest.mark.parametrize("bad", ["#/settings", "https://evil.example", "javascript:alert(1)", "#/device/1", "map"])
def test_only_known_pages(env, bad):
    c, _ = env
    assert c.put("/api/me/preferences", json={"start_page": bad}, headers=ADMIN).status_code == 422


def test_each_user_has_their_own_and_a_viewer_may_set_it(env):
    c, app = env
    make(c, "alice", "admin")
    make(c, "vera", "viewer")
    alice, vera = sign_in(app, "alice"), sign_in(app, "vera")
    assert vera.put("/api/me/preferences", json={"start_page": "#/map"}).json()["start_page"] == "#/map"
    assert alice.get("/api/me/preferences").json()["start_page"] is None
    assert vera.get("/api/session").json()["start_page"] == "#/map"
    assert vera.put("/api/me/preferences", json={"start_page": "#/remote"}).status_code == 422     # administrators only
    assert {"value": "#/remote", "label": "Remote access"} not in vera.get("/api/me/preferences").json()["start_pages"]
    assert alice.put("/api/me/preferences", json={"start_page": "#/remote"}).status_code == 200
