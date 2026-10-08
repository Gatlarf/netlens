import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.main import create_app

AUTH = {"Authorization": "Bearer secret"}


@pytest.fixture
def client(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app, headers=AUTH) as c:
        yield c


def test_default_is_free_and_choice_is_saved(client):
    assert client.get("/api/map-settings").json() == {"default_layout": "free", "layouts": ["free", "tree", "horizontal"]}
    r = client.put("/api/map-settings", json={"default_layout": "horizontal"})
    assert r.status_code == 200 and r.json()["default_layout"] == "horizontal"
    assert client.get("/api/map-settings").json()["default_layout"] == "horizontal"


@pytest.mark.parametrize("body", [{}, {"default_layout": "circle"}, {"default_layout": None}])
def test_invalid_layout_rejected(client, body):
    assert client.put("/api/map-settings", json=body).status_code == 422
    assert client.get("/api/map-settings").json()["default_layout"] == "free"


def test_requires_auth(client):
    assert client.get("/api/map-settings", headers={"Authorization": "Bearer no"}).status_code == 401
    assert client.put("/api/map-settings", json={"default_layout": "tree"}, headers={"Authorization": "Bearer no"}).status_code == 401


def test_corrupt_stored_value_falls_back(client, tmp_path):
    from app.db import connect, set_setting

    conn = connect(tmp_path / "t.db")
    set_setting(conn, "map_default_layout", "garbage")
    conn.close()
    assert client.get("/api/map-settings").json()["default_layout"] == "free"
