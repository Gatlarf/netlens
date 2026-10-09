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
    assert client.get("/api/map-settings").json() == {"default_layout": "free", "layouts": ["free", "tree", "horizontal"], "domain_suffix": ""}
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


def test_domain_suffix_is_cleaned_saved_and_independent_of_layout(client):
    r = client.put("/api/map-settings", json={"domain_suffix": "  .Home.CodeShrimp.com. "})
    assert r.status_code == 200 and r.json()["domain_suffix"] == "home.codeshrimp.com"
    assert r.json()["default_layout"] == "free"
    client.put("/api/map-settings", json={"default_layout": "tree"})
    assert client.get("/api/map-settings").json()["domain_suffix"] == "home.codeshrimp.com"
    assert client.put("/api/map-settings", json={"domain_suffix": ""}).json()["domain_suffix"] == ""


@pytest.mark.parametrize("value", ["bad suffix", "a..b", "-x.com", "x_y.com", "a" * 300])
def test_bad_domain_suffix_rejected(client, value):
    assert client.put("/api/map-settings", json={"domain_suffix": value}).status_code == 422
