"""Card layouts: own layout beats the template, a type beats "all types", admins only for templates, bad input is cleaned."""

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app

LAYOUT = {"order": {"overview": ["details", "events"]}, "hidden": ["why"], "sizes": {"events": "f"}}


@pytest.fixture
def client(tmp_path):
    db = tmp_path / "l.db"
    c = connect(db)
    init_db(c)
    c.close()
    return TestClient(create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db), headers={"Authorization": "Bearer secret"})


def test_nothing_saved_means_the_built_in_layout(client):
    r = client.get("/api/layouts/device?type=windows").json()
    assert r["source"] == "builtin" and r["effective"] is None


def test_a_template_applies_and_my_own_layout_wins(client):
    assert client.put("/api/layouts/device/template?type=windows", json=LAYOUT).status_code == 200
    assert client.get("/api/layouts/device?type=windows").json()["source"] == "template"
    assert client.get("/api/layouts/device?type=linux").json()["source"] == "builtin"
    client.put("/api/layouts/device/template?type=*", json={"order": {}, "hidden": ["names"], "sizes": {}})
    assert client.get("/api/layouts/device?type=linux").json()["effective"]["hidden"] == ["names"]
    client.put("/api/layouts/device/mine?type=windows", json={"order": {}, "hidden": [], "sizes": {"details": "w"}})
    r = client.get("/api/layouts/device?type=windows").json()
    assert r["source"] == "mine" and r["effective"]["sizes"] == {"details": "w"} and r["template"]["hidden"] == ["why"]
    client.delete("/api/layouts/device/mine?type=windows")
    assert client.get("/api/layouts/device?type=windows").json()["source"] == "template"
    assert client.get("/api/layouts/device/templates").json()["types"] == ["*", "windows"]
    client.delete("/api/layouts/device/template?type=windows")
    assert client.get("/api/layouts/device/templates").json()["types"] == ["*"]


def test_input_is_cleaned_and_checked(client):
    r = client.put("/api/layouts/device/mine?type=*", json={"order": {"overview": ["ok", "../x", "ok", 5]}, "hidden": "no", "full": ["a b"], "sizes": {"x": "huge", "ok": "s"}})
    assert r.json() == {"order": {"overview": ["ok"]}, "hidden": [], "sizes": {"ok": "s"}}
    assert client.put("/api/layouts/device/mine?type=Bad%20Type", json=LAYOUT).status_code == 422
    assert client.get("/api/layouts/nope?type=*").status_code == 422
