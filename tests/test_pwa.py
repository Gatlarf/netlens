import json

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.main import create_app


@pytest.fixture
def client(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app) as c:  # no credentials
        yield c


def test_manifest_and_worker_are_public_files(client):
    m = client.get("/manifest.webmanifest")
    assert m.status_code == 200 and "json" in m.headers["content-type"]
    data = json.loads(m.text)
    assert data["display"] == "standalone" and {i["sizes"] for i in data["icons"]} == {"192x192", "512x512"}
    for icon in data["icons"]:
        assert client.get("/" + icon["src"]).status_code == 200
    sw = client.get("/sw.js")
    assert sw.status_code == 200 and "javascript" in sw.headers["content-type"] and sw.headers["cache-control"] == "no-cache"


def test_the_worker_never_handles_data(client):
    text = client.get("/sw.js").text
    for never in ('"api/"', '"share"', '"metrics"'):
        assert never in text
    assert 'req.method !== "GET"' in text


def test_data_still_needs_a_login(client):
    for path in ("/api/devices", "/api/map", "/api/events", "/metrics"):
        assert client.get(path).status_code in (401, 403), path
