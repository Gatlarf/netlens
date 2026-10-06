import pytest
from fastapi.testclient import TestClient
from pathlib import Path

from app.main import create_app, VERSION
from app.config import Settings, load_settings


def test_health_endpoint():
    settings = load_settings({"NETLENS_TOKEN": "t"})
    app = create_app(settings)
    client = TestClient(app)

    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": VERSION}


def test_app_state_settings():
    settings = load_settings({"NETLENS_TOKEN": "t"})
    app = create_app(settings)
    assert app.state.settings is settings


def test_unknown_path_returns_404():
    settings = load_settings({"NETLENS_TOKEN": "t"})
    app = create_app(settings)
    client = TestClient(app)

    response = client.get("/api/unknown")
    assert response.status_code == 404


def test_app_title():
    settings = load_settings({"NETLENS_TOKEN": "t"})
    app = create_app(settings)
    assert app.title == "Netlens"