import pytest
from fastapi.testclient import TestClient
from app.config import load_settings
from app.main import create_app
from pathlib import Path
import tempfile
import os


def test_login_plain_http_no_secure(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret"})
    app = create_app(settings, db_path=tmp_path / "t.db")
    with TestClient(app, headers={"Authorization": "Bearer wrong"}) as client:
        response = client.post("/api/login", json={"token": "secret"})
        assert response.status_code == 200
        set_cookie = response.headers.get("Set-Cookie", "")
        assert "samesite=strict" in set_cookie.lower()
        assert "httponly" in set_cookie.lower()
        assert "secure" not in set_cookie.lower()


def test_login_https_secure(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret"})
    app = create_app(settings, db_path=tmp_path / "t.db")
    with TestClient(app, headers={"Authorization": "Bearer wrong"}) as client:
        response = client.post(
            "/api/login",
            json={"token": "secret"},
            headers={"X-Forwarded-Proto": "https"},
        )
        assert response.status_code == 200
        set_cookie = response.headers.get("Set-Cookie", "")
        assert "secure" in set_cookie.lower()
        assert "samesite=strict" in set_cookie.lower()
        assert "httponly" in set_cookie.lower()


def test_login_https_first_value_wins(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret"})
    app = create_app(settings, db_path=tmp_path / "t.db")
    with TestClient(app, headers={"Authorization": "Bearer wrong"}) as client:
        response = client.post(
            "/api/login",
            json={"token": "secret"},
            headers={"X-Forwarded-Proto": "https, http"},
        )
        assert response.status_code == 200
        set_cookie = response.headers.get("Set-Cookie", "")
        assert "secure" in set_cookie.lower()
        assert "samesite=strict" in set_cookie.lower()
        assert "httponly" in set_cookie.lower()


def test_login_http_no_secure(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret"})
    app = create_app(settings, db_path=tmp_path / "t.db")
    with TestClient(app, headers={"Authorization": "Bearer wrong"}) as client:
        response = client.post(
            "/api/login",
            json={"token": "secret"},
            headers={"X-Forwarded-Proto": "http"},
        )
        assert response.status_code == 200
        set_cookie = response.headers.get("Set-Cookie", "")
        assert "secure" not in set_cookie.lower()
        assert "samesite=strict" in set_cookie.lower()
        assert "httponly" in set_cookie.lower()


def test_login_base_url_https_secure(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret"})
    app = create_app(settings, db_path=tmp_path / "t.db")
    with TestClient(app, base_url="https://testserver", headers={"Authorization": "Bearer wrong"}) as client:
        response = client.post("/api/login", json={"token": "secret"})
        assert response.status_code == 200
        set_cookie = response.headers.get("Set-Cookie", "")
        assert "secure" in set_cookie.lower()
        assert "samesite=strict" in set_cookie.lower()
        assert "httponly" in set_cookie.lower()


def test_logout_https_secure(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret"})
    app = create_app(settings, db_path=tmp_path / "t.db")
    with TestClient(app, headers={"Authorization": "Bearer wrong"}) as client:
        # First login to establish session
        login_response = client.post(
            "/api/login",
            json={"token": "secret"},
            headers={"X-Forwarded-Proto": "https"},
        )
        assert login_response.status_code == 200
        # Then logout
        logout_response = client.post(
            "/api/logout",
            headers={"X-Forwarded-Proto": "https"},
        )
        assert logout_response.status_code == 200
        set_cookie = logout_response.headers.get("Set-Cookie", "")
        assert "netlens_session" in set_cookie.lower()
        assert "secure" in set_cookie.lower()
        assert "httponly" in set_cookie.lower()