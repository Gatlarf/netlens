import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.main import create_app


def _make_client(settings: Any, db_path: Path, headers: dict[str, str] | None = None) -> TestClient:
    app = create_app(settings, db_path=db_path)
    client = TestClient(app, headers=headers)
    return client


def test_health_public(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.1.0/24", "NETLENS_SNMP_COMMUNITY": "public"})
    with _make_client(settings, tmp_path / "t.db", headers={"Authorization": "Bearer wrong"}) as client:
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()['status'] == 'ok'


def test_devices_requires_auth(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.1.0/24", "NETLENS_SNMP_COMMUNITY": "public"})
    with _make_client(settings, tmp_path / "t.db", headers={"Authorization": "Bearer wrong"}) as client:
        resp = client.get("/api/devices")
        assert resp.status_code == 401
        assert resp.json() == {"detail": "authentication required"}


def test_scans_requires_auth(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.1.0/24", "NETLENS_SNMP_COMMUNITY": "public"})
    with _make_client(settings, tmp_path / "t.db", headers={"Authorization": "Bearer wrong"}) as client:
        resp = client.get("/api/scans")
        assert resp.status_code == 401
        assert resp.json() == {"detail": "authentication required"}


def test_events_requires_auth(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.1.0/24", "NETLENS_SNMP_COMMUNITY": "public"})
    with _make_client(settings, tmp_path / "t.db", headers={"Authorization": "Bearer wrong"}) as client:
        resp = client.get("/api/events")
        assert resp.status_code == 401
        assert resp.json() == {"detail": "authentication required"}


def test_config_requires_auth(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.1.0/24", "NETLENS_SNMP_COMMUNITY": "public"})
    with _make_client(settings, tmp_path / "t.db", headers={"Authorization": "Bearer wrong"}) as client:
        resp = client.get("/api/config")
        assert resp.status_code == 401
        assert resp.json() == {"detail": "authentication required"}


def test_devices_with_auth(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.1.0/24", "NETLENS_SNMP_COMMUNITY": "public"})
    with _make_client(settings, tmp_path / "t.db", headers={"Authorization": "Bearer secret"}) as client:
        resp = client.get("/api/devices")
        assert resp.status_code == 200


def test_scans_with_auth(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.1.0/24", "NETLENS_SNMP_COMMUNITY": "public"})
    with _make_client(settings, tmp_path / "t.db", headers={"Authorization": "Bearer secret"}) as client:
        resp = client.get("/api/scans")
        assert resp.status_code == 200


def test_events_with_auth(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.1.0/24", "NETLENS_SNMP_COMMUNITY": "public"})
    with _make_client(settings, tmp_path / "t.db", headers={"Authorization": "Bearer secret"}) as client:
        resp = client.get("/api/events")
        assert resp.status_code == 200


def test_config_with_auth(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.1.0/24", "NETLENS_SNMP_COMMUNITY": "public"})
    with _make_client(settings, tmp_path / "t.db", headers={"Authorization": "Bearer secret"}) as client:
        resp = client.get("/api/config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ranges"] == ["192.168.1.0/24"]
        assert data["quick_interval"] == 900
        assert data["deep_interval"] == 86400
        assert data["terminal_enabled"] is True
        assert data["snmp_enabled"] is True
        assert data["bind"] == "0.0.0.0:8080"
        assert "version" in data
        body = resp.text
        assert "secret" not in body
        assert "public" not in body


def test_login_success_sets_cookie(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.1.0/24", "NETLENS_SNMP_COMMUNITY": "public"})
    with _make_client(settings, tmp_path / "t.db", headers={"Authorization": "Bearer wrong"}) as client:
        resp = client.post("/api/login", json={"token": "secret"})
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}
        set_cookie = resp.headers.get("set-cookie", "")
        assert "netlens_session" in set_cookie
        assert "httponly" in set_cookie.lower()
        assert "samesite=strict" in set_cookie.lower()


def test_login_wrong_token(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.1.0/24", "NETLENS_SNMP_COMMUNITY": "public"})
    with _make_client(settings, tmp_path / "t.db", headers={"Authorization": "Bearer wrong"}) as client:
        resp = client.post("/api/login", json={"token": "wrong"})
        assert resp.status_code == 401
        assert resp.json() == {"detail": "invalid token"}


def test_login_rate_limit_sixth_attempt(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.1.0/24", "NETLENS_SNMP_COMMUNITY": "public"})
    with _make_client(settings, tmp_path / "t.db", headers={"Authorization": "Bearer wrong"}) as client:
        for _ in range(5):
            resp = client.post("/api/login", json={"token": "wrong"})
            assert resp.status_code == 401
        resp = client.post("/api/login", json={"token": "wrong"})
        assert resp.status_code == 429


def test_login_blocked_after_five_failures(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.1.0/24", "NETLENS_SNMP_COMMUNITY": "public"})
    with _make_client(settings, tmp_path / "t.db", headers={"Authorization": "Bearer wrong"}) as client:
        for _ in range(5):
            resp = client.post("/api/login", json={"token": "wrong"})
            assert resp.status_code == 401
        resp = client.post("/api/login", json={"token": "secret"})
        assert resp.status_code == 429


def test_session_reports_authenticated(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.1.0/24", "NETLENS_SNMP_COMMUNITY": "public"})
    with _make_client(settings, tmp_path / "t.db", headers={"Authorization": "Bearer wrong"}) as client:
        resp = client.get("/api/session")
        assert resp.status_code == 200
        assert resp.json() == {"authenticated": False}

        resp = client.post("/api/login", json={"token": "secret"})
        assert resp.status_code == 200

        resp = client.get("/api/session")
        assert resp.status_code == 200
        assert resp.json() == {"authenticated": True}


def test_logout_clears_cookie(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.1.0/24", "NETLENS_SNMP_COMMUNITY": "public"})
    with _make_client(settings, tmp_path / "t.db", headers={"Authorization": "Bearer wrong"}) as client:
        resp = client.post("/api/login", json={"token": "secret"})
        assert resp.status_code == 200

        resp = client.post("/api/logout")
        assert resp.status_code == 200
        set_cookie = resp.headers.get("set-cookie", "")
        assert "netlens_session=" in set_cookie
        assert "Max-Age=0" in set_cookie or any(
            part.strip().startswith("expires=") and part.strip().split("=")[1] < time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
            for part in set_cookie.split(";")
        )


def test_cookie_only_request_after_login(tmp_path: Path) -> None:
    settings = load_settings({"NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.1.0/24", "NETLENS_SNMP_COMMUNITY": "public"})
    app = create_app(settings, db_path=tmp_path / "t.db")
    with TestClient(app, headers={"Authorization": "Bearer wrong"}) as client:
        resp = client.get("/api/devices")
        assert resp.status_code == 401

        resp = client.post("/api/login", json={"token": "secret"})
        assert resp.status_code == 200

        client.headers.pop("Authorization", None)

        resp = client.get("/api/devices")
        assert resp.status_code == 200