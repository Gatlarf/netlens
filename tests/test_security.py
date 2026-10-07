"""Tests for app.security.SecurityHeadersMiddleware."""

import pytest
from fastapi import FastAPI, WebSocket
from fastapi.responses import PlainTextResponse
from fastapi.testclient import TestClient

from app.security import SecurityHeadersMiddleware


def _build_app() -> FastAPI:
    app = FastAPI()

    @app.get("/api/x")
    def api_x():
        return {"ok": True}

    @app.get("/page")
    def page():
        return PlainTextResponse("hi")

    @app.get("/cached")
    def cached():
        resp = PlainTextResponse("hi")
        resp.headers["Cache-Control"] = "max-age=60"
        return resp

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        await websocket.accept()
        await websocket.send_text("ok")
        await websocket.close()

    app.add_middleware(SecurityHeadersMiddleware)
    return app


@pytest.fixture
def client():
    app = _build_app()
    return TestClient(app)


def test_x_content_type_options(client):
    r = client.get("/api/x")
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_x_frame_options(client):
    r = client.get("/api/x")
    assert r.headers["X-Frame-Options"] == "DENY"


def test_referrer_policy(client):
    r = client.get("/api/x")
    assert r.headers["Referrer-Policy"] == "no-referrer"


def test_content_security_policy(client):
    r = client.get("/api/x")
    csp = r.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_permissions_policy(client):
    r = client.get("/api/x")
    assert "Permissions-Policy" in r.headers


def test_cross_origin_opener_policy(client):
    r = client.get("/api/x")
    assert "Cross-Origin-Opener-Policy" in r.headers


def test_api_cache_control_no_store(client):
    r = client.get("/api/x")
    assert r.headers["Cache-Control"] == "no-store"


def test_page_revalidates(client):
    r = client.get("/page")
    assert r.headers["Cache-Control"] == "no-cache"


def test_cached_keeps_own_cache_control(client):
    r = client.get("/cached")
    assert r.headers["Cache-Control"] == "max-age=60"
    assert "no-store" not in r.headers.get("Cache-Control", "")


def test_headers_not_duplicated(client):
    r = client.get("/api/x")
    # A single value for X-Frame-Options
    values = [v for v in r.headers.values() if v == "DENY"]
    assert len(values) == 1
    # Ensure no duplicate header keys
    seen = {}
    for key, value in r.headers.items():
        if key in seen:
            assert seen[key] == value
        else:
            seen[key] = value


def test_websocket_works_through_middleware(client):
    with client.websocket_connect("/ws") as ws:
        msg = ws.receive_text()
        assert msg == "ok"


def test_integration_real_app_health_csp(tmp_path):
    from app.main import create_app
    from app.config import load_settings

    settings = load_settings({"NETLENS_TOKEN": "t"})
    app = create_app(settings, db_path=tmp_path / "t.db")
    with TestClient(app) as c:
        r = c.get("/api/health")
        assert "Content-Security-Policy" in r.headers