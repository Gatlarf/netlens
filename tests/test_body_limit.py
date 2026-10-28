"""Request bodies are capped before the framework reads them."""

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.main import create_app
from app.security import DEFAULT_LIMIT, MIB, limit_for

ADMIN = {"Authorization": "Bearer secret"}


@pytest.fixture
def client(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app) as c:
        yield c


def test_the_limits_by_address():
    assert limit_for("/api/devices/3") == DEFAULT_LIMIT == 4 * MIB
    assert limit_for("/api/login") == 16 * 1024 and limit_for("/share-api/abc/unlock") == 16 * 1024
    assert limit_for("/api/restore") >= 512 * MIB and limit_for("/api/plugins") == 3 * MIB and limit_for("/api/probe/push") == 64 * MIB


def test_a_declared_size_over_the_limit_is_refused_at_once(client):
    big = b"{" + b" " * (5 * MIB) + b"}"
    r = client.post("/api/users", content=big, headers={**ADMIN, "Content-Type": "application/json"})
    assert r.status_code == 413 and "too large" in r.json()["detail"] and "4 MiB" in r.json()["detail"]
    assert r.headers["x-content-type-options"] == "nosniff"                               # the refusal carries the security headers too


def test_a_chunked_body_that_grows_past_the_limit_is_cut_off(client):
    def chunks():
        for _ in range(80):
            yield b" " * 65536
    r = client.post("/api/login", content=chunks(), headers={"Content-Type": "application/json"})
    assert r.status_code == 413                                                            # 5 MiB sent in pieces to a 16 KiB address


def test_normal_requests_are_not_affected(client):
    assert client.post("/api/login", json={"token": "secret"}).status_code == 200
    assert client.post("/api/users", json={"username": "a", "password": "longenough1", "role": "viewer"}, headers=ADMIN).status_code == 201
    assert client.get("/api/devices", headers=ADMIN).status_code == 200
    assert client.post("/api/login", content=b"x", headers={"Content-Length": "abc", "Content-Type": "application/json"}).status_code in (400, 422)


def test_the_server_header_is_not_sent_by_main():
    import inspect

    from app import main
    assert "server_header=False" in inspect.getsource(main.main)
