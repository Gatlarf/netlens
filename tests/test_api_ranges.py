from pathlib import Path

from fastapi.testclient import TestClient

from app.config import load_settings, normalize_ranges
from app.main import create_app

import pytest

AUTH = {"Authorization": "Bearer secret"}


async def _fake_detect():
    return ["10.9.8.0/24"]


def _settings(**extra):
    env = {"NETLENS_TOKEN": "secret", **extra}
    return load_settings(env)


def _client(db: Path, **env) -> TestClient:
    app = create_app(_settings(**env), db_path=db)
    app.state.scan_manager.ranges_provider = _fake_detect
    return TestClient(app, headers=AUTH)


def test_default_source_is_auto(tmp_path):
    with _client(tmp_path / "t.db") as c:
        cfg = c.get("/api/config").json()
        assert cfg["ranges"] == []
        assert cfg["ranges_source"] == "auto"
        assert cfg["detected_ranges"] == ["10.9.8.0/24"]


def test_env_source(tmp_path):
    with _client(tmp_path / "t.db", NETLENS_RANGES="192.168.1.0/24") as c:
        cfg = c.get("/api/config").json()
        assert cfg["ranges"] == ["192.168.1.0/24"]
        assert cfg["ranges_source"] == "env"


def test_put_ranges_applies_everywhere(tmp_path):
    with _client(tmp_path / "t.db") as c:
        r = c.put("/api/config/ranges", json={"ranges": ["192.168.5.7/24", "10.0.0.0/22", "192.168.5.0/24"]})
        assert r.status_code == 200
        body = r.json()
        assert body["ranges"] == ["192.168.5.0/24", "10.0.0.0/22"]
        assert body["ranges_source"] == "ui"
        app = c.app
        assert app.state.settings.ranges == ("192.168.5.0/24", "10.0.0.0/22")
        assert app.state.scan_manager.settings.ranges == ("192.168.5.0/24", "10.0.0.0/22")
        assert c.get("/api/config").json()["ranges"] == ["192.168.5.0/24", "10.0.0.0/22"]


def test_single_ip_is_accepted(tmp_path):
    with _client(tmp_path / "t.db") as c:
        r = c.put("/api/config/ranges", json={"ranges": ["192.168.1.10"]})
        assert r.status_code == 200
        assert r.json()["ranges"] == ["192.168.1.10/32"]


@pytest.mark.parametrize("bad", ["8.8.8.0/24", "192.168.0.0/16", "not-an-ip", "fe80::/64", "0.0.0.0/0"])
def test_put_rejects_bad_ranges(tmp_path, bad):
    with _client(tmp_path / "t.db") as c:
        r = c.put("/api/config/ranges", json={"ranges": ["192.168.1.0/24", bad]})
        assert r.status_code == 422
        assert bad in r.json()["detail"]
        # nothing was changed or saved
        cfg = c.get("/api/config").json()
        assert cfg["ranges"] == [] and cfg["ranges_source"] == "auto"


def test_put_rejects_too_many(tmp_path):
    with _client(tmp_path / "t.db") as c:
        r = c.put("/api/config/ranges", json={"ranges": [f"10.0.{i}.0/24" for i in range(17)]})
        assert r.status_code == 422


def test_requires_auth(tmp_path):
    with _client(tmp_path / "t.db") as c:
        r = c.put("/api/config/ranges", json={"ranges": ["192.168.1.0/24"]}, headers={"Authorization": "Bearer wrong"})
        assert r.status_code == 401


def test_empty_resets_to_env(tmp_path):
    with _client(tmp_path / "t.db", NETLENS_RANGES="192.168.1.0/24") as c:
        c.put("/api/config/ranges", json={"ranges": ["10.1.0.0/24"]})
        assert c.get("/api/config").json()["ranges"] == ["10.1.0.0/24"]
        r = c.put("/api/config/ranges", json={"ranges": []})
        assert r.json()["ranges"] == ["192.168.1.0/24"]
        assert r.json()["ranges_source"] == "env"
        assert c.app.state.scan_manager.settings.ranges == ("192.168.1.0/24",)


def test_override_survives_restart_and_beats_env(tmp_path):
    db = tmp_path / "t.db"
    with _client(db, NETLENS_RANGES="192.168.1.0/24") as c:
        c.put("/api/config/ranges", json={"ranges": ["10.1.0.0/24"]})
    with _client(db, NETLENS_RANGES="192.168.1.0/24") as c:
        cfg = c.get("/api/config").json()
        assert cfg["ranges"] == ["10.1.0.0/24"]
        assert cfg["ranges_source"] == "ui"
        assert c.app.state.scan_manager.settings.ranges == ("10.1.0.0/24",)
    # reset removes the saved value for good
    with _client(db, NETLENS_RANGES="192.168.1.0/24") as c:
        c.put("/api/config/ranges", json={"ranges": []})
    with _client(db, NETLENS_RANGES="192.168.1.0/24") as c:
        assert c.get("/api/config").json()["ranges_source"] == "env"


def test_normalize_ranges_skips_blanks():
    assert normalize_ranges(["", " 192.168.1.5/24 ", "192.168.1.0/24"]) == ["192.168.1.0/24"]
