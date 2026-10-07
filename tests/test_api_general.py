from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.main import create_app

AUTH = {"Authorization": "Bearer secret"}


def _client(db: Path, **env) -> TestClient:
    app = create_app(load_settings({"NETLENS_TOKEN": "secret", **env}), db_path=db)

    async def detect():
        return []

    app.state.scan_manager.ranges_provider = detect
    return TestClient(app, headers=AUTH)


def test_defaults_come_from_env(tmp_path):
    with _client(tmp_path / "t.db", NETLENS_QUICK_INTERVAL="600") as c:
        cfg = c.get("/api/config").json()
        assert cfg["quick_interval"] == 600 and cfg["quick_interval_source"] == "env"
        assert cfg["deep_interval"] == 86400
        assert cfg["terminal_enabled"] is True and cfg["terminal_source"] == "env"


def test_set_and_reset_intervals(tmp_path):
    with _client(tmp_path / "t.db") as c:
        r = c.put("/api/config/general", json={"quick_interval": 300, "deep_interval": 7200})
        body = r.json()
        assert (body["quick_interval"], body["deep_interval"]) == (300, 7200)
        assert body["quick_interval_source"] == "ui"
        assert c.app.state.settings.quick_interval == 300
        assert c.app.state.scan_manager.settings.deep_interval == 7200
        # only the supplied field changes; null resets just that one
        r = c.put("/api/config/general", json={"quick_interval": None})
        assert r.json()["quick_interval"] == 900 and r.json()["deep_interval"] == 7200


@pytest.mark.parametrize("bad", [0, 59, 30 * 86400 + 1, -5])
def test_interval_bounds(tmp_path, bad):
    with _client(tmp_path / "t.db") as c:
        r = c.put("/api/config/general", json={"quick_interval": bad})
        assert r.status_code == 422
        assert c.get("/api/config").json()["quick_interval"] == 900


def test_settings_survive_restart(tmp_path):
    db = tmp_path / "t.db"
    with _client(db) as c:
        c.put("/api/config/general", json={"deep_interval": 3600, "terminal_enabled": False})
    with _client(db) as c:
        cfg = c.get("/api/config").json()
        assert cfg["deep_interval"] == 3600 and cfg["terminal_source"] == "ui"
        assert cfg["terminal_enabled"] is False


def test_terminal_can_be_toggled_at_runtime(tmp_path):
    with _client(tmp_path / "t.db") as c:
        # on: the hostkey route exists (device missing -> 404 from the handler, not the gate)
        r = c.delete("/api/devices/1/hostkey")
        enabled_detail = r.json().get("detail")
        assert enabled_detail != "web terminal is disabled"
        c.put("/api/config/general", json={"terminal_enabled": False})
        r = c.delete("/api/devices/1/hostkey")
        assert r.status_code == 404 and r.json()["detail"] == "web terminal is disabled"
        with pytest.raises(Exception):
            with c.websocket_connect("/api/terminal/1/ws?proto=ssh") as ws:
                ws.receive_text()
        c.put("/api/config/general", json={"terminal_enabled": None})
        r = c.delete("/api/devices/1/hostkey")
        assert r.json().get("detail") != "web terminal is disabled"


def test_requires_auth(tmp_path):
    with _client(tmp_path / "t.db") as c:
        assert c.put("/api/config/general", json={}, headers={"Authorization": "Bearer no"}).status_code == 401
