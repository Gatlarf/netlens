import pytest
from fastapi.testclient import TestClient

from app import interface_settings, tsdb
from app.config import load_settings
from app.db import add_event, connect, init_db
from app.main import create_app


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "i.db")
    init_db(c)
    yield c
    c.close()


def test_defaults_and_validation(conn):
    assert interface_settings.get(conn) == interface_settings.DEFAULTS
    out = interface_settings.save(conn, {"pulse_seconds": 3.26, "default_look": "hud", "hud_sweep": False})
    assert out["pulse_seconds"] == 3.3 and out["default_look"] == "hud" and out["hud_sweep"] is False and out["pulse_for"] == "all"
    for bad in ({"pulse_seconds": 11}, {"pulse_seconds": True}, {"default_look": "neon"}, {"pulse_scope": "some"}, {"hud_lines": "yes"}, {"nonsense": 1}):
        with pytest.raises(ValueError):
            interface_settings.save(conn, bad)
    assert interface_settings.get(conn)["default_look"] == "hud"


def test_api_session_and_events(tmp_path):
    tsdb.forget_all()
    settings = load_settings({"NETLENS_DATA_DIR": str(tmp_path), "NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.250.0/30"})
    with TestClient(create_app(settings)) as client:
        h = {"Authorization": "Bearer secret"}
        assert client.get("/api/session").json()["interface"]["default_look"] == "system"          # known before sign-in
        assert client.get("/api/interface", headers=h).json()["settings"]["pulse_seconds"] == 2.0
        assert client.put("/api/interface", json={"default_look": "hud", "pulse_seconds": 4}, headers=h).json()["settings"]["pulse_seconds"] == 4.0
        assert client.put("/api/interface", json={"pulse_seconds": 99}, headers=h).status_code == 422
        assert client.get("/api/session").json()["interface"]["default_look"] == "hud"
        conn = connect(tmp_path / "netlens.db")
        conn.execute("INSERT INTO devices (id, primary_ip, mac, online, always_on, tier, first_seen, last_seen) VALUES (1, '10.0.0.1', 'aa:00:00:00:00:01', 0, 1, 'critical', '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z')")
        add_event(conn, "device_offline", "down", device_id=1)
        conn.commit()
        conn.close()
        event = client.get("/api/events?limit=1", headers=h).json()[0]
        assert event["kind"] == "device_offline" and event["tier"] == "critical" and event["always_on"] is True
    tsdb.forget_all()
