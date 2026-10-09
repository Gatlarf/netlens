import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import connect, get_or_create_device
from app.main import create_app
from app.scanner.passive import Control

ADMIN = {"Authorization": "Bearer secret"}


@pytest.fixture
def client(tmp_path):
    path = tmp_path / "t.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app, headers=ADMIN) as c:
        c.app_ = app
        c.path = path
        yield c


def test_not_available_without_the_background_tasks(client):
    assert client.get("/api/passive").status_code == 404


def test_switch_and_status(client):
    client.app_.state.passive = Control(client.path)
    assert client.get("/api/passive").json()["enabled"] is True
    r = client.put("/api/passive", json={"enabled": False})
    assert r.status_code == 200 and r.json()["enabled"] is False and r.json()["running"] is False
    assert client.get("/api/passive").json()["enabled"] is False
    assert client.put("/api/passive", json={"enabled": "maybe"}).status_code == 422
    client.put("/api/passive", json={"enabled": False})


def test_device_detail_explains_the_type(client):
    conn = connect(client.path)
    device_id = get_or_create_device(conn, "aa:bb:cc:00:00:01", "10.0.0.5")
    conn.execute("INSERT INTO device_names (device_id, name, source, first_seen, last_seen) VALUES (?, 'office-printer', 'ptr', 'x', 'x')", (device_id,))
    conn.commit()
    conn.close()
    info = client.get(f"/api/devices/{device_id}").json()["identification"]
    assert info["evidence"][0]["type"] == "printer" and "printer" in info["evidence"][0]["why"]


def test_overriding_twice_teaches_the_vendor(client):
    conn = connect(client.path)
    ids = []
    for i in range(1, 4):
        d = get_or_create_device(conn, f"aa:bb:cc:00:00:0{i}", f"10.0.0.{i}")
        conn.execute("UPDATE devices SET vendor = 'Acme' WHERE id = ?", (d,))
        ids.append(d)
    conn.commit()
    conn.close()
    for d in ids[:2]:
        assert client.patch(f"/api/devices/{d}", json={"type_override": "speaker"}).status_code == 200
    third = client.get(f"/api/devices/{ids[2]}").json()
    assert third["device_type"] == "speaker"
    assert any("you set 2 other Acme" in e["why"] for e in third["identification"]["evidence"])
