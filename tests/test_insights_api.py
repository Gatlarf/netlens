import pytest
from fastapi.testclient import TestClient

from app import licence
from app.config import load_settings
from app.db import add_event, connect
from app.main import create_app

AUTH = {"Authorization": "Bearer secret"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("NETLENS_TOKEN", "secret")
    monkeypatch.setenv("NETLENS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NETLENS_RANGES", "192.168.250.0/30")
    app = create_app(load_settings())
    with TestClient(app) as c:
        conn = connect(tmp_path / "netlens.db")
        conn.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, device_type, first_seen, last_seen) VALUES (1, 'aa:bb:cc:dd:ee:01', '192.168.1.20', 'nas', 0, 'unknown', '2026-10-01T00:00:00Z', '2026-10-17T00:00:00Z')")
        conn.commit()
        add_event(conn, "device_offline", "nas is offline", device_id=1)
        conn.close()
        yield c, tmp_path


def test_locked_without_a_licence(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: feature != "insights")
    body = c.get("/api/insights", headers=AUTH).json()
    assert body["status"]["allowed"] is False and "incidents" not in body
    assert c.post("/api/insights/ask", json={"question": "what is wrong"}, headers=AUTH).status_code == 402
    assert c.get("/api/insights/identify/1", headers=AUTH).status_code == 402


def test_overview_ask_identify_and_settings(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    body = c.get("/api/insights", headers=AUTH).json()
    assert body["status"]["allowed"] and body["status"]["llm_ready"] is False and body["presets"]
    assert body["unknown_devices"][0]["id"] == 1 and body["incidents"][0]["title"].startswith("nas")
    assert body["predictions"] == {"disks": [], "memory": []}
    answer = c.post("/api/insights/ask", json={"question": "what is wrong right now?"}, headers=AUTH).json()
    assert answer["source"] == "rules" and "nas" in answer["answer"]
    assert c.get("/api/insights/identify/1", headers=AUTH).json()["device_id"] == 1
    assert c.get("/api/insights/identify/99", headers=AUTH).status_code == 404
    assert c.get("/api/insights/postmortem/99", headers=AUTH).status_code == 404
    first = body["incidents"][0]["id"]
    words = c.post(f"/api/insights/incidents/{first}/words", headers=AUTH).json()
    assert words["source"] == "rules" and words["text"]
    assert c.put("/api/insights/settings", json={"llm": False}, headers=AUTH).json()["llm_wanted"] is False


def test_the_mode_of_a_question_is_chosen_by_the_caller(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    assert c.post("/api/insights/ask", json={"question": "how many devices per type?", "mode": "rules"}, headers=AUTH).json()["source"] == "rules"
    assert "No language model" in c.post("/api/insights/ask", json={"question": "how many devices?", "mode": "model"}, headers=AUTH).json()["answer"]
    assert c.post("/api/insights/ask", json={"question": "x", "mode": "nonsense"}, headers=AUTH).status_code == 422


def test_causes_and_impact_need_insights_and_answer(client, monkeypatch):
    c, tmp_path = client
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: feature != "insights")
    assert c.get("/api/insights/devices/1/causes", headers=AUTH).status_code == 402
    assert c.get("/api/insights/devices/1/impact", headers=AUTH).status_code == 402
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    conn = connect(tmp_path / "netlens.db")
    add_event(conn, "port_opened", "tcp/23 telnet", device_id=1)
    conn.close()
    body = c.get("/api/insights/devices/1/causes", headers=AUTH).json()
    assert body["device"] == "nas" and body["suspects"] == [] or any(s["text"] == "tcp/23 telnet" for s in body["suspects"])
    assert c.get("/api/insights/devices/1/causes?at=yesterday", headers=AUTH).status_code == 400
    assert c.get("/api/insights/devices/99/causes", headers=AUTH).status_code == 404
    assert c.get("/api/insights/devices/1/impact", headers=AUTH).json()["risk"] == "none"
    assert c.get("/api/insights/devices/99/impact", headers=AUTH).status_code == 404
    assert c.get("/api/insights", headers=AUTH).json()["incidents"] is not None


def test_cascade_needs_insights_and_a_known_incident(client, monkeypatch):
    c, _ = client
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: feature != "insights")
    assert c.get("/api/insights/incidents/1/cascade", headers=AUTH).status_code == 402
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    assert c.get("/api/insights/incidents/999999/cascade", headers=AUTH).status_code == 404
    first = c.get("/api/insights", headers=AUTH).json()["incidents"]
    if first:
        assert c.get(f"/api/insights/incidents/{first[0]['id']}/cascade", headers=AUTH).json()["steps"]
    assert c.get("/api/devices/1/calendar", headers=AUTH).json()["device_id"] == 1
    assert c.get("/api/devices/99/calendar", headers=AUTH).status_code == 404
    assert c.get("/api/devices/1/calendar?days=3", headers=AUTH).status_code == 422
