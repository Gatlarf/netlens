from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from tests.fake_terminal import FakeBackend
from app.config import load_settings
from app.main import create_app
from app.db import connect, init_db, get_or_create_device
from app.scanner.store import save_scan_results
from app.scanner.nmap_parser import parse_nmap_xml
from app.terminal.hostkeys import get_fingerprint

FIXTURE = Path(__file__).parent / "fixtures" / "deep.xml"

def make_app(tmp_path):
    settings = load_settings({"NETLENS_TOKEN": "t"})
    db_path = tmp_path / "t.db"
    conn = connect(db_path)
    init_db(conn)
    save_scan_results(conn, parse_nmap_xml(FIXTURE.read_text(encoding="utf-8")), "deep")
    conn.close()
    app = create_app(settings, db_path=db_path)
    app.state.terminal_backends = {"ssh": FakeBackend, "telnet": FakeBackend}
    return app

@pytest.fixture(autouse=True)
def reset_fake_backend():
    FakeBackend.reset()

AUTH = {"Authorization": "Bearer t"}
AUTH_MSG = {"type": "auth", "username": "bob", "password": "pw", "cols": 100, "rows": 30}
URL = "/api/terminal/1/ws?proto=ssh"

def test_happy_path(tmp_path):
    app = make_app(tmp_path)
    with TestClient(app) as client:
        with client.websocket_connect(URL, headers=AUTH) as ws:
            ws.send_json(AUTH_MSG)
            status = ws.receive_json()
            assert status["type"] == "status"
            assert status["state"] == "connected"
            assert status["proto"] == "ssh"
            assert status["port"] == 22
            assert status["fingerprint"] == "SHA256:fake"
            assert status["new_key"] is True
            assert ws.receive_bytes() == b"welcome\r\n"
            ws.send_bytes(b"ls\n")
            assert ws.receive_bytes() == b"echo:ls\n"
            created = FakeBackend.created[0]
            assert created["host"] == "192.168.1.1"
            assert created["port"] == 22
            assert created["username"] == "bob"
            assert created["password"] == "pw"
            assert created["cols"] == 100
            assert created["rows"] == 30
            assert created["known_fingerprint"] is None

def test_fingerprint_stored_and_reused(tmp_path):
    app = make_app(tmp_path)
    with TestClient(app) as client:
        with client.websocket_connect(URL, headers=AUTH) as ws:
            ws.send_json(AUTH_MSG)
            ws.receive_json()
            ws.receive_bytes()
            ws.send_bytes(b"exit\n")
            ws.receive_bytes()
    conn = connect(app.state.db_path)
    assert get_fingerprint(conn, 1) == "SHA256:fake"
    conn.close()
    with TestClient(app) as client:
        with client.websocket_connect(URL, headers=AUTH) as ws:
            ws.send_json(AUTH_MSG)
            ws.receive_json()
            ws.receive_bytes()
            ws.send_bytes(b"exit\n")
            ws.receive_bytes()
    created = FakeBackend.created[1]
    assert created["known_fingerprint"] == "SHA256:fake"

def test_resize_and_invalid_messages(tmp_path):
    app = make_app(tmp_path)
    with TestClient(app) as client:
        with client.websocket_connect(URL, headers=AUTH) as ws:
            ws.send_json(AUTH_MSG)
            ws.receive_json()
            ws.receive_bytes()
            ws.send_json({"type": "resize", "cols": 120, "rows": 40})
            ws.send_bytes(b"x")
            msg = ws.receive()
            while msg.get("bytes") != b"echo:x":
                msg = ws.receive()
            assert (120, 40) in FakeBackend.resizes
            ws.send_json({"type": "resize", "cols": 9999, "rows": 1})
            ws.send_bytes(b"x")
            msg = ws.receive()
            while msg.get("bytes") != b"echo:x":
                msg = ws.receive()
            assert (500, 5) in FakeBackend.resizes
            ws.send_text("invalid json")
            ws.send_json({"type": "ping"})
            ws.send_bytes(b"x")
            msg = ws.receive()
            while msg.get("bytes") != b"echo:x":
                msg = ws.receive()

def test_delete_hostkey(tmp_path):
    app = make_app(tmp_path)
    with TestClient(app) as client:
        with client.websocket_connect(URL, headers=AUTH) as ws:
            ws.send_json(AUTH_MSG)
            ws.receive_json()
            ws.receive_bytes()
            ws.send_bytes(b"exit\n")
            ws.receive_bytes()
        resp = client.delete("/api/devices/1/hostkey", headers=AUTH)
        assert resp.status_code == 204
        resp = client.delete("/api/devices/1/hostkey", headers=AUTH)
        assert resp.status_code == 404
        assert resp.json()["detail"] == "no stored host key"
        resp = client.delete("/api/devices/1/hostkey", headers={"Authorization": "Bearer wrong"})
        assert resp.status_code == 401

def test_idle_timeout(tmp_path):
    app = make_app(tmp_path)
    app.state.terminal_idle_timeout = 0.3
    with TestClient(app) as client:
        with client.websocket_connect(URL, headers=AUTH) as ws:
            ws.send_json(AUTH_MSG)
            ws.receive_json()
            ws.receive_bytes()
            while True:
                msg = ws.receive()
                if msg.get("text"):
                    data = msg["text"]
                    if isinstance(data, str):
                        import json
                        data = json.loads(data)
                    if data.get("type") == "closed" and data.get("reason") == "idle timeout":
                        break

def test_session_limit(tmp_path):
    app = make_app(tmp_path)
    app.state.terminal_sessions = 5
    with TestClient(app) as client:
        with client.websocket_connect(URL, headers=AUTH) as ws:
            ws.send_json(AUTH_MSG)
            msg = ws.receive_json()
            assert msg["type"] == "error"
            assert msg["code"] == "limit"