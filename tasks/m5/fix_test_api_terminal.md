Fix the defects below and output the COMPLETE corrected file. Keep everything else identical.

DEFECTS:
The FastAPI app has no attribute db_path; the path is app.state.db_path (set by create_app). Replace every app.db_path with app.state.db_path (connect(app.state.db_path)).

CURRENT FILE:
import asyncio
import pytest
from fastapi.testclient import TestClient
from fastapi import WebSocketDisconnect
from pathlib import Path
from app.config import load_settings
from app.main import create_app
from app.db import connect, init_db, get_or_create_device
from app.scanner.store import save_scan_results
from app.scanner.nmap_parser import parse_nmap_xml
from app.terminal.base import TerminalBackend, AuthFailed, ConnectFailed, HostKeyMismatch
from app.terminal.hostkeys import get_fingerprint

created = []
resizes = []
connect_error = None
queue = None

class FakeBackend(TerminalBackend):
    def __init__(self, **kwargs):
        created.append(kwargs)
        self.fingerprint = "SHA256:fake"
        self.new_key = True
        self._queue = queue
        self._closed = False

    async def connect(self):
        if connect_error:
            raise connect_error

    async def read(self):
        if self._closed:
            return b""
        item = await self._queue.get()
        if item is None:
            return b""
        return item

    async def write(self, data):
        await self._queue.put(b"echo:" + data)

    async def resize(self, cols, rows):
        resizes.append((cols, rows))

    async def close(self):
        self._closed = True

FakeFactory = FakeBackend

@pytest.fixture(autouse=True)
def reset_state():
    global created, resizes, connect_error, queue
    created.clear()
    resizes.clear()
    connect_error = None
    queue = asyncio.Queue()
    yield

def setup_app(tmp_path):
    settings = load_settings({"NETLENS_TOKEN": "t"})
    app = create_app(settings, db_path=tmp_path / "t.db")
    app.state.terminal_backends = {"ssh": FakeFactory, "telnet": FakeFactory}
    conn = connect(app.db_path)
    init_db(conn)
    xml = Path(__file__).parent.joinpath("fixtures", "deep.xml").read_text(encoding="utf-8")
    save_scan_results(conn, parse_nmap_xml(xml), "deep")
    conn.commit()
    return app, conn

def seed_devices(conn):
    # Device 1: 192.168.1.1, ssh 22 open
    id1 = get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.1")
    conn.execute("INSERT INTO ports (device_id, proto, port, state, service, updated) VALUES (?, 'tcp', 22, 'open', 'ssh', '2026-01-01T00:00:00Z')", (id1,))
    # Device 2: 192.168.1.20, ssh 22 open
    id2 = get_or_create_device(conn, "aa:bb:cc:dd:ee:02", "192.168.1.20")
    conn.execute("INSERT INTO ports (device_id, proto, port, state, service, updated) VALUES (?, 'tcp', 22, 'open', 'ssh', '2026-01-01T00:00:00Z')", (id2,))
    # Device 3: 192.168.1.30, no port 22 or 23
    id3 = get_or_create_device(conn, "aa:bb:cc:dd:ee:03", "192.168.1.30")
    # Device 4: 192.168.1.50, only 8080
    id4 = get_or_create_device(conn, "aa:bb:cc:dd:ee:04", "192.168.1.50")
    conn.execute("INSERT INTO ports (device_id, proto, port, state, service, updated) VALUES (?, 'tcp', 8080, 'open', 'http', '2026-01-01T00:00:00Z')", (id4,))
    # Public IP device
    id5 = get_or_create_device(conn, "aa:bb:cc:dd:ee:99", "8.8.8.8")
    conn.execute("INSERT INTO ports (device_id, proto, port, state, service, updated) VALUES (?, 'tcp', 22, 'open', 'ssh', '2026-01-01T00:00:00Z')", (id5,))
    conn.commit()
    return id1, id2, id3, id4, id5

def test_unauthenticated():
    app, conn = setup_app(Path("/tmp"))
    seed_devices(conn)
    with TestClient(app) as client:
        try:
            client.websocket_connect("/ws/terminal/1", headers={"Authorization": "Bearer wrong"})
        except WebSocketDisconnect:
            pass

def test_origin():
    app, conn = setup_app(Path("/tmp"))
    seed_devices(conn)
    with TestClient(app) as client:
        try:
            client.websocket_connect("/ws/terminal/1", headers={"Authorization": "Bearer t", "Origin": "https://evil.example"})
        except WebSocketDisconnect:
            pass
        try:
            client.websocket_connect("/ws/terminal/1", headers={"Authorization": "Bearer t", "Origin": "http://testserver"})
        except WebSocketDisconnect:
            pass

def test_happy_path():
    app, conn = setup_app(Path("/tmp"))
    id1, _, _, _, _ = seed_devices(conn)
    with TestClient(app) as client:
        ws = client.websocket_connect("/ws/terminal/1", headers={"Authorization": "Bearer t"})
        ws.send_json({"type": "auth", "username": "bob", "password": "pw", "cols": 100, "rows": 30})
        msg = ws.receive_json()
        assert msg["type"] == "status"
        assert msg["state"] == "connected"
        assert msg["fingerprint"] == "SHA256:fake"
        assert msg["new_key"] is True
        assert ws.receive_bytes() == b"welcome\r\n"
        ws.send_bytes(b"ls\n")
        assert ws.receive_bytes() == b"echo:ls\n"
        kwargs = created[0]
        assert kwargs["host"] == "192.168.1.1"
        assert kwargs["port"] == 22
        assert kwargs["username"] == "bob"
        assert kwargs["password"] == "pw"
        assert kwargs["cols"] == 100
        assert kwargs["rows"] == 30
        assert kwargs["known_fingerprint"] is None

def test_fingerprint_stored():
    app, conn = setup_app(Path("/tmp"))
    id1, _, _, _, _ = seed_devices(conn)
    with TestClient(app) as client:
        ws = client.websocket_connect("/ws/terminal/1", headers={"Authorization": "Bearer t"})
        ws.send_json({"type": "auth", "username": "bob", "password": "pw", "cols": 100, "rows": 30})
        ws.receive_json()
        ws.receive_bytes()
        ws.send_bytes(b"ls\n")
        ws.receive_bytes()
        ws.close()
    conn2 = connect(app.db_path)
    init_db(conn2)
    fp = get_fingerprint(conn2, id1)
    assert fp == "SHA256:fake"
    created.clear()
    queue.put(None)
    with TestClient(app) as client:
        ws = client.websocket_connect("/ws/terminal/1", headers={"Authorization": "Bearer t"})
        ws.send_json({"type": "auth", "username": "bob", "password": "pw", "cols": 100, "rows": 30})
        ws.receive_json()
        ws.receive_bytes()
        ws.send_bytes(b"ls\n")
        ws.receive_bytes()
        ws.close()
    assert created[0]["known_fingerprint"] == "SHA256:fake"

def test_resize():
    app, conn = setup_app(Path("/tmp"))
    id1, _, _, _, _ = seed_devices(conn)
    with TestClient(app) as client:
        ws = client.websocket_connect("/ws/terminal/1", headers={"Authorization": "Bearer t"})
        ws.send_json({"type": "auth", "username": "bob", "password": "pw", "cols": 100, "rows": 30})
        ws.receive_json()
        ws.receive_bytes()
        ws.send_json({"type": "resize", "cols": 120, "rows": 40})
        ws.send_bytes(b"ls\n")
        ws.receive_bytes()
        assert (120, 40) in resizes
        ws.send_json({"type": "resize", "cols": 9999, "rows": 40})
        ws.send_bytes(b"ls\n")
        ws.receive_bytes()
        assert (500, 40) in resizes

def test_telnet_no_port():
    app, conn = setup_app(Path("/tmp"))
    _, _, _, _, _ = seed_devices(conn)
    with TestClient(app) as client:
        ws = client.websocket_connect("/ws/terminal/1?proto=telnet", headers={"Authorization": "Bearer t"})
        ws.send_json({"type": "auth", "username": "bob", "password": "pw", "cols": 100, "rows": 30})
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert msg["code"] == "port"

def test_device_no_ssh():
    app, conn = setup_app(Path("/tmp"))
    _, _, id3, _, _ = seed_devices(conn)
    with TestClient(app) as client:
        ws = client.websocket_connect(f"/ws/terminal/{id3}", headers={"Authorization": "Bearer t"})
        ws.send_json({"type": "auth", "username": "bob", "password": "pw", "cols": 100, "rows": 30})
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert msg["code"] == "port"

def test_unknown_device():
    app, conn = setup_app(Path("/tmp"))
    seed_devices(conn)
    with TestClient(app) as client:
        ws = client.websocket_connect("/ws/terminal/999", headers={"Authorization": "Bearer t"})
        ws.send_json({"type": "auth", "username": "bob", "password": "pw", "cols": 100, "rows": 30})
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert msg["code"] == "device"

def test_public_ip():
    app, conn = setup_app(Path("/tmp"))
    _, _, _, _, id5 = seed_devices(conn)
    with TestClient(app) as client:
        ws = client.websocket_connect(f"/ws/terminal/{id5}", headers={"Authorization": "Bearer t"})
        ws.send_json({"type": "auth", "username": "bob", "password": "pw", "cols": 100, "rows": 30})
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert msg["code"] == "policy"

def test_invalid_proto():
    app, conn = setup_app(Path("/tmp"))
    seed_devices(conn)
    with TestClient(app) as client:
        ws = client.websocket_connect("/ws/terminal/1?proto=rdp", headers={"Authorization": "Bearer t"})
        ws.send_json({"type": "auth", "username": "bob", "password": "pw", "cols": 100, "rows": 30})
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert msg["code"] == "proto"

def test_missing_username():
    app, conn = setup_app(Path("/tmp"))
    seed_devices(conn)
    with TestClient(app) as client:
        ws = client.websocket_connect("/ws/terminal/1", headers={"Authorization": "Bearer t"})
        ws.send_json({"type": "auth", "password": "pw", "cols": 100, "rows": 30})
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert msg["code"] == "auth_message"

def test_connect_errors():
    app, conn = setup_app(Path("/tmp"))
    seed_devices(conn)
    global connect_error
    connect_error = AuthFailed("authentication failed")
    with TestClient(app) as client:
        ws = client.websocket_connect("/ws/terminal/1", headers={"Authorization": "Bearer t"})
        ws.send_json({"type": "auth", "username": "bob", "password": "pw", "cols": 100, "rows": 30})
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert msg["code"] == "auth"
        assert "pw" not in msg.get("message", "")
    connect_error = ConnectFailed("down")
    with TestClient(app) as client:
        ws = client.websocket_connect("/ws/terminal/1", headers={"Authorization": "Bearer t"})
        ws.send_json({"type": "auth", "username": "bob", "password": "pw", "cols": 100, "rows": 30})
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert msg["code"] == "connect"
        assert msg["message"] == "down"
    connect_error = HostKeyMismatch("SHA256:a", "SHA256:b")
    with TestClient(app) as client:
        ws = client.websocket_connect("/ws/terminal/1", headers={"Authorization": "Bearer t"})
        ws.send_json({"type": "auth", "username": "bob", "password": "pw", "cols": 100, "rows": 30})
        msg = ws.receive_json()
        assert msg["type"] == "hostkey_mismatch"
        assert msg["expected"] == "SHA256:a"
        assert msg["actual"] == "SHA256:b"

def test_delete_hostkey():
    app, conn = setup_app(Path("/tmp"))
    id1, _, _, _, _ = seed_devices(conn)
    with TestClient(app) as client:
        ws = client.websocket_connect("/ws/terminal/1", headers={"Authorization": "Bearer t"})
        ws.send_json({"type": "auth", "username": "bob", "password": "pw", "cols": 100, "rows": 30})
        ws.receive_json()
        ws.receive_bytes()
        ws.send_bytes(b"ls\n")
        ws.receive_bytes()
        ws.close()
    resp = client.delete("/api/devices/1/hostkey", headers={"Authorization": "Bearer t"})
    assert resp.status_code == 204
    resp = client.delete("/api/devices/1/hostkey", headers={"Authorization": "Bearer t"})
    assert resp.status_code == 404
    resp = client.delete("/api/devices/1/hostkey")
    assert resp.status_code == 401

def test_terminal_off():
    settings = load_settings({"NETLENS_TOKEN": "t", "NETLENS_TERMINAL": "off"})
    app = create_app(settings, db_path=Path("/tmp") / "t.db")
    app.state.terminal_backends = {"ssh": FakeFactory, "telnet": FakeFactory}
    conn = connect(app.db_path)
    init_db(conn)
    seed_devices(conn)
    with TestClient(app) as client:
        resp = client.get("/api/devices/1/hostkey", headers={"Authorization": "Bearer t"})
        assert resp.status_code == 404
        resp = client.delete("/api/devices/1/hostkey", headers={"Authorization": "Bearer t"})
        assert resp.status_code == 404
        try:
            client.websocket_connect("/ws/terminal/1", headers={"Authorization": "Bearer t"})
        except WebSocketDisconnect:
            pass

def test_idle_timeout():
    app, conn = setup_app(Path("/tmp"))
    seed_devices(conn)
    app.state.terminal_idle_timeout = 0.3
    with TestClient(app) as client:
        ws = client.websocket_connect("/ws/terminal/1", headers={"Authorization": "Bearer t"})
        ws.send_json({"type": "auth", "username": "bob", "password": "pw", "cols": 100, "rows": 30})
        msg = ws.receive_json()
        assert msg["type"] == "status"
        msg = ws.receive_json()
        assert msg["type"] == "closed"
        assert msg["reason"] == "idle timeout"

def test_session_limit():
    app, conn = setup_app(Path("/tmp"))
    seed_devices(conn)
    app.state.terminal_sessions = 5
    with TestClient(app) as client:
        # Fill sessions
        for _ in range(5):
            ws = client.websocket_connect("/ws/terminal/1", headers={"Authorization": "Bearer t"})
            ws.send_json({"type": "auth", "username": "bob", "password": "pw", "cols": 100, "rows": 30})
            ws.receive_json()
            ws.receive_bytes()
            ws.send_bytes(b"ls\n")
            ws.receive_bytes()
            ws.close()
        # Next should fail
        ws = client.websocket_connect("/ws/terminal/1", headers={"Authorization": "Bearer t"})
        ws.send_json({"type": "auth", "username": "bob", "password": "pw", "cols": 100, "rows": 30})
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert msg["code"] == "limit"