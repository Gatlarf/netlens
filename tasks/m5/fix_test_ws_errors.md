Fix the defects below and output the COMPLETE corrected file. Keep everything else identical.

DEFECTS:
1. test_no_credentials: a conftest patches TestClient so every client sends 'Authorization: Bearer t' by default; to test 'no credentials' call client.headers.pop('Authorization', None) after creating the client and connect with headers={}. 2. test_terminal_off: when the terminal is off the DELETE route is absent and the static file mount answers non-GET methods with 405, so assert resp.status_code in (404, 405).

CURRENT FILE:
import json
from pathlib import Path
from typing import Optional

import pytest
from fastapi import WebSocketDisconnect
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import connect, init_db, get_or_create_device
from app.main import create_app
from app.scanner.nmap_parser import parse_nmap_xml
from app.scanner.store import save_scan_results
from app.terminal.base import AuthFailed, ConnectFailed, HostKeyMismatch
from tests.fake_terminal import FakeBackend

FIXTURE = Path(__file__).parent / "fixtures" / "deep.xml"
AUTH = {"Authorization": "Bearer t"}
AUTH_MSG = {"type": "auth", "username": "bob", "password": "pw", "cols": 80, "rows": 24}


def make_app(tmp_path, env=None):
    settings = load_settings({"NETLENS_TOKEN": "t", **(env or {})})
    db_path = tmp_path / "t.db"
    conn = connect(db_path)
    init_db(conn)
    save_scan_results(conn, parse_nmap_xml(FIXTURE.read_text(encoding="utf-8")), "deep")
    pub = get_or_create_device(conn, "aa:bb:cc:dd:ee:99", "8.8.8.8")
    conn.execute(
        "INSERT INTO ports (device_id, proto, port, state, service, updated) VALUES (?, 'tcp', 22, 'open', 'ssh', '2026-01-01T00:00:00Z')",
        (pub,),
    )
    conn.commit()
    conn.close()
    app = create_app(settings, db_path=db_path)
    app.state.terminal_backends = {"ssh": FakeBackend, "telnet": FakeBackend}
    return app


@pytest.fixture(autouse=True)
def reset_backend():
    FakeBackend.reset()


def first_message(client, url, headers=AUTH, send=AUTH_MSG):
    with client.websocket_connect(url, headers=headers) as ws:
        if send is not None:
            ws.send_json(send)
        return ws.receive_json()


def test_wrong_bearer(tmp_path):
    app = make_app(tmp_path)
    with TestClient(app) as client:
        url = "/api/terminal/1/ws?proto=ssh"
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(url, headers={"Authorization": "Bearer wrong"}) as ws:
                ws.receive_text()


def test_no_credentials(tmp_path):
    app = make_app(tmp_path)
    with TestClient(app) as client:
        url = "/api/terminal/1/ws?proto=ssh"
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(url, headers={}) as ws:
                ws.receive_text()


def test_evil_origin(tmp_path):
    app = make_app(tmp_path)
    with TestClient(app) as client:
        url = "/api/terminal/1/ws?proto=ssh"
        headers = {"Authorization": "Bearer t", "Origin": "https://evil.example"}
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(url, headers=headers) as ws:
                ws.receive_text()


def test_valid_origin(tmp_path):
    app = make_app(tmp_path)
    with TestClient(app) as client:
        url = "/api/terminal/1/ws?proto=ssh"
        headers = {"Authorization": "Bearer t", "Origin": "http://testserver"}
        msg = first_message(client, url, headers=headers)
        assert isinstance(msg, dict)


def test_unknown_device(tmp_path):
    app = make_app(tmp_path)
    with TestClient(app) as client:
        url = "/api/terminal/999/ws?proto=ssh"
        msg = first_message(client, url)
        assert msg["code"] == "device"


def test_public_ip_policy(tmp_path):
    app = make_app(tmp_path)
    with TestClient(app) as client:
        url = "/api/terminal/5/ws?proto=ssh"
        msg = first_message(client, url)
        assert msg["code"] == "policy"


def test_ssh_port_missing(tmp_path):
    app = make_app(tmp_path)
    with TestClient(app) as client:
        url = "/api/terminal/3/ws?proto=ssh"
        msg = first_message(client, url)
        assert msg["code"] == "port"


def test_telnet_port_missing(tmp_path):
    app = make_app(tmp_path)
    with TestClient(app) as client:
        url = "/api/terminal/1/ws?proto=telnet"
        msg = first_message(client, url)
        assert msg["code"] == "port"


def test_unknown_proto(tmp_path):
    app = make_app(tmp_path)
    with TestClient(app) as client:
        url = "/api/terminal/1/ws?proto=rdp"
        msg = first_message(client, url)
        assert msg["code"] == "proto"


def test_auth_message_no_username(tmp_path):
    app = make_app(tmp_path)
    with TestClient(app) as client:
        url = "/api/terminal/1/ws?proto=ssh"
        msg = first_message(client, url, send={"type": "auth", "password": "pw", "cols": 80, "rows": 24})
        assert msg["code"] == "auth_message"


def test_auth_message_bad_type(tmp_path):
    app = make_app(tmp_path)
    with TestClient(app) as client:
        url = "/api/terminal/1/ws?proto=ssh"
        msg = first_message(client, url, send={"type": "x"})
        assert msg["code"] == "auth_message"


def test_auth_failed(tmp_path):
    app = make_app(tmp_path)
    FakeBackend.connect_error = AuthFailed("authentication failed")
    with TestClient(app) as client:
        url = "/api/terminal/1/ws?proto=ssh"
        msg = first_message(client, url)
        assert msg["code"] == "auth"
        assert msg["message"] == "authentication failed"
        assert "pw" not in json.dumps(msg)


def test_connect_failed(tmp_path):
    app = make_app(tmp_path)
    FakeBackend.connect_error = ConnectFailed("down")
    with TestClient(app) as client:
        url = "/api/terminal/1/ws?proto=ssh"
        msg = first_message(client, url)
        assert msg["code"] == "connect"
        assert msg["message"] == "down"


def test_hostkey_mismatch(tmp_path):
    app = make_app(tmp_path)
    FakeBackend.connect_error = HostKeyMismatch("SHA256:a", "SHA256:b")
    with TestClient(app) as client:
        url = "/api/terminal/1/ws?proto=ssh"
        msg = first_message(client, url)
        assert msg["type"] == "hostkey_mismatch"
        assert msg["expected"] == "SHA256:a"
        assert msg["actual"] == "SHA256:b"


def test_terminal_off(tmp_path):
    app = make_app(tmp_path, {"NETLENS_TERMINAL": "off"})
    with TestClient(app) as client:
        url = "/api/terminal/1/ws?proto=ssh"
        with pytest.raises(Exception):
            with client.websocket_connect(url, headers=AUTH) as ws:
                ws.receive_text()
        resp = client.delete("/api/devices/1/hostkey", headers=AUTH)
        assert resp.status_code == 404