import json
import socket
import threading
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app import licence, siem, tsdb
from app.config import load_settings
from app.db import add_event, connect, init_db
from app.main import create_app

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def conn(tmp_path, monkeypatch):
    tsdb.forget_all()
    c = connect(tmp_path / "s.db")
    init_db(c)
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    c.execute("INSERT INTO devices (id, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, '192.168.1.20', 'nas', 1, '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z')")
    c.commit()
    yield c
    c.close()
    tsdb.forget_all()


def test_message_format_is_rfc5424_and_safe():
    msg = siem.format_message("local3", 2, "2026-11-01T12:00:00Z", "netlens", "EVENT", {"kind": "service_down", "device": 'na"s]\\x'}, "line one\nline two\r")
    assert msg.startswith("<154>1 2026-11-01T12:00:00Z ") and "\n" not in msg and "\r" not in msg
    assert 'device="na\\"s\\]\\\\x"' in msg and msg.endswith("line one line two")


def test_severity_by_kind():
    assert siem.severity("service_down") == 2 and siem.severity("backup_failed") == 2 and siem.severity("device_offline") == 4 and siem.severity("device_new") == 6


def test_policy_is_validated(conn):
    with pytest.raises(siem.SiemError):
        siem.save_policy(conn, {"enabled": True, "host": ""})
    with pytest.raises(siem.SiemError):
        siem.save_policy(conn, {"host": "x", "port": 99999})
    with pytest.raises(siem.SiemError):
        siem.save_policy(conn, {"host": "x", "facility": "kernel"})
    assert siem.save_policy(conn, {"enabled": True, "host": "10.0.0.9", "protocol": "tcp"})["protocol"] == "tcp"


def test_only_new_lines_are_sent_and_a_failure_is_retried(conn):
    add_event(conn, "device_new", "before the switch-on", device_id=1)
    siem.save_policy(conn, {"enabled": True, "host": "10.0.0.9"})
    sent = []
    assert siem.run_once(conn, lambda p, m: sent.extend(m), NOW) == 0                         # the first look only sets the cursors
    add_event(conn, "service_down", "smb down", device_id=1)
    conn.execute("INSERT INTO audit_log (ts, user, role, ip, method, path, status, action) VALUES ('2026-11-01T12:00:00Z', 'bert', 'admin', '10.0.0.2', 'POST', '/api/x', 200, 'Changed a thing')")
    conn.commit()

    def down(policy, messages):
        raise siem.SiemError("connection refused")

    assert siem.run_once(conn, down, NOW) == 0 and siem.status(conn)["ok"] is False
    assert siem.run_once(conn, lambda p, m: sent.extend(m), NOW) == 2
    assert any("smb down" in m and 'device="nas"' in m for m in sent) and any("AUDIT" in m and 'user="bert"' in m for m in sent)
    assert siem.run_once(conn, lambda p, m: sent.extend(m), NOW) == 0 and siem.status(conn)["ok"] is True


def test_real_udp_and_tcp_delivery(conn):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(3)
    siem.save_policy(conn, {"enabled": True, "host": "127.0.0.1", "port": udp.getsockname()[1], "protocol": "udp"})
    siem.test_message(conn)
    assert b"log forwarding test" in udp.recvfrom(2000)[0]
    udp.close()
    tcp = socket.socket()
    tcp.bind(("127.0.0.1", 0))
    tcp.listen(1)
    got = []
    threading.Thread(target=lambda: got.append(tcp.accept()[0].recv(4000)), daemon=True).start()
    siem.save_policy(conn, {"host": "127.0.0.1", "port": tcp.getsockname()[1], "protocol": "tcp"})
    siem.test_message(conn)
    for _ in range(50):
        if got:
            break
        threading.Event().wait(0.05)
    assert got and got[0].endswith(b"\n") and b"TEST" in got[0]
    tcp.close()


def test_api_needs_a_licence(tmp_path):
    tsdb.forget_all()
    settings = load_settings({"NETLENS_DATA_DIR": str(tmp_path), "NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.250.0/30"})
    with TestClient(create_app(settings)) as client:
        h = {"Authorization": "Bearer secret"}
        assert client.get("/api/siem", headers=h).json()["allowed"] is False
        assert client.put("/api/siem", json={"enabled": True, "host": "x"}, headers=h).status_code == 402
        client.post("/api/licence/trial", headers=h)
        assert client.put("/api/siem", json={"enabled": True, "host": "10.0.0.9"}, headers=h).json()["policy"]["host"] == "10.0.0.9"
        assert client.put("/api/siem", json={"port": 0}, headers=h).status_code == 422
        assert client.put("/api/siem", json={"host": "127.0.0.1", "protocol": "tcp", "port": 1}, headers=h).status_code == 200
        assert client.post("/api/siem/test", headers=h).status_code == 502                   # nobody listens there
    tsdb.forget_all()
