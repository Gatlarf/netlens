import json

import pytest

from app import identify, licence
from app.db import connect, init_db


@pytest.fixture
def conn(tmp_path, monkeypatch):
    c = connect(tmp_path / "id.db")
    init_db(c)
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, vendor, device_type, online, first_seen, last_seen) VALUES (1, 'aa:bb:cc:dd:ee:01', '192.168.1.40', 'esp-1234', 'Hikvision Digital', 'unknown', 1, '2026-10-01T00:00:00Z', '2026-10-17T00:00:00Z')")
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, vendor, device_type, online, first_seen, last_seen) VALUES (2, 'aa:bb:cc:dd:ee:02', '192.168.1.41', 'nas', 'Synology', 'nas', 1, '2026-10-01T00:00:00Z', '2026-10-17T00:00:00Z')")
    c.execute("INSERT INTO ports (device_id, proto, port, state, service, updated) VALUES (1, 'tcp', 554, 'open', 'rtsp', '2026-10-17T00:00:00Z')")
    c.commit()
    yield c
    c.close()


def test_only_devices_without_a_type_are_listed(conn):
    assert [d["id"] for d in identify.unknown_devices(conn)] == [1]


def test_the_rules_come_first_and_work_without_a_model(conn):
    out = identify.suggest(conn, 1)
    assert out["model"] is None and out["rules"]["type"] == "camera" and out["clues"] and out["facts"]["open_ports"][0]["port"] == 554
    assert identify.suggest(conn, 99) is None


def test_a_model_answer_is_checked_and_the_names_are_hidden_on_the_way_out(conn):
    seen = {}

    def ask(messages):
        seen["text"] = messages[1]["content"]
        return 'Sure:\n{"type": "camera", "name": "Garden camera", "confidence": "high", "reason": "RTSP port and a camera vendor"}'

    out = identify.suggest(conn, 1, ask=ask)
    assert out["model"] == {"type": "camera", "name": "Garden camera", "confidence": "high", "reason": "RTSP port and a camera vendor"}
    assert "esp-1234" not in seen["text"] and "192.168" not in seen["text"]
    assert identify.suggest(conn, 1, ask=lambda m: '{"type": "toaster"}')["model"] is None             # not an allowed type
    assert identify.suggest(conn, 1, ask=lambda m: "no idea")["model"] is None
