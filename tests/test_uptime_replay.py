from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import ago, connect, get_or_create_device
from app.main import create_app


def _client(tmp_path):
    db = tmp_path / "t.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db)
    client = TestClient(app, headers={"Authorization": "Bearer secret"})
    client.__enter__()
    return client, connect(db)


def _check(conn, device, hours_ago, up):
    conn.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (?, ?, ?, NULL)", (device, ago(hours=hours_ago), up))
    conn.commit()


def test_replay_returns_the_start_state_and_only_the_changes(tmp_path):
    client, conn = _client(tmp_path)
    a = get_or_create_device(conn, "aa:00:00:00:00:01", "10.0.0.1", ago(hours=30))
    b = get_or_create_device(conn, "aa:00:00:00:00:02", "10.0.0.2", ago(hours=30))
    for hrs, up in ((30, 1), (20, 1), (10, 0), (9, 0), (5, 1), (1, 1)):     # a: up, up, down, down, up, up: two changes after the first check in the window
        _check(conn, a, hrs, up)
    _check(conn, b, 3, 1)
    _check(conn, a, 40, 0)                                                   # outside the window: ignored
    body = client.get("/api/uptime/replay?hours=24").json()
    mine = [c for c in body["changes"] if c["id"] == a]
    assert [(c["up"], c["initial"]) for c in mine] == [(True, True), (False, False), (True, False)]
    assert mine[0]["ts"] == body["from"]
    assert [c for c in body["changes"] if c["id"] == b] == [{"id": b, "ts": body["from"], "up": True, "initial": True}]
    assert client.get("/api/uptime/replay?hours=0").status_code == 422
    assert client.get("/api/uptime/replay?hours=500").status_code == 422
