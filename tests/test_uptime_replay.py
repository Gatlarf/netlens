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


def test_a_viewer_can_load_what_the_hud_reads_but_a_customer_view_not_the_whole_network(tmp_path):
    from app.config import load_settings as ls
    db = tmp_path / "v.db"
    app = create_app(ls({"NETLENS_TOKEN": "secret"}), db_path=db)
    admin = {"Authorization": "Bearer secret"}
    with TestClient(app) as c:
        assert c.post("/api/users", json={"username": "vera", "password": "longenough1", "role": "viewer"}, headers=admin).status_code == 201
        viewer = TestClient(app)
        assert viewer.post("/api/login", json={"username": "vera", "password": "longenough1"}).status_code == 200
        for path in ("/api/uptime/latest", "/api/uptime/replay?hours=6", "/api/reliability", "/api/traffic?range=1h"):
            assert viewer.get(path).status_code == 200, path
        assert viewer.post("/api/scans", json={"kind": "quick"}).status_code == 403          # reading is all a viewer gets


def test_an_id_too_large_for_the_database_is_not_found_not_a_server_error(tmp_path):
    client, _ = _client(tmp_path)
    for path in ("/api/devices/99999999999999999999", "/api/devices/99999999999999999999/applications"):
        assert client.get(path).status_code == 404, path
