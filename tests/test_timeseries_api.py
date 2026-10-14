import pytest
from fastapi.testclient import TestClient

from app import tsdb
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app
from app.services import Result, record_result
from app.uptime import record_checks

AUTH = {"Authorization": "Bearer secret"}
NOW = "2026-03-10T12:00:00Z"


@pytest.fixture
def env(tmp_path):
    tsdb.forget_all()
    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'nas', 1, ?, ?)", (NOW, NOW))
    c.execute("INSERT INTO service_checks (id, device_id, name, kind, host, port, interval_s, timeout_s, created) VALUES (1, 1, 'Web', 'tcp', '10.0.0.5', 80, 60, 5, ?)", (NOW,))
    c.commit()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app, headers=AUTH) as tc:
        yield c, tc
    c.close()
    tsdb.forget_all()


def test_scan_presence_is_recorded(env):
    conn, client = env
    record_checks(conn, {1}, ["10.0.0.0/24"], now=NOW, rtts={1: 12.5})
    data = client.get("/api/timeseries/device/1").json()
    assert {s["metric"] for s in data["series"]} == {"up", "rtt_ms"}
    rtt = client.get("/api/timeseries/device/1/rtt_ms?range=24h").json()
    assert rtt["unit"] == "ms"


def test_service_result_is_recorded(env):
    conn, client = env
    check = dict(conn.execute("SELECT * FROM service_checks WHERE id = 1").fetchone())
    record_result(conn, check, Result(True, 8.0, "port open"), now=NOW)
    data = client.get("/api/timeseries/service/1").json()
    assert {s["metric"] for s in data["series"]} == {"up", "response_ms"}


def test_bad_requests(env):
    _conn, client = env
    assert client.get("/api/timeseries/banana/1").status_code == 404
    assert client.get("/api/timeseries/device/1/rtt_ms?range=2w").status_code == 422
    assert client.get("/api/timeseries/device/1/nothing").json()["points"] == []


def test_viewer_may_read_graphs(env):
    _conn, client = env
    from app.users import create_user

    c = connect(client.app.state.db_path)
    create_user(c, "view", "a-long-enough-password", "viewer")
    c.close()
    anon = TestClient(client.app)
    login = anon.post("/api/login", json={"username": "view", "password": "a-long-enough-password"})
    assert login.status_code == 200
    assert anon.get("/api/timeseries/device/1").status_code == 200


def test_deleting_a_check_forgets_its_series(env):
    conn, client = env
    check = dict(conn.execute("SELECT * FROM service_checks WHERE id = 1").fetchone())
    record_result(conn, check, Result(True, 8.0, "ok"), now=NOW)
    assert client.delete("/api/service-checks/1").status_code == 200
    assert client.get("/api/timeseries/service/1").json()["series"] == []
