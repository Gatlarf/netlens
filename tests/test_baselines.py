import pytest
from fastapi.testclient import TestClient

from app import baselines
from app.config import load_settings
from app.db import connect, get_or_create_device, init_db
from app.main import create_app
from app.scanner.nmap_parser import ScanHost, ScanPort
from app.scanner.store import save_scan_results

AUTH = {"Authorization": "Bearer secret"}
T = "2026-10-09T12:00:00Z"


def host(*ports):
    return ScanHost(ip="10.0.0.5", mac="aa:bb:cc:00:00:05", vendor=None, hostnames=[], via="arp", os_name=None, os_accuracy=None, os_type=None, ttl=None,
                    ports=[ScanPort("tcp", p, "open", "svc", None, None, None) for p in ports])


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    yield c
    c.close()


def kinds(conn):
    return [r["kind"] for r in conn.execute("SELECT kind FROM events WHERE kind LIKE 'port_%' ORDER BY id")]


def device_id(conn):
    return conn.execute("SELECT id FROM devices").fetchone()["id"]


def test_without_baseline_new_ports_are_plain_and_closed_ports_are_reported(conn):
    save_scan_results(conn, [host(22)], "deep", now=T)
    save_scan_results(conn, [host(22, 80)], "deep", now=T)
    save_scan_results(conn, [host(80)], "deep", now=T)
    assert kinds(conn) == ["port_opened", "port_closed"]


def test_with_baseline_unexpected_and_missing(conn):
    save_scan_results(conn, [host(22, 80)], "deep", now=T)
    did = device_id(conn)
    assert baselines.accept(conn, [did]) == 1
    save_scan_results(conn, [host(22, 80, 23)], "deep", now=T)  # 23 is new
    save_scan_results(conn, [host(22, 23)], "deep", now=T)  # 80 is gone, 23 is not in the baseline
    assert kinds(conn) == ["port_unexpected", "port_missing"]
    d = baselines.drift(conn, did)
    assert d["expected"] == ["tcp/22", "tcp/80"] and d["unexpected"] == ["tcp/23"] and d["missing"] == ["tcp/80"]


def test_quick_scan_never_reports_closed(conn):
    save_scan_results(conn, [host(22, 80)], "deep", now=T)
    save_scan_results(conn, [host(22)], "quick", now=T)
    assert "port_closed" not in kinds(conn)


def test_baseline_with_no_ports_and_clear(conn):
    save_scan_results(conn, [host()], "deep", now=T)
    did = device_id(conn)
    assert baselines.baseline_ports(conn, did) is None
    baselines.accept(conn, [did])
    assert baselines.baseline_ports(conn, did) == set()
    save_scan_results(conn, [host(8080)], "deep", now=T)
    assert kinds(conn) == ["port_unexpected"]
    baselines.clear(conn, [did])
    assert baselines.drift(conn, did) is None


def test_deleting_a_device_removes_its_baseline(conn):
    save_scan_results(conn, [host(22)], "deep", now=T)
    did = device_id(conn)
    baselines.accept(conn, [did])
    conn.execute("DELETE FROM devices WHERE id = ?", (did,))
    assert conn.execute("SELECT COUNT(*) FROM port_baselines").fetchone()[0] == 0


@pytest.fixture
def client(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app, headers=AUTH) as c:
        yield c, tmp_path / "t.db"


def test_api_accept_list_detail_and_clear(client):
    c, path = client
    conn = connect(path)
    save_scan_results(conn, [host(22)], "deep", now=T)
    did = device_id(conn)
    assert c.get("/api/devices").json()[0]["ports_drift"] is None
    assert c.post("/api/devices/baseline", json={"ids": [did]}).json() == {"changed": 1}
    assert c.get("/api/devices").json()[0]["ports_drift"] == 0
    save_scan_results(conn, [host(22, 443)], "deep", now=T)
    assert c.get("/api/devices").json()[0]["ports_drift"] == 1
    assert c.get(f"/api/devices/{did}").json()["baseline"]["unexpected"] == ["tcp/443"]
    assert c.post("/api/devices/baseline", json={"accept": False}).json() == {"changed": 1}
    assert c.get(f"/api/devices/{did}").json()["baseline"] is None
    conn.close()


def test_requires_auth(client):
    c, _ = client
    assert c.post("/api/devices/baseline", json={}, headers={"Authorization": "Bearer no"}).status_code == 401
