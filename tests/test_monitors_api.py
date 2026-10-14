import pytest
from fastapi.testclient import TestClient

from app import tsdb
from app.config import load_settings
from app.db import connect, init_db
from app.hostmetrics import snmp
from app.main import create_app
from tests.test_hostmetrics import answering, host_mib, oid_values  # noqa: F401  (the fixture is used by every test here)

AUTH = {"Authorization": "Bearer secret"}
NOW = "2026-03-10T12:00:00Z"


@pytest.fixture
def client(tmp_path):
    tsdb.forget_all()
    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'nas', 1, ?, ?)", (NOW, NOW))
    c.commit()
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app, headers=AUTH) as tc:
        yield tc
    tsdb.forget_all()


def test_no_monitor_yet(client):
    r = client.get("/api/devices/1/monitor").json()
    assert r["monitor"] is None and r["default_address"] == "10.0.0.5"
    assert client.get("/api/devices/99/monitor").status_code == 404


def test_save_show_and_delete(client):
    r = client.put("/api/devices/1/monitor", json={"method": "snmp", "community": "s3cret"})
    assert r.status_code == 200
    m = r.json()["monitor"]
    assert m["address"] == "10.0.0.5" and m["port"] == 161 and m["has_community"] is True
    assert "s3cret" not in client.get("/api/devices/1/monitor").text
    assert client.put("/api/devices/1/monitor", json={"method": "ssh", "username": "me"}).status_code == 422
    assert client.delete("/api/devices/1/monitor").status_code == 200
    assert client.get("/api/devices/1/monitor").json()["monitor"] is None
    assert client.delete("/api/devices/1/monitor").status_code == 404


def test_test_reads_without_saving(client, monkeypatch):
    mib = host_mib(community="s3cret")
    monkeypatch.setattr(snmp, "SEND", answering(mib))
    monkeypatch.setattr("asyncio.sleep", _no_sleep)
    r = client.post("/api/devices/1/monitor/test", json={"method": "snmp", "community": "s3cret"}).json()
    assert r["ok"] and {"cpu", "memory", "disk"} <= set(r["found"])
    assert any(v["metric"] == "disk_pct" and v["label"] == "/" for v in r["values"])
    assert client.get("/api/devices/1/monitor").json()["monitor"] is None            # nothing was saved
    bad = client.post("/api/devices/1/monitor/test", json={"method": "snmp", "community": "nope"}).json()
    assert bad["ok"] is False and bad["error"]


async def _no_sleep(*args, **kwargs):
    return None


def test_run_now_then_overview(client, monkeypatch):
    mib = host_mib(community="s3cret", cpu=(20, 30), disk_pct=97)
    monkeypatch.setattr(snmp, "SEND", answering(mib))
    client.put("/api/devices/1/monitor", json={"method": "snmp", "community": "s3cret"})
    r = client.post("/api/devices/1/monitor/run").json()
    assert r["ok"] and r["monitor"]["last_ok"] is True and "disk" in r["monitor"]["groups"]
    o = client.get("/api/monitors").json()
    row = o["monitors"][0]
    assert row["name"] == "nas" and row["level"] == "critical"
    assert row["latest"]["cpu"] == 25 and row["latest"]["disk"] == pytest.approx(97) and row["latest"]["disk_label"] == "/"
    assert o["problems"][0]["metric"] == "disk_pct"


def test_limits(client):
    assert client.get("/api/monitoring/limits").json()["rules"]["disk_pct"]["warn"] == 85
    r = client.put("/api/monitoring/limits", json={"rules": {"disk_pct": {"warn": 70, "crit": 90}}})
    assert r.status_code == 200 and r.json()["rules"]["disk_pct"]["warn"] == 70
    assert client.put("/api/monitoring/limits", json={"rules": {"disk_pct": {"warn": 95, "crit": 90}}}).status_code == 422


def test_viewer_sees_overview_but_cannot_change(client):
    from app.users import create_user

    c = connect(client.app.state.db_path)
    create_user(c, "view", "a-long-enough-password", "viewer")
    c.close()
    anon = TestClient(client.app)
    assert anon.post("/api/login", json={"username": "view", "password": "a-long-enough-password"}).status_code == 200
    assert anon.get("/api/monitors").status_code == 200
    assert anon.get("/api/devices/1/monitor").status_code == 403
    assert anon.put("/api/devices/1/monitor", json={"method": "snmp"}).status_code == 403


def test_dashboard_attention_lists_health_problems(client, monkeypatch):
    mib = host_mib(community="s3cret", cpu=(20, 30), disk_pct=97)
    monkeypatch.setattr(snmp, "SEND", answering(mib))
    client.put("/api/devices/1/monitor", json={"method": "snmp", "community": "s3cret"})
    client.post("/api/devices/1/monitor/run")
    texts = [a["text"] for a in client.get("/api/dashboard").json()["attention"]]
    assert any("nas" in t and "disk" in t.lower() for t in texts)


def test_prometheus_has_host_readings(client, monkeypatch):
    mib = host_mib(community="s3cret", cpu=(20, 30), disk_pct=50)
    monkeypatch.setattr(snmp, "SEND", answering(mib))
    client.put("/api/devices/1/monitor", json={"method": "snmp", "community": "s3cret"})
    client.post("/api/devices/1/monitor/run")
    text = client.get("/metrics").text
    assert 'netlens_host_cpu_ratio{device="nas"} 0.25' in text
    assert 'netlens_host_disk_used_ratio{device="nas",name="/"} 0.5' in text


def test_process_check_must_belong_to_a_device(client):
    body = {"kind": "process", "name": "nginx", "host": "10.0.0.5", "path": "nginx"}
    assert client.post("/api/service-checks", json=body).status_code == 422
    assert client.post("/api/service-checks", json={**body, "device_id": 1}).status_code == 201
    r = client.post("/api/service-checks", json={"kind": "cert", "name": "site", "host": "example.org"})
    assert r.status_code == 201 and r.json()["target"] == "certificate of example.org:443"
