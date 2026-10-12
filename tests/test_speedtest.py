import io
import json
import time
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app import auth, iperf, speedtest
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app


@pytest.fixture
def env(tmp_path):
    settings = load_settings({"NETLENS_DATA_DIR": str(tmp_path), "NETLENS_TOKEN": "tok"})
    app = create_app(settings)
    with TestClient(app, headers={"Authorization": "Bearer tok"}) as c:
        yield c, app, tmp_path / "netlens.db"
    speedtest.PROGRESS.finish()


def server_doc(reverse=False, bidir=False):
    end = {"sum_sent": {"bits_per_second": 940e6, "retransmits": 3}, "sum_received": {"bits_per_second": 935e6, "seconds": 10.0}}
    return {"start": {"connected": [{"remote_host": "192.168.0.50"}], "test_start": {"protocol": "TCP", "num_streams": 4, "reverse": int(reverse), "bidir": int(bidir), "duration": 10}}, "end": end}


# ---- iperf3 output ----
def test_server_result_forward_reverse_and_bidirectional():
    fwd = iperf.parse_server_result(server_doc())
    assert fwd["client"] == "192.168.0.50" and fwd["up"] == pytest.approx(935) and fwd["down"] is None and fwd["detail"]["streams"] == 4
    rev = iperf.parse_server_result(server_doc(reverse=True))
    assert rev["down"] == pytest.approx(940) and rev["up"] is None
    both = iperf.parse_server_result(server_doc(bidir=True))
    assert both["up"] == pytest.approx(935) and both["down"] == pytest.approx(940)


def test_server_result_error_and_junk():
    err = iperf.parse_server_result({"start": {"connected": [{"remote_host": "10.0.0.2"}]}, "error": "the client has terminated"})
    assert err["ok"] is False and "terminated" in err["error"]
    assert iperf.parse_server_result({"hello": 1}) is None and iperf.parse_server_result([]) is None


def test_server_reads_one_json_document_per_finished_test(env):
    _, app, db = env
    server = iperf.Server(str(db))
    text = json.dumps(server_doc(), indent=2) + "\n" + json.dumps(server_doc(reverse=True), indent=2) + "\n"
    server._read(type("P", (), {"stdout": io.StringIO(text)})())
    conn = connect(db)
    rows = speedtest.history(conn, "iperf-in")
    assert len(rows) == 2 and {r["target"] for r in rows} == {"192.168.0.50"}
    assert server.last_test["client"] == "192.168.0.50"


@pytest.mark.parametrize("host,ok", [("192.168.0.5", True), ("nas.home", True), ("fe80::1", True), ("-oProxyCommand=x", False), ("", False), ("a b", False), ("x;y", False)])
def test_host_validation_blocks_option_injection(host, ok):
    assert iperf.valid_host(host) is ok


def test_client_runs_both_directions_and_reports_errors(monkeypatch):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        reverse = "-R" in cmd
        doc = {"end": {"sum_sent": {"bits_per_second": 900e6, "retransmits": 2}, "sum_received": {"bits_per_second": 880e6 if reverse else 899e6}}}
        return type("R", (), {"stdout": json.dumps(doc), "stderr": ""})()

    monkeypatch.setattr(iperf, "available", lambda: "/usr/bin/iperf3")
    monkeypatch.setattr(iperf.subprocess, "run", fake_run)
    r = iperf.run_client("192.168.0.9", 5201, 5, "both", 2)
    assert r["up"] == pytest.approx(900) and r["down"] == pytest.approx(880) and len(calls) == 2 and "-R" in calls[1]
    monkeypatch.setattr(iperf.subprocess, "run", lambda cmd, **kw: type("R", (), {"stdout": json.dumps({"error": "unable to connect to server: Connection refused"}), "stderr": ""})())
    with pytest.raises(RuntimeError, match="Connection refused"):
        iperf.run_client("192.168.0.9", 5201, 5, "up", 1)
    with pytest.raises(ValueError):
        iperf.run_client("-x", 5201, 5, "up", 1)


# ---- settings and the schedule ----
def test_schedule_validation_and_due(tmp_path):
    conn = connect(tmp_path / "x.db")
    init_db(conn)
    assert speedtest.due(conn) is False
    speedtest.set_schedule(conn, True, 6)
    assert speedtest.due(conn) is True                                    # never run
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    speedtest.record(conn, "internet", "Cloudflare", down=100, up=10, latency=5, jitter=1, now=now)
    assert speedtest.due(conn) is False
    with pytest.raises(ValueError):
        speedtest.set_schedule(conn, True, 5)
    with pytest.raises(ValueError):
        speedtest.set_iperf_settings(conn, True, 70000)


def test_prune_keeps_the_newest_rows(tmp_path, monkeypatch):
    conn = connect(tmp_path / "x.db")
    init_db(conn)
    monkeypatch.setattr(speedtest, "KEEP_ROWS", 3)
    for i in range(6):
        speedtest.record(conn, "browser", "x", down=i)
    speedtest.prune(conn)
    assert [r["down_mbps"] for r in speedtest.history(conn)] == [5, 4, 3]


# ---- the API ----
def test_overview_and_browser_endpoints(env):
    c, _, _ = env
    data = c.get("/api/speedtest").json()
    assert data["current"] is None and data["internet"]["schedule"]["enabled"] is False and data["history"] == []
    assert data["iperf"]["configured_port"] == 5201 and "addresses" in data["iperf"]
    r = c.get("/api/speedtest/down?bytes=1000000")
    assert r.status_code == 200 and len(r.content) == 1000000 and r.headers["cache-control"] == "no-store"
    assert c.get("/api/speedtest/down?bytes=999999999").status_code == 422
    assert c.post("/api/speedtest/up", content=b"x" * 300000).json() == {"bytes": 300000}
    assert c.get("/api/speedtest/ping").status_code == 200
    assert c.post("/api/speedtest/browser", json={"down_mbps": 300, "up_mbps": 100, "latency_ms": 3, "jitter_ms": 0.5, "label": "kitchen"}).status_code == 201
    row = c.get("/api/speedtest").json()["history"][0]
    assert row["kind"] == "browser" and row["down_mbps"] == 300 and row["detail"]["label"] == "kitchen"
    assert c.post("/api/speedtest/browser", json={"down_mbps": -1}).status_code == 422
    assert c.delete("/api/speedtest/history").status_code == 200 and c.get("/api/speedtest").json()["history"] == []


def test_internet_test_runs_in_the_background_and_is_stored(env, monkeypatch):
    c, _, _ = env

    def fake(progress, seconds=8):
        progress.update(phase="download", live_mbps=123.4)
        time.sleep(0.4)
        return {"down": 420.0, "up": 40.0, "latency": 9.0, "jitter": 1.0, "detail": {"server": "Brussels", "isp": "Test ISP"}}

    monkeypatch.setattr(speedtest, "run_internet_test", fake)
    assert c.post("/api/speedtest/internet").status_code == 202
    assert c.post("/api/speedtest/internet").status_code == 409                 # one at a time
    assert c.post("/api/speedtest/iperf/run", json={"host": "10.0.0.2"}).status_code in (409, 202)
    for _ in range(40):
        if c.get("/api/speedtest/status").json()["current"] is None:
            break
        time.sleep(0.1)
    last = c.get("/api/speedtest").json()["internet"]["last"]
    assert last["down_mbps"] == 420.0 and last["detail"]["isp"] == "Test ISP"


def test_failed_internet_test_is_recorded(env, monkeypatch):
    c, _, _ = env
    monkeypatch.setattr(speedtest, "run_internet_test", lambda progress, seconds=8: (_ for _ in ()).throw(OSError("Could not reach the test server.")))
    c.post("/api/speedtest/internet")
    for _ in range(40):
        if c.get("/api/speedtest/status").json()["current"] is None:
            break
        time.sleep(0.1)
    row = c.get("/api/speedtest").json()["history"][0]
    assert row["ok"] is False and "reach" in row["error"]


def test_iperf_endpoints_validate_and_need_the_program(env, monkeypatch):
    c, _, _ = env
    monkeypatch.setattr(iperf, "available", lambda: None)
    assert c.post("/api/speedtest/iperf/run", json={"host": "10.0.0.2"}).status_code == 409
    assert c.put("/api/speedtest/iperf/server", json={"enabled": True, "port": 5201}).status_code == 409      # not installed: switched back off
    assert c.get("/api/speedtest").json()["iperf"]["enabled"] is False
    monkeypatch.setattr(iperf, "available", lambda: "/usr/bin/iperf3")
    assert c.post("/api/speedtest/iperf/run", json={"host": "-oProxyCommand=x"}).status_code == 422
    assert c.post("/api/speedtest/iperf/run", json={"host": "10.0.0.2", "seconds": 1}).status_code == 422
    assert c.put("/api/speedtest/schedule", json={"enabled": True, "every_hours": 7}).status_code == 422
    assert c.put("/api/speedtest/schedule", json={"enabled": True, "every_hours": 12}).json() == {"enabled": True, "every_hours": 12}


def test_viewers_may_test_from_their_device_but_not_run_server_side_tests():
    for path in ("/api/speedtest", "/api/speedtest/status", "/api/speedtest/ping", "/api/speedtest/down"):
        assert auth.VIEWER_READABLE.match(path), path
    assert "/api/speedtest/up" in auth.VIEWER_MAY_POST and "/api/speedtest/browser" in auth.VIEWER_MAY_POST
    assert not any(p in auth.VIEWER_MAY_POST for p in ("/api/speedtest/internet", "/api/speedtest/iperf/run", "/api/speedtest/iperf/server"))
    assert not auth.VIEWER_READABLE.match("/api/speedtest/history")


def test_demo_has_speed_history_and_blocks_server_side_tests(tmp_path):
    settings = load_settings({"NETLENS_DATA_DIR": str(tmp_path), "NETLENS_DEMO": "on"})
    with TestClient(create_app(settings)) as c:
        c.post("/api/login", json={"username": "demo", "password": "netlens-demo"})
        data = c.get("/api/speedtest").json()
        kinds = {r["kind"] for r in data["history"]}
        assert {"internet", "iperf-in"} <= kinds and data["internet"]["last"]["down_mbps"] > 100 and data["iperf"]["running"] is True
        assert c.post("/api/speedtest/internet").status_code == 403
        assert c.post("/api/speedtest/up", content=b"x" * 1000).status_code == 200          # the browser test only measures


# ---- statistics, summary, metrics ----
NOW = "2026-10-12T12:00:00Z"


@pytest.fixture
def filled(tmp_path):
    conn = connect(tmp_path / "x.db")
    init_db(conn)
    speedtest.record(conn, "internet", "Cloudflare", down=400, up=40, latency=10, jitter=1, detail={"server": "Brussels", "isp": "ISP"}, now="2026-10-10T12:00:00Z")
    speedtest.record(conn, "internet", "Cloudflare", ok=False, error="down", now="2026-10-11T12:00:00Z")
    speedtest.record(conn, "internet", "Cloudflare", down=500, up=50, latency=12, jitter=2, detail={"server": "Brussels", "isp": "ISP"}, now="2026-10-12T06:00:00Z")
    speedtest.record(conn, "iperf-in", "192.168.0.5", up=930, now="2026-10-12T07:00:00Z")
    speedtest.record(conn, "browser", "192.168.0.9", down=300, up=100, latency=4, detail={"label": "kitchen"}, now="2026-10-12T08:00:00Z")
    return conn


def test_summary_block(filled):
    s = speedtest.summary(filled, NOW)
    assert s["total"] == 3 and s["last_ok"] is True and s["failed_24h"] == 1
    assert s["internet"]["down_mbps"] == 500 and s["internet"]["age_s"] == 6 * 3600 and s["internet"]["isp"] == "ISP"
    assert s["avg_down_7d"] == 450 and s["tests_7d"] == 2 and s["iperf"]["up_mbps"] == 930
    empty = connect(":memory:")
    init_db(empty)
    assert speedtest.summary(empty, NOW)["internet"] is None and speedtest.summary(empty, NOW)["total"] == 0


def test_stats_block(filled):
    s = speedtest.stats(filled, NOW, 7)
    assert s["tests"] == 3 and s["failed"] == 1 and s["down"] == {"avg": 450.0, "min": 400.0, "max": 500.0}
    assert [p["down"] for p in s["series"]] == [400, 500] and s["browser"][0]["label"] == "kitchen" and s["iperf"][0]["target"] == "192.168.0.5"
    assert speedtest.stats(filled, NOW, 1)["tests"] == 2          # a 24 hour window: yesterday noon's failure and this morning's test


def test_metrics_and_summary_endpoints_carry_the_speed(env):
    from app.metrics import render_metrics

    c, _, db = env
    conn = connect(db)
    speedtest.record(conn, "internet", "Cloudflare", down=450, up=45, latency=11, jitter=1.5)
    text = render_metrics(conn)
    assert "netlens_speedtest_download_bits_per_second 4.5e+08" in text and "netlens_speedtest_latency_seconds 0.011" in text and "netlens_speedtest_last_ok 1" in text
    assert c.get("/api/stats/summary").json()["speed"]["internet"]["down_mbps"] == 450
    assert c.get("/api/stats?range=7d").json()["speed"]["tests"] == 1
