import gzip
import json

import pytest
from fastapi.testclient import TestClient

from app import central, probes, tsdb
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app

AUTH = {"Authorization": "Bearer secret"}
NOW = "2026-03-10T12:00:00Z"
LATER = "2026-03-10T12:01:00Z"


def device(key, name, online=True, **kw):
    return {"key": key, "mac": key if ":" in key else None, "ip": kw.get("ip", "192.168.1.10"), "name": name, "vendor": kw.get("vendor", "Acme"), "type": kw.get("type", "pc"),
            "online": online, "always_on": kw.get("always_on", False), "ports": kw.get("ports", [22]), "first_seen": NOW, "last_seen": NOW}


def service(key, name, state="up"):
    return {"key": key, "name": name, "kind": "http", "target": "http://192.168.1.2/", "state": state, "ms": 12.0, "detail": "HTTP 200" if state == "up" else "timed out",
            "since": NOW, "checked": NOW}


@pytest.fixture
def conn(tmp_path):
    tsdb.forget_all()
    c = connect(tmp_path / "t.db")
    init_db(c)
    yield c
    c.close()
    tsdb.forget_all()


def make(conn, name="Branch office"):
    probe, token = probes.create(conn, name)
    return conn.execute("SELECT * FROM probes WHERE id = ?", (probe["id"],)).fetchone(), token


def kinds(conn):
    return [r["kind"] for r in conn.execute("SELECT kind FROM events ORDER BY id")]


def test_token_is_stored_as_a_hash(conn):
    row, token = make(conn)
    assert token.startswith("nlp_") and token not in row["token_hash"] and row["token_hash"] == probes.hash_token(token)
    assert probes.find_by_token(conn, token)["id"] == row["id"]
    assert probes.find_by_token(conn, "nlp_wrong") is None and probes.find_by_token(conn, "x") is None
    with pytest.raises(probes.ProbeError):
        probes.create(conn, "branch OFFICE")
    new = probes.rotate_token(conn, row["id"])
    assert probes.find_by_token(conn, token) is None and probes.find_by_token(conn, new)


def test_first_report_is_the_baseline_and_changes_raise_events(conn):
    row, _ = make(conn)
    first = {"devices": [device("aa:00:00:00:00:01", "printer"), device("aa:00:00:00:00:02", "nas", always_on=True)], "services": [service("svc:1", "Web")]}
    result = probes.ingest(conn, row, first, now=NOW)
    assert result["devices"] == 2 and kinds(conn) == []                   # nothing is "new" on the first report
    row = conn.execute("SELECT * FROM probes WHERE id = ?", (row["id"],)).fetchone()
    second = {"devices": [device("aa:00:00:00:00:01", "printer", online=False), device("aa:00:00:00:00:02", "nas", always_on=True), device("aa:00:00:00:00:03", "phone")],
              "services": [service("svc:1", "Web", "down")]}
    probes.ingest(conn, row, second, now=LATER)
    assert set(kinds(conn)) == {"remote_offline", "remote_new", "remote_service_down"}
    details = [r["detail"] for r in conn.execute("SELECT detail FROM events")]
    assert any("Branch office: printer (192.168.1.10) went offline" == d for d in details)
    assert any("Web" in d and "timed out" in d for d in details)
    p = probes.get(conn, row["id"])
    assert p["devices"] == {"total": 3, "online": 2, "core_down": 0} and p["services"] == {"total": 1, "down": 1} and p["state"] in ("connected", "silent")


def test_health_problems_are_diffed(conn):
    row, _ = make(conn)
    probes.ingest(conn, row, {"devices": [device("aa:00:00:00:00:01", "nas")], "problems": []}, now=NOW)
    row = conn.execute("SELECT * FROM probes").fetchone()
    problem = {"device_key": "aa:00:00:00:00:01", "device": "nas", "metric": "disk_pct", "label": "/data", "level": "warning", "value": 91.0, "title": "Disk full", "unit": "%", "since": NOW}
    probes.ingest(conn, row, {"devices": [device("aa:00:00:00:00:01", "nas")], "problems": [problem]}, now=LATER)
    assert kinds(conn) == ["remote_metric_warning"]
    row = conn.execute("SELECT * FROM probes").fetchone()
    probes.ingest(conn, row, {"devices": [device("aa:00:00:00:00:01", "nas")], "problems": [problem]}, now="2026-03-10T12:02:00Z")
    assert kinds(conn) == ["remote_metric_warning"]                       # the same problem is not announced twice
    row = conn.execute("SELECT * FROM probes").fetchone()
    probes.ingest(conn, row, {"devices": [device("aa:00:00:00:00:01", "nas")], "problems": []}, now="2026-03-10T12:03:00Z")
    assert kinds(conn)[-1] == "remote_metric_ok"


def test_measurements_are_stored_for_the_remote_device(conn):
    import time

    row, _ = make(conn)
    t = int(time.time()) - 60
    payload = {"devices": [device("aa:00:00:00:00:01", "nas")], "services": [service("svc:1", "Web")],
               "samples": [{"ts": t, "entity": "device", "ref": "aa:00:00:00:00:01", "metric": "cpu_pct", "label": "", "value": 12.5, "unit": "%"},
                           {"ts": t, "entity": "service", "ref": "svc:1", "metric": "response_ms", "label": "", "value": 9.0, "unit": "ms"},
                           {"ts": t, "entity": "device", "ref": "unknown", "metric": "cpu_pct", "value": 1},
                           {"ts": t - 10 * 86400, "entity": "device", "ref": "aa:00:00:00:00:01", "metric": "cpu_pct", "value": 1},
                           {"ts": t, "entity": "device", "ref": "aa:00:00:00:00:01", "metric": "x", "value": "bad"}]}
    probes.ingest(conn, row, payload, now=NOW)
    dev_id = conn.execute("SELECT id FROM remote_devices").fetchone()[0]
    svc_id = conn.execute("SELECT id FROM remote_services").fetchone()[0]
    store = tsdb.for_conn(conn)
    assert store.latest("remote", dev_id, "cpu_pct") == (t, 12.5)
    assert store.latest("remote_service", svc_id, "response_ms") == (t, 9.0)
    assert len(store.metrics_of("remote", dev_id)) == 1                    # the unknown reference, old and bad samples were dropped


def test_a_device_the_probe_dropped_is_removed_with_its_graphs(conn):
    row, _ = make(conn)
    probes.ingest(conn, row, {"devices": [device("aa:00:00:00:00:01", "a"), device("aa:00:00:00:00:02", "b")]}, now=NOW)
    row = conn.execute("SELECT * FROM probes").fetchone()
    probes.ingest(conn, row, {"devices": [device("aa:00:00:00:00:01", "a")]}, now=LATER)
    assert [r["name"] for r in conn.execute("SELECT name FROM remote_devices")] == ["a"]


def test_garbage_is_ignored_not_trusted(conn):
    row, _ = make(conn)
    probes.ingest(conn, row, {"devices": ["x", None, {"key": ""}, {"key": "k", "name": "n" * 500, "ports": [1, 70000, "x", True]}], "services": 5, "problems": [1, {"level": "x"}]}, now=NOW)
    d = conn.execute("SELECT * FROM remote_devices").fetchone()
    assert len(d["name"]) == 100 and json.loads(d["ports"]) == [1]
    with pytest.raises(probes.ProbeError):
        probes.ingest(conn, row, ["not", "an", "object"], now=NOW)


def test_silent_probe_is_reported_once_and_recovers(conn):
    import calendar
    import time

    row, _ = make(conn)
    probes.ingest(conn, row, {"devices": [device("aa:00:00:00:00:01", "a")]}, now=NOW)
    t0 = calendar.timegm(time.strptime(NOW, "%Y-%m-%dT%H:%M:%SZ"))
    assert probes.check_silent(conn, t0 + 60) == []
    assert probes.check_silent(conn, t0 + 3600) == ["Branch office"]
    assert probes.check_silent(conn, t0 + 7200) == []                      # once
    row = conn.execute("SELECT * FROM probes").fetchone()
    probes.ingest(conn, row, {"devices": [device("aa:00:00:00:00:01", "a")]}, now=LATER)
    assert kinds(conn) == ["probe_offline", "probe_online"]


def test_delete_removes_everything(conn):
    row, _ = make(conn)
    probes.ingest(conn, row, {"devices": [device("aa:00:00:00:00:01", "a")], "services": [service("svc:1", "w")]}, now=NOW)
    probes.delete(conn, row["id"])
    for table in ("probes", "remote_devices", "remote_services"):
        assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


# ------------------------------------------------------------------ the HTTP side
@pytest.fixture
def client(tmp_path):
    tsdb.forget_all()
    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app, headers=AUTH) as tc:
        yield tc
    tsdb.forget_all()


def test_admin_flow_and_push(client):
    r = client.post("/api/probes", json={"name": "Holiday house"})
    assert r.status_code == 201
    token, pid = r.json()["token"], r.json()["probe"]["id"]
    assert client.post("/api/probes", json={"name": "Holiday house"}).status_code == 422
    anon = TestClient(client.app)                                         # the probe: no session, only its token
    body = gzip.compress(json.dumps({"version": "0.4.0", "devices": [device("aa:00:00:00:00:01", "tv")], "services": []}).encode())
    assert anon.post("/api/probe/push", content=body, headers={"Authorization": "Bearer nope", "Content-Encoding": "gzip"}).status_code == 401
    ok = anon.post("/api/probe/push", content=body, headers={"Authorization": f"Bearer {token}", "Content-Encoding": "gzip", "Content-Type": "application/json"})
    assert ok.status_code == 200 and ok.json()["devices"] == 1
    detail = client.get(f"/api/probes/{pid}").json()
    assert detail["probe"]["state"] == "connected" and detail["probe"]["version"] == "0.4.0" and detail["devices"][0]["name"] == "tv"
    assert "token" not in json.dumps(client.get("/api/probes").json())
    # a new token locks the old one out
    new = client.post(f"/api/probes/{pid}/token").json()["token"]
    assert anon.post("/api/probe/push", json={"devices": []}, headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert anon.post("/api/probe/push", json={"devices": []}, headers={"Authorization": f"Bearer {new}"}).status_code == 200
    # paused: refused
    client.patch(f"/api/probes/{pid}", json={"enabled": False})
    assert anon.post("/api/probe/push", json={"devices": []}, headers={"Authorization": f"Bearer {new}"}).status_code == 401
    assert client.delete(f"/api/probes/{pid}").status_code == 200


def test_the_push_endpoint_does_not_open_the_rest(client):
    anon = TestClient(client.app)
    assert anon.get("/api/probes").status_code == 401
    assert anon.get("/api/devices").status_code == 401


def test_bad_bodies(client):
    token = client.post("/api/probes", json={"name": "x"}).json()["token"]
    anon = TestClient(client.app)
    h = {"Authorization": f"Bearer {token}"}
    assert anon.post("/api/probe/push", content=b"not json", headers=h).status_code == 400
    assert anon.post("/api/probe/push", content=b"not gzip", headers={**h, "Content-Encoding": "gzip"}).status_code == 400
    assert anon.post("/api/probe/push", content=b"[1,2]", headers=h).status_code == 422


# ------------------------------------------------------------------ the probe's side
def test_link_validation(conn):
    assert central.set_link(conn, {"url": "https://netlens.example.com/", "token": "nlp_x", "enabled": True})["url"] == "https://netlens.example.com"
    assert central.public_link(conn)["has_token"] is True and "nlp_x" not in json.dumps(central.public_link(conn))
    assert central.set_link(conn, {"url": "http://192.168.0.5:8080"})["url"] == "http://192.168.0.5:8080"
    with pytest.raises(central.LinkError):
        central.set_link(conn, {"url": "http://example.com"})                  # plain http across the internet
    with pytest.raises(central.LinkError):
        central.set_link(conn, {"url": "ftp://x"})
    with pytest.raises(central.LinkError):
        central.set_link(conn, {"url": "https://x.example/api/probe"})
    with pytest.raises(central.LinkError):
        central.set_link(conn, {"url": "https://x.example", "interval_s": 3})
    with pytest.raises(central.LinkError):
        central.set_link(conn, {"url": "", "enabled": True})


def test_the_token_is_encrypted_in_the_database(conn):
    from app import vault

    central.set_link(conn, {"url": "https://netlens.example.com", "token": "nlp_topsecret", "enabled": True})
    raw = conn.execute("SELECT value FROM settings WHERE key = 'central.link'").fetchone()[0]
    assert vault.is_encrypted(raw) and "topsecret" not in raw


def test_snapshot_and_a_real_round_trip(tmp_path):
    """A remote Netlens builds its report and a central one takes it in, through the real endpoint."""
    tsdb.forget_all()
    central_path, remote_path = tmp_path / "central.db", tmp_path / "remote" / "r.db"
    remote_path.parent.mkdir()
    c = connect(central_path)
    init_db(c)
    c.close()
    r = connect(remote_path)
    init_db(r)
    r.execute("INSERT INTO devices (id, mac, primary_ip, hostname, vendor, online, always_on, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.1.0.5', 'nas', 'Synology', 1, 1, ?, ?)", (NOW, NOW))
    r.execute("INSERT INTO ports (device_id, proto, port, state, updated) VALUES (1, 'tcp', 445, 'open', ?)", (NOW,))
    r.execute("INSERT INTO service_checks (id, device_id, name, kind, host, port, interval_s, timeout_s, last_up, last_ms, last_ts, created) VALUES (1, 1, 'SMB', 'tcp', '10.1.0.5', 445, 60, 5, 1, 4.0, ?, ?)", (NOW, NOW))
    r.commit()
    import time

    tsdb.for_conn(r).record([("device", 1, "rtt_ms", 3.5, "", "ms"), ("service", 1, "response_ms", 4.0, "", "ms")], ts=int(time.time()) - 30)
    snap = central.snapshot(r, int(time.time()) - 600)
    assert snap["devices"][0]["key"] == "aa:00:00:00:00:01" and snap["devices"][0]["ports"] == [445] and snap["devices"][0]["always_on"] is True
    assert snap["services"][0]["state"] == "up" and snap["services"][0]["key"] == "svc:1"
    assert {(s["entity"], s["metric"]) for s in snap["samples"]} == {("device", "rtt_ms"), ("service", "response_ms")}
    r.close()

    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=central_path)
    with TestClient(app, headers=AUTH) as client:
        token = client.post("/api/probes", json={"name": "Remote"}).json()["token"]
        sent = []

        def fake_send(url, tok, payload, timeout=25.0):
            sent.append(payload)
            anon = TestClient(app)
            body = gzip.compress(json.dumps(payload).encode())
            resp = anon.post("/api/probe/push", content=body, headers={"Authorization": f"Bearer {tok}", "Content-Encoding": "gzip"})
            if resp.status_code != 200:
                raise central.LinkError(resp.text)
            return resp.json()

        import app.central as cm

        orig = cm.send
        cm.send = fake_send
        try:
            rc = connect(remote_path)
            central.set_link(rc, {"url": "https://central.example", "token": token, "enabled": True})
            rc.close()
            status = central.push_once(str(remote_path))
        finally:
            cm.send = orig
        assert status["ok"] and status["devices"] == 1
        probes_list = client.get("/api/probes").json()
        assert probes_list[0]["devices"]["total"] == 1 and probes_list[0]["services"]["total"] == 1
        detail = client.get(f"/api/probes/{probes_list[0]['id']}").json()
        did = detail["devices"][0]["id"]
        graph = client.get(f"/api/timeseries/remote/{did}/rtt_ms?range=24h").json()
        assert graph["points"] and graph["points"][0][1] == 3.5
    tsdb.forget_all()


def test_unknown_metric_names_are_not_stored(conn):
    import time

    row, _ = make(conn)
    t = int(time.time()) - 30
    probes.ingest(conn, row, {"devices": [device("aa:00:00:00:00:01", "a")],
                              "samples": [{"ts": t, "entity": "device", "ref": "aa:00:00:00:00:01", "metric": "made_up", "value": 1},
                                          {"ts": t, "entity": "device", "ref": "aa:00:00:00:00:01", "metric": "cpu_pct", "value": 2}]}, now=NOW)
    dev = conn.execute("SELECT id FROM remote_devices").fetchone()[0]
    assert [m["metric"] for m in tsdb.for_conn(conn).metrics_of("remote", dev)] == ["cpu_pct"]


def test_a_gzip_bomb_is_refused(client):
    import zlib

    token = client.post("/api/probes", json={"name": "bomb"}).json()["token"]
    c = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    bomb = c.compress(b"0" * (64 * 1024 * 1024)) + c.flush()
    assert len(bomb) < 12 * 1024 * 1024
    anon = TestClient(client.app)
    r = anon.post("/api/probe/push", content=bomb, headers={"Authorization": f"Bearer {token}", "Content-Encoding": "gzip"})
    assert r.status_code == 413
