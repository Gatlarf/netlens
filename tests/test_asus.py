import json

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import connect, get_or_create_device, init_db
from app.hierarchy import build_hierarchy
from app.integrations.asus_client import AsusAuthError, AsusClient, AsusError, build_snapshot, parse_onboarding
from app.integrations.asus_config import AsusConfig, is_configured, normalize_url, save_config
from app.integrations.asus_sync import apply_asus_relations, asus_after_scan, sync_now
from app.main import create_app
from app.scanner.relations import Edge
from app.scanner.relstore import delete_relation, list_relations, replace_inferred

AUTH = {"Authorization": "Bearer secret"}
MAIN, N1, N2 = "aa:00:00:00:00:10", "aa:00:00:00:00:20", "aa:00:00:00:00:30"

NODES = [
    {"alias": "Main", "model_name": "RT-AX92U", "ip": "10.0.0.1", "mac": MAIN.upper(), "re_path": "0", "ap2g": MAIN.upper(),
     "wired_mac": [N1.upper()]},
    {"alias": "Garden", "model_name": "RT-AX92U", "ip": "10.0.0.50", "mac": N1.upper(), "re_path": "1", "wired_mac": []},
    {"alias": "Attic", "model_name": "RT-AX92U", "ip": "10.0.0.60", "mac": N2.upper(), "re_path": "1", "wired_mac": []},
]
ONBOARDING = "﻿get_onboardinglist = [{}][0];\nget_cfg_clientlist = [" + json.dumps(NODES) + "];\nnext = 1;"


def _client_entry(mac, ip, wl="0", node="", online="1", name=""):
    return {"mac": mac.upper(), "ip": ip, "isWL": wl, "amesh_papMac": node.upper(), "isOnline": online, "name": name}


CLIENTS = {"get_clientlist": {
    "maclist": ["x"],
    "ClientAPILevel": "1",
    "02:00:00:00:00:01": _client_entry("02:00:00:00:00:01", "10.0.0.11", "0", "", name="wired on main"),
    "02:00:00:00:00:02": _client_entry("02:00:00:00:00:02", "10.0.0.12", "2", N1, name="wifi on garden"),
    "02:00:00:00:00:03": _client_entry("02:00:00:00:00:03", "10.0.0.13", "0", N1),
    "02:00:00:00:00:04": _client_entry("02:00:00:00:00:04", "10.0.0.14", "1", N2, online="0"),
}}


class FakeTransport:
    def __init__(self, login=None, fail_on=None):
        self.calls = []
        self.login = login if login is not None else {"asus_token": "TOK"}
        self.fail_on = fail_on

    def __call__(self, method, url, headers, data):
        path = url.split("8443", 1)[-1]
        self.calls.append((method, path, headers.get("Cookie")))
        if self.fail_on and self.fail_on in path:
            raise AsusError("boom")
        if path == "/login.cgi":
            return 200, json.dumps(self.login).encode()
        if path.startswith("/appGet.cgi"):
            return 200, json.dumps(CLIENTS).encode()
        if path == "/ajax_onboarding.asp":
            return 200, ONBOARDING.encode()
        if path == "/Logout.asp":
            return 200, b""
        return 404, b""


CFG = AsusConfig(enabled=True, url="10.0.0.1", username="u", password="pw")


def test_normalize_url_and_configured():
    assert normalize_url("192.168.0.1") == "https://192.168.0.1:8443"
    assert normalize_url("https://r.lan:9443/") == "https://r.lan:9443"
    assert normalize_url("http://192.168.0.1") == "http://192.168.0.1"
    assert normalize_url("") == ""
    for bad in ("ftp://x", "https://x/admin"):
        with pytest.raises(ValueError):
            normalize_url(bad)
    assert is_configured(CFG) and not is_configured(AsusConfig(url="x"))


def test_parse_onboarding_and_snapshot():
    nodes = parse_onboarding(ONBOARDING)
    assert [n["alias"] for n in nodes] == ["Main", "Garden", "Attic"]
    snap = build_snapshot(CLIENTS, nodes)
    assert [n["main"] for n in snap["nodes"]] == [True, False, False]
    assert snap["nodes"][0]["wired_macs"] == [N1]
    assert {c["mac"] for c in snap["clients"]} == {"02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03"}  # offline one dropped
    wifi = next(c for c in snap["clients"] if c["mac"].endswith(":02"))
    assert wifi == {"mac": "02:00:00:00:00:02", "ip": "10.0.0.12", "name": "wifi on garden", "wired": False, "band": "5 GHz", "node_mac": N1}
    assert next(c for c in snap["clients"] if c["mac"].endswith(":01"))["node_mac"] is None
    with pytest.raises(AsusError):
        parse_onboarding("nothing here")


def test_client_logs_in_reads_and_always_logs_out():
    t = FakeTransport()
    snap = AsusClient(CFG, transport=t).snapshot()
    assert len(snap["nodes"]) == 3
    assert [c[1] for c in t.calls] == ["/login.cgi", "/appGet.cgi?hook=get_clientlist()", "/ajax_onboarding.asp", "/Logout.asp"]
    assert t.calls[1][2] == "asus_token=TOK" and t.calls[0][2] is None

    t = FakeTransport(fail_on="ajax_onboarding")
    with pytest.raises(AsusError):
        AsusClient(CFG, transport=t).snapshot()
    assert t.calls[-1][1] == "/Logout.asp"  # no session left open after an error


def test_refused_login_is_one_attempt_and_no_logout():
    t = FakeTransport(login={"error_status": "3"})
    with pytest.raises(AsusAuthError) as exc:
        AsusClient(CFG, transport=t).snapshot()
    assert "username and password" in str(exc.value)
    assert [c[1] for c in t.calls] == ["/login.cgi"]

    t = FakeTransport(login={"error_status": "7"})
    with pytest.raises(AsusAuthError) as exc:
        AsusClient(CFG, transport=t).snapshot()
    assert "blocked" in str(exc.value)


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    ids = {
        "main": get_or_create_device(conn, MAIN, "10.0.0.1"),
        "garden": get_or_create_device(conn, N1, "10.0.0.50"),
        "attic": get_or_create_device(conn, None, "10.0.0.60"),  # no MAC seen: matched by IP
        "wired": get_or_create_device(conn, "02:00:00:00:00:01", "10.0.0.11"),
        "wifi": get_or_create_device(conn, "02:00:00:00:00:02", "10.0.0.12"),
        "gardenwired": get_or_create_device(conn, None, "10.0.0.13"),  # matched by IP
        "stranger": get_or_create_device(conn, "02:00:00:00:00:99", "10.0.0.99"),
    }
    conn.close()
    return path, ids


class FakeFactory:
    error = None

    def __init__(self, cfg):
        pass

    def snapshot(self):
        if FakeFactory.error:
            raise FakeFactory.error
        return build_snapshot(CLIENTS, parse_onboarding(ONBOARDING))


@pytest.fixture(autouse=True)
def _reset():
    FakeFactory.error = None


def _edges(path):
    conn = connect(path)
    try:
        return {(r["src_id"], r["dst_id"], r["kind"], r["source"], r["manual"]) for r in list_relations(conn)}
    finally:
        conn.close()


def _enable(path):
    conn = connect(path)
    save_config(conn, CFG)
    conn.close()


@pytest.mark.asyncio
async def test_sync_creates_uplinks_and_survives_reinference(db):
    path, ids = db
    _enable(path)
    result = await sync_now(str(path), client_factory=FakeFactory)
    assert result == {"nodes": 3, "clients": 3, "links": 5}
    expected = {
        (ids["garden"], ids["main"], "uplink", "asus-mesh", 0),  # node wired to the main router
        (ids["attic"], ids["main"], "uplink", "asus-mesh", 0),  # node found by IP, no wired info: below the main router
        (ids["wired"], ids["main"], "uplink", "asus-mesh", 0),  # no node = main router
        (ids["wifi"], ids["garden"], "uplink", "asus-mesh", 0),
        (ids["gardenwired"], ids["garden"], "uplink", "asus-mesh", 0),
    }
    assert _edges(path) == expected

    conn = connect(path)  # a scan wipes every non-manual edge; the hook puts them back
    replace_inferred(conn, [Edge(ids["wifi"], ids["stranger"], "gateway", "heuristic", 0.5)])
    conn.close()
    assert not expected <= _edges(path)
    await asus_after_scan(str(path))
    assert expected <= _edges(path)


@pytest.mark.asyncio
async def test_user_deleted_edge_stays_hidden(db):
    path, ids = db
    _enable(path)
    await sync_now(str(path), client_factory=FakeFactory)
    conn = connect(path)
    rel = next(r for r in list_relations(conn) if r["src_id"] == ids["wifi"])
    assert delete_relation(conn, rel["id"]) is True
    apply_asus_relations(conn)
    conn.close()
    assert not any(e[0] == ids["wifi"] for e in _edges(path))


@pytest.mark.asyncio
async def test_hierarchy_ranks_uplink_above_gateway(db):
    path, ids = db
    _enable(path)
    await sync_now(str(path), client_factory=FakeFactory)
    conn = connect(path)
    replace_inferred(conn, [Edge(ids["wifi"], ids["stranger"], "gateway", "heuristic", 0.9)])
    apply_asus_relations(conn)
    devices = [dict(r) for r in conn.execute("SELECT id, parent_mode, parent_device_id FROM devices")]
    rels = [dict(r) for r in conn.execute("SELECT src_id, dst_id, kind, source, confidence FROM relations WHERE manual >= 0")]
    conn.close()
    parent = build_hierarchy(devices, rels)[ids["wifi"]]
    assert (parent.parent_id, parent.source) == (ids["garden"], "uplink")


@pytest.mark.asyncio
async def test_failed_sync_keeps_links_and_refused_login_pauses_hook(db):
    path, ids = db
    _enable(path)
    await sync_now(str(path), client_factory=FakeFactory)
    before = _edges(path)

    FakeFactory.error = AsusError("timed out")
    assert await sync_now(str(path), client_factory=FakeFactory) == {"error": "timed out"}
    assert _edges(path) == before  # last good links kept

    FakeFactory.error = AsusAuthError("login refused")
    await sync_now(str(path), client_factory=FakeFactory)
    conn = connect(path)
    status = json.loads(conn.execute("SELECT value FROM settings WHERE key='asus_status'").fetchone()[0])
    conn.close()
    assert status["ok"] is False and status["auth_failed"] is True

    # the hook must not touch the router again, but still restores the links after a re-inference
    calls = []

    class Counting(FakeFactory):
        def __init__(self, cfg):
            calls.append(1)

    import app.integrations.asus_sync as mod
    orig = mod.AsusClient
    mod.AsusClient = Counting
    try:
        conn = connect(path)
        replace_inferred(conn, [])
        conn.close()
        await asus_after_scan(str(path))
    finally:
        mod.AsusClient = orig
    assert calls == [] and _edges(path) == before


@pytest.mark.asyncio
async def test_hook_does_nothing_when_disabled(db):
    path, ids = db
    conn = connect(path)
    save_config(conn, AsusConfig(enabled=False, url="10.0.0.1", username="u", password="pw"))
    conn.close()
    await asus_after_scan(str(path))
    assert _edges(path) == set()


def _api(path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    app.state.asus_factory = FakeFactory
    return TestClient(app, headers=AUTH)


def test_api_masks_password_and_syncs_on_enable(db):
    path, ids = db
    with _api(path) as c:
        r = c.put("/api/asus", json={"url": "10.0.0.1", "username": "admin", "password": "TOPSECRET", "enabled": True})
        assert r.status_code == 200
        out = r.json()
        assert out["url"] == "https://10.0.0.1:8443" and out["password_set"] is True and "TOPSECRET" not in r.text
        assert out["status"]["ok"] is True and out["status"]["links"] == 5

        c.put("/api/asus", json={"verify_tls": True})  # partial update keeps the password
        conn = connect(path)
        assert json.loads(conn.execute("SELECT value FROM settings WHERE key='asus'").fetchone()[0])["password"] == "TOPSECRET"
        conn.close()

        assert (ids["wifi"], ids["garden"], "uplink") in {(e["from"], e["to"], e["kind"]) for e in c.get("/api/map").json()["edges"]}
        c.put("/api/asus", json={"enabled": False})
        assert not any(e[3] == "asus-mesh" for e in _edges(path))


@pytest.mark.parametrize("payload", [{"enabled": True}, {"url": "ftp://x"}, {"enabled": True, "url": "10.0.0.1"}])
def test_api_validation(db, payload):
    path, _ = db
    with _api(path) as c:
        assert c.put("/api/asus", json=payload).status_code == 422


def test_api_test_and_sync_endpoints(db):
    path, _ = db
    with _api(path) as c:
        r = c.post("/api/asus/test", json={"url": "10.0.0.1", "username": "u", "password": "pw"})
        assert r.json() == {"ok": True, "nodes": 3, "clients": 3}
        assert c.get("/api/asus").json()["configured"] is False  # a test saves nothing
        assert c.post("/api/asus/test", json={}).status_code == 422
        FakeFactory.error = AsusAuthError("login refused")
        r = c.post("/api/asus/test", json={"url": "10.0.0.1", "username": "u", "password": "pw"})
        assert r.status_code == 502 and "refused" in r.json()["detail"]
        assert c.post("/api/asus/sync").status_code == 502  # not configured
        assert c.post("/api/asus/sync", headers={"Authorization": "Bearer no"}).status_code == 401
