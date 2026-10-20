import json

import pytest
from fastapi.testclient import TestClient

from app import licence, mcp
from app.config import load_settings
from app.main import create_app

ADMIN = {"Authorization": "Bearer secret"}


@pytest.fixture(autouse=True)
def licensed(monkeypatch):
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)


@pytest.fixture(autouse=True)
def fresh_rate_counters():
    mcp._calls.clear()
    yield
    mcp._calls.clear()


@pytest.fixture
def env(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app) as c:
        c.post("/api/users", json={"username": "boss", "password": "longenough1", "role": "admin"}, headers=ADMIN)
        boss = TestClient(app)
        assert boss.post("/api/login", json={"username": "boss", "password": "longenough1"}).status_code == 200
        yield c, app, boss


def token(boss, mode):
    r = boss.post("/api/assistant/token", json={"name": f"t-{mode}", "mode": mode})
    assert r.status_code == 201, r.text
    return {"Authorization": "Bearer " + r.json()["token"]}


def rpc(client, headers, method, params=None, mid=1):
    body = {"jsonrpc": "2.0", "method": method}
    if mid is not None:
        body["id"] = mid
    if params is not None:
        body["params"] = params
    return client.post("/mcp", json=body, headers=headers)


def call(client, headers, tool_name, **arguments):
    r = rpc(client, headers, "tools/call", {"name": tool_name, "arguments": arguments})
    assert r.status_code == 200, r.text
    return r.json()["result"]


def text(result):
    return result["content"][0]["text"]


def switch_on(client, **extra):
    r = client.put("/api/mcp", json={"enabled": True, **extra}, headers=ADMIN)
    assert r.status_code == 200, r.text


def test_off_by_default_and_says_so(env):
    c, app, boss = env
    h = token(boss, "read")
    anon = TestClient(app)
    r = rpc(anon, h, "initialize", {"protocolVersion": "2025-06-18"})
    assert r.status_code == 404 and "switched off" in r.json()["error"]["message"]
    assert c.get("/api/mcp", headers=ADMIN).json()["enabled"] is False


def test_needs_an_assistant_token_not_a_session_or_the_full_token(env):
    c, app, boss = env
    switch_on(c)
    anon = TestClient(app)
    assert rpc(anon, {}, "ping").status_code == 401
    assert rpc(anon, {"Authorization": "Bearer nonsense"}, "ping").status_code == 401
    r = rpc(anon, ADMIN, "ping")                           # the built-in access token is a full administrator: not for MCP
    assert r.status_code == 403 and "assistant token" in r.json()["error"]["message"]
    assert rpc(boss, {}, "ping").status_code == 401        # a browser session does not work either


def test_handshake_and_tool_lists_follow_the_mode(env):
    c, app, boss = env
    switch_on(c)
    anon = TestClient(app)
    read, change = token(boss, "read"), token(boss, "change")
    init = rpc(anon, read, "initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}).json()["result"]
    assert init["protocolVersion"] == "2025-03-26" and init["serverInfo"]["name"] == "netlens" and "Look before you change" in init["instructions"]
    assert rpc(anon, read, "initialize", {"protocolVersion": "1999-01-01"}).json()["result"]["protocolVersion"] == mcp.PROTOCOLS[0]
    assert rpc(anon, read, "notifications/initialized", mid=None).status_code == 202
    names_read = {t["name"] for t in rpc(anon, read, "tools/list").json()["result"]["tools"]}
    names_change = {t["name"] for t in rpc(anon, change, "tools/list").json()["result"]["tools"]}
    assert {"list_devices", "get_dashboard", "api_request", "list_api_endpoints"} <= names_read
    assert not {"start_scan", "update_device", "snooze", "create_maintenance", "send_site_command"} & names_read
    assert names_read < names_change and {"start_scan", "update_device", "snooze", "create_maintenance", "send_site_command", "set_scan_ranges"} <= names_change
    assert len(names_change) > 60


def test_reading_goes_through_the_real_api(env):
    c, app, boss = env
    switch_on(c)
    anon = TestClient(app)
    h = token(boss, "read")
    out = call(anon, h, "get_config")
    assert not out["isError"] and "ranges" in json.loads(text(out)) or "quick_interval" in text(out)
    out = call(anon, h, "list_groups")
    assert not out["isError"] and json.loads(text(out)) is not None
    out = call(anon, h, "get_device", device_id=9999)
    assert out["isError"] and "404" in text(out)


def test_changing_works_for_a_change_token_and_is_audited(env):
    c, app, boss = env
    switch_on(c)
    anon = TestClient(app)
    h = token(boss, "change")
    out = call(anon, h, "create_group", name="Garden", color="#336699")
    assert not out["isError"], text(out)
    groups = c.get("/api/groups", headers=ADMIN).json()
    assert "Garden" in json.dumps(groups)
    rows = c.get("/api/audit", headers=ADMIN).json()
    rows = rows["entries"] if isinstance(rows, dict) else rows
    assert any("assistant: t-change" in r["user"] and r["method"] == "POST" and r["path"] == "/api/groups" for r in rows)
    out = call(anon, h, "snooze", subject="device:1", minutes=30, note="test")
    assert not out["isError"], text(out)
    assert not call(anon, h, "end_snooze", subject="device:1")["isError"]


def test_a_read_token_cannot_call_a_change_tool_even_by_name(env):
    c, app, boss = env
    switch_on(c)
    anon = TestClient(app)
    h = token(boss, "read")
    out = call(anon, h, "create_group", name="x")
    assert out["isError"] and "only read" in text(out)
    out = call(anon, h, "api_request", method="POST", path="/api/groups", body={"name": "x"})
    assert out["isError"] and "only read" in text(out)
    assert c.get("/api/groups", headers=ADMIN).json() in ([], {"groups": []}) or "x" not in json.dumps(c.get("/api/groups", headers=ADMIN).json())


def test_the_assistant_boundary_still_holds_through_mcp(env):
    c, app, boss = env
    switch_on(c)
    anon = TestClient(app)
    h = token(boss, "change")
    for path in ("/api/users", "/api/vault", "/api/backup", "/api/mcp", "/api/central"):
        out = call(anon, h, "api_request", method="GET", path=path)
        assert out["isError"] and "403" in text(out), path
    out = call(anon, h, "api_request", method="PUT", path="/api/mcp", body={"enabled": False})
    assert out["isError"] and "403" in text(out)
    assert c.get("/api/mcp", headers=ADMIN).json()["enabled"] is True
    out = call(anon, h, "api_request", method="DELETE", path="/api/devices/1")
    assert out["isError"] and "403" in text(out)
    assert call(anon, h, "api_request", method="GET", path="/etc/passwd")["isError"]
    assert call(anon, h, "api_request", method="GET", path="/api/../x")["isError"]


def test_the_owner_can_turn_groups_and_changes_off(env):
    c, app, boss = env
    switch_on(c, disabled_groups=["devices"])
    anon = TestClient(app)
    h = token(boss, "change")
    names = {t["name"] for t in rpc(anon, h, "tools/list").json()["result"]["tools"]}
    assert "list_devices" not in names and "list_groups" not in names and "get_dashboard" in names
    out = call(anon, h, "list_devices")
    assert out["isError"] and "switched this group" in text(out)
    c.put("/api/mcp", json={"disabled_groups": [], "allow_changes": False}, headers=ADMIN)
    names = {t["name"] for t in rpc(anon, h, "tools/list").json()["result"]["tools"]}
    assert "list_devices" in names and "start_scan" not in names
    out = call(anon, h, "start_scan")
    assert out["isError"] and "does not allow changes" in text(out)
    out = call(anon, h, "api_request", method="POST", path="/api/scans", body={})
    assert out["isError"] and "does not allow changes" in text(out)
    assert c.put("/api/mcp", json={"disabled_groups": ["nonsense"]}, headers=ADMIN).status_code == 422
    c.put("/api/mcp", json={"enabled": False}, headers=ADMIN)
    assert rpc(anon, h, "ping").status_code == 404


def test_argument_checks_explain_themselves(env):
    c, app, boss = env
    switch_on(c)
    anon = TestClient(app)
    h = token(boss, "change")
    assert "unknown argument" in text(call(anon, h, "get_device", device_id=1, evil="x"))
    assert "missing argument" in text(call(anon, h, "get_device"))
    assert "whole number" in text(call(anon, h, "get_device", device_id="abc"))
    assert "one of" in text(call(anon, h, "get_system_log", level="LOUD"))
    r = rpc(anon, h, "tools/call", {"name": "nope", "arguments": {}})
    assert r.json()["error"]["code"] == -32602
    assert rpc(anon, h, "no/such/method").json()["error"]["code"] == -32601
    assert rpc(anon, h, "tools/call", {"name": "get_device", "arguments": {"device_id": "7"}}).status_code == 200      # a number sent as text is accepted


def test_rate_limit(env):
    c, app, boss = env
    switch_on(c, rate_per_minute=3)
    anon = TestClient(app)
    h = token(boss, "read")
    codes = [rpc(anon, h, "ping").status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    mcp._calls.clear()


def test_batches_resources_and_no_stream(env):
    c, app, boss = env
    switch_on(c)
    anon = TestClient(app)
    h = token(boss, "read")
    r = anon.post("/mcp", json=[{"jsonrpc": "2.0", "id": 1, "method": "ping"}, {"jsonrpc": "2.0", "method": "notifications/initialized"}, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}], headers=h)
    assert [x["id"] for x in r.json()] == [1, 2]
    guide = rpc(anon, h, "resources/read", {"uri": "netlens://guide"}).json()["result"]["contents"][0]
    assert "Netlens" in guide["text"] and "{{" not in guide["text"]
    assert anon.get("/mcp", headers=h).status_code == 405
    assert anon.post("/mcp", content=b"not json", headers=h).status_code == 400


def test_database_maintenance_defaults_to_a_dry_run():
    method, path, query, body = mcp.build_request(mcp.TOOLS["run_database_maintenance"], {"task": "purge"})
    assert (method, path, body) == ("POST", "/api/database/purge", {"dry_run": True})
    assert mcp.build_request(mcp.TOOLS["run_database_maintenance"], {"task": "optimize", "dry_run": False})[3] == {}


def test_group_zero_means_none_and_paths_are_quoted():
    assert mcp.build_request(mcp.TOOLS["update_device"], {"device_id": 3, "group_id": 0, "notes": "x"})[3] == {"group_id": None, "notes": "x"}
    assert mcp.build_request(mcp.TOOLS["get_metric"], {"entity": "device", "entity_id": 3, "metric": "a/b", "range": "24h"})[1:3] == ("/api/timeseries/device/3/a%2Fb", {"range": "24h"})


def test_every_tool_points_at_a_real_route(env):
    c, app, boss = env
    import re

    paths = {re.sub(r"\{[^}]+\}", "{}", p): ops for p, ops in app.openapi()["paths"].items()}      # the tools name their arguments their own way (site_id for probe_id)
    for t in mcp.TOOLS.values():
        if not t["path"]:
            continue
        for real in ([t["path"].replace("{task}", x) for x in t["props"]["task"]["enum"]] if "{task}" in t["path"] else [t["path"]]):
            shape = re.sub(r"\{[^}]+\}", "{}", real)
            assert shape in paths and t["method"].lower() in paths[shape], (t["name"], t["method"], real)
        assert set(t["required"]) <= set(t["props"]) and set(t["query"]) <= set(t["props"]), t["name"]
        assert t["group"] in mcp.GROUP_IDS
