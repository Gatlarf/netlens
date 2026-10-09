from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import netchecks
from app.actions import ActionError
from app.config import load_settings
from app.db import connect, get_or_create_device, init_db
from app.main import create_app

XML = (Path(__file__).parent / "fixtures" / "dhcp_discover.xml").read_text()
ADMIN = {"Authorization": "Bearer secret"}
T = "2026-10-09T12:00:00Z"


def second_server_xml(ip="192.168.0.99", router="192.168.0.99"):
    return XML.replace('<elem key="Router">192.168.0.1</elem>\n</table>', f'<elem key="Router">192.168.0.1</elem>\n</table>\n<table key="Response 2 of 2"><elem key="Interface">eth0</elem><elem key="IP Offered">192.168.0.222</elem>'
                       f'<elem key="Server Identifier">{ip}</elem><elem key="Router">{router}</elem></table>')


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    yield c
    c.close()


def kinds(conn, *k):
    return [r["kind"] for r in conn.execute("SELECT kind FROM events WHERE kind IN (%s) ORDER BY id" % ",".join("?" for _ in k), k)]


def test_parse_the_real_nmap_output():
    offers = netchecks.parse_dhcp_xml(XML)
    assert offers == [{"server": "192.168.0.1", "offered_ip": "192.168.0.185", "router": "192.168.0.1", "dns": ["192.168.0.181", "192.168.0.200"],
                       "domain": "home.codeshrimp.com", "interface": "eth0"}]
    assert netchecks.parse_dhcp_xml(second_server_xml())[1]["server"] == "192.168.0.99"
    assert netchecks.parse_dhcp_xml("<nmaprun></nmaprun>") == []
    for bad in ("not xml", "<!ENTITY x>"):
        with pytest.raises(ValueError):
            netchecks.parse_dhcp_xml(bad)


async def test_first_probe_trusts_what_it_finds_and_a_new_server_is_rogue(conn):
    async def runner(args):
        return state["xml"]

    state = {"xml": XML}
    r = await netchecks.check_dhcp(conn, runner, T)
    assert r == {"ok": True, "servers": ["192.168.0.1"], "rogue": []} and kinds(conn, "dhcp_rogue") == []
    assert netchecks.list_servers(conn)[0]["trusted"] is True
    state["xml"] = second_server_xml()
    r = await netchecks.check_dhcp(conn, runner, "2026-10-09T13:00:00Z")
    assert r["rogue"] == ["192.168.0.99"] and kinds(conn, "dhcp_rogue") == ["dhcp_rogue"]
    # reported once, not at every probe
    await netchecks.check_dhcp(conn, runner, "2026-10-09T14:00:00Z")
    assert kinds(conn, "dhcp_rogue") == ["dhcp_rogue"]
    servers = {s["ip"]: s for s in netchecks.list_servers(conn)}
    assert servers["192.168.0.99"]["trusted"] is False and servers["192.168.0.99"]["last_seen"] == "2026-10-09T14:00:00Z"
    netchecks.set_trusted(conn, "192.168.0.99", True)
    assert netchecks.list_servers(conn)[1]["trusted"] is True
    netchecks.forget_server(conn, "192.168.0.99")
    await netchecks.check_dhcp(conn, runner, "2026-10-09T15:00:00Z")  # forgotten and seen again: untrusted, reported again
    assert kinds(conn, "dhcp_rogue") == ["dhcp_rogue", "dhcp_rogue"]
    with pytest.raises(KeyError):
        netchecks.set_trusted(conn, "1.2.3.4", True)


async def test_rogue_event_names_the_device_when_known(conn):
    get_or_create_device(conn, "aa:bb:cc:00:00:99", "192.168.0.99")
    netchecks.record_dhcp(conn, [{"server": "192.168.0.1"}], T)
    netchecks.record_dhcp(conn, [{"server": "192.168.0.99", "router": "192.168.0.99", "dns": ["8.8.8.8"]}], T)
    row = conn.execute("SELECT detail, device_id FROM events WHERE kind = 'dhcp_rogue'").fetchone()
    assert "192.168.0.99 (aa:bb:cc:00:00:99)" in row["detail"] and "8.8.8.8" in row["detail"] and row["device_id"]


async def test_a_failing_probe_is_recorded_not_raised(conn):
    async def broken(args):
        raise ActionError("nmap is not available")

    r = await netchecks.check_dhcp(conn, broken, T)
    assert r["ok"] is False and netchecks.get_last(conn)["ok"] is False and "not available" in netchecks.get_last(conn)["error"]


def test_due_logic_and_settings(conn):
    assert netchecks.dhcp_due(conn, T)  # never ran
    netchecks.run_result(conn, True, T, [])
    assert not netchecks.dhcp_due(conn, "2026-10-09T23:00:00Z") and netchecks.dhcp_due(conn, "2026-10-10T00:00:00Z")  # every 12 hours
    netchecks.set_settings(conn, hours=1)
    assert netchecks.dhcp_due(conn, "2026-10-09T13:00:00Z")
    netchecks.run_result(conn, False, T, [], "boom")
    assert not netchecks.dhcp_due(conn, "2026-10-09T12:30:00Z") and netchecks.dhcp_due(conn, "2026-10-09T13:00:00Z")  # a failure is retried after an hour
    netchecks.set_settings(conn, enabled=False)
    assert not netchecks.dhcp_due(conn, "2030-01-01T00:00:00Z")
    with pytest.raises(ValueError):
        netchecks.set_settings(conn, hours=5)


def test_gateway_change_is_reported_once(conn):
    gw = get_or_create_device(conn, "aa:bb:cc:00:00:01", "192.168.0.1")
    assert netchecks.check_gateway(conn, "192.168.0.1", T)["mac"] == "aa:bb:cc:00:00:01"
    assert netchecks.check_gateway(conn, "192.168.0.1", T)["mac"] == "aa:bb:cc:00:00:01" and kinds(conn, "gateway_changed") == []
    conn.execute("UPDATE devices SET mac = 'aa:bb:cc:00:00:66' WHERE id = ?", (gw,))
    conn.commit()
    state = netchecks.check_gateway(conn, "192.168.0.1", "2026-10-09T13:00:00Z")
    assert state["mac"] == "aa:bb:cc:00:00:66" and kinds(conn, "gateway_changed") == ["gateway_changed"]
    netchecks.check_gateway(conn, "192.168.0.1", "2026-10-09T14:00:00Z")
    assert kinds(conn, "gateway_changed") == ["gateway_changed"]
    # a different gateway address (moved network) is a new baseline, not an alarm
    get_or_create_device(conn, "aa:bb:cc:00:00:77", "10.0.0.1")
    netchecks.check_gateway(conn, "10.0.0.1", "2026-10-09T15:00:00Z")
    assert kinds(conn, "gateway_changed") == ["gateway_changed"]
    assert netchecks.check_gateway(conn, None) is None and netchecks.check_gateway(conn, "10.9.9.9") is None


@pytest.fixture
def client(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    app.state.xml = XML

    async def runner(args):
        return app.state.xml

    app.state.action_runner = runner
    with TestClient(app, headers=ADMIN) as c:
        c.app_ = app
        yield c


def test_api_roundtrip(client):
    assert client.get("/api/netchecks").json()["settings"] == {"dhcp_enabled": True, "dhcp_hours": 12}
    r = client.post("/api/netchecks/dhcp/run").json()
    assert r["result"]["servers"] == ["192.168.0.1"] and r["servers"][0]["trusted"] is True and r["last"]["ok"] is True
    client.app_.state.xml = second_server_xml()
    r = client.post("/api/netchecks/dhcp/run").json()
    assert r["result"]["rogue"] == ["192.168.0.99"]
    assert client.put("/api/netchecks/dhcp/192.168.0.99", json={"trusted": True}).json()["servers"][1]["trusted"] is True
    assert client.put("/api/netchecks", json={"dhcp_hours": 24, "dhcp_enabled": False}).json()["settings"] == {"dhcp_enabled": False, "dhcp_hours": 24}
    assert client.put("/api/netchecks", json={"dhcp_hours": 7}).status_code == 422
    assert client.delete("/api/netchecks/dhcp/192.168.0.99").status_code == 200
    assert client.delete("/api/netchecks/dhcp/192.168.0.99").status_code == 404
    assert client.put("/api/netchecks/dhcp/9.9.9.9", json={}).status_code == 404


def test_api_probe_failure_is_a_clean_error(client):
    async def broken(args):
        raise ActionError("timed out")

    client.app_.state.action_runner = broken
    r = client.post("/api/netchecks/dhcp/run")
    assert r.status_code == 502 and "timed out" in r.json()["detail"]


def test_requires_admin(client):
    anon = TestClient(client.app_)
    assert anon.get("/api/netchecks").status_code == 401
    client.post("/api/users", json={"username": "vera", "password": "longenough1", "role": "viewer"})
    anon.post("/api/login", json={"username": "vera", "password": "longenough1"})
    assert anon.get("/api/netchecks").status_code == 403 and anon.post("/api/netchecks/dhcp/run").status_code == 403
