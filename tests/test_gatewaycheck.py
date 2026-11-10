import asyncio
import json

import pytest

from app import gatewaycheck as g
from app.db import connect, init_db


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    yield c
    c.close()


def closed():
    return {p: "closed" for p in g.PORTS}


def by_id(findings):
    return {f["id"]: f for f in findings}


def test_everything_closed_is_ok_with_honest_unknowns():
    f = by_id(g.evaluate("192.168.1.1", closed(), {"found": False}))
    assert f["tr069"]["status"] == "ok" and f["telnet"]["status"] == "ok" and f["upnp"]["status"] == "ok"
    assert "admin-password" not in f and "wps" not in f                      # what can not be seen from here is not listed


def test_tr069_and_telnet_are_risks():
    ports = {**closed(), 7547: "open", 23: "open"}
    f = by_id(g.evaluate("192.168.1.1", ports, {"found": False}))
    assert f["tr069"]["status"] == "risk" and "7547" in f["tr069"]["evidence"] and f["tr069"]["steps"]
    assert f["telnet"]["status"] == "risk"
    assert g.score(list(f.values())) == 100 - 30 - 15


def test_a_silent_router_proves_nothing():
    ports = {p: "filtered" for p in g.PORTS}
    f = by_id(g.evaluate("192.168.1.1", ports, {"found": False}))
    assert f["tr069"]["status"] == "unknown" and f["telnet"]["status"] == "unknown" and f["admin-http"]["status"] == "unknown"


def test_plain_http_admin_only_without_https():
    assert by_id(g.evaluate("10.0.0.1", {**closed(), 80: "open"}, {}))["admin-http"]["status"] == "warn"
    assert by_id(g.evaluate("10.0.0.1", {**closed(), 80: "open", 443: "open"}, {}))["admin-http"]["status"] == "warn"
    redirect = {"redirect": "https://10.0.0.1:8443/"}
    assert by_id(g.evaluate("10.0.0.1", {**closed(), 80: "open", 8443: "open"}, {}, redirect))["admin-http"]["status"] == "ok"
    assert by_id(g.evaluate("10.0.0.1", {**closed(), 80: "open"}, {}, {"redirect": "http://10.0.0.1/login"}))["admin-http"]["status"] == "warn"


def test_upnp_mappings_are_listed():
    up = {"found": True, "manufacturer": "TP-Link", "model": "X", "readable": True,
          "mappings": [{"proto": "UDP", "external": "3478", "client": "192.168.1.57", "internal": "3478", "description": "voice"}]}
    f = by_id(g.evaluate("192.168.1.1", closed(), up))["upnp"]
    assert f["status"] == "warn" and f["severity"] == "high" and "UDP 3478 -> 192.168.1.57:3478" in f["evidence"]


@pytest.mark.parametrize("ip", [None, "", "8.8.8.8", "127.0.0.1", "169.254.1.1", "fe80::1", "not-an-ip"])
def test_only_a_private_gateway_is_probed(conn, ip):
    with pytest.raises(ValueError):
        asyncio.run(g.run(conn, ip))


def fake(ports=None, upnp=None):
    async def p(ip):
        return ports or closed()

    async def u(ip):
        return upnp or {"found": False}
    return p, u


def run(conn, ports=None, upnp=None, now="2026-11-10T10:00:00Z"):
    p, u = fake(ports, upnp)

    async def w(ip):
        return {"redirect": None}
    return asyncio.run(g.run(conn, "192.168.1.1", now=now, ports_probe=p, upnp_probe=u, web_probe=w))


def events(conn):
    return [r["detail"] for r in conn.execute("SELECT detail FROM events WHERE kind = 'gateway_exposure' ORDER BY id")]


def test_a_newly_opened_port_raises_one_event(conn):
    run(conn)
    assert events(conn) == []
    run(conn, {**closed(), 7547: "open"}, now="2026-11-11T10:00:00Z")
    assert len(events(conn)) == 1 and "7547" in events(conn)[0]
    run(conn, {**closed(), 7547: "open"}, now="2026-11-12T10:00:00Z")
    assert len(events(conn)) == 1                                   # still open: not announced again


def test_first_run_announces_risks_but_not_warnings(conn):
    run(conn, {**closed(), 23: "open", 22: "open"})
    assert len(events(conn)) == 1 and "Telnet" in events(conn)[0]


def test_run_is_audited_and_stored(conn):
    result = run(conn)
    assert g.get_last(conn)["at"] == result["at"]
    assert conn.execute("SELECT COUNT(*) FROM audit_log WHERE action LIKE 'Router exposure check%'").fetchone()[0] == 1


def test_off_by_default_and_due_follows_interval(conn):
    from datetime import datetime, timezone
    assert g.get_settings(conn)["enabled"] is False and g.due(conn) is False
    g.set_settings(conn, True, 24)
    assert g.due(conn) is True
    run(conn, now="2026-11-10T10:00:00Z")
    assert g.due(conn, datetime(2026, 11, 10, 20, tzinfo=timezone.utc)) is False
    assert g.due(conn, datetime(2026, 11, 11, 11, tzinfo=timezone.utc)) is True
    with pytest.raises(ValueError):
        g.set_settings(conn, hours=5)


def test_upnp_description_on_another_host_is_not_followed(monkeypatch):
    monkeypatch.setattr(g, "_ssdp", lambda ip: "http://10.9.9.9:5000/rootDesc.xml")
    monkeypatch.setattr(g, "_get", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not fetch")))
    out = g._upnp("192.168.1.1")
    assert out["found"] is True and out["mappings"] == []


def test_upnp_reads_mappings_until_the_fault(monkeypatch):
    desc = b"""<root xmlns="urn:schemas-upnp-org:device-1-0"><device><manufacturer>Acme</manufacturer><modelName>R1</modelName>
      <serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl</controlURL></service></serviceList></device></root>"""
    entry = b"<e><NewProtocol>TCP</NewProtocol><NewExternalPort>443</NewExternalPort><NewInternalClient>192.168.1.9</NewInternalClient><NewInternalPort>443</NewInternalPort><NewPortMappingDescription>web</NewPortMappingDescription></e>"
    calls = []

    def get(url, data=None, headers=None):
        calls.append(url)
        if data is None:
            return desc
        if b"<NewPortMappingIndex>0<" in data:
            return entry
        raise OSError("500 fault")
    monkeypatch.setattr(g, "_ssdp", lambda ip: "http://192.168.1.1:5000/rootDesc.xml")
    monkeypatch.setattr(g, "_get", get)
    out = g._upnp("192.168.1.1")
    assert out["manufacturer"] == "Acme" and [m["external"] for m in out["mappings"]] == ["443"] and out["readable"] is True


def test_probe_ports_states():
    async def main():
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        res = await g.probe_ports("127.0.0.1", (port, 1), timeout=0.5)
        server.close()
        return port, res
    port, res = asyncio.run(main())
    assert res[port] == "open" and res[1] in ("closed", "filtered")


@pytest.fixture
def client(tmp_path):
    from fastapi.testclient import TestClient
    from app.config import load_settings
    from app.main import create_app

    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as c:
        c.app_ = app
        yield c


def test_api_is_off_until_switched_on_and_needs_admin(client):
    from fastapi.testclient import TestClient

    view = client.get("/api/netchecks").json()["exposure"]
    assert view["settings"] == {"enabled": False, "hours": 24} and view["last"] is None
    assert client.post("/api/netchecks/exposure/run").status_code == 409
    assert client.put("/api/netchecks/exposure", json={"hours": 5}).status_code == 422
    assert client.put("/api/netchecks/exposure", json={"enabled": True}).json()["exposure"]["settings"]["enabled"] is True
    assert client.post("/api/netchecks/exposure/run").status_code == 422          # no gateway known yet
    anon = TestClient(client.app_)
    client.post("/api/users", json={"username": "vera", "password": "longenough1", "role": "viewer"})
    anon.post("/api/login", json={"username": "vera", "password": "longenough1"})
    assert anon.put("/api/netchecks/exposure", json={"enabled": False}).status_code == 403
    assert anon.post("/api/netchecks/exposure/run").status_code == 403


def test_web_probe_reads_the_redirect_without_following_it():
    import http.server
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "https://router.lan:8443/")
            self.end_headers()

        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    import http.client
    orig = http.client.HTTPConnection

    class C(orig):
        def __init__(self, host, port=80, timeout=None):
            super().__init__(host, srv.server_address[1], timeout=timeout)
    http.client.HTTPConnection = C
    try:
        assert g._web("127.0.0.1") == {"redirect": "https://router.lan:8443/"}
    finally:
        http.client.HTTPConnection = orig
        srv.shutdown()
