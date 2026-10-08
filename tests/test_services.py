import asyncio
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app
from app.services import (
    CheckError,
    Result,
    build_dns_query,
    check_dns,
    check_http,
    check_tcp,
    due_checks,
    parse_dns_answer,
    prune_results,
    record_result,
    run_check,
    run_due_checks,
    validate_check,
)

AUTH = {"Authorization": "Bearer secret"}
NOW = "2026-03-10T12:00:00Z"


def at(seconds):
    from datetime import datetime, timedelta, timezone

    return (datetime.strptime(NOW, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------------------------ validation
@pytest.mark.parametrize("data,message", [
    ({"kind": "ping", "name": "x", "host": "a"}, "kind"),
    ({"kind": "tcp", "name": "", "host": "a", "port": 1}, "name"),
    ({"kind": "tcp", "name": "x", "host": "bad host!", "port": 1}, "host"),
    ({"kind": "tcp", "name": "x", "host": "169.254.169.254", "port": 80}, "cannot be checked"),
    ({"kind": "tcp", "name": "x", "host": "a"}, "port"),
    ({"kind": "tcp", "name": "x", "host": "a", "port": 70000}, "port"),
    ({"kind": "http", "name": "x", "host": "a", "port": 80, "expect": "ok"}, "expect"),
    ({"kind": "dns", "name": "x", "host": "1.1.1.1"}, "DNS check"),
    ({"kind": "tcp", "name": "x", "host": "a", "port": 1, "interval_s": 5}, "interval"),
    ({"kind": "tcp", "name": "x", "host": "a", "port": 1, "timeout_s": 99}, "timeout"),
])
def test_invalid_checks(data, message):
    with pytest.raises(CheckError, match=message):
        validate_check(data)


def test_valid_checks_get_defaults():
    http = validate_check({"kind": "http", "name": " Web ", "host": "10.0.0.5", "path": "status"})
    assert http == {"kind": "http", "name": "Web", "host": "10.0.0.5", "port": 80, "path": "/status", "expect": "", "interval_s": 60, "timeout_s": 5, "enabled": 1}
    assert validate_check({"kind": "dns", "name": "DNS", "host": "10.0.0.1", "path": "example.com", "expect": "1.2.3.4"})["port"] == 53
    assert validate_check({"kind": "http", "name": "x", "host": "a", "expect": "text:Welcome"})["expect"] == "text:Welcome"
    assert validate_check({"kind": "tcp", "name": "x", "host": "a", "port": 22, "path": "ignored"})["path"] == ""


# ------------------------------------------------------------------ the checks, against real local servers
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        code, body = {"/ok": (200, b"Welcome home"), "/missing": (404, b"nope"), "/moved": (302, b""), "/boom": (500, b"err")}.get(self.path, (200, b"root"))
        self.send_response(code)
        if code == 302:
            self.send_header("Location", "/ok")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def web():
    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()


def http_check(port, path="/ok", expect=""):
    return {"kind": "http", "host": "127.0.0.1", "port": port, "path": path, "expect": expect, "timeout_s": 3}


async def test_tcp(web):
    up = await check_tcp("127.0.0.1", web, 2)
    assert up.up and up.ms is not None and up.detail == "port open"
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    closed = sock.getsockname()[1]
    sock.close()
    down = await check_tcp("127.0.0.1", closed, 2)
    assert not down.up and down.ms is None and down.detail


async def test_http_status_text_and_redirect(web):
    assert (await check_http(http_check(web), 3)).up
    assert not (await check_http(http_check(web, "/missing"), 3)).up
    r = await check_http(http_check(web, "/boom"), 3)
    assert not r.up and r.detail == "HTTP 500"
    assert (await check_http(http_check(web, "/missing", "404"), 3)).up  # expecting a 404
    assert not (await check_http(http_check(web, "/ok", "404"), 3)).up
    assert (await check_http(http_check(web, "/ok", "text:Welcome"), 3)).up
    r = await check_http(http_check(web, "/ok", "text:Goodbye"), 3)
    assert not r.up and "text not found" in r.detail
    assert (await check_http(http_check(web, "/moved"), 3)).detail == "HTTP 302"  # a redirect is an answer, not followed
    assert not (await check_http({**http_check(1), "host": "127.0.0.1"}, 1)).up


def dns_answer(query, rcode=0, addresses=("93.184.216.34",), compress=True):
    ident = struct.unpack(">H", query[:2])[0]
    header = struct.pack(">HHHHHH", ident, 0x8180 | rcode, 1, len(addresses), 0, 0)
    body = query[12:]
    answers = b"".join((b"\xc0\x0c" if compress else b"\x01a\x00") + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(a) for a in addresses)
    return header + body + answers


def test_dns_packets_round_trip():
    q = build_dns_query("example.com")
    assert q[12:] == b"\x07example\x03com\x00\x00\x01\x00\x01"
    assert parse_dns_answer(dns_answer(q, addresses=("1.2.3.4", "5.6.7.8"))) == (0, ["1.2.3.4", "5.6.7.8"])
    assert parse_dns_answer(dns_answer(q, addresses=("1.2.3.4",), compress=False)) == (0, ["1.2.3.4"])
    assert parse_dns_answer(dns_answer(q, rcode=3, addresses=())) == (3, [])
    for bad in (b"", b"x" * 20):
        with pytest.raises(ValueError):
            parse_dns_answer(bad)


@pytest.fixture
def dns_server():
    state = {"rcode": 0, "addresses": ("93.184.216.34",), "silent": False}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.2)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(512)
            except (socket.timeout, OSError):
                continue
            if not state["silent"]:
                sock.sendto(dns_answer(data, state["rcode"], state["addresses"]), addr)

    threading.Thread(target=serve, daemon=True).start()
    yield sock.getsockname()[1], state
    stop.set()
    sock.close()


async def test_dns_checks(dns_server):
    port, state = dns_server
    check = {"kind": "dns", "host": "127.0.0.1", "port": port, "path": "example.com", "expect": "", "timeout_s": 2}
    ok = await check_dns(check, 2)
    assert ok.up and ok.detail == "93.184.216.34"
    assert (await check_dns({**check, "expect": "93.184.216.34"}, 2)).up
    wrong = await check_dns({**check, "expect": "1.1.1.1"}, 2)
    assert not wrong.up and "expected 1.1.1.1" in wrong.detail
    state["rcode"], state["addresses"] = 3, ()
    assert (await check_dns(check, 2)).detail == "name does not exist"
    state["rcode"], state["addresses"] = 0, ()
    assert (await check_dns(check, 2)).detail == "no address in the answer"
    state["silent"] = True
    silent = await check_dns(check, 0.5)
    assert not silent.up and "no answer within" in silent.detail


async def test_run_check_never_raises():
    r = await run_check({"kind": "tcp", "host": "127.0.0.1", "port": 1, "timeout_s": 1, "name": "x"})
    assert isinstance(r, Result) and not r.up


# ------------------------------------------------------------------ state and events
@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 1, ?, ?)", (NOW, NOW))
    c.execute("INSERT INTO service_checks (id, device_id, name, kind, host, port, interval_s, timeout_s, created) VALUES (1, 1, 'Web', 'tcp', '10.0.0.5', 80, 60, 5, ?)", (NOW,))
    c.commit()
    return c


def fresh(conn):
    return dict(conn.execute("SELECT * FROM service_checks WHERE id = 1").fetchone())


def test_state_changes_need_two_matching_results(conn):
    assert record_result(conn, fresh(conn), Result(True, 3.0, "port open"), at(0)) is None  # first result: the starting point
    assert fresh(conn)["last_up"] == 1
    assert record_result(conn, fresh(conn), Result(False, None, "timed out"), at(60)) is None  # one failure is not an outage yet
    assert fresh(conn)["last_up"] == 1 and fresh(conn)["last_detail"] == "timed out"
    assert record_result(conn, fresh(conn), Result(True, 3.0, "port open"), at(120)) is None  # a flap that recovered: nothing
    assert record_result(conn, fresh(conn), Result(False, None, "timed out"), at(180)) is None
    assert record_result(conn, fresh(conn), Result(False, None, "timed out"), at(240)) == "down"
    c = fresh(conn)
    assert c["last_up"] == 0 and c["since"] == at(240)
    events = [tuple(r) for r in conn.execute("SELECT kind, detail, device_id FROM events")]
    assert events == [("service_down", "Web (10.0.0.5:80) is down: timed out", 1)]
    assert record_result(conn, fresh(conn), Result(False, None, "timed out"), at(300)) is None  # still down: no repeat
    assert record_result(conn, fresh(conn), Result(True, 2.0, "port open"), at(360)) is None
    assert record_result(conn, fresh(conn), Result(True, 2.0, "port open"), at(420)) == "up"
    assert [r[0] for r in conn.execute("SELECT kind FROM events")] == ["service_down", "service_up"]
    assert conn.execute("SELECT COUNT(*) FROM service_results").fetchone()[0] == 8


def test_due_checks_follow_their_interval_and_enabled_flag(conn):
    assert [c["id"] for c in due_checks(conn, NOW)] == [1]  # never ran
    record_result(conn, fresh(conn), Result(True, 1.0, "ok"), NOW)
    assert due_checks(conn, at(59)) == [] and [c["id"] for c in due_checks(conn, at(60))] == [1]
    conn.execute("UPDATE service_checks SET enabled = 0")
    assert due_checks(conn, at(600)) == []


def test_old_results_are_pruned(conn):
    record_result(conn, fresh(conn), Result(True, 1.0, "ok"), "2026-01-01T00:00:00Z")
    record_result(conn, fresh(conn), Result(True, 1.0, "ok"), NOW)
    prune_results(conn, NOW)
    assert conn.execute("SELECT COUNT(*) FROM service_results").fetchone()[0] == 1


async def test_run_due_checks_end_to_end(tmp_path, web):
    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)
    c.execute("INSERT INTO service_checks (name, kind, host, port, interval_s, timeout_s, created) VALUES ('up', 'tcp', '127.0.0.1', ?, 60, 2, ?)", (web, NOW))
    c.execute("INSERT INTO service_checks (name, kind, host, port, interval_s, timeout_s, created) VALUES ('down', 'tcp', '127.0.0.1', 1, 60, 2, ?)", (NOW,))
    c.commit()
    c.close()
    assert await run_due_checks(str(path)) == 2
    c = connect(path)
    state = {r["name"]: r["last_up"] for r in c.execute("SELECT name, last_up FROM service_checks")}
    assert state == {"up": 1, "down": 0}
    c.close()
    assert await run_due_checks(str(path)) == 0  # not due again yet


# ------------------------------------------------------------------ API
@pytest.fixture
def client(tmp_path):
    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'nas', 1, ?, ?)", (NOW, NOW))
    c.commit()
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app, headers=AUTH) as tc:
        yield tc


def test_api_crud(client, web):
    r = client.post("/api/service-checks", json={"name": "Local web", "kind": "http", "host": "127.0.0.1", "port": web, "path": "/ok", "device_id": 1})
    assert r.status_code == 201
    check = r.json()
    assert check["target"] == f"http://127.0.0.1:{web}/ok" and check["state"] is None and check["device_name"] == "nas" and check["enabled"] is True
    cid = check["id"]
    run = client.post(f"/api/service-checks/{cid}/run").json()
    assert run["up"] is True and run["check"]["state"] == "up" and run["check"]["uptime_24h"] == 100.0
    assert [x["up"] for x in client.get(f"/api/service-checks/{cid}/results").json()] == [True]
    assert [c["name"] for c in client.get("/api/service-checks", params={"device_id": 1}).json()] == ["Local web"]
    assert client.get("/api/service-checks", params={"device_id": 2}).json() == []

    changed = client.patch(f"/api/service-checks/{cid}", json={"interval_s": 120, "name": "Renamed"}).json()
    assert changed["interval_s"] == 120 and changed["name"] == "Renamed" and changed["state"] == "up"  # history kept
    retargeted = client.patch(f"/api/service-checks/{cid}", json={"path": "/missing"}).json()
    assert retargeted["state"] is None and client.get(f"/api/service-checks/{cid}/results").json() == []  # a new target starts afresh
    assert client.patch(f"/api/service-checks/{cid}", json={"enabled": False}).json()["enabled"] is False

    assert client.delete(f"/api/service-checks/{cid}").json() == {"removed": cid}
    assert client.get("/api/service-checks").json() == []
    assert client.delete(f"/api/service-checks/{cid}").status_code == 404
    assert client.post(f"/api/service-checks/{cid}/run").status_code == 404


def test_api_validation_and_auth(client):
    assert client.post("/api/service-checks", json={"name": "x", "kind": "tcp", "host": "a"}).status_code == 422
    r = client.post("/api/service-checks", json={"name": "x", "kind": "tcp", "host": "a", "port": 1, "device_id": 99})
    assert r.status_code == 422 and "device" in r.json()["detail"]
    ok = client.post("/api/service-checks", json={"name": "x", "kind": "tcp", "host": "10.0.0.5", "port": 22}).json()
    assert client.patch(f"/api/service-checks/{ok['id']}", json={"port": 0}).status_code == 422
    bad = {"Authorization": "Bearer no"}
    for method, url in (("get", "/api/service-checks"), ("post", "/api/service-checks"), ("delete", f"/api/service-checks/{ok['id']}")):
        assert getattr(client, method)(url, headers=bad).status_code == 401
