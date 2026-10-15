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


def test_the_payloads_of_the_open_ports_button_are_accepted(client):
    """The device page's "Add check" button sends exactly these (see checkFor in pages/device.js)."""
    web = client.post("/api/service-checks", json={"device_id": 1, "name": "nas http", "kind": "http", "host": "10.0.0.5", "port": 443, "path": "/", "expect": "alive"})
    plain = client.post("/api/service-checks", json={"device_id": 1, "name": "nas port 8006", "kind": "tcp", "host": "10.0.0.5", "port": 8006})
    assert web.status_code == plain.status_code == 201
    assert web.json()["target"] == "https://10.0.0.5:443/" and plain.json()["target"] == "10.0.0.5:8006"
    assert {(c["kind"], c["port"]) for c in client.get("/api/service-checks", params={"device_id": 1}).json()} == {("http", 443), ("tcp", 8006)}


# ------------------------------------------------------------------ certificate and process checks
def test_cert_and_process_validation():
    ok = validate_check({"kind": "cert", "name": "site", "host": "example.org"})
    assert ok["port"] == 443 and ok["expect"] == "" and ok["path"] == ""
    assert validate_check({"kind": "cert", "name": "site", "host": "example.org", "port": 993, "expect": "30"})["expect"] == "30"
    with pytest.raises(CheckError):
        validate_check({"kind": "cert", "name": "site", "host": "example.org", "expect": "soon"})
    p = validate_check({"kind": "process", "name": "web", "host": "10.0.0.5", "path": "nginx"})
    assert p["port"] is None and p["path"] == "nginx"
    for bad in ("", "a b", "x;rm -rf /", "$(id)", "a" * 70, "-f", "--help"):
        with pytest.raises(CheckError):
            validate_check({"kind": "process", "name": "web", "host": "10.0.0.5", "path": bad})


@pytest.fixture
def tls_server(tmp_path):
    """A TLS listener with a self-signed certificate that ends in `days` days."""
    import datetime
    import ssl

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    servers = []

    def start(days):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.local")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
                .not_valid_before(now - datetime.timedelta(days=30)).not_valid_after(now + datetime.timedelta(days=days))
                .sign(key, hashes.SHA256()))
        crt, pem = tmp_path / f"c{days}.pem", tmp_path / f"k{days}.pem"
        crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, pem)
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen(5)
        stop = threading.Event()

        def serve():
            sock.settimeout(0.2)
            while not stop.is_set():
                try:
                    c, _ = sock.accept()
                except (socket.timeout, OSError):
                    continue
                try:
                    with ctx.wrap_socket(c, server_side=True):
                        pass
                except (ssl.SSLError, OSError):
                    pass

        threading.Thread(target=serve, daemon=True).start()
        servers.append((sock, stop))
        return sock.getsockname()[1]

    yield start
    for sock, stop in servers:
        stop.set()
        sock.close()


async def test_certificate_days_left(tls_server):
    from app.services import check_cert

    port = tls_server(40)
    ok = await check_cert({"host": "127.0.0.1", "port": port, "expect": ""}, 3)
    assert ok.up and "valid for 39 more days" in ok.detail or "valid for 40 more days" in ok.detail
    assert 39 < ok.metrics["cert_days"] <= 40
    soon = await check_cert({"host": "127.0.0.1", "port": port, "expect": "60"}, 3)
    assert not soon.up and "limit 60" in soon.detail
    ended = await check_cert({"host": "127.0.0.1", "port": tls_server(-3), "expect": ""}, 3)
    assert not ended.up and "expired" in ended.detail and ended.metrics["cert_days"] < 0


async def test_certificate_of_a_closed_port():
    from app.services import check_cert

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    res = await check_cert({"host": "127.0.0.1", "port": port, "expect": ""}, 2)
    assert not res.up and res.ms is None


async def test_process_check_needs_a_monitored_device(tmp_path):
    from app.hostmetrics.service import check_process

    c = connect(tmp_path / "t.db")
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 1, ?, ?)", (NOW, NOW))
    c.commit()
    running, detail, _ms = await check_process(str(tmp_path / "t.db"), 1, "nginx")
    assert not running and "no health monitoring" in detail
    running, detail, _ms = await check_process(str(tmp_path / "t.db"), None, "nginx")
    assert not running and "choose the device" in detail


async def test_process_check_over_snmp(tmp_path, monkeypatch):
    from app.hostmetrics import service as hm, snmp
    from tests.test_hostmetrics import answering, oid
    from tests import test_plugin_snmp as sim

    c = connect(tmp_path / "t.db")
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 1, ?, ?)", (NOW, NOW))
    c.commit()
    hm.save_monitor(c, 1, {"method": "snmp", "address": "10.0.0.5", "community": "public"})
    mib = sim.Mib("public")
    mib.set(oid(snmp.HR_SW_RUN_NAME, 100), b"sqlservr.exe")
    mib.set(oid(snmp.HR_SW_RUN_NAME, 200), b"svchost.exe")
    monkeypatch.setattr(snmp, "SEND", answering(mib))
    db = str(tmp_path / "t.db")
    assert (await hm.check_process(db, 1, "sqlservr"))[:2] == (True, "running")
    assert (await hm.check_process(db, 1, "SQLSERVR.EXE"))[0] is True
    assert (await hm.check_process(db, 1, "nginx"))[0] is False


# ---------------------------------------------------------------- certificate renewal style
def test_certificate_policy():
    from app.services import cert_policy

    assert cert_policy("", "Let's Encrypt") == ("auto", 14)
    assert cert_policy("", "ZeroSSL") == ("auto", 14)
    assert cert_policy("", "My Own CA") == ("manual", 30)
    assert cert_policy("manual", "Let's Encrypt") == ("manual", 30)
    assert cert_policy("auto", "My Own CA") == ("auto", 14)
    assert cert_policy("45", "Let's Encrypt") == ("custom", 45)
