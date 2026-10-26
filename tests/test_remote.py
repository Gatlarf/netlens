import asyncio
import json
import threading

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app
from app.remote import guac

AUTH = {"Authorization": "Bearer secret"}


# ------------------------------------------------------------------ the protocol
def test_encode_counts_characters_not_bytes():
    assert guac.encode("select", "rdp") == "6.select,3.rdp;"
    assert guac.encode("clipboard", "héllo") == "9.clipboard,5.héllo;"
    assert guac.encode("sync") == "4.sync;"


def test_parser_reads_partial_and_multiple_instructions():
    p = guac.Parser()
    assert p.feed("4.sync,3.123;5.mo") == [("sync", ["123"])]
    assert p.feed("use,1.5,1.6;") == [("mouse", ["5", "6"])]
    assert p.feed("0.,4.ping,3.123;") == [("", ["ping", "123"])]
    assert p.feed("6.select,3.r") == [] and p.feed("dp;") == [("select", ["rdp"])]
    with pytest.raises(guac.ProtocolError):
        p.feed("x.bad;")


def test_parser_handles_commas_semicolons_and_unicode_inside_values():
    p = guac.Parser()
    text = guac.encode("clipboard", "a,b;c.d", "☃\U0001f600")
    assert p.feed(text) == [("clipboard", ["a,b;c.d", "☃\U0001f600"])]


# ------------------------------------------------------------------ services of a device
def test_services_are_found_by_port_or_service_name():
    ports = [{"proto": "tcp", "port": 22, "state": "open", "service": "ssh"}, {"proto": "tcp", "port": 3389, "state": "open", "service": "ms-wbt-server"},
             {"proto": "tcp", "port": 5901, "state": "open", "service": "vnc-1"}, {"proto": "tcp", "port": 8080, "state": "open", "service": "http"},
             {"proto": "udp", "port": 3389, "state": "open", "service": "rdp"}, {"proto": "tcp", "port": 23, "state": "closed", "service": "telnet"}]
    from app.api.remote import services_of

    assert [(s["proto"], s["port"]) for s in services_of(ports)] == [("ssh", 22), ("rdp", 3389), ("vnc", 5901)]
    assert services_of([{"proto": "tcp", "port": 2222, "state": "open|filtered", "service": "ssh"}])[0]["port"] == 2222


# ------------------------------------------------------------------ against a fake guacd
class FakeGuacd:
    """Speaks just enough of guacd: select -> args -> ... -> connect -> ready, then answers every key with a sync."""

    def __init__(self):
        self.received = []
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        assert self.ready.wait(5)

    def _run(self):
        asyncio.set_event_loop(self.loop)

        async def handle(reader, writer):
            parser = guac.Parser()
            args_sent = False
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    for op, args in parser.feed(data.decode()):
                        self.received.append((op, args))
                        if op == "select":
                            writer.write(guac.encode("args", "VERSION_1_5_0", "hostname", "port", "username", "password", "domain", "security", "ignore-cert").encode())
                            args_sent = True
                        elif op == "connect":
                            writer.write(guac.encode("ready", "$fake-id").encode())
                        elif op == "key":
                            writer.write(guac.encode("sync", "1").encode())
                        await writer.drain()
            finally:
                writer.close()

        async def main():
            server = await asyncio.start_server(handle, "127.0.0.1", 0)
            self.port = server.sockets[0].getsockname()[1]
            self.ready.set()
            async with server:
                await server.serve_forever()

        self.loop.run_until_complete(main())


@pytest.fixture
def guacd(monkeypatch):
    fake = FakeGuacd()
    monkeypatch.setenv("NETLENS_GUACD", f"127.0.0.1:{fake.port}")
    return fake


@pytest.fixture
def client(tmp_path):
    db_path = tmp_path / "t.db"
    conn = connect(db_path)
    init_db(conn)
    conn.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen, device_type) VALUES (1, 'aa:bb:cc:00:00:01', '192.168.1.50', 'winbox', 1, 'x', 'x', 'pc')")
    conn.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen, device_type) VALUES (2, 'aa:bb:cc:00:00:02', '192.168.1.60', 'webonly', 1, 'x', 'x', 'server')")
    for dev, port, service in ((1, 3389, "ms-wbt-server"), (1, 22, "ssh"), (1, 5900, "vnc"), (2, 80, "http")):
        conn.execute("INSERT INTO ports (device_id, proto, port, state, service, updated) VALUES (?, 'tcp', ?, 'open', ?, 'x')", (dev, port, service))
    conn.commit()
    conn.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db_path)
    with TestClient(app, headers=AUTH) as c:
        yield c


def test_the_list_has_devices_with_a_remote_service_and_the_helper_state(client, guacd):
    data = client.get("/api/remote").json()
    assert data["available"] is True and data["helper"]["reachable"] is True
    assert [d["name"] for d in data["devices"]] == ["winbox"]                        # the web-only device is not listed
    assert [(s["proto"], s["port"]) for s in data["devices"][0]["services"]] == [("ssh", 22), ("rdp", 3389), ("vnc", 5900)]


def test_helper_missing_is_explained(client, monkeypatch):
    monkeypatch.setenv("NETLENS_GUACD", "127.0.0.1:1")
    helper = client.get("/api/remote").json()["helper"]
    assert helper["configured"] and not helper["reachable"] and helper["error"]
    r = client.post("/api/remote/1/session", json={"proto": "rdp", "username": "u", "password": "p"})
    assert r.status_code == 503 and "guacd" in r.json()["detail"]
    monkeypatch.setenv("NETLENS_GUACD", "off")
    assert client.get("/api/remote").json()["helper"]["configured"] is False


def test_session_goes_through_guacd_with_the_credentials(client, guacd):
    r = client.post("/api/remote/1/session", json={"proto": "rdp", "username": "bert", "password": "s3cret", "domain": "HOME", "width": 1000, "height": 700})
    assert r.status_code == 200 and r.json()["port"] == 3389
    ticket = r.json()["ticket"]
    with client.websocket_connect(f"/api/remote/ws?ticket={ticket}", headers=AUTH) as ws:
        first = ws.receive_text()
        assert first == guac.encode("", "$fake-id")                                   # the tunnel's session id
        ws.send_text(guac.encode("", "ping", "42"))                                    # the client's keep-alive is answered here
        assert ws.receive_text() == guac.encode("", "ping", "42")
        ws.send_text(guac.encode("key", "65", "1"))
        assert ws.receive_text() == guac.encode("sync", "1")
    ops = {op: args for op, args in guacd.received}
    assert ops["select"] == ["rdp"] and ops["size"][:2] == ["1000", "700"]
    assert ops["connect"] == ["VERSION_1_5_0", "192.168.1.50", "3389", "bert", "s3cret", "HOME", "any", "true"]
    assert not any(op == "" for op, _ in guacd.received)                              # internal messages never reach guacd
    # a ticket works once
    with client.websocket_connect(f"/api/remote/ws?ticket={ticket}", headers=AUTH) as ws:
        assert ws.receive_text().startswith("5.error,")


def test_policy_is_enforced(client, guacd):
    assert client.post("/api/remote/2/session", json={"proto": "rdp"}).status_code == 422          # port not open
    assert client.post("/api/remote/99/session", json={"proto": "rdp"}).status_code == 404
    assert client.post("/api/remote/1/session", json={"proto": "ssh"}).status_code == 422          # the terminal does that
    assert client.post("/api/remote/1/session", json={"proto": "rdp", "port": 4444}).status_code == 422
    assert TestClient(client.app).get("/api/remote").status_code == 401
    with pytest.raises(Exception):
        with TestClient(client.app).websocket_connect("/api/remote/ws?ticket=x"):
            pass


def test_saved_credentials_are_encrypted_and_never_returned(client, guacd):
    t = client.post("/api/remote/1/session", json={"proto": "vnc", "username": "", "password": "vncpw", "remember": True}).json()["ticket"]
    with client.websocket_connect(f"/api/remote/ws?ticket={t}", headers=AUTH) as ws:
        ws.receive_text()
    listing = client.get("/api/remote").json()
    vnc = next(s for s in listing["devices"][0]["services"] if s["proto"] == "vnc")
    assert vnc["saved"] == {"username": "", "domain": "", "name": "VNC winbox"} and "vncpw" not in json.dumps(listing)
    conn = connect(client.app.state.db_path)
    stored = conn.execute("SELECT value FROM settings WHERE key = 'credstore.entries'").fetchone()[0]
    conn.close()
    assert stored.startswith("enc:v1:") and "vncpw" not in stored
    # connecting with the saved login does not need the password again
    t2 = client.post("/api/remote/1/session", json={"proto": "vnc", "use_saved": True}).json()["ticket"]
    with client.websocket_connect(f"/api/remote/ws?ticket={t2}", headers=AUTH) as ws:
        ws.receive_text()
    assert [a for op, a in guacd.received if op == "connect"][-1][4] == "vncpw"
    stored_list = client.get("/api/credentials").json()["credentials"]
    assert [c["name"] for c in stored_list] == ["VNC winbox"] and "vncpw" not in json.dumps(stored_list) and stored_list[0]["has_secret"]
    assert client.delete("/api/remote/1/saved/vnc").json() == {"forgotten": True}
    assert client.post("/api/remote/1/session", json={"proto": "vnc", "use_saved": True}).status_code == 404


def test_terminal_switch_and_viewers(tmp_path, guacd):
    from tests.test_users import make, sign_in

    db_path = tmp_path / "t.db"
    app = create_app(load_settings({"NETLENS_TOKEN": "secret", "NETLENS_TERMINAL": "off"}), db_path=db_path)
    with TestClient(app, headers=AUTH) as c:
        data = c.get("/api/remote").json()
        assert data["available"] is False and "NETLENS_TERMINAL" in data["why"]
        assert c.post("/api/remote/1/session", json={"proto": "rdp"}).status_code == 403
        make(c, "vera", "viewer")
        assert sign_in(app, "vera").get("/api/remote").status_code == 403
