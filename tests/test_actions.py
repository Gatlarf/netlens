import pytest
from fastapi.testclient import TestClient

from app import actions
from app.config import load_settings
from app.db import connect, get_or_create_device
from app.main import create_app

AUTH = {"Authorization": "Bearer secret"}
PING_XML = '''<nmaprun><host><status state="up"/><address addr="10.0.0.9" addrtype="ipv4"/><times srtt="2500" rttvar="1" to="100000"/></host></nmaprun>'''
TRACE_XML = '''<nmaprun><host><status state="up"/><address addr="10.0.0.9" addrtype="ipv4"/>
<trace proto="icmp"><hop ttl="1" ipaddr="10.0.0.1" rtt="1.0"/><hop ttl="2" ipaddr="10.0.0.2" rtt="2.0"/></trace></host></nmaprun>'''
DOWN_XML = "<nmaprun></nmaprun>"


def test_magic_packet_layout():
    p = actions.magic_packet("aa:bb:cc:dd:ee:ff")
    assert len(p) == 102 and p[:6] == b"\xff" * 6 and p[6:12] == bytes.fromhex("aabbccddeeff") and p[-6:] == bytes.fromhex("aabbccddeeff")


@pytest.mark.parametrize("mac", [None, "", "aa:bb", "zz:bb:cc:dd:ee:ff", "aa-bb-cc-dd-ee-ff"])
def test_magic_packet_rejects_bad_mac(mac):
    with pytest.raises(actions.ActionError):
        actions.magic_packet(mac)


def test_broadcast_targets():
    assert actions.broadcast_targets("192.168.0.50") == ["255.255.255.255", "192.168.0.255"]
    assert actions.broadcast_targets(None) == ["255.255.255.255"]
    assert actions.broadcast_targets("garbage") == ["255.255.255.255"]


def test_wake_sends_to_every_target_and_port_and_reports_failure():
    seen = []
    sent = actions.wake("aa:bb:cc:dd:ee:ff", "10.0.0.5", sender=lambda pkt, t, p: seen.append((t, p)))
    assert sent == ["255.255.255.255", "10.0.0.255"] and len(seen) == 4

    def broken(*a):
        raise OSError("network unreachable")

    with pytest.raises(actions.ActionError, match="unreachable"):
        actions.wake("aa:bb:cc:dd:ee:ff", "10.0.0.5", sender=broken)


@pytest.fixture
def client(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db")
    app.state.sent = []
    with TestClient(app, headers=AUTH) as c:
        conn = connect(tmp_path / "t.db")
        c.dev = get_or_create_device(conn, "aa:bb:cc:00:00:09", "10.0.0.9")
        c.nomac = get_or_create_device(conn, None, "10.0.0.10")
        conn.close()
        yield c, app, tmp_path


def use_runner(app, xml):
    async def runner(args):
        app.state.last_args = args
        return xml
    app.state.action_runner = runner


def test_ping_and_trace(client):
    c, app, _ = client
    use_runner(app, PING_XML)
    r = c.post(f"/api/devices/{c.dev}/ping").json()
    assert r["up"] is True and r["rtt_ms"] == 2.5 and app.state.last_args[-1] == "10.0.0.9"
    use_runner(app, DOWN_XML)
    assert c.post(f"/api/devices/{c.dev}/ping").json() == {"ip": "10.0.0.9", "up": False, "rtt_ms": None}
    use_runner(app, TRACE_XML)
    assert c.post(f"/api/devices/{c.dev}/trace").json()["hops"] == ["10.0.0.1", "10.0.0.2"]


def test_ping_public_ip_refused(client):
    c, app, tmp = client
    conn = connect(tmp / "t.db")
    pub = get_or_create_device(conn, "aa:bb:cc:00:00:99", "8.8.8.8")
    conn.close()
    use_runner(app, PING_XML)
    assert c.post(f"/api/devices/{pub}/ping").status_code == 422
    assert not hasattr(app.state, "last_args")


def test_wake_without_mac_and_unknown_device(client):
    c, _, _ = client
    assert c.post(f"/api/devices/{c.nomac}/wake").status_code == 422
    assert c.post("/api/devices/9999/wake").status_code == 404
    assert c.post("/api/devices/9999/ping").status_code == 404


def test_wake_endpoint_sends_and_logs(client, monkeypatch):
    c, _, tmp = client
    calls = []
    monkeypatch.setattr(actions, "_send_udp_broadcast", lambda pkt, t, p: calls.append((t, p)))
    r = c.post(f"/api/devices/{c.dev}/wake")
    assert r.status_code == 200 and r.json()["sent_to"] == ["255.255.255.255", "10.0.0.255"] and calls
    conn = connect(tmp / "t.db")
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind='wake_sent'").fetchone()[0] == 1
    conn.close()


def test_requires_auth(client):
    c, _, _ = client
    for action in ("wake", "ping", "trace"):
        assert c.post(f"/api/devices/{c.dev}/{action}", headers={"Authorization": "Bearer no"}).status_code == 401
