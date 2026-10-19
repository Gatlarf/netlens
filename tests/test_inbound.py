import asyncio
import socket

import pytest
from fastapi.testclient import TestClient

from app import inbound
from app.config import load_settings
from app.db import connect, get_or_create_device, init_db
from app.hostmetrics import snmp
from app.hostmetrics.snmp import _int, _oid, _tlv
from app.main import create_app

ADMIN = {"Authorization": "Bearer secret"}


def oid(text):
    return tuple(int(n) for n in text.split("."))


def vb(name, tag, content):
    return _tlv(0x30, _oid(oid(name)) + _tlv(tag, content))


def v2_trap(trap_oid, extra=(), community="public", pdu=0xA7, request_id=7):
    binds = vb("1.3.6.1.2.1.1.3.0", 0x43, b"\x01\x00") + vb("1.3.6.1.6.3.1.1.4.1.0", 0x06, _oid(oid(trap_oid))[2:])
    binds += b"".join(extra)
    body = _int(request_id) + _int(0) + _int(0) + _tlv(0x30, binds)
    return _tlv(0x30, _int(1) + _tlv(0x04, community.encode()) + _tlv(pdu, body))


def v1_trap(generic, agent=(10, 0, 0, 5), enterprise="1.3.6.1.4.1.8072", specific=0, extra=(), community="public"):
    body = _tlv(0x06, _oid(oid(enterprise))[2:]) + _tlv(0x40, bytes(agent)) + _int(generic) + _int(specific) + _tlv(0x43, b"\x05") + _tlv(0x30, b"".join(extra))
    return _tlv(0x30, _int(0) + _tlv(0x04, community.encode()) + _tlv(0xA4, body))


IF3 = [vb("1.3.6.1.2.1.2.2.1.1.3", 0x02, b"\x03"), vb("1.3.6.1.2.1.2.2.1.2.3", 0x04, b"GigabitEthernet1/0/3")]


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    get_or_create_device(c, "aa:bb:cc:00:00:01", "10.0.0.1")
    yield c
    c.close()


def test_v2c_link_down_names_the_interface():
    trap = inbound.parse_trap(v2_trap("1.3.6.1.6.3.1.1.5.3", IF3))
    assert inbound.classify_trap(trap) == ("link_down", "link down: GigabitEthernet1/0/3")


def test_v1_generic_traps_and_enterprise_traps():
    assert inbound.classify_trap(inbound.parse_trap(v1_trap(0)))[0] == "device_restarted"
    assert inbound.classify_trap(inbound.parse_trap(v1_trap(3, extra=[vb("1.3.6.1.2.1.2.2.1.1.9", 0x02, b"\x09")]))) == ("link_up", "link up: interface 9")
    kind, text = inbound.classify_trap(inbound.parse_trap(v1_trap(6, specific=12, extra=[vb("1.3.6.1.4.1.8072.1", 0x04, b"fan failed")])))
    assert kind == "snmp_trap" and "1.3.6.1.4.1.8072.0.12" in text and "fan failed" in text


def test_known_vendor_neutral_traps_get_a_sentence():
    kind, text = inbound.classify_trap(inbound.parse_trap(v2_trap("1.3.6.1.2.1.33.2.1")))
    assert (kind, text) == ("snmp_trap", "UPS is running on battery")


def test_garbage_and_other_versions_are_refused():
    for data in (b"", b"\x30\x03\x02\x01", b"hello", v2_trap("1.3.6.1.6.3.1.1.5.3").replace(b"\xa7", b"\xa0", 1)):
        with pytest.raises(snmp.SnmpError):
            inbound.parse_trap(data)


def test_inform_is_acknowledged_with_a_response():
    trap = inbound.parse_trap(v2_trap("1.3.6.1.6.3.1.1.5.4", IF3, pdu=0xA6, request_id=4242))
    request_id, status, binds = snmp.parse_response(inbound.ack_inform(trap))
    assert request_id == 4242 and status == 0 and len(binds) == 4


def test_trap_becomes_an_event_on_the_sender(conn):
    inbound.record_trap(conn, inbound.parse_trap(v2_trap("1.3.6.1.6.3.1.1.5.3", IF3)), "10.0.0.1")
    inbound.record_trap(conn, inbound.parse_trap(v2_trap("1.3.6.1.6.3.1.1.5.3", IF3)), "10.9.9.9")
    rows = conn.execute("SELECT kind, detail, device_id FROM events WHERE kind = 'link_down' ORDER BY id").fetchall()
    assert rows[0]["device_id"] == 1 and rows[0]["detail"] == "link down: GigabitEthernet1/0/3"
    assert rows[1]["device_id"] is None and rows[1]["detail"].startswith("10.9.9.9: ")


def test_v1_trap_uses_the_agent_address(conn):
    inbound.record_trap(conn, inbound.parse_trap(v1_trap(2, agent=(10, 0, 0, 1), extra=IF3)), "172.16.0.1")   # arrives through a relay
    assert conn.execute("SELECT device_id FROM events WHERE kind = 'link_down'").fetchone()["device_id"] == 1


@pytest.mark.parametrize("raw,sev,host,app,msg", [
    (b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed on /dev/pts/8", 2, "mymachine", "su", "'su root' failed on /dev/pts/8"),
    (b"<165>1 2026-10-19T12:00:00Z sw1 sshd 888 ID47 [exampleSDID@32473 iut=\"3\"] Failed password", 5, "sw1", "sshd", "Failed password"),
    (b"<13>Oct  1 01:02:03 host-a plain message without tag", 5, "host-a", "", "plain message without tag"),
    (b"<189>Oct 11 22:14:15 sw2 kernel[0]: link lost", 5, "sw2", "kernel", "link lost"),
])
def test_syslog_formats(raw, sev, host, app, msg):
    m = inbound.parse_syslog(raw)
    assert (m["severity"], m["host"], m["app"], m["message"]) == (sev, host, app, msg)


def test_syslog_without_priority_is_not_syslog():
    assert inbound.parse_syslog(b"hello world") is None and inbound.parse_syslog(b"<999>x") is None


def test_syslog_severity_filter_and_unknown_senders(conn):
    warn = inbound.parse_syslog(b"<opt".replace(b"<opt", b"<12>Oct 11 22:14:15 sw1 kernel: fan failed"))
    info = inbound.parse_syslog(b"<14>Oct 11 22:14:15 sw1 kernel: all good")
    assert inbound.record_syslog(conn, warn, "10.0.0.1", "warning") is not None
    assert inbound.record_syslog(conn, info, "10.0.0.1", "warning") is None
    assert inbound.record_syslog(conn, warn, "10.5.5.5", "warning") is None          # nobody we know
    assert inbound.record_syslog(conn, info, "10.0.0.1", "debug") is not None
    rows = [r["detail"] for r in conn.execute("SELECT detail FROM events WHERE kind = 'device_log' ORDER BY id")]
    assert rows == ["[warning] kernel: fan failed", "[info] kernel: all good"]


def test_syslog_host_name_finds_a_device_behind_a_relay(conn):
    conn.execute("UPDATE devices SET hostname = 'core-sw' WHERE id = 1")
    m = inbound.parse_syslog(b"<11>Oct 11 22:14:15 core-sw app: boom")
    assert inbound.record_syslog(conn, m, "172.16.0.9", "warning") is not None


def test_a_chatty_sender_is_limited():
    now = [0.0]
    limiter = inbound.Limiter(lambda: now[0])
    assert sum(limiter.allow("a") for _ in range(100)) == inbound.RATE_PER_MINUTE
    assert limiter.allow("b")
    now[0] = 61
    assert limiter.allow("a")


def test_policy_validation():
    assert inbound.clean_policy({})["traps"]["port"] == 1162
    for bad in ({"traps": {"port": 0}}, {"syslog": {"port": "x"}}, {"syslog": {"min_severity": "loud"}}, {"traps": {"communities": ["x" * 65]}},
                {"traps": {"enabled": True, "port": 2000}, "syslog": {"enabled": True, "port": 2000}}):
        with pytest.raises(inbound.InboundError):
            inbound.clean_policy(bad)


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_real_udp_round_trip(tmp_path):
    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)
    get_or_create_device(c, "aa:bb:cc:00:00:01", "127.0.0.1")
    tport, sport = free_port(), free_port()
    inbound.save_policy(c, {"traps": {"enabled": True, "port": tport, "communities": ["secret"]}, "syslog": {"enabled": True, "port": sport, "min_severity": "warning"}})

    async def scenario():
        receiver = inbound.Receiver(str(path))
        await receiver.apply()
        assert receiver.errors == {}
        loop = asyncio.get_running_loop()

        class Catch(asyncio.DatagramProtocol):
            def __init__(self):
                self.got = loop.create_future()

            def datagram_received(self, data, addr):
                self.got.set_result(data)

        catch = Catch()
        transport, _ = await loop.create_datagram_endpoint(lambda: catch, local_addr=("127.0.0.1", 0))
        transport.sendto(v2_trap("1.3.6.1.6.3.1.1.5.3", IF3, community="wrong"), ("127.0.0.1", tport))      # refused: wrong community
        transport.sendto(v2_trap("1.3.6.1.6.3.1.1.5.3", IF3, community="secret"), ("127.0.0.1", tport))
        transport.sendto(v2_trap("1.3.6.1.6.3.1.1.5.4", IF3, community="secret", pdu=0xA6, request_id=9), ("127.0.0.1", tport))
        transport.sendto(b"<12>Oct 11 22:14:15 sw1 kernel: fan failed", ("127.0.0.1", sport))
        transport.sendto(b"<14>Oct 11 22:14:15 sw1 kernel: fine", ("127.0.0.1", sport))
        ack = await asyncio.wait_for(catch.got, 3)
        await asyncio.sleep(0.2)
        status = receiver.status(c)
        receiver.stop()
        transport.close()
        return ack, status

    ack, status = asyncio.run(scenario())
    assert snmp.parse_response(ack)[0] == 9
    kinds = [r["kind"] for r in c.execute("SELECT kind FROM events ORDER BY id")]
    assert sorted(kinds) == ["device_log", "link_down", "link_up"]
    assert status["traps"]["received"] == 2 and status["syslog"]["received"] == 2 and status["syslog"]["kept"] == 1 and status["ignored"] == 1
    c.close()


def test_a_port_that_is_taken_is_reported(tmp_path):
    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as blocker:
        blocker.bind(("0.0.0.0", 0))
        port = blocker.getsockname()[1]
        inbound.save_policy(c, {"traps": {"enabled": True, "port": port, "communities": ["public"]}})
        receiver = inbound.Receiver(str(path))
        asyncio.run(receiver.apply())
        assert "cannot listen" in receiver.status(c)["traps"]["error"] and not receiver.status(c)["traps"]["listening"]
    c.close()


def test_api_roundtrip_and_admin_only(tmp_path):
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=tmp_path / "t.db", scheduler=True)
    with TestClient(app) as c:
        r = c.get("/api/inbound", headers=ADMIN)
        assert r.status_code == 200 and r.json()["policy"]["traps"]["enabled"] is False and r.json()["traps"]["listening"] is False
        port = free_port()
        r = c.put("/api/inbound", json={"traps": {"enabled": True, "port": port, "communities": ["public"]}}, headers=ADMIN)
        assert r.status_code == 200 and r.json()["traps"]["listening"] is True
        assert c.put("/api/inbound", json={"traps": {"port": 70000}}, headers=ADMIN).status_code == 422
        r = c.put("/api/inbound", json={"traps": {"enabled": False}}, headers=ADMIN)
        assert r.json()["traps"]["listening"] is False
        assert c.get("/api/inbound").status_code == 401
