import socket
import sqlite3
import struct

import pytest

from app.db import init_db
from app.scanner import passive


def eth_ip_udp(payload: bytes, *, src_mac="02:aa:bb:cc:dd:01", src_ip="10.0.0.77", dport=67, sport=68, options_ihl=5) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x40 | options_ihl, 0, 20 + len(udp), 0, 0, 64, 17, 0, socket.inet_aton(src_ip), socket.inet_aton("255.255.255.255"))
    eth = bytes.fromhex("ffffffffffff") + bytes.fromhex(src_mac.replace(":", "")) + b"\x08\x00"
    return eth + ip + udp


def dhcp(mac="02:aa:bb:cc:dd:01", *, hostname=None, vendor_class=None, params=None, msg=1, requested=None) -> bytes:
    body = bytearray(240)
    body[0], body[1], body[2] = 1, 1, 6
    body[28:34] = bytes.fromhex(mac.replace(":", ""))
    body[236:240] = b"\x63\x82\x53\x63"
    opts = bytes([53, 1, msg])
    if requested:
        opts += bytes([50, 4]) + socket.inet_aton(requested)
    if hostname:
        opts += bytes([12, len(hostname)]) + hostname.encode()
    if vendor_class:
        opts += bytes([60, len(vendor_class)]) + vendor_class.encode()
    if params:
        opts += bytes([55, len(params)]) + bytes(params)
    return bytes(body) + opts + b"\xff"


WINDOWS_PARAMS = [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]


def test_dhcp_request_gives_name_and_os():
    obs = passive.parse_frame(eth_ip_udp(dhcp(hostname="DESKTOP-ABC", params=WINDOWS_PARAMS, requested="10.0.0.77")))
    assert obs.mac == "02:aa:bb:cc:dd:01" and obs.ip == "10.0.0.77"
    assert obs.names == {"DESKTOP-ABC": "dhcp"} and "os:Windows" in obs.hints


def test_vendor_class_beats_nothing_and_unknown_is_kept_as_text():
    obs = passive.parse_frame(eth_ip_udp(dhcp(vendor_class="android-dhcp-13")))
    assert "os:Android 13" in obs.hints
    obs = passive.parse_frame(eth_ip_udp(dhcp(vendor_class="Acme Gadgets")))
    assert obs.vendor_class == "Acme Gadgets" and not obs.hints


def test_server_replies_and_garbage_are_ignored():
    assert passive.parse_frame(eth_ip_udp(dhcp(msg=5))) is None            # an ACK is not a client request
    assert passive.parse_frame(eth_ip_udp(b"\x01" * 30)) is None
    assert passive.parse_frame(b"\x00" * 10) is None
    assert passive.parse_frame(eth_ip_udp(dhcp(), dport=9999)) is None


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def record(name, rtype, rdata):
    return dns_name(name) + struct.pack("!HHIH", rtype, 1, 120, len(rdata)) + rdata


def test_mdns_announcement():
    txt = b"".join(bytes([len(x)]) + x.encode() for x in ("md=Chromecast", "fn=Living room"))
    records = [
        record("_googlecast._tcp.local", 12, dns_name("Living-room._googlecast._tcp.local")),
        record("Living-room._googlecast._tcp.local", 16, txt),
        record("chromecast123.local", 1, socket.inet_aton("10.0.0.77")),
    ]
    packet = struct.pack("!HHHHHH", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)
    obs = passive.parse_frame(eth_ip_udp(packet, dport=5353, sport=5353))
    assert "mdns:_googlecast._tcp" in obs.hints and "model:Chromecast" in obs.hints
    assert obs.names["chromecast123"] == "mdns" and obs.names["Living room"] == "mdns"


def test_mdns_query_is_ignored():
    assert passive.parse_frame(eth_ip_udp(struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + dns_name("x.local") + b"\x00\x01\x00\x01", dport=5353)) is None


def test_ssdp_notify():
    text = b"NOTIFY * HTTP/1.1\r\nNT: urn:schemas-upnp-org:device:MediaRenderer:1\r\nNTS: ssdp:alive\r\n\r\n"
    obs = passive.parse_frame(eth_ip_udp(text, dport=1900, sport=1900))
    assert obs.hints == ["upnp:mediarenderer"]


def test_bpf_program_has_the_right_shape():
    program = passive._bpf_program()
    assert len(program) % 8 == 0 and len(program) // 8 == 14
    # every jump stays inside the program
    ins = [struct.unpack("HBBI", program[i:i + 8]) for i in range(0, len(program), 8)]
    for index, (code, jt, jf, k) in enumerate(ins):
        if code & 0x07 == 0x05:  # BPF_JMP
            assert index + 1 + jt < len(ins) and index + 1 + jf < len(ins)


@pytest.fixture
def conn(tmp_path):
    c = sqlite3.connect(tmp_path / "t.db")
    c.row_factory = sqlite3.Row
    init_db(c)
    c.execute("INSERT INTO devices (primary_ip, mac, first_seen, last_seen, online) VALUES ('10.0.0.77', '02:aa:bb:cc:dd:01', 'x', 'x', 1)")
    c.commit()
    return c


def test_apply_names_and_classifies_a_randomised_phone(conn):
    obs = passive.parse_frame(eth_ip_udp(dhcp(hostname="Berts-iPhone", vendor_class="Acme", params=[1, 121, 3, 6, 15, 119, 252])))
    assert passive.apply(conn, obs) is True
    row = conn.execute("SELECT hostname, device_type, hints FROM devices").fetchone()
    assert row["hostname"] == "Berts-iPhone" and row["device_type"] == "phone"


def test_apply_waits_for_an_unknown_device(conn):
    obs = passive.Observation(mac="02:00:00:00:99:99", ip="10.0.0.99", names={"x": "dhcp"})
    assert passive.apply(conn, obs) is False


def test_listener_keeps_pending_until_the_device_exists(tmp_path):
    db = str(tmp_path / "l.db")
    c = sqlite3.connect(db)
    c.row_factory = sqlite3.Row
    init_db(c)
    c.close()
    listener = passive.Listener(db)
    listener.feed(eth_ip_udp(dhcp(hostname="late-device")))
    assert listener.flush() == 0 and len(listener.pending) == 1
    c = sqlite3.connect(db)
    c.execute("INSERT INTO devices (primary_ip, mac, first_seen, last_seen, online) VALUES ('10.0.0.77', '02:aa:bb:cc:dd:01', 'x', 'x', 1)")
    c.commit()
    c.close()
    assert listener.flush() == 1 and not listener.pending


def run_bpf(program: bytes, frame: bytes) -> int:
    """Just enough of a classic-BPF interpreter for the opcodes the filter uses."""
    ins = [struct.unpack("HBBI", program[i:i + 8]) for i in range(0, len(program), 8)]
    a = x = pc = 0
    while True:
        code, jt, jf, k = ins[pc]
        pc += 1
        if code == 0x28:   a = struct.unpack("!H", frame[k:k + 2])[0]
        elif code == 0x30: a = frame[k]
        elif code == 0xB1: x = (frame[k] & 0xF) * 4
        elif code == 0x48: a = struct.unpack("!H", frame[x + k:x + k + 2])[0]
        elif code == 0x15: pc += jt if a == k else jf
        elif code == 0x45: pc += jt if a & k else jf
        elif code == 0x06: return k
        else: raise AssertionError(hex(code))


@pytest.mark.parametrize("port,accepted", [(67, True), (68, True), (1900, True), (5353, True), (80, False), (53, False)])
def test_bpf_filter_accepts_only_discovery_ports(port, accepted):
    frame = eth_ip_udp(b"x" * 20, dport=port)
    assert (run_bpf(passive._bpf_program(), frame) > 0) is accepted


def test_bpf_filter_rejects_tcp_arp_and_fragments():
    program = passive._bpf_program()
    udp = eth_ip_udp(b"x" * 20, dport=67)
    assert run_bpf(program, udp[:23] + b"\x06" + udp[24:]) == 0                      # TCP
    assert run_bpf(program, udp[:12] + b"\x08\x06" + udp[14:]) == 0                  # ARP
    assert run_bpf(program, udp[:20] + b"\x00\x08" + udp[22:]) == 0                  # fragment
    with_options = eth_ip_udp(b"x" * 20, dport=5353, options_ihl=5)
    assert run_bpf(program, with_options) > 0
