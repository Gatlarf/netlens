"""A host nmap gave up on (--host-timeout) is reported up but with an empty port list."""

from app.db import connect, init_db
from app.scanner.nmap_parser import parse_nmap_xml
from app.scanner.presence import mark_offline
from app.scanner.store import save_scan_results


def _host(ip, mac, ports="", timedout=False):
    attr = ' timedout="true"' if timedout else ""
    return (
        f'<host starttime="1" endtime="9"{attr}><status state="up" reason="arp-response"/>'
        f'<address addr="{ip}" addrtype="ipv4"/><address addr="{mac}" addrtype="mac"/>{ports}</host>'
    )


OPEN_22 = '<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports>'
OPEN_80 = '<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports>'


def _xml(*hosts):
    return '<?xml version="1.0"?><nmaprun>' + "".join(hosts) + "</nmaprun>"


def _setup():
    conn = connect(":memory:")
    init_db(conn)
    return conn


def _ports(conn):
    return [r["port"] for r in conn.execute("SELECT port FROM ports ORDER BY port")]


def test_parser_flags_timed_out_hosts():
    hosts = parse_nmap_xml(_xml(_host("192.168.1.1", "aa:00:00:00:00:01", timedout=True), _host("192.168.1.2", "aa:00:00:00:00:02")))
    assert [h.timed_out for h in hosts] == [True, False]


def test_deep_scan_keeps_ports_of_a_host_that_timed_out():
    conn = _setup()
    save_scan_results(conn, parse_nmap_xml(_xml(_host("192.168.1.1", "aa:00:00:00:00:01", OPEN_22))), "deep", now="2026-03-10T10:00:00Z")
    assert _ports(conn) == [22]

    result = save_scan_results(
        conn, parse_nmap_xml(_xml(_host("192.168.1.1", "aa:00:00:00:00:01", timedout=True))), "deep", now="2026-03-11T10:00:00Z"
    )
    assert _ports(conn) == [22]  # not wiped
    events = [dict(r) for r in conn.execute("SELECT kind, detail, device_id FROM events WHERE kind = 'host_timeout'")]
    assert len(events) == 1 and "192.168.1.1" in events[0]["detail"] and events[0]["device_id"] is not None

    # the host counts as seen, so it is not marked offline by the same scan
    assert mark_offline(conn, result["device_ids"], ["192.168.1.0/24"], now="2026-03-11T10:00:05Z") == []
    assert conn.execute("SELECT online FROM devices").fetchone()["online"] == 1


def test_a_normal_deep_scan_still_removes_ports_that_closed():
    conn = _setup()
    save_scan_results(conn, parse_nmap_xml(_xml(_host("192.168.1.1", "aa:00:00:00:00:01", OPEN_22))), "deep", now="2026-03-10T10:00:00Z")
    save_scan_results(conn, parse_nmap_xml(_xml(_host("192.168.1.1", "aa:00:00:00:00:01", OPEN_80))), "deep", now="2026-03-11T10:00:00Z")
    assert _ports(conn) == [80]
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'host_timeout'").fetchone()[0] == 0


def test_quick_scan_with_a_timed_out_host_changes_no_ports():
    conn = _setup()
    save_scan_results(conn, parse_nmap_xml(_xml(_host("192.168.1.1", "aa:00:00:00:00:01", OPEN_22))), "deep", now="2026-03-10T10:00:00Z")
    save_scan_results(conn, parse_nmap_xml(_xml(_host("192.168.1.1", "aa:00:00:00:00:01", timedout=True))), "quick", now="2026-03-10T11:00:00Z")
    assert _ports(conn) == [22]
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'host_timeout'").fetchone()[0] == 1
