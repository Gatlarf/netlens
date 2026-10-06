Fix ONE defect and output the COMPLETE corrected file, everything else identical. Defect: in the test for host 192.168.1.20, port 445 is expected to have service 'smb', but the fixture XML declares service name 'netbios-ssn' and the parser correctly returns it unchanged. Expect 'netbios-ssn'.

CURRENT FILE:
"""Tests for app.scanner.nmap_parser."""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

import pytest

from app.scanner.nmap_parser import ScanHost, ScanPort, parse_nmap_xml


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "deep.xml"


def _load_fixture() -> str:
    return FIXTURE_PATH.read_text(encoding="utf-8")


def _parse(xml_text: str) -> list[ScanHost]:
    return parse_nmap_xml(xml_text)


def _host_by_ip(hosts: list[ScanHost], ip: str) -> Optional[ScanHost]:
    for h in hosts:
        if h.ip == ip:
            return h
    return None


def _port_by_number(host: ScanHost, number: int) -> Optional[ScanPort]:
    for p in host.ports:
        if p.port == number:
            return p
    return None


# ---------------------------------------------------------------------------
# Fixture-based tests
# ---------------------------------------------------------------------------


def test_fixture_returns_four_hosts_in_document_order() -> None:
    hosts = _parse(_load_fixture())
    assert len(hosts) == 4
    ips = [h.ip for h in hosts]
    assert ips == ["192.168.1.1", "192.168.1.20", "192.168.1.30", "192.168.1.50"]


def test_host_192_168_1_1_mac_and_vendor() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.1")
    assert h is not None
    assert h.mac == "c0:56:27:aa:bb:01"
    assert h.vendor == "Belkin International"


def test_host_192_168_1_1_hostname() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.1")
    assert h is not None
    assert h.hostnames == [("router.lan", "PTR")]


def test_host_192_168_1_1_ports() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.1")
    assert h is not None
    assert len(h.ports) == 4
    port_numbers = sorted(p.port for p in h.ports)
    assert port_numbers == [22, 53, 80, 443]
    for p in h.ports:
        assert p.proto == "tcp"
        assert p.state == "open"


def test_host_192_168_1_1_port_22_service() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.1")
    assert h is not None
    p = _port_by_number(h, 22)
    assert p is not None
    assert p.service == "ssh"
    assert p.product == "Dropbear sshd"
    assert p.version == "2020.81"


def test_host_192_168_1_1_best_osmatch() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.1")
    assert h is not None
    assert h.os_name == "Linux 4.15 - 5.8"
    assert h.os_accuracy == 96
    assert h.os_type == "router"


def test_host_192_168_1_1_status_reason_ttl_none() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.1")
    assert h is not None
    assert h.via == "arp-response"
    assert h.ttl is None


def test_host_192_168_1_20_mac_vendor_hostname() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.20")
    assert h is not None
    assert h.mac == "b8:27:eb:12:34:56"
    assert h.vendor == "Raspberry Pi Foundation"
    assert h.hostnames == [("pi-nas", "PTR")]


def test_host_192_168_1_20_ports() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.20")
    assert h is not None
    assert len(h.ports) == 2
    p22 = _port_by_number(h, 22)
    assert p22 is not None
    assert p22.service == "ssh"
    assert p22.product == "OpenSSH"
    assert p22.version == "9.2p1 Debian 2"
    assert p22.extrainfo == "protocol 2.0"
    p445 = _port_by_number(h, 445)
    assert p445 is not None
    assert p445.service == "smb"
    assert p445.product == "Samba smbd"
    assert p445.version == "4.6.2"


def test_host_192_168_1_20_osmatch() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.20")
    assert h is not None
    assert h.os_name == "Linux 5.4"
    assert h.os_accuracy == 100
    assert h.os_type == "general purpose"


def test_host_192_168_1_30_no_vendor_no_hostnames() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.30")
    assert h is not None
    assert h.mac == "3c:2a:f4:00:00:09"
    assert h.vendor is None
    assert h.hostnames == []


def test_host_192_168_1_30_ports_and_open_filtered() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.30")
    assert h is not None
    assert len(h.ports) == 2
    p631 = _port_by_number(h, 631)
    assert p631 is not None
    assert p631.proto == "tcp"
    assert p631.service == "ipp"
    assert p631.product == "CUPS"
    assert p631.version == "2.4"
    p161 = _port_by_number(h, 161)
    assert p161 is not None
    assert p161.proto == "udp"
    assert p161.state == "open|filtered"


def test_host_192_168_1_30_no_osmatches() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.30")
    assert h is not None
    assert h.os_name is None
    assert h.os_accuracy is None
    assert h.os_type is None


def test_host_192_168_1_50_no_mac_hostnames_and_port() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.50")
    assert h is not None
    assert h.mac is None
    assert h.hostnames == [("scanbox", "user"), ("scanbox.lan", "PTR")]
    assert len(h.ports) == 1
    p = h.ports[0]
    assert p.port == 8080
    assert p.proto == "tcp"
    assert p.state == "open"
    assert h.via == "localhost-response"


def test_host_192_168_1_99_down_is_absent() -> None:
    hosts = _parse(_load_fixture())
    assert _host_by_ip(hosts, "192.168.1.99") is None


# ---------------------------------------------------------------------------
# Edge-case / error tests
# ---------------------------------------------------------------------------


def test_invalid_xml_raises_value_error() -> None:
    with pytest.raises(ValueError):
        _parse("this is not xml")


def test_wrong_root_tag_raises_value_error() -> None:
    with pytest.raises(ValueError):
        _parse("<root><host/></root>")


def test_ipv6_only_host_is_skipped() -> None:
    xml = """<nmaprun>
        <host>
            <status state="up"/>
            <address addr="fe80::1" addrtype="ipv6"/>
            <ports>
                <port protocol="tcp" portid="80"><state state="open"/></port>
            </ports>
        </host>
    </nmaprun>"""
    hosts = _parse(xml)
    assert len(hosts) == 0


def test_closed_port_is_dropped() -> None:
    xml = """<nmaprun>
        <host>
            <status state="up"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
            <ports>
                <port protocol="tcp" portid="22"><state state="closed"/></port>
                <port protocol="tcp" portid="80"><state state="open"/></port>
            </ports>
        </host>
    </nmaprun>"""
    hosts = _parse(xml)
    assert len(hosts) == 1
    h = hosts[0]
    assert len(h.ports) == 1
    assert h.ports[0].port == 80


def test_empty_nmaprun_returns_empty_list() -> None:
    hosts = _parse("<nmaprun></nmaprun>")
    assert hosts == []