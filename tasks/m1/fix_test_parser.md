Fix the defects below and output the COMPLETE corrected file. Keep everything else identical.

DEFECTS:
The tests use attributes that do not exist. The real dataclasses are: ScanPort(proto, port, state, service, product, version, extrainfo) - the port number attribute is .port, not .number. ScanHost(ip, mac, vendor, hostnames: list[tuple[name,type]], ports, os_name, os_accuracy, os_type, ttl, via) - there is no .hostname, .status or .osmatches. Only the BEST osmatch is exposed (highest accuracy) via os_name/os_accuracy/os_type, so tests about a 'second osmatch' must be removed or replaced by one asserting the best match (accuracy 96, 'Linux 4.15 - 5.8') was chosen over the 90 one. status reason is .via; reason_ttl is .ttl. Rewrite all affected tests to these real names.

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
        if p.number == number:
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
    assert h.hostname == "router.lan"


def test_host_192_168_1_1_ports() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.1")
    assert h is not None
    assert len(h.ports) == 4
    port_numbers = sorted(p.number for p in h.ports)
    assert port_numbers == [22, 53, 80, 443]
    for p in h.ports:
        assert p.protocol == "tcp"
        assert p.state == "open"


def test_host_192_168_1_1_port_22_service() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.1")
    assert h is not None
    p = _port_by_number(h, 22)
    assert p is not None
    assert p.service == "ssh"
    assert p.product == "Dropbear sshd 2020.81"


def test_host_192_168_1_1_osmatch_first_entry() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.1")
    assert h is not None
    assert len(h.osmatches) == 2
    first = h.osmatches[0]
    assert first.name == "Linux 4.15 - 5.8"
    assert first.accuracy == 96
    assert first.type == "router"


def test_host_192_168_1_1_osmatch_second_entry() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.1")
    assert h is not None
    second = h.osmatches[1]
    assert second.name == "OpenWrt 21.02 (Linux 5.4)"
    assert second.accuracy == 90
    assert second.type == "WAP"


def test_host_192_168_1_1_status_reason_ttl_none() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.1")
    assert h is not None
    assert h.status == "up"
    assert h.reason == "arp-response"
    assert h.ttl is None


def test_host_192_168_1_20_mac_vendor_hostname() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.20")
    assert h is not None
    assert h.mac == "b8:27:eb:12:34:56"
    assert h.vendor == "Raspberry Pi Foundation"
    assert h.hostname == "pi-nas"


def test_host_192_168_1_20_ports() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.20")
    assert h is not None
    assert len(h.ports) == 2
    p22 = _port_by_number(h, 22)
    assert p22 is not None
    assert p22.service == "ssh"
    assert p22.product == "OpenSSH 9.2p1 Debian 2"
    assert p22.extrainfo == "protocol 2.0"
    p445 = _port_by_number(h, 445)
    assert p445 is not None
    assert p445.service == "smb"
    assert p445.product == "Samba smbd 4.6.2"


def test_host_192_168_1_20_osmatch() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.20")
    assert h is not None
    assert len(h.osmatches) == 1
    osm = h.osmatches[0]
    assert osm.name == "Linux 5.4"
    assert osm.accuracy == 100
    assert osm.type == "general purpose"


def test_host_192_168_1_30_no_vendor_no_hostnames() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.30")
    assert h is not None
    assert h.mac == "3c:2a:f4:00:00:09"
    assert h.vendor is None
    assert h.hostname is None


def test_host_192_168_1_30_ports_and_open_filtered() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.30")
    assert h is not None
    assert len(h.ports) == 2
    p631 = _port_by_number(h, 631)
    assert p631 is not None
    assert p631.protocol == "tcp"
    assert p631.service == "ipp"
    assert p631.product == "CUPS 2.4"
    p161 = _port_by_number(h, 161)
    assert p161 is not None
    assert p161.protocol == "udp"
    assert p161.state == "open|filtered"


def test_host_192_168_1_30_no_osmatches() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.30")
    assert h is not None
    assert len(h.osmatches) == 0


def test_host_192_168_1_50_no_mac_hostnames_and_port() -> None:
    hosts = _parse(_load_fixture())
    h = _host_by_ip(hosts, "192.168.1.50")
    assert h is not None
    assert h.mac is None
    assert h.hostname == "scanbox.lan"
    assert len(h.ports) == 1
    p = h.ports[0]
    assert p.number == 8080
    assert p.protocol == "tcp"
    assert p.state == "open"
    assert h.reason == "localhost-response"


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
    assert h.ports[0].number == 80


def test_empty_nmaprun_returns_empty_list() -> None:
    hosts = _parse("<nmaprun></nmaprun>")
    assert hosts == []