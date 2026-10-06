import pathlib
from typing import Optional

import pytest

from app.scanner.nmap_parser import parse_nmap_xml


def test_parse_trace_xml_basic():
    fixture_path = pathlib.Path(__file__).parent / "fixtures" / "trace.xml"
    xml_text = fixture_path.read_text(encoding="utf-8")
    hosts = parse_nmap_xml(xml_text)

    assert len(hosts) == 2

    # First host: 10.0.5.20
    host1 = hosts[0]
    assert host1.ip == "10.0.5.20"
    assert host1.mac is None
    assert host1.hostnames == [("lab-srv", "PTR")]
    assert len(host1.ports) == 1
    port = host1.ports[0]
    assert port.proto == "tcp"
    assert port.port == 22
    assert port.state == "open"
    assert port.service == "ssh"
    assert port.product == "OpenSSH"
    assert port.version == "8.9"
    assert host1.ttl == 62
    assert host1.hops == ["192.168.1.1", "10.0.0.2"]

    # Second host: 192.168.1.20
    host2 = hosts[1]
    assert host2.ip == "192.168.1.20"
    assert host2.mac == "b8:27:eb:12:34:56"
    assert host2.hops == []


def test_parse_deep_xml_hops_empty():
    fixture_path = pathlib.Path(__file__).parent / "fixtures" / "deep.xml"
    xml_text = fixture_path.read_text(encoding="utf-8")
    hosts = parse_nmap_xml(xml_text)

    assert len(hosts) > 0
    for host in hosts:
        assert host.hops == []


def test_trace_element_no_hop_children():
    xml_text = """
    <nmaprun>
        <host>
            <status state="up" reason="arp-response" reason_ttl="0"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
            <trace>
            </trace>
        </host>
    </nmaprun>
    """
    hosts = parse_nmap_xml(xml_text)
    assert len(hosts) == 1
    assert hosts[0].ip == "10.0.0.1"
    assert hosts[0].hops == []


def test_trace_hop_without_ipaddr_skipped():
    xml_text = """
    <nmaprun>
        <host>
            <status state="up" reason="arp-response" reason_ttl="0"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
            <trace>
                <hop ttl="1"/>
                <hop ttl="2" ipaddr="192.168.1.1"/>
                <hop ttl="3"/>
            </trace>
        </host>
    </nmaprun>
    """
    hosts = parse_nmap_xml(xml_text)
    assert len(hosts) == 1
    assert hosts[0].ip == "10.0.0.1"
    assert hosts[0].hops == ["192.168.1.1"]


def test_trace_hop_with_only_ipaddr():
    xml_text = """
    <nmaprun>
        <host>
            <status state="up" reason="arp-response" reason_ttl="0"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
            <trace>
                <hop ipaddr="192.168.1.1"/>
            </trace>
        </host>
    </nmaprun>
    """
    hosts = parse_nmap_xml(xml_text)
    assert len(hosts) == 1
    assert hosts[0].ip == "10.0.0.1"
    assert hosts[0].hops == ["192.168.1.1"]