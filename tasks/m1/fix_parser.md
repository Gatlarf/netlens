Fix the defects below and output the COMPLETE corrected file. Keep everything else identical.

DEFECTS:
1. MAC/vendor are never found: the code looks for a child element named mac. In nmap XML the MAC is an <address> element with addrtype="mac" (attributes addr and vendor), a sibling of the ipv4 address element. Find it among the host's address elements.

CURRENT FILE:
from dataclasses import dataclass
from typing import Optional
import xml.etree.ElementTree as ET


@dataclass
class ScanPort:
    proto: str
    port: int
    state: str
    service: Optional[str]
    product: Optional[str]
    version: Optional[str]
    extrainfo: Optional[str]


@dataclass
class ScanHost:
    ip: str
    mac: Optional[str]
    vendor: Optional[str]
    hostnames: list[tuple[str, str]]
    ports: list[ScanPort]
    os_name: Optional[str]
    os_accuracy: Optional[int]
    os_type: Optional[str]
    ttl: Optional[int]
    via: str


def parse_nmap_xml(xml_text: str) -> list[ScanHost]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError("invalid nmap xml") from exc

    if root.tag != "nmaprun":
        raise ValueError("invalid nmap xml")

    hosts: list[ScanHost] = []

    for host in root.findall("host"):
        # Status check
        status_elem = host.find("status")
        if status_elem is None:
            continue
        status_state = status_elem.get("state", "")
        if status_state != "up":
            continue

        # IPv4 address
        address_elem = host.find("address")
        if address_elem is None:
            continue
        addr_type = address_elem.get("addrtype", "")
        if addr_type != "ipv4":
            continue
        ip = address_elem.get("addr", "")
        if not ip:
            continue

        # MAC
        mac: Optional[str] = None
        vendor: Optional[str] = None
        mac_elem = host.find("mac")
        if mac_elem is not None:
            raw_mac = mac_elem.get("addr", "")
            if raw_mac:
                mac = raw_mac.lower()
            vendor = mac_elem.get("vendor")

        # Hostnames
        hostnames: list[tuple[str, str]] = []
        hostnames_elem = host.find("hostnames")
        if hostnames_elem is not None:
            for hostname in hostnames_elem.findall("hostname"):
                name = hostname.get("name", "")
                htype = hostname.get("type", "")
                if name:
                    hostnames.append((name, htype))

        # Ports
        ports: list[ScanPort] = []
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port_state_elem = port_elem.find("state")
                if port_state_elem is None:
                    continue
                state = port_state_elem.get("state", "")
                if not state.startswith("open"):
                    continue

                proto = port_elem.get("protocol", "")
                port_num_str = port_elem.get("portid", "")
                try:
                    port_num = int(port_num_str)
                except ValueError:
                    continue

                service_name: Optional[str] = None
                product: Optional[str] = None
                version: Optional[str] = None
                extrainfo: Optional[str] = None

                service_elem = port_elem.find("service")
                if service_elem is not None:
                    service_name = service_elem.get("name")
                    product = service_elem.get("product")
                    version = service_elem.get("version")
                    extrainfo = service_elem.get("extrainfo")

                ports.append(ScanPort(
                    proto=proto,
                    port=port_num,
                    state=state,
                    service=service_name,
                    product=product,
                    version=version,
                    extrainfo=extrainfo,
                ))

        # OS
        os_name: Optional[str] = None
        os_accuracy: Optional[int] = None
        os_type: Optional[str] = None

        os_elem = host.find("os")
        if os_elem is not None:
            best_match: Optional[ET.Element] = None
            best_accuracy = -1

            for osmatch in os_elem.findall("osmatch"):
                accuracy_str = osmatch.get("accuracy", "")
                try:
                    accuracy = int(accuracy_str)
                except ValueError:
                    continue
                if accuracy > best_accuracy:
                    best_accuracy = accuracy
                    best_match = osmatch

            if best_match is not None:
                os_name = best_match.get("name")
                os_accuracy = best_accuracy

                first_osclass = best_match.find("osclass")
                if first_osclass is not None:
                    os_type = first_osclass.get("type")

        # TTL and via from status element
        ttl: Optional[int] = None
        via = status_elem.get("reason", "")

        reason_ttl_str = status_elem.get("reason_ttl", "")
        if reason_ttl_str:
            try:
                ttl_val = int(reason_ttl_str)
                if ttl_val > 0:
                    ttl = ttl_val
            except ValueError:
                pass

        hosts.append(ScanHost(
            ip=ip,
            mac=mac,
            vendor=vendor,
            hostnames=hostnames,
            ports=ports,
            os_name=os_name,
            os_accuracy=os_accuracy,
            os_type=os_type,
            ttl=ttl,
            via=via,
        ))

    return hosts