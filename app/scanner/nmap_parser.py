from dataclasses import dataclass, field
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
    hops: list[str] = field(default_factory=list)
    rtt_ms: Optional[float] = None
    timed_out: bool = False  # nmap gave up on this host (--host-timeout): its port list is incomplete


def parse_nmap_xml(xml_text: str) -> list[ScanHost]:
    if '<!ENTITY' in xml_text:
        raise ValueError('invalid nmap xml')

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
        for addr_elem in host.findall("address"):
            if addr_elem.get("addrtype", "") == "mac":
                raw_mac = addr_elem.get("addr", "")
                if raw_mac:
                    mac = raw_mac.lower()
                vendor = addr_elem.get("vendor")
                break

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

        # Trace hops
        hops: list[str] = []
        trace_elem = host.find("trace")
        if trace_elem is not None:
            for hop in trace_elem.findall("hop"):
                hop_ip = hop.get("ipaddr", "")
                if hop_ip and hop_ip != ip:
                    hops.append(hop_ip)

        # Smoothed round-trip time (nmap reports microseconds)
        rtt_ms: Optional[float] = None
        times_elem = host.find("times")
        if times_elem is not None:
            try:
                srtt = int(times_elem.get("srtt", ""))
                if srtt > 0:
                    rtt_ms = round(srtt / 1000.0, 2)
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
            hops=hops,
            rtt_ms=rtt_ms,
            timed_out=host.get("timedout") == "true",
        ))

    return hosts