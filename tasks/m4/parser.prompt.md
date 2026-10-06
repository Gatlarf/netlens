INTERFACES OF EXISTING CODE (use these exact names; do not invent attributes, columns or functions that are not listed):

## Database schema (app/db.py, SQLite, connections use row_factory=sqlite3.Row)
CREATE TABLE schema_version (
            version INTEGER
        )
CREATE TABLE devices (
            id INTEGER PRIMARY KEY,
            mac TEXT UNIQUE,
            primary_ip TEXT,
            hostname TEXT,
            vendor TEXT,
            os_name TEXT,
            os_confidence INTEGER,
            device_type TEXT,
            type_override TEXT,
            custom_name TEXT,
            notes TEXT,
            tags TEXT,
            online INTEGER NOT NULL DEFAULT 1,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            pos_x REAL,
            pos_y REAL,
            raw_xml TEXT
        )
CREATE TABLE device_ips (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            ip TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(device_id, ip)
        )
CREATE TABLE device_names (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(device_id, name, source)
        )
CREATE TABLE ports (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            proto TEXT NOT NULL,
            port INTEGER NOT NULL,
            state TEXT NOT NULL,
            service TEXT,
            product TEXT,
            version TEXT,
            updated TEXT NOT NULL,
            UNIQUE(device_id, proto, port)
        )
CREATE TABLE scans (
            id INTEGER PRIMARY KEY,
            kind TEXT NOT NULL,
            status TEXT NOT NULL,
            started TEXT NOT NULL,
            finished TEXT,
            hosts_found INTEGER NOT NULL DEFAULT 0,
            error TEXT
        )
CREATE TABLE events (
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            kind TEXT NOT NULL,
            detail TEXT
        )
CREATE TABLE relations (
            id INTEGER PRIMARY KEY,
            src_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            dst_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 1.0,
            manual INTEGER NOT NULL DEFAULT 0,
            UNIQUE(src_id, dst_id, kind)
        )
CREATE TABLE settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
CREATE TABLE host_keys (
            device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
            fingerprint TEXT NOT NULL,
            first_seen TEXT NOT NULL
        )

## app/scanner/nmap_parser.py
6:@dataclass
7:class ScanPort:
8:    proto: str
9:    port: int
10:    state: str
11:    service: Optional[str]
12:    product: Optional[str]
13:    version: Optional[str]
14:    extrainfo: Optional[str]
17:@dataclass
18:class ScanHost:
19:    ip: str
20:    mac: Optional[str]
21:    vendor: Optional[str]
22:    hostnames: list[tuple[str, str]]
23:    ports: list[ScanPort]
24:    os_name: Optional[str]
25:    os_accuracy: Optional[int]
26:    os_type: Optional[str]
27:    ttl: Optional[int]
28:    via: str
31:def parse_nmap_xml(xml_text: str) -> list[ScanHost]:
40:    hosts: list[ScanHost] = []

TASK:
Fix and extend app/scanner/nmap_parser.py (output the COMPLETE file; the current file is given as CURRENT FILE). Keep every existing behaviour and field. Add one dataclass field to ScanHost at the END with a default: hops: list[str] = field(default_factory=list) (import field from dataclasses). Fill it from the host's <trace> element: the ipaddr attribute of every <hop> child in document order, EXCLUDING hops whose ipaddr equals the host's own ipv4 address (the destination is listed as the last hop). Hosts without a trace element get []. Example: for 10.0.5.20 with hops 192.168.1.1, 10.0.0.2, 10.0.5.20 the result is ["192.168.1.1", "10.0.0.2"].

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