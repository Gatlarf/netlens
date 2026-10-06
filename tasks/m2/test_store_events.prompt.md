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

## app/scanner/store.py
9:def save_scan_results(
10:    conn: Any,
11:    hosts: list[ScanHost],
12:    kind: str,
13:    now: str | None = None,
14:    extra_names: dict[str, list[tuple[str, str]]] | None = None,
23:    processed_hosts: list[ScanHost] = []
42:    device_ids: list[int] = []

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
Create tests/test_store_events.py with pytest for app.scanner.store.save_scan_results(conn, hosts, kind, now=None, extra_names=None). Use app.db.connect(":memory:") + init_db and parse tests/fixtures/deep.xml with app.scanner.nmap_parser.parse_nmap_xml(path.read_text(encoding="utf-8")) (path relative to the test file). Fixture hosts: 192.168.1.1 (mac c0:56:27:aa:bb:01, vendor Belkin International, ports tcp 22,53,80,443, os Linux 4.15 - 5.8), 192.168.1.20 (mac b8:27:eb:12:34:56, ports 22,445), 192.168.1.30 (mac 3c:2a:f4:00:00:09, ports tcp 631 and udp 161 open|filtered), 192.168.1.50 (no mac, port 8080). Build modified hosts with dataclasses.replace(host, ...). Read events with conn.execute("SELECT kind, detail, device_id FROM events ORDER BY id").
Tests: first deep save creates exactly 4 events of kind device_new and no port_opened events; saving the identical hosts again creates no further events; replace host .1 ip with 192.168.1.2 (same mac) -> exactly one ip_changed event with detail "192.168.1.1 -> 192.168.1.2"; set devices.online=0 for the .20 device then resave -> one device_online event and online back to 1; replace .1 with ports plus an extra ScanPort(proto="tcp", port=8443, state="open", service="https-alt", product=None, version=None, extrainfo=None) -> one port_opened event with detail "tcp/8443 https-alt"; replace .1 with os_name "OpenWrt 21.02" -> one os_changed event "Linux 4.15 - 5.8 -> OpenWrt 21.02"; a rescan whose host has os_name None produces no os_changed event; classification: after the deep save device_type of .30 is "printer", of .1 is "router", of .20 is "server"; type_override stays unchanged when set to "nas" before a rescan while device_type is still recalculated; extra_names {"192.168.1.30": [("office-printer", "mdns")]} adds a device_names row with source "mdns" and (because no PTR exists) sets hostname to "office-printer"; the input hosts list is not mutated by extra_names. At least 11 tests.
