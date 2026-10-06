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
29:    hops: list[str] = field(default_factory=list)
32:def parse_nmap_xml(xml_text: str) -> list[ScanHost]:
41:    hosts: list[ScanHost] = []

TASK:
Create tests/test_nmap_trace.py with pytest for app.scanner.nmap_parser.parse_nmap_xml (returns list[ScanHost]; new field ScanHost.hops: list[str]). Load tests/fixtures/trace.xml (path relative to the test file; read_text(encoding="utf-8")). Expected: 2 hosts in order: 10.0.5.20 (no mac, hostnames [("lab-srv","PTR")], one open port tcp 22 ssh OpenSSH 8.9, ttl 62, hops == ["192.168.1.1", "10.0.0.2"]) and 192.168.1.20 (mac b8:27:eb:12:34:56, hops == [] because its only hop is itself). Also: tests/fixtures/deep.xml hosts all have hops == []; a host with a trace element that has no hop children gets []; a trace hop without an ipaddr attribute is skipped (inline XML). At least 5 tests.
