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

## app/scanner/relations.py
5:@dataclass(frozen=True)
6:class Edge:
7:    src_id: int
8:    dst_id: int
9:    kind: str
10:    source: str
11:    confidence: float
14:def infer_relations(
15:    devices: list[dict],
16:    hops: Optional[dict[str, list[str]]] = None,
17:    gateway_ip: Optional[str] = None,
22:    ip_to_id: dict[str, int] = {}
29:    gw_id: Optional[int] = None
30:    gw_source: str = "default-route"
31:    gw_confidence: float = 1.0
43:    edges: list[Edge] = []
44:    seen: set[tuple[int, int, str]] = set()
46:    def add_edge(src_id: int, dst_id: int, kind: str, source: str, confidence: float) -> None:
119:    candidates: list[dict] = []

TASK:
Create tests/test_relations.py with pytest for app.scanner.relations (Edge, infer_relations). Helper mk(id, ip, type="pc", hostname=None, vendor=None, ports=(), online=1) returns the dict {"id","primary_ip","type","hostname","vendor","ports":list(ports),"online"}. Cases: (1) router id1 192.168.1.1, pcs ids 2,3, gateway_ip "192.168.1.1" -> exactly Edge(2,1,"gateway","default-route",1.0) and Edge(3,1,...) and no edge from 1; (2) gateway_ip None and exactly one router -> edges with source "heuristic" confidence 0.5; (3) gateway_ip None and two routers (or none) -> []; (4) gateway_ip "192.168.1.254" not among devices -> no gateway edges; (5) route: devices gw id1 192.168.1.1 (router), core id2 10.0.0.2 (router), srv id3 10.0.5.20, hops {"10.0.5.20": ["192.168.1.1","10.0.0.2"]}, gateway_ip "192.168.1.1" -> srv has a "route" edge to id2 (Edge(3,2,"route","traceroute",0.9)), a "route" edge Edge(2,1,"route",...) chaining core to the gateway, and srv gets NO gateway edge; (6) unknown hop IPs are ignored and when ALL hops are unknown the device gets a gateway edge instead; (7) host-of: vm id4 (type "vm") and one device with port 8006 id5 -> Edge(4,5,"host-of","heuristic",0.5); two candidates -> none; hostname "proxmox1" counts as a candidate; zero candidates -> none; (8) result sorted by (kind, src_id, dst_id) with no duplicates and no self edges; empty device list -> []. At least 10 tests.
