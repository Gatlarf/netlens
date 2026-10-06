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

## app/db.py
11:SCHEMA_VERSION = 1
14:def utcnow() -> str:
19:def connect(path: str | os.PathLike) -> sqlite3.Connection:
43:def init_db(conn: sqlite3.Connection) -> None:
210:def _normalize_mac(mac: str | None) -> str | None:
223:def get_or_create_device(
224:    conn: sqlite3.Connection,
225:    mac: str | None,
226:    ip: str,
227:    now: str | None = None,
236:    device_id: int | None = None
298:def add_event(
299:    conn: sqlite3.Connection,
300:    kind: str,
301:    detail: str | None = None,
302:    device_id: int | None = None,
303:    now: str | None = None,
321:def list_devices(conn: sqlite3.Connection) -> list[dict[str, Any]]:

TASK:
Create app/scanner/relstore.py (stdlib sqlite3; connections use row_factory=sqlite3.Row). Table: relations(id INTEGER PRIMARY KEY, src_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, dst_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, kind TEXT NOT NULL, source TEXT NOT NULL, confidence REAL NOT NULL DEFAULT 1.0, manual INTEGER NOT NULL DEFAULT 0, UNIQUE(src_id, dst_id, kind)). manual values: 0 = inferred, 1 = added by the owner, -1 = an inferred edge hidden by the owner (suppressed). Edge is the dataclass app.scanner.relations.Edge(src_id, dst_id, kind, source, confidence).
- def replace_inferred(conn, edges: list[Edge]) -> None: delete every row with manual = 0, then insert each edge with manual = 0 unless a row with the same (src_id, dst_id, kind) already exists (manual 1 or -1 rows are kept untouched and win). Commit.
- def list_relations(conn) -> list[dict]: rows with manual >= 0 (hide suppressed) as dicts {id, src_id, dst_id, kind, source, confidence, manual}, ordered by id.
- def add_manual(conn, src_id: int, dst_id: int, kind: str = "manual") -> int: ValueError if src_id == dst_id, kind not in {"manual","gateway","route","host-of","service"}, or either device id does not exist (KeyError is NOT used: raise ValueError("unknown device")). If a row with the same (src,dst,kind) exists: set manual = 1, source "manual", confidence 1.0 and return its id (this re-activates a suppressed edge). Otherwise insert with manual 1, source "manual", confidence 1.0. Commit, return id.
- def delete_relation(conn, relation_id: int) -> bool: if the row has manual == 1 delete it; if manual == 0 set manual = -1; if manual == -1 or missing return False. Commit. Return True when something changed.
