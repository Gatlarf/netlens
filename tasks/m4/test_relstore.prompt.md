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

## app/scanner/relstore.py
7:def replace_inferred(conn: sqlite3.Connection, edges: list[Edge]) -> None:
21:def list_relations(conn: sqlite3.Connection) -> list[dict[str, Any]]:
33:def add_manual(
34:    conn: sqlite3.Connection,
35:    src_id: int,
36:    dst_id: int,
37:    kind: str = "manual",
83:def delete_relation(conn: sqlite3.Connection, relation_id: int) -> bool:

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
Create tests/test_relstore.py with pytest for app.scanner.relstore (replace_inferred, list_relations, add_manual, delete_relation) and app.scanner.relations.Edge. Use app.db.connect(":memory:"), init_db, and app.db.get_or_create_device(conn, mac, ip) for ids (mac strings like "aa:bb:cc:dd:ee:01"). Tests: replace_inferred stores edges with manual 0 and list_relations returns dicts with keys id, src_id, dst_id, kind, source, confidence, manual; calling it again with different edges removes the old inferred ones; manual edges survive replace_inferred; replace_inferred does not overwrite or duplicate an existing manual edge with the same (src,dst,kind); add_manual returns an id, rejects self links, unknown devices and invalid kinds with ValueError; delete_relation on a manual edge removes it; on an inferred edge hides it (list_relations no longer shows it) and a later replace_inferred with the same edge does NOT bring it back; add_manual on a suppressed edge re-activates it (manual 1); delete_relation of an unknown id returns False; deleting a device cascades its relations. At least 10 tests.
