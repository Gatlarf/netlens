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

## app/scanner/orchestrator.py
19:class ScanBusy(RuntimeError):
23:class ScanManager:
24:    def __init__(
44:    def is_running(self) -> bool:
47:    def recover(self) -> int:
69:    async def start(self, kind: str) -> int:
85:    async def wait(self) -> None:
89:    async def _run(self, kind: str, scan_id: int) -> None:

## app/scanner/relstore.py
7:def replace_inferred(conn: sqlite3.Connection, edges: list[Edge]) -> None:
21:def list_relations(conn: sqlite3.Connection) -> list[dict[str, Any]]:
33:def add_manual(
34:    conn: sqlite3.Connection,
35:    src_id: int,
36:    dst_id: int,
37:    kind: str = "manual",
83:def delete_relation(conn: sqlite3.Connection, relation_id: int) -> bool:

TASK:
Create tests/test_orchestrator_relations.py with pytest (asyncio_mode=auto) for the relation step of app.scanner.orchestrator.ScanManager. Setup: settings = app.config.load_settings({"NETLENS_TOKEN": "t", "NETLENS_RANGES": "192.168.1.0/24"}); db_path = tmp_path/"t.db" initialised with app.db.connect + init_db (close it). XML text from tests/fixtures/deep.xml (hosts .1 router, .20, .30, .50) via Path(__file__).parent. Fakes: async def fake_runner(kind, targets, *, nmap_path="nmap") returning the XML; async def fake_names(): return {}; async def fake_gateway(): return "192.168.1.1"; ScanManager(db_path, settings, runner=fake_runner, names_provider=fake_names, ranges_provider=<async returning ["192.168.1.0/24"]>, gateway_provider=fake_gateway). Tests: after start("deep") and wait(), app.scanner.relstore.list_relations(conn) has exactly 3 gateway edges, all with dst_id equal to the id of the device with primary_ip 192.168.1.1 and source "default-route"; a gateway_provider that raises RuntimeError does not fail the scan (status done) and, since no gateway IP is known but exactly one device (192.168.1.1, type router) is a router, still yields 3 edges with source "heuristic"; a manual relation added before the scan (relstore.add_manual between two devices created via get_or_create_device with the same macs as the fixture: .20 mac b8:27:eb:12:34:56 and .30 mac 3c:2a:f4:00:00:09) survives the scan; hiding an inferred edge with delete_relation and scanning again keeps it hidden; a second scan does not duplicate edges. At least 5 tests.
