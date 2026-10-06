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

## app/main.py
21:VERSION = "0.1.0"
25:async def lifespan(app: FastAPI):
52:def create_app(
53:    settings: Any,
54:    db_path: str | os.PathLike | None = None,
56:    scheduler: bool = False,
57:    scan_manager: ScanManager | None = None,
78:    async def health() -> dict[str, str]:
88:def main() -> None:

## app/api/relations.py
13:class RelationCreate(BaseModel):
14:    src_id: int
15:    dst_id: int
16:    kind: str = "manual"
20:def get_relations(conn: sqlite3.Connection = Depends(get_conn)) -> list[dict[str, Any]]:
25:def create_relation(
26:    body: RelationCreate,
27:    conn: sqlite3.Connection = Depends(get_conn),
37:def remove_relation(
38:    relation_id: int,
39:    conn: sqlite3.Connection = Depends(get_conn),
46:def get_map(conn: sqlite3.Connection = Depends(get_conn)) -> dict[str, Any]:
47:    nodes: list[dict[str, Any]] = []
77:    edges: list[dict[str, Any]] = []

## app/api/export.py
15:def _csv_safe(value: str) -> str:
21:def _build_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
22:    rows: list[dict[str, Any]] = []
104:def export_devices_json(
105:    request: Request,
106:    conn: sqlite3.Connection = Depends(get_conn),
117:def export_devices_csv(
118:    request: Request,
119:    conn: sqlite3.Connection = Depends(get_conn),

TASK:
Create tests/test_api_m4.py with pytest and fastapi.testclient.TestClient for the relations, map and export endpoints. Build: settings = app.config.load_settings({"NETLENS_TOKEN": "t"}); app = app.main.create_app(settings, db_path=tmp_path/"t.db"); seed BEFORE starting the client with a connection from app.db.connect(tmp_path/"t.db") + init_db: save_scan_results(conn, parse_nmap_xml(Path(__file__).parent.joinpath("fixtures","deep.xml").read_text(encoding="utf-8")), "deep") from app.scanner.store / app.scanner.nmap_parser; then close it; use `with TestClient(app) as client:` (a conftest adds the right Authorization header by default). Devices: id 1 = 192.168.1.1, 2 = .20 (pi-nas, vendor Raspberry Pi Foundation), 3 = .30, 4 = .50.
Tests: GET /api/relations is [] at first; POST /api/relations {"src_id":2,"dst_id":1} -> 201 with an int id and it then appears in GET with manual 1 and kind "manual"; POST self link -> 422; POST unknown device 999 -> 422; POST invalid kind "bogus" -> 422; DELETE existing -> 204 and the list is empty again; DELETE unknown -> 404 with detail "relation not found"; second DELETE of the same -> 404; GET /api/map has "nodes" (4, ordered by id, each with keys id,label,ip,mac,vendor,type,online,pos_x,pos_y,open_ports,tags; node 1 label "router.lan", open_ports 4, online true, type "router") and "edges" (after one POST: one edge with keys id,from,to,kind,source,confidence,manual and from 2, to 1, manual true); PATCH /api/devices/1 with {"pos_x": 12.5, "pos_y": -3} is reflected in /api/map node 1 positions. Export: GET /api/export/devices.json returns 4 dicts with keys id,name,ip,mac,hostname,vendor,type,os,os_confidence,online,first_seen,last_seen,tags,notes,open_ports, a Content-Disposition header containing attachment and netlens-devices.json, device 1 open_ports == ["tcp/22/ssh","tcp/53/domain","tcp/80/http","tcp/443/https"]; GET /api/export/devices.csv has content-type starting with text/csv, header row equal to those keys joined by commas, 4 data rows (parse with csv.reader), and a CSV injection check: PATCH device 3 custom_name "=cmd|' /C calc'!A0" then the name cell in the CSV starts with a single quote; all these endpoints return 401 without credentials (client.headers.pop("Authorization") on a fresh client). At least 14 tests.
