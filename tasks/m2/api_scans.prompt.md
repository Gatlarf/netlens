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

## app/api/devices.py
11:DEVICE_TYPES = {
27:def get_conn(request: Request):
38:class DevicePatch(BaseModel):
39:    custom_name: str | None = None
40:    notes: str | None = None
41:    tags: list[str] | None = None
42:    type_override: str | None = None
45:def _parse_tags(value: str | None) -> list[str]:
51:def _device_dict(row: sqlite3.Row) -> dict[str, Any]:
72:def _build_device_detail(conn: sqlite3.Connection, device_id: int, row: sqlite3.Row) -> dict[str, Any]:
106:def list_devices(
107:    request: Request,
108:    online: bool | None = None,
109:    q: str | None = None,
110:    conn: sqlite3.Connection = Depends(get_conn),
130:    params: list[Any] = []
131:    conditions: list[str] = []
154:def get_device(
155:    device_id: int,
156:    conn: sqlite3.Connection = Depends(get_conn),
188:def patch_device(
189:    device_id: int,
190:    body: DevicePatch,
191:    conn: sqlite3.Connection = Depends(get_conn),
224:    updates: dict[str, Any] = {}

## app/scanner/scans.py
7:def create_scan(conn: sqlite3.Connection, kind: str, now: str | None = None) -> int:
18:def finish_scan(
19:    conn: sqlite3.Connection,
20:    scan_id: int,
21:    status: str,
22:    hosts_found: int = 0,
23:    error: str | None = None,
24:    now: str | None = None,
43:def list_scans(conn: sqlite3.Connection, limit: int = 50) -> list[dict]:
52:def running_scan(conn: sqlite3.Connection) -> dict | None:

## app/scanner/orchestrator.py
16:class ScanBusy(RuntimeError):
20:class ScanManager:
21:    def __init__(
39:    def is_running(self) -> bool:
42:    def recover(self) -> int:
64:    async def start(self, kind: str) -> int:
80:    async def wait(self) -> None:
84:    async def _run(self, kind: str, scan_id: int) -> None:

TASK:
Rewrite app/api/scans.py (COMPLETE file, only this one file). Routes receive the sqlite connection with conn: sqlite3.Connection = Depends(get_conn) (from app.api.devices import get_conn; it is a generator dependency, never call it directly). The scan manager is request.app.state.scan_manager (app.scanner.orchestrator.ScanManager: async start(kind) -> int, raises ScanBusy).
router = APIRouter(prefix="/api", tags=["scans"]). Keep GET /scans?limit=50 (limit 1-200 else 422; uses app.scanner.scans.list_scans(conn, limit)) and GET /scans/current -> {"running": bool, "scan": dict | None} using app.scanner.scans.running_scan(conn). Add POST /scans with a pydantic body {"kind": Literal["quick","deep"]} (default "quick"; the body itself may be omitted or {}) -> status 202 {"id": <scan id>} using await request.app.state.scan_manager.start(kind); ScanBusy -> HTTPException 409 with detail "scan already running".
