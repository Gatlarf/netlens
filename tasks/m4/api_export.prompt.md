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
43:    pos_x: float | None = None
44:    pos_y: float | None = None
47:def _parse_tags(value: str | None) -> list[str]:
53:def _device_dict(row: sqlite3.Row) -> dict[str, Any]:
78:def _build_device_detail(conn: sqlite3.Connection, device_id: int, row: sqlite3.Row) -> dict[str, Any]:
129:def list_devices(
130:    request: Request,
131:    online: bool | None = None,
132:    q: str | None = None,
133:    conn: sqlite3.Connection = Depends(get_conn),
157:    params: list[Any] = []
158:    conditions: list[str] = []
181:def get_device(
182:    device_id: int,
183:    conn: sqlite3.Connection = Depends(get_conn),
219:def patch_device(
220:    device_id: int,
221:    body: DevicePatch,
222:    conn: sqlite3.Connection = Depends(get_conn),
259:    updates: dict[str, Any] = {}

TASK:
Create app/api/export.py (FastAPI, stdlib csv/io/json). Routes receive the sqlite connection via conn: sqlite3.Connection = Depends(get_conn) (from app.api.devices import get_conn; a generator dependency, never call it directly). router = APIRouter(prefix="/api/export", tags=["export"]).
Build rows once with a helper: for every device (ordered by primary_ip, id): id, name (custom_name or hostname or primary_ip), ip (primary_ip), mac, hostname, vendor, type (type_override or device_type or "unknown"), os (os_name), os_confidence, online (bool), first_seen, last_seen, tags (comma separated string), notes, open_ports (list of "proto/port/service" strings from the ports table where state LIKE 'open%', ordered by proto, port; service omitted when null).
- GET /devices.json -> a JSON response (list of dicts, open_ports as a list, tags as a list) with header Content-Disposition: attachment; filename="netlens-devices.json".
- GET /devices.csv -> text/csv; charset=utf-8 with Content-Disposition: attachment; filename="netlens-devices.csv". Header row = the keys above in that order; open_ports joined with " " and tags with ", ". CSV injection protection: any string cell whose first character is one of = + - @ (or a tab or carriage return) is prefixed with a single quote. Use csv.writer with QUOTE_MINIMAL into io.StringIO and return Response(content=..., media_type="text/csv; charset=utf-8", headers=...).
