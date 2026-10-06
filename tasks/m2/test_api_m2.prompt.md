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
16:VERSION = "0.1.0"
19:async def lifespan(app: FastAPI):
46:def create_app(
47:    settings: Any,
48:    db_path: str | os.PathLike | None = None,
50:    scheduler: bool = False,
51:    scan_manager: ScanManager | None = None,
65:    async def health() -> dict[str, str]:
71:def main() -> None:

## app/api/scans.py
14:class ScanBody(BaseModel):
15:    kind: Literal["quick", "deep"] = "quick"
19:def get_scans(
20:    request: Request,
21:    limit: int = Field(default=50, ge=1, le=200),
22:    conn: sqlite3.Connection = Depends(get_conn),
28:def get_current_scan(
29:    request: Request,
30:    conn: sqlite3.Connection = Depends(get_conn),
37:async def create_scan(
38:    request: Request,
39:    body: ScanBody,
40:    conn: sqlite3.Connection = Depends(get_conn),
62:def get_events(
63:    request: Request,
64:    limit: int = 100,
65:    kind: str | None = None,
66:    device_id: int | None = None,
67:    conn: sqlite3.Connection = Depends(get_conn),
72:    conditions: list[str] = []
73:    params: list[Any] = []

## app/api/events.py
13:class EventDict(BaseModel):
14:    id: int
15:    ts: str
16:    device_id: int | None
17:    kind: str
18:    detail: str | None
22:def list_events(
23:    limit: int = Query(100, ge=1, le=500),
24:    kind: str | None = None,
25:    device_id: int | None = None,
26:    conn: sqlite3.Connection = Depends(get_conn),
28:    conditions: list[str] = []
29:    params: list[Any] = []

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
Create tests/test_api_m2.py with pytest and fastapi.testclient.TestClient. Build the app: settings = app.config.load_settings({"NETLENS_TOKEN": "t"}); create_app(settings, db_path=tmp_path / "t.db", scan_manager=fake) where fake is a simple object with: recover() returning 0; async start(kind) that records the kind and returns 42 (or raises app.scanner.orchestrator.ScanBusy("scan already running") when a flag is set); is_running(). Use `with TestClient(app) as client:` so the lifespan runs. Seed events with a connection from app.db.connect(tmp_path/"t.db"): add_event(conn, "device_new", "x", device_id=<id from get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.5")>), more events of kinds "device_offline", "port_opened".
Tests: POST /api/scans with {"kind":"deep"} returns 202 {"id": 42} and the fake saw "deep"; POST with {} defaults to quick; invalid kind "full" gives 422; busy gives 409 with detail "scan already running"; GET /api/events returns newest first with keys id, ts, device_id, kind, detail; kind filter; device_id filter; limit works; limit=0 and limit=501 give 422; unknown kind filter returns []; GET /api/health still ok; the lifespan calls recover() once (count calls on the fake). Also an end-to-end test with the REAL ScanManager: create_app(settings, db_path=..., ) with default manager but monkeypatch nothing: instead construct app.scanner.orchestrator.ScanManager(db_path, settings, runner=fake_async_runner returning the text of tests/fixtures/deep.xml, names_provider=async lambda returning {}, ranges_provider=async returning ["192.168.1.0/24"]) and pass it as scan_manager; POST /api/scans then poll GET /api/scans/current until running is false (max 5 s, sleep 0.05) and assert GET /api/devices returns 4 devices and GET /api/events contains four device_new events. At least 12 tests.
