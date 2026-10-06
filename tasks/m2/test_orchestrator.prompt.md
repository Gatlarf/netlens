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
16:class ScanBusy(RuntimeError):
20:class ScanManager:
21:    def __init__(
39:    def is_running(self) -> bool:
42:    def recover(self) -> int:
64:    async def start(self, kind: str) -> int:
80:    async def wait(self) -> None:
84:    async def _run(self, kind: str, scan_id: int) -> None:

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
Create tests/test_orchestrator.py with pytest (asyncio_mode=auto) for app.scanner.orchestrator (ScanManager, ScanBusy). Setup helper: settings = app.config.load_settings({"NETLENS_TOKEN": "t"}) (ranges empty) or with {"NETLENS_RANGES": "192.168.1.0/24"}; db_path = tmp_path / "t.db" initialised with app.db.connect(db_path) + init_db; the XML fixture text is Path(__file__).parent/"fixtures"/"deep.xml" read_text(encoding="utf-8") (4 up hosts: 192.168.1.1, .20, .30, .50). Inject fakes: async def fake_runner(kind, targets, *, nmap_path="nmap") returning the XML text and recording (kind, targets); async def fake_names() returning {}; async def fake_ranges() returning ["192.168.1.0/24"]. Construct ScanManager(db_path, settings, runner=..., names_provider=..., ranges_provider=...). Read results with app.db.connect(db_path) and SQL on scans/devices/events.
Tests: start("quick") returns an int id, after await manager.wait() the scan row has status "done", hosts_found 4, finished not NULL and devices has 4 rows; runner received kind and targets ["192.168.1.0/24"] from the ranges provider; when settings.ranges is set the ranges provider is not called and the runner gets those ranges; with no ranges from provider (returns []) and settings.ranges empty the scan ends failed with error containing "no scan ranges"; runner raising app.scanner.nmap_runner.ScanError("boom") -> status failed, error "boom"; names provider raising an exception does not fail the scan; extra names from the provider ({"192.168.1.30": [("office-printer","mdns")]}) end up in device_names; starting a second scan while the first runner is blocked on an asyncio.Event raises ScanBusy, after releasing the event and wait() a new start works; is_running() is True during and False after; invalid kind raises ValueError; offline marking: pre-seed devices 192.168.1.77 (in range, not in the XML) and 10.9.9.9 (outside range) via get_or_create_device; after the scan the first is online=0 with a device_offline event and the second still online=1; recover() marks a pre-created running scan (create_scan) as failed with error "interrupted by restart" and returns 1, and returns 0 when nothing is running. At least 12 tests.
