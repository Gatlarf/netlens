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
12:VERSION = "0.1.0"
16:async def lifespan(app: FastAPI):
26:def create_app(settings: Any, db_path: str | os.PathLike | None = None) -> FastAPI:
38:    async def health() -> dict[str, str]:
44:def main() -> None:

## app/scanner/orchestrator.py
16:class ScanBusy(RuntimeError):
20:class ScanManager:
21:    def __init__(
39:    def is_running(self) -> bool:
42:    def recover(self) -> int:
64:    async def start(self, kind: str) -> int:
80:    async def wait(self) -> None:
84:    async def _run(self, kind: str, scan_id: int) -> None:

## app/scanner/scheduler.py
15:def due_kind(
16:    now: float,
17:    started_at: float,
18:    last_quick: Optional[float],
19:    last_deep: Optional[float],
20:    quick_interval: float,
21:    deep_interval: float,
50:async def scheduler_loop(
51:    manager: ScanManager,
52:    quick_interval: float,
53:    deep_interval: float,
55:    poll: float = 15.0,
56:    clock: callable = time.monotonic,
57:    sleep: callable = asyncio.sleep,
73:    last_quick: Optional[float] = None
74:    last_deep: Optional[float] = None

TASK:
Rewrite app/main.py (COMPLETE file). Keep: VERSION = "0.1.0"; GET /api/health -> {"status": "ok", "version": VERSION} unauthenticated; the devices and scans routers (app.api.devices.router, app.api.scans.router); lifespan that opens app.db.connect(app.state.db_path), runs app.db.init_db(conn) and closes it (nothing touches the database inside create_app itself); main() that loads settings with app.config.load_settings() and runs uvicorn on settings.bind_host/bind_port; no module-level app instance; FastAPI(title="Netlens"); app.state.settings and app.state.db_path (str; default settings.data_dir / "netlens.db").
Changes: signature create_app(settings, db_path=None, *, scheduler: bool = False, scan_manager=None). Create app.state.scan_manager = scan_manager or app.scanner.orchestrator.ScanManager(app.state.db_path, settings). Also include the new router app.api.events.router. In the lifespan, after init_db call app.state.scan_manager.recover(); if scheduler is True start asyncio.create_task(app.scanner.scheduler.scheduler_loop(manager, settings.quick_interval, settings.deep_interval)) and on shutdown cancel it and await it (suppress CancelledError). main() must call create_app(settings, scheduler=True).
