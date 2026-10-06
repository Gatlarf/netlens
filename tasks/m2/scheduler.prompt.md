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

TASK:
Create app/scanner/scheduler.py (asyncio, stdlib). Uses app.scanner.orchestrator ScanManager (async start(kind) -> int, raises ScanBusy if busy, is_running()) and ScanBusy.
def due_kind(now: float, started_at: float, last_quick: float | None, last_deep: float | None, quick_interval: float, deep_interval: float) -> str | None:
- if last_quick is None and last_deep is None -> "quick" (immediately after start).
- deep is due when (last_deep is not None and now - last_deep >= deep_interval) or (last_deep is None and now - started_at >= 600); return "deep" if deep is due.
- else "quick" if last_quick is not None and now - last_quick >= quick_interval; else None.
async def scheduler_loop(manager, quick_interval: float, deep_interval: float, *, poll: float = 15.0, clock=time.monotonic, sleep=asyncio.sleep) -> None: started_at = clock(); loop forever: kind = due_kind(...); if kind and not manager.is_running(): try: await manager.start(kind) except ScanBusy: pass; except Exception: log with logging.getLogger(__name__).exception and continue; on success set last_quick = now (and last_deep = now if kind == "deep"; a deep scan also counts as quick); then await sleep(poll). asyncio.CancelledError must propagate (do not catch BaseException).
