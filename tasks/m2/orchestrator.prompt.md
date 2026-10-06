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

## app/scanner/nmap_runner.py
13:class ScanError(RuntimeError):
17:def build_args(kind: str, targets: list[str], timing: int = 3) -> list[str]:
58:def _is_valid_target(target: str) -> bool:
83:async def run_nmap(
84:    kind: str,
85:    targets: list[str],
87:    nmap_path: str = "nmap",
88:    timing: int = 3,
89:    timeout: float = 3600.0,

## app/scanner/store.py
9:def save_scan_results(
10:    conn: Any,
11:    hosts: list[ScanHost],
12:    kind: str,
13:    now: str | None = None,
14:    extra_names: dict[str, list[tuple[str, str]]] | None = None,
23:    processed_hosts: list[ScanHost] = []
42:    device_ids: list[int] = []

## app/scanner/presence.py
8:def mark_offline(
9:    conn: sqlite3.Connection,
10:    seen_ids: set[int] | list[int] | tuple[int, ...],
11:    ranges: list[str],
12:    now: str | None = None,
27:    offline_ids: list[int] = []

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

## app/scanner/netinfo.py
10:def parse_ip_addr(text: str) -> list[str]:
16:    networks: set[str] = set()
62:def parse_default_gateway(text: str) -> Optional[str]:
100:async def run_ip(args: list[str], ip_path: str = "ip", timeout: float = 5.0) -> str:
130:async def detect_ranges(ip_path: str = "ip") -> list[str]:
136:async def detect_gateway(ip_path: str = "ip") -> Optional[str]:

## app/scanner/names.py
14:def parse_ssdp_response(text: str) -> dict[str, str]:
22:    result: dict[str, str] = {}
45:def parse_upnp_description(xml_text: str) -> dict[str, str]:
59:    result: dict[str, str] = {}
85:async def ssdp_search(timeout: float = 3.0) -> dict[str, list[tuple[str, str]]]:
93:    result: dict[str, list[tuple[str, str]]] = {}
161:async def mdns_browse(timeout: float = 3.0) -> dict[str, list[tuple[str, str]]]:
167:    result: dict[str, list[tuple[str, str]]] = {}
229:async def collect_names(timeout: float = 3.0) -> dict[str, list[tuple[str, str]]]:
251:    merged: dict[str, list[tuple[str, str]]] = {}

TASK:
Create app/scanner/orchestrator.py (asyncio). Existing pieces you use:
- app.scanner.nmap_runner: ScanError, async run_nmap(kind, targets, *, nmap_path="nmap", timing=3, timeout=3600.0) -> str (nmap XML text).
- app.scanner.nmap_parser.parse_nmap_xml(xml_text) -> list[ScanHost].
- app.scanner.store.save_scan_results(conn, hosts, kind, now=None, extra_names=None) -> {"new","updated","device_ids"}.
- app.scanner.presence.mark_offline(conn, seen_ids, ranges, now=None) -> list[int].
- app.scanner.scans: create_scan(conn, kind) -> int, finish_scan(conn, scan_id, status, hosts_found=0, error=None, now=None), running_scan(conn) -> dict | None.
- app.scanner.netinfo.detect_ranges() (async) -> list[str].
- app.scanner.names.collect_names(timeout=3.0) (async) -> dict[ip, list[(name, source)]].
- app.db.connect(path), app.db.utcnow(); app.config.Settings has .ranges (tuple[str,...], empty = autodetect).

class ScanBusy(RuntimeError).
class ScanManager:
  def __init__(self, db_path, settings, *, runner=run_nmap, names_provider=collect_names, ranges_provider=detect_ranges, nmap_path: str = "nmap"): store everything; self._task = None.
  def is_running(self) -> bool: a task exists and is not done.
  def recover(self) -> int: open a connection; every scan row with status "running" is finished as "failed" with error "interrupted by restart"; returns how many; closes the connection.
  async def start(self, kind: str) -> int: kind must be "quick" or "deep" else ValueError; if is_running() raise ScanBusy("scan already running"); open a connection, create_scan, close it; self._task = asyncio.create_task(self._run(kind, scan_id)); return scan_id.
  async def wait(self) -> None: await self._task if there is one (swallow nothing; _run never raises).
  async def _run(self, kind, scan_id): never raises. Steps in try/except Exception as exc: targets = list(settings.ranges) or await ranges_provider(); if no targets raise ScanError("no scan ranges found"); xml = await runner(kind, targets, nmap_path=self.nmap_path); hosts = parse_nmap_xml(xml); try: extra = await names_provider() except Exception: extra = {}; then with a fresh connection: result = save_scan_results(conn, hosts, kind, extra_names=extra); mark_offline(conn, result["device_ids"], targets); finish_scan(conn, scan_id, "done", hosts_found=len(hosts)). On exception: finish_scan(conn, scan_id, "failed", error=str(exc)[:300]) using a fresh connection. Always close connections. The blocking sqlite work may run directly (it is fast).
