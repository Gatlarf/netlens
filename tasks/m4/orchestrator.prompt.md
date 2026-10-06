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
54:    hop_ips: set[str] = set()
129:    candidates: list[dict] = []

## app/scanner/relstore.py
7:def replace_inferred(conn: sqlite3.Connection, edges: list[Edge]) -> None:
21:def list_relations(conn: sqlite3.Connection) -> list[dict[str, Any]]:
33:def add_manual(
34:    conn: sqlite3.Connection,
35:    src_id: int,
36:    dst_id: int,
37:    kind: str = "manual",
83:def delete_relation(conn: sqlite3.Connection, relation_id: int) -> bool:

## app/scanner/netinfo.py
10:def parse_ip_addr(text: str) -> list[str]:
16:    networks: set[str] = set()
62:def parse_default_gateway(text: str) -> Optional[str]:
100:async def run_ip(args: list[str], ip_path: str = "ip", timeout: float = 5.0) -> str:
130:async def detect_ranges(ip_path: str = "ip") -> list[str]:
136:async def detect_gateway(ip_path: str = "ip") -> Optional[str]:

TASK:
Rewrite app/scanner/orchestrator.py (COMPLETE file; current file below) keeping ALL existing behaviour, names and signatures, and adding relation inference.
Additions:
1. Constructor gets one more keyword-only parameter: gateway_provider=detect_gateway (import detect_gateway from app.scanner.netinfo; it is an async function returning the default gateway IP string or None). Store it.
2. After a successful save_scan_results and mark_offline (inside the same try block in _run, before finish_scan), compute relations: gateway_ip = await self.gateway_provider() wrapped in try/except Exception -> None. hops = {host.ip: host.hops for host in hosts if host.hops} (ScanHost.hops is list[str]). devices = a list of dicts, one for EVERY device row in the devices table: {"id": id, "primary_ip": primary_ip, "type": type_override or device_type or "unknown", "hostname": hostname, "vendor": vendor, "ports": [open port numbers from the ports table where state LIKE 'open%'], "online": online}. edges = infer_relations(devices, hops, gateway_ip) (from app.scanner.relations import infer_relations); then replace_inferred(conn, edges) (from app.scanner.relstore import replace_inferred). Failures in this relation step must not fail the scan: wrap just that step in try/except Exception and log with logging.getLogger(__name__).exception.
CURRENT FILE:
import asyncio
import sqlite3
from typing import Any

from app.scanner.nmap_runner import ScanError, run_nmap
from app.scanner.nmap_parser import parse_nmap_xml
from app.scanner.store import save_scan_results
from app.scanner.presence import mark_offline
from app.scanner.scans import create_scan, finish_scan, running_scan
from app.scanner.netinfo import detect_ranges
from app.scanner.names import collect_names
from app.db import connect, utcnow
from app.config import Settings


class ScanBusy(RuntimeError):
    pass


class ScanManager:
    def __init__(
        self,
        db_path: str,
        settings: Settings,
        *,
        runner=run_nmap,
        names_provider=collect_names,
        ranges_provider=detect_ranges,
        nmap_path: str = "nmap",
    ) -> None:
        self.db_path = db_path
        self.settings = settings
        self.runner = runner
        self.names_provider = names_provider
        self.ranges_provider = ranges_provider
        self.nmap_path = nmap_path
        self._task: asyncio.Task | None = None

    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()

    def recover(self) -> int:
        conn = connect(self.db_path)
        try:
            cursor = conn.execute(
                "SELECT id FROM scans WHERE status = 'running'"
            )
            scan_ids = [row["id"] for row in cursor.fetchall()]
            count = 0
            for scan_id in scan_ids:
                finish_scan(
                    conn,
                    scan_id,
                    "failed",
                    error="interrupted by restart",
                    now=utcnow(),
                )
                count += 1
            conn.commit()
            return count
        finally:
            conn.close()

    async def start(self, kind: str) -> int:
        if kind not in ("quick", "deep"):
            raise ValueError("kind must be 'quick' or 'deep'")
        if self.is_running():
            raise ScanBusy("scan already running")

        conn = connect(self.db_path)
        try:
            scan_id = create_scan(conn, kind, now=utcnow())
            conn.commit()
        finally:
            conn.close()

        self._task = asyncio.create_task(self._run(kind, scan_id))
        return scan_id

    async def wait(self) -> None:
        if self._task is not None:
            await self._task

    async def _run(self, kind: str, scan_id: int) -> None:
        conn: sqlite3.Connection | None = None
        try:
            targets = list(self.settings.ranges)
            if not targets:
                targets = await self.ranges_provider()
            if not targets:
                raise ScanError("no scan ranges found")

            xml = await self.runner(
                kind,
                targets,
                nmap_path=self.nmap_path,
            )
            hosts = parse_nmap_xml(xml)

            try:
                extra = await self.names_provider()
            except Exception:
                extra = {}

            conn = connect(self.db_path)
            result = save_scan_results(
                conn,
                hosts,
                kind,
                now=utcnow(),
                extra_names=extra,
            )
            mark_offline(
                conn,
                result["device_ids"],
                targets,
                now=utcnow(),
            )
            finish_scan(
                conn,
                scan_id,
                "done",
                hosts_found=len(hosts),
                now=utcnow(),
            )
            conn.commit()
        except Exception as exc:
            conn = connect(self.db_path)
            try:
                finish_scan(
                    conn,
                    scan_id,
                    "failed",
                    error=str(exc)[:300],
                    now=utcnow(),
                )
                conn.commit()
            finally:
                conn.close()
        finally:
            if conn is not None:
                conn.close()