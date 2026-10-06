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