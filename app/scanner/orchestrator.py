import asyncio
import logging
import sqlite3
from typing import Any

from app.scanner.errors import explain_scan_error
from app.scanner.nmap_runner import ScanError, run_nmap
from app.scanner.nmap_parser import parse_nmap_xml
from app.scanner.store import save_scan_results
from app.uptime import record_checks
from app.scanner.presence import mark_offline
from app.scanner.scans import create_scan, finish_scan, running_scan
from app.scanner.netinfo import detect_ranges, detect_gateway
from app.scanner.names import collect_names
from app.scanner.relations import infer_relations
from app.scanner.relstore import replace_inferred
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
        gateway_provider=detect_gateway,
        nmap_path: str = "nmap",
    ) -> None:
        self.db_path = db_path
        self.settings = settings
        self.runner = runner
        self.names_provider = names_provider
        self.ranges_provider = ranges_provider
        self.gateway_provider = gateway_provider
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
                    error=explain_scan_error("interrupted by restart"),
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

            try:
                record_checks(
                    conn,
                    set(result["device_ids"]),
                    targets,
                    now=utcnow(),
                    rtts=result.get("rtts"),
                )
            except Exception:
                logging.getLogger(__name__).exception("recording uptime checks failed")

            try:
                gateway_ip = await self.gateway_provider()
            except Exception:
                gateway_ip = None

            hops = {host.ip: host.hops for host in hosts if host.hops}

            devices = []
            cursor = conn.execute(
                "SELECT id, primary_ip, type_override, device_type, hostname, vendor, online FROM devices"
            )
            for row in cursor.fetchall():
                ports_cursor = conn.execute(
                    "SELECT port FROM ports WHERE device_id = ? AND state LIKE 'open%'",
                    (row["id"],),
                )
                open_ports = [p["port"] for p in ports_cursor.fetchall()]
                devices.append({
                    "id": row["id"],
                    "primary_ip": row["primary_ip"],
                    "type": row["type_override"] or row["device_type"] or "unknown",
                    "hostname": row["hostname"],
                    "vendor": row["vendor"],
                    "ports": open_ports,
                    "online": row["online"],
                })

            try:
                edges = infer_relations(devices, hops, gateway_ip)
                replace_inferred(conn, edges)
            except Exception:
                logging.getLogger(__name__).exception("relation inference failed")

            finish_scan(
                conn,
                scan_id,
                "done",
                hosts_found=len(hosts),
                now=utcnow(),
            )
            conn.commit()
        except Exception as exc:
            logging.getLogger(__name__).warning("scan %s failed: %r", scan_id, exc)
            conn = connect(self.db_path)
            try:
                finish_scan(
                    conn,
                    scan_id,
                    "failed",
                    error=explain_scan_error(exc)[:400],
                    now=utcnow(),
                )
                conn.commit()
            finally:
                conn.close()
        finally:
            if conn is not None:
                conn.close()