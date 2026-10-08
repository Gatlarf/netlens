import asyncio
import inspect
import ipaddress
import logging
import sqlite3
from typing import Any

from app.scanner.errors import explain_scan_error
from app.scanner.nmap_runner import ScanError, _is_valid_target, run_nmap
from app.scanner.options import ScanOptions
from app.scanner.nmap_parser import parse_nmap_xml
from app.scanner.store import save_scan_results
from app.uptime import record_checks
from app.notify.service import process_notifications
from app.integrations.asus_sync import asus_after_scan
from app.integrations.proxmox_sync import proxmox_after_scan
from app.scanner.presence import mark_offline
from app.scanner.scans import create_scan, finish_scan, running_scan
from app.scanner.netinfo import detect_ranges, detect_gateway
from app.scanner.names import collect_names
from app.scanner.relations import infer_relations
from app.scanner.relstore import replace_inferred
from app.db import connect, utcnow
from app.config import Settings


def _is_single_private_host(target: str) -> bool:
    """One IPv4 address (not a range) that is allowed to be scanned."""
    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        return False
    return addr.version == 4 and _is_valid_target(target)


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
        after_scan: list | None = None,
    ) -> None:
        # Async callables f(db_path) run after every successful scan; failures never fail the scan.
        self.after_scan = [proxmox_after_scan, asus_after_scan, process_notifications] if after_scan is None else list(after_scan)
        self.db_path = db_path
        self.settings = settings
        self.runner = runner
        self.names_provider = names_provider
        self.ranges_provider = ranges_provider
        self.gateway_provider = gateway_provider
        self.nmap_path = nmap_path
        self._task: asyncio.Task | None = None
        # Live state of the running scan for the UI: phase, nmap task/percent, hosts found so far.
        self.progress: dict | None = None
        # nmap options chosen on the Settings page (ports, timing, ...); read at the start of each scan
        self.options: ScanOptions = ScanOptions()

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

    async def start(self, kind: str, target: str | None = None) -> int:
        """Start a scan. kind 'full' scans the single host `target` thoroughly; the others scan the ranges."""
        if kind not in ("quick", "deep", "full"):
            raise ValueError("kind must be 'quick', 'deep' or 'full'")
        if kind == "full":
            if not target or not _is_single_private_host(target):
                raise ValueError("a full scan needs one private IPv4 address as its target")
        elif target is not None:
            raise ValueError("only a full scan takes a target")
        if self.is_running():
            raise ScanBusy("scan already running")

        conn = connect(self.db_path)
        try:
            scan_id = create_scan(conn, kind, now=utcnow(), target=target)
            conn.commit()
        finally:
            conn.close()

        self._task = asyncio.create_task(self._run(kind, scan_id, target))
        return scan_id

    async def wait(self) -> None:
        if self._task is not None:
            await self._task

    # Phases in which a scan can still be cancelled without leaving half-saved results behind.
    CANCELLABLE_PHASES = ("preparing", "scanning", "names")

    def can_cancel(self) -> bool:
        return self.is_running() and (self.progress or {}).get("phase") in self.CANCELLABLE_PHASES

    async def cancel(self) -> bool:
        """Stop the running scan (kills nmap, marks the scan 'cancelled'). False if it cannot be cancelled now."""
        if not self.can_cancel():
            return False
        task = self._task
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        return True

    def _set_progress(self, **fields: Any) -> None:
        self.progress = {**(self.progress or {}), **fields}

    def _runner_accepts(self, name: str) -> bool:
        try:
            params = inspect.signature(self.runner).parameters.values()
        except (TypeError, ValueError):
            return False
        return any(p.name == name or p.kind is inspect.Parameter.VAR_KEYWORD for p in params)

    async def _run(self, kind: str, scan_id: int, target: str | None = None) -> None:
        conn: sqlite3.Connection | None = None
        self.progress = {"scan_id": scan_id, "kind": kind, "target": target, "phase": "preparing", "task": None, "percent": None, "hosts_found": 0}
        try:
            if kind == "full":
                targets = [target]
            else:
                targets = list(self.settings.ranges)
                if not targets:
                    targets = await self.ranges_provider()
                if not targets:
                    raise ScanError("no scan ranges found")

            self._set_progress(phase="scanning", targets=targets)
            kwargs: dict[str, Any] = {"nmap_path": self.nmap_path}
            if self._runner_accepts("progress"):
                kwargs["progress"] = lambda update: self._set_progress(**update)
            if self._runner_accepts("options"):
                kwargs["options"] = self.options
            xml = await self.runner(kind, targets, **kwargs)
            hosts = parse_nmap_xml(xml)
            self._set_progress(phase="names", task=None, percent=None, hosts_found=len(hosts))

            try:
                extra = await self.names_provider()
            except Exception:
                extra = {}

            self._set_progress(phase="saving")

            conn = connect(self.db_path)
            result = save_scan_results(
                conn,
                hosts,
                # a full scan reports the complete port list of its host: store it like a deep scan
                "deep" if kind == "full" else kind,
                now=utcnow(),
                extra_names=extra,
            )
            mark_offline(
                conn,
                result["device_ids"],
                targets,
                now=utcnow(),
            )

            # A full scan looks at ONE host: it adds no uptime heartbeat (those mark the regular scan
            # cadence) and must not re-infer the network's relations from a single host's traceroute.
            if kind != "full":
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

            self._set_progress(phase="finishing")
            for hook in self.after_scan:
                try:
                    await hook(str(self.db_path))
                except Exception:
                    logging.getLogger(__name__).exception("after-scan hook %r failed", hook)
        except asyncio.CancelledError:
            # Cancelled by the user before anything was saved: record it and end quietly.
            logging.getLogger(__name__).info("scan %s cancelled", scan_id)
            conn = connect(self.db_path)
            try:
                row = conn.execute("SELECT status FROM scans WHERE id = ?", (scan_id,)).fetchone()
                if row is not None and row["status"] == "running":
                    finish_scan(conn, scan_id, "cancelled", error="Cancelled by the user", now=utcnow())
                    conn.commit()
            finally:
                conn.close()
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
            self.progress = None
