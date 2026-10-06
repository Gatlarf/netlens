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
