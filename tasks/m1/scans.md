Create app/scanner/scans.py (stdlib sqlite3; connections use row_factory=sqlite3.Row; import utcnow from app.db). Table: scans(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, status TEXT NOT NULL, started TEXT NOT NULL, finished TEXT, hosts_found INTEGER NOT NULL DEFAULT 0, error TEXT).
- def create_scan(conn, kind: str, now: str | None = None) -> int: inserts status "running", started=now or utcnow(), commits, returns id.
- def finish_scan(conn, scan_id: int, status: str, hosts_found: int = 0, error: str | None = None, now: str | None = None) -> None: status must be "done" or "failed" else ValueError; sets finished, hosts_found, error; commits. Unknown scan_id raises KeyError.
- def list_scans(conn, limit: int = 50) -> list[dict]: newest first (ORDER BY id DESC), plain dicts.
- def running_scan(conn) -> dict | None: the newest scan with status "running", or None.
