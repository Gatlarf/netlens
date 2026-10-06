Create app/terminal/hostkeys.py (stdlib sqlite3; connections use row_factory=sqlite3.Row; import utcnow from app.db). Table: host_keys(device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE, fingerprint TEXT NOT NULL, first_seen TEXT NOT NULL).
- def get_fingerprint(conn, device_id: int) -> str | None.
- def remember_fingerprint(conn, device_id: int, fingerprint: str, now: str | None = None) -> None: insert (first_seen = now or utcnow()); if a row already exists leave it unchanged (never silently overwrite). Commit.
- def forget_fingerprint(conn, device_id: int) -> bool: delete the row, commit, return True if a row was deleted.
- def check_fingerprint(conn, device_id: int, fingerprint: str) -> str: returns "new" when nothing is stored (and does NOT store it), "match" when equal, "mismatch" when different.
