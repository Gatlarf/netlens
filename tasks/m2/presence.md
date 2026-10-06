Create app/scanner/presence.py (stdlib sqlite3 + ipaddress). Uses app.db.add_event(conn, kind, detail=None, device_id=None, now=None) and app.db.utcnow().
def mark_offline(conn, seen_ids, ranges, now: str | None = None) -> list[int]:
- seen_ids: iterable of device ids seen in the scan; ranges: list of CIDR strings that were scanned.
- Select devices with online = 1 and id not in seen_ids whose primary_ip is inside at least one of the ranges (parse with ipaddress.ip_network(r, strict=False) and compare with ipaddress.ip_address; skip rows whose primary_ip is NULL or invalid).
- For each: UPDATE devices SET online = 0 WHERE id = ?, and add_event(conn, "device_offline", primary_ip, device_id=id, now=now). Commit. Return the list of ids marked offline (ascending). Empty ranges -> returns [] and changes nothing.
