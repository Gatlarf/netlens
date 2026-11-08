"""Data for the pictures: the year of a device by day, and an incident as a cascade through the network tree. Everything is read from what Netlens already stores."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from app import incidents
from app.hierarchy import ancestors, device_name, load_hierarchy

STAMP = "%Y-%m-%dT%H:%M:%SZ"
MARK_KINDS = ("firmware_update", "os_changed")           # what is worth a mark on the calendar of a device


def calendar(conn: sqlite3.Connection, device_id: int, days: int = 365, now: datetime | None = None) -> dict[str, Any] | None:
    """Availability per day from the hourly roll-up (kept 400 days), outages per day and the firmware and OS changes as marks. None for an unknown device."""
    row = conn.execute("SELECT id FROM devices WHERE id = ?", (device_id,)).fetchone()
    if row is None:
        return None
    now = now or datetime.now(timezone.utc)
    days = min(max(int(days), 7), 400)
    first = (now - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    outages = {r["d"]: r["n"] for r in conn.execute("SELECT substr(ts, 1, 10) AS d, COUNT(*) AS n FROM events WHERE device_id = ? AND kind = 'device_offline' AND ts >= ? GROUP BY d", (device_id, first))}
    out = [{"d": r["d"], "pct": round(r["up"] / r["n"] * 100, 2), "outages": outages.get(r["d"], 0)}
           for r in conn.execute("SELECT substr(hour, 1, 10) AS d, SUM(n) AS n, SUM(up) AS up FROM checks_hourly WHERE device_id = ? AND substr(hour, 1, 10) >= ? GROUP BY d HAVING SUM(n) > 0 ORDER BY d", (device_id, first))]
    marks = [{"d": r["ts"][:10], "kind": r["kind"], "text": (r["detail"] or r["kind"].replace("_", " "))[:120]}
             for r in conn.execute(f"SELECT ts, kind, detail FROM events WHERE device_id = ? AND ts >= ? AND kind IN ({','.join('?' * len(MARK_KINDS))}) ORDER BY id DESC LIMIT 60", (device_id, first, *MARK_KINDS))]
    return {"device_id": device_id, "from": first, "to": now.strftime("%Y-%m-%d"), "days": out, "marks": marks}


def cascade(conn: sqlite3.Connection, incident_id: int, now: datetime | None = None) -> dict[str, Any] | None:
    """An incident as it unfolded: the affected devices (and what they hang below) as a tree, and when each went wrong and came back, in seconds from the start."""
    found = next((i for i in incidents.incidents(conn, 30, now) if i["id"] == incident_id), None)
    if found is None:
        return None
    ids = list(found["event_ids"])
    marks = ",".join("?" * len(ids))
    rows = [dict(r) for r in conn.execute(f"SELECT id, ts, device_id, kind, detail FROM events WHERE id IN ({marks}) ORDER BY id", tuple(ids))]
    start = datetime.strptime(found["start"], STAMP)
    steps: list[dict[str, Any]] = []
    went: set[int] = set()
    for e in rows:
        dev = e["device_id"]
        if dev is None:
            continue
        t = max(0.0, (datetime.strptime(e["ts"], STAMP) - start).total_seconds())
        if e["kind"] in incidents.PROBLEMS and dev not in went:
            went.add(dev)
            steps.append({"t": t, "id": dev, "state": "down", "text": (e["detail"] or e["kind"].replace("_", " "))[:140]})
        elif e["kind"] in incidents.RECOVERS and dev in went:
            went.discard(dev)
            steps.append({"t": t, "id": dev, "state": "up", "text": (e["detail"] or "back").strip()[:140]})
    devices, tree = load_hierarchy(conn)
    affected = {s["id"] for s in steps if s["id"] in devices}
    keep = set(affected)
    for dev in affected:
        keep.update(a for a in ancestors(tree, dev) if a in devices)
    nodes = [{"id": i, "name": device_name(devices[i]), "parent_id": tree[i].parent_id if i in tree and tree[i].parent_id in keep else None, "affected": i in affected} for i in sorted(keep)]
    end = datetime.strptime(found["end"], STAMP)
    return {"id": incident_id, "ref": found["ref"], "title": found["title"], "start": found["start"], "duration": max(1.0, (end - start).total_seconds()), "nodes": nodes,
            "steps": [s for s in steps if s["id"] in keep]}
