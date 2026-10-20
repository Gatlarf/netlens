"""Availability of a remote site in a calendar month, from the history the site reported (the `up` measurements of its devices and checks).

The figures have the same shape as the monthly availability of this Netlens itself (app/reports.py), so the same table and CSV serve both. A remote
site is measured at the resolution of its history: 5 minutes for the last 90 days, an hour before that, so an outage is as exact as that. Time in
which the site did not report at all (its Netlens or its connection was down) is not a measurement; it is listed separately as "silent".
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any

from app import reports, tsdb
from app.probes import STAMP

SMALL_GAP = 2                       # buckets that are apart by up to this many widths still belong to one outage


def figures(rows: list[tuple], start: int, end: int, now: int) -> dict[str, Any] | None:
    """Availability and outages from the buckets of one `up` series; None when there is nothing in the period."""
    checks = sum(r[2] for r in rows)
    if not checks:
        return None
    ups = sum(r[3] for r in rows)
    down_s, runs, run = 0.0, [], None
    for ts, width, n, total, low in rows:
        bad = low < 1 and n > 0
        if bad:
            share = 1 - total / n
            down_s += width * share if width > 1 else width
            if run is not None and ts - run["end"] <= width * SMALL_GAP:
                run["end"] = ts + width
            else:
                run = {"start": ts, "end": ts + width}
                runs.append(run)
        else:
            run = None
    outs = [min(r["end"], end) - max(r["start"], start) for r in runs]
    return {"checks": checks, "availability": round(ups / checks * 100, 2), "down_seconds": round(down_s), "down_text": reports.duration(down_s), "outages": len(runs),
            "longest": reports.duration(max(outs, default=0)), "ongoing": bool(runs) and runs[-1]["end"] >= min(end, now) - 600}


def silent_seconds(conn: sqlite3.Connection, probe_id: int, start: datetime, end: datetime, now: datetime) -> int:
    """How long the site was not reporting in the period, from the "site silent" and "reporting again" events."""
    row = conn.execute("SELECT name, customer FROM probes WHERE id = ?", (probe_id,)).fetchone()
    if row is None:
        return 0
    label = f"{row['customer']} / {row['name']}" if row["customer"] else row["name"]
    like = label.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    a, b = start.strftime(STAMP), end.strftime(STAMP)
    events = conn.execute("SELECT ts, kind FROM events WHERE kind IN ('probe_offline', 'probe_online') AND detail LIKE ? ESCAPE '\\' AND ts < ? ORDER BY id",
                          (like + " %", b)).fetchall()
    total, since = 0.0, None
    for e in events:
        t = datetime.strptime(e["ts"], STAMP).replace(tzinfo=timezone.utc)
        if e["kind"] == "probe_offline":
            since = since or t
        elif since is not None:
            total += max(0.0, (min(t, end) - max(since, start)).total_seconds()) if t > start else 0.0
            since = None
    if since is not None:
        total += max(0.0, (min(now, end) - max(since, start)).total_seconds())
    return round(total)


def availability(conn: sqlite3.Connection, probe_id: int, month: str, scope: str = "all", with_services: bool = True, now: datetime | None = None) -> dict[str, Any]:
    start, end = reports.month_bounds(month)
    now = now or datetime.now(timezone.utc)
    s0, s1, n = int(start.timestamp()), int(min(end, now).timestamp()), int(now.timestamp())
    store = tsdb.for_conn(conn)
    devices, services = [], []
    if store is not None:
        for d in conn.execute("SELECT id, name, ip, type, always_on FROM remote_devices WHERE probe_id = ? ORDER BY name COLLATE NOCASE", (probe_id,)):
            if scope == "core" and not d["always_on"]:
                continue
            f = figures(store.buckets("remote", d["id"], "up", s0, s1, now=n), s0, s1, n)
            if f:
                devices.append({"id": d["id"], "name": d["name"] or d["ip"], "ip": d["ip"], "type": d["type"], "always_on": bool(d["always_on"]), **f})
        for sv in conn.execute("SELECT id, name, kind, target FROM remote_services WHERE probe_id = ? ORDER BY name COLLATE NOCASE", (probe_id,)) if with_services else []:
            f = figures(store.buckets("remote_service", sv["id"], "up", s0, s1, now=n), s0, s1, n)
            if f:
                services.append({"id": sv["id"], "name": sv["name"], "kind": sv["kind"], "target": sv["target"] or "", **f})
    core = [d for d in devices if d["always_on"]]

    def mean(items):
        total = sum(i["checks"] for i in items)
        return round(sum(i["availability"] * i["checks"] for i in items) / total, 2) if total else None

    silent = silent_seconds(conn, probe_id, start, end, now)
    summary = {"devices": len(devices), "devices_availability": mean(devices), "core_devices": len(core), "core_availability": mean(core), "services": len(services),
               "services_availability": mean(services), "with_outages": sum(1 for r in devices + services if r["outages"]), "scope": scope, "target": None,
               "hours": "all", "ignore_maintenance": False, "silent_seconds": silent, "silent_text": reports.duration(silent)}
    return {"month": month, "start": start.strftime(STAMP), "end": end.strftime(STAMP), "span_days": round((end - start).total_seconds() / 86400, 1), "devices": devices,
            "services": services, "summary": summary}


def months(conn: sqlite3.Connection, probe_id: int, now: datetime | None = None, count: int = 12) -> list[str]:
    """This month and the earlier ones back to the day the site was added."""
    now = now or datetime.now(timezone.utc)
    row = conn.execute("SELECT created FROM probes WHERE id = ?", (probe_id,)).fetchone()
    first = (row["created"] or now.strftime(STAMP))[:7] if row else now.strftime(STAMP)[:7]
    out, y, m = [], now.year, now.month
    while len(out) < count:
        label = f"{y:04d}-{m:02d}"
        out.append(label)
        if label <= first:
            break
        y, m = (y - 1, 12) if m == 1 else (y, m - 1)
    return out
