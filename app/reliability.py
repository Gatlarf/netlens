"""Reliability in numbers: how often the things that matter were down, how long it took to recover, how good the alerts were.

The figures are the ones an operations team reports (the "KPIs" of monitoring guides): outages and the mean/median time to recover (MTTR) from the
offline/online and down/up events, the availability against a target, how long it takes Netlens to notice an outage at the longest (the detection
time follows from the check interval and the number of misses), and the quality of the alerts: how many cleared by themselves within five minutes
(noise), how many were acknowledged, how many were held back by a snooze or a maintenance window. Only the devices marked always-on, and the ones
marked critical, count as "the things that matter"; every outage of a low-importance device is left out.
"""

from __future__ import annotations

import sqlite3
import statistics
from datetime import datetime, timedelta, timezone

from app.db import get_setting, set_setting, utcnow

TARGET_KEY = "reliability.target"
DEFAULT_TARGET = 99.5
DAYS = (7, 30, 90)
QUICK = 300                      # an alert that cleared within this many seconds counts as noise


def _ts(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def target(conn: sqlite3.Connection) -> float:
    try:
        value = float(get_setting(conn, TARGET_KEY) or DEFAULT_TARGET)
    except ValueError:
        return DEFAULT_TARGET
    return value if 50 <= value <= 100 else DEFAULT_TARGET


def set_target(conn: sqlite3.Connection, value: float) -> float:
    if not 50 <= value <= 100:
        raise ValueError("the availability target is between 50 and 100 percent")
    set_setting(conn, TARGET_KEY, str(value))
    conn.commit()
    return value


def _pairs(rows, start_kind: str, end_kind: str, now: datetime) -> list[dict]:
    """Outages from the events of one kind pair, per subject: {subject, start, end (None while it goes on), seconds}."""
    open_at: dict = {}
    out: list[dict] = []
    for r in rows:
        key = r["key"]
        if r["kind"] == start_kind:
            if key not in open_at:
                open_at[key] = r["ts"]
        elif r["kind"] == end_kind and key in open_at:
            start = open_at.pop(key)
            out.append({"key": key, "start": start, "end": r["ts"], "seconds": (_ts(r["ts"]) - _ts(start)).total_seconds()})
    for key, start in open_at.items():
        out.append({"key": key, "start": start, "end": None, "seconds": (now - _ts(start)).total_seconds()})
    return out


def _detection(conn: sqlite3.Connection) -> dict:
    """The longest a problem can go unnoticed: quick checks every N seconds and M misses for devices, the interval and two results for services."""
    from app import beats

    interval, misses = beats.settings(conn)
    device = interval * misses if interval else None
    slowest = conn.execute("SELECT MAX(interval_s) FROM service_checks WHERE enabled = 1").fetchone()[0]
    return {"device_seconds": device, "device_note": "quick checks of the always-on devices" if device else "no quick checks: the next scan",
            "service_seconds": (slowest or 60) * 2, "scan_seconds": None}


def build(conn: sqlite3.Connection, days: int = 30, now: str | None = None) -> dict:
    days = days if days in DAYS else 30
    stamp = now or utcnow()
    current = _ts(stamp)
    since = (current - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.row_factory = sqlite3.Row

    matter = {r["id"]: r["name"] for r in conn.execute(
        "SELECT id, COALESCE(custom_name, hostname, primary_ip, 'device ' || id) AS name FROM devices WHERE (always_on = 1 OR tier = 'critical') AND tier != 'low'")}
    dev_rows = conn.execute(
        "SELECT device_id AS key, kind, ts FROM events WHERE kind IN ('device_offline', 'device_online') AND ts >= ? AND device_id IS NOT NULL ORDER BY ts, id", (since,)).fetchall()
    dev_outages = [o for o in _pairs([r for r in dev_rows if r["key"] in matter], "device_offline", "device_online", current)]
    for o in dev_outages:
        o["name"] = matter.get(o["key"], "")

    svc_names = {r["id"]: r["name"] for r in conn.execute("SELECT id, name FROM service_checks WHERE tier != 'low'")}
    svc_rows = conn.execute("SELECT detail, kind, ts FROM events WHERE kind IN ('service_down', 'service_up') AND ts >= ? ORDER BY ts, id", (since,)).fetchall()
    # the events name the check in their text ("<name> (<target>) is down"); pair them by that name
    named = []
    for r in svc_rows:
        text = (r["detail"] or "")
        name = text.split(" (", 1)[0]
        if name in svc_names.values():
            named.append({"key": name, "kind": r["kind"], "ts": r["ts"]})
    svc_outages = _pairs(named, "service_down", "service_up", current)
    for o in svc_outages:
        o["name"] = o["key"]

    done = [o["seconds"] for o in dev_outages + svc_outages if o["end"]]
    window = days * 86400

    def part(items: list[dict]) -> dict:
        finished = [o["seconds"] for o in items if o["end"]]
        down = sum(o["seconds"] for o in items)
        return {"outages": len(items), "ongoing": sum(1 for o in items if not o["end"]), "down_seconds": round(down),
                "mttr_seconds": round(statistics.mean(finished)) if finished else None, "median_seconds": round(statistics.median(finished)) if finished else None,
                "longest_seconds": round(max((o["seconds"] for o in items), default=0)) or None}

    n_dev = max(1, len(matter))
    availability = round(100 * (1 - sum(o["seconds"] for o in dev_outages) / (window * n_dev)), 3) if matter else None
    worst = sorted(({"name": o["name"], "seconds": round(o["seconds"]), "start": o["start"], "ongoing": o["end"] is None, "kind": "device"} for o in dev_outages), key=lambda x: -x["seconds"])
    worst += sorted(({"name": o["name"], "seconds": round(o["seconds"]), "start": o["start"], "ongoing": o["end"] is None, "kind": "service"} for o in svc_outages), key=lambda x: -x["seconds"])
    worst.sort(key=lambda x: -x["seconds"])

    # alert quality: the problems announced (down/offline/critical) and what happened to them
    problems = conn.execute(
        "SELECT COUNT(*) FROM events WHERE kind IN ('device_offline', 'service_down', 'metric_critical') AND ts >= ?", (since,)).fetchone()[0]
    quick = sum(1 for o in dev_outages + svc_outages if o["end"] and o["seconds"] <= QUICK)
    held = conn.execute("SELECT COUNT(*) FROM events WHERE maintenance IS NOT NULL AND kind IN ('device_offline', 'service_down', 'metric_critical') AND ts >= ?", (since,)).fetchone()[0]
    try:
        acked = conn.execute("SELECT COUNT(*) FROM escalation_state WHERE acked_at IS NOT NULL AND acked_at >= ?", (since,)).fetchone()[0]
        escalated = conn.execute("SELECT COUNT(*) FROM escalation_state WHERE sent_at IS NOT NULL AND sent_at >= ?", (since,)).fetchone()[0]
    except sqlite3.Error:
        acked = escalated = 0
    return {
        "days": days, "target": target(conn), "watching": {"devices": len(matter), "services": len(svc_names)},
        "availability": availability, "meets_target": None if availability is None else availability >= target(conn),
        "devices": part(dev_outages), "services": part(svc_outages),
        "mttr_seconds": round(statistics.mean(done)) if done else None, "median_seconds": round(statistics.median(done)) if done else None,
        "detection": _detection(conn),
        "alerts": {"problems": problems, "cleared_within_5_min": quick, "noise_percent": round(100 * quick / max(1, len(done))) if done else None,
                   "held_back": held, "escalated": escalated, "acknowledged": acked},
        "longest": worst[:5],
    }
