"""When will a disk be full? A straight-line estimate from the growth of the last weeks.

Disks fill slowly and in steps (a backup, a log that is rotated), so the fit is the median of the slopes between pairs of
points (Theil-Sen): one big file or one clean-up does not move it. A series needs a few days of history and a clear rise
before it gets a date; otherwise it is reported as steady and no date is given.
"""

from __future__ import annotations

import json
import logging
import statistics
import time
from typing import Any

from app import tsdb
from app.db import add_event, get_setting, set_setting, utcnow

log = logging.getLogger(__name__)

SPAN = 30 * 86400
MIN_POINTS = 24
MIN_DAYS = 3.0
MIN_RISE = 0.5               # percentage points between the start and the end of the period, below that it is "steady"
MIN_SLOPE = 0.02             # percentage points per day
HORIZON_DAYS = 365
FRESH = 3 * 3600
STATE_KEY = "forecast.state"
ALERT_DAYS_KEY = "forecast.alert_days"
DEFAULT_ALERT_DAYS = 14
CRITICAL_DAYS = 3


def slope_per_day(points: list[list[float]]) -> float | None:
    """Percentage points per day by the median of pairwise slopes, or None when there is too little to go on."""
    pts = [(p[0], p[1]) for p in points if p[1] is not None]
    if len(pts) < MIN_POINTS or (pts[-1][0] - pts[0][0]) < MIN_DAYS * 86400:
        return None
    step = max(1, len(pts) // 120)                     # at most ~120 points: 7000 pairs
    pts = pts[::step]
    slopes = [(b[1] - a[1]) / (b[0] - a[0]) for i, a in enumerate(pts) for b in pts[i + 1:] if b[0] - a[0] >= 6 * 3600]
    if not slopes:
        return None
    return statistics.median(slopes) * 86400


def estimate(points: list[list[float]], current: float, now: float) -> dict[str, Any]:
    slope = slope_per_day(points)
    out: dict[str, Any] = {"slope_per_day": None, "days_to_full": None, "full_on": None, "trend": "unknown"}
    if slope is None:
        return out
    vals = [p[1] for p in points if p[1] is not None]
    q = max(1, len(vals) // 4)
    rise = statistics.median(vals[-q:]) - statistics.median(vals[:q])
    out["slope_per_day"] = round(slope, 3)
    if slope >= MIN_SLOPE and rise >= MIN_RISE:
        out["trend"] = "growing"
        days = max(0.0, (100.0 - current) / slope)
        if days <= HORIZON_DAYS:
            out["days_to_full"] = round(days, 1)
            out["full_on"] = time.strftime("%Y-%m-%d", time.gmtime(now + days * 86400))
    elif slope <= -MIN_SLOPE and rise <= -MIN_RISE:
        out["trend"] = "shrinking"
    else:
        out["trend"] = "steady"
    return out


def forecasts(conn, now: float | None = None) -> list[dict[str, Any]]:
    """Every monitored disk with its trend, the ones that fill soonest first."""
    now = now if now is not None else time.time()
    store = tsdb.for_conn(conn)
    if store is None:
        return []
    out = []
    rows = conn.execute(
        "SELECT m.device_id, m.alerts, COALESCE(d.custom_name, d.hostname, d.primary_ip) AS name FROM host_monitors m JOIN devices d ON d.id = m.device_id WHERE m.enabled = 1").fetchall()
    known = store.metrics_of_many("device", [r["device_id"] for r in rows])
    for r in rows:
        for s in known.get(r["device_id"], []):
            if s["metric"] != "disk_pct" or s["last"] is None or s["last_ts"] is None or now - s["last_ts"] > FRESH:
                continue
            data = store.query("device", r["device_id"], "disk_pct", s["label"], span=SPAN, end=int(now), points=300)
            item = {"device_id": r["device_id"], "device": r["name"], "label": s["label"], "current": round(s["last"], 1), "alerts": bool(r["alerts"]),
                    "days_of_data": round((data["points"][-1][0] - data["points"][0][0]) / 86400, 1) if len(data["points"]) > 1 else 0}
            item.update(estimate(data["points"], s["last"], now))
            out.append(item)
    out.sort(key=lambda i: (i["days_to_full"] is None, i["days_to_full"] if i["days_to_full"] is not None else 0, -i["current"]))
    return out


MEM_SPAN = 60 * 86400
MEM_MIN_DAYS = 7              # a leak needs a week of history before it is called one
MEM_MIN_FIT = 0.7             # how well the days must follow one straight line (R squared)
MEM_DROP = 4.0                # percentage points of memory given back from one day to the next: a restart or a clean-up
MEM_QUIET_ABOVE = 85.0        # a rise that is not a straight line is only mentioned when memory is nearly full


def _theil_sen(xs: list[float], ys: list[float]) -> tuple[float, float]:
    """(slope, intercept) by the median of pairwise slopes."""
    slopes = [(ys[j] - ys[i]) / (xs[j] - xs[i]) for i in range(len(xs)) for j in range(i + 1, len(xs)) if xs[j] > xs[i]]
    slope = statistics.median(slopes) if slopes else 0.0
    return slope, statistics.median(y - slope * x for x, y in zip(xs, ys))


def memory_pattern(points: list[list[float]]) -> dict[str, Any]:
    """How memory use moved over the history, judged on the daily medians (the daily rhythm and short peaks do not count):
    "steady" (one straight line: what a leak looks like), "levelling" (it rose but the rise slows down: a cache filling up),
    "resets" (memory is given back now and then: restarts or clean-ups, so there is no running out), "irregular" (no line fits) or "unknown" (too little history)."""
    by_day: dict[int, list[float]] = {}
    for p in points:
        if p[1] is not None:
            by_day.setdefault(int(p[0] // 86400), []).append(p[1])
    days = sorted(by_day)
    out: dict[str, Any] = {"pattern": "unknown", "slope_per_day": None, "fit": None, "days_of_data": len(days), "rise": None}
    if len(days) < MEM_MIN_DAYS:
        return out
    xs = [float(d - days[0]) for d in days]
    ys = [statistics.median(by_day[d]) for d in days]
    slope, icpt = _theil_sen(xs, ys)
    mean = statistics.fmean(ys)
    total = sum((y - mean) ** 2 for y in ys)
    resid = sum((y - (icpt + slope * x)) ** 2 for x, y in zip(xs, ys))
    fit = 1 - resid / total if total > 1e-9 else 0.0
    out.update(slope_per_day=round(slope, 3), fit=round(fit, 2), rise=round(ys[-1] - ys[0], 1))
    drops = sum(1 for a, b in zip(ys, ys[1:]) if a - b >= MEM_DROP)
    half = len(ys) // 2
    first, _ = _theil_sen(xs[:half], ys[:half]) if half >= 3 else (slope, 0)
    recent, _ = _theil_sen(xs[half:], ys[half:]) if len(ys) - half >= 3 else (slope, 0)
    if drops:
        out["pattern"] = "resets"
    elif slope < MIN_SLOPE:
        out["pattern"] = "irregular"
    elif recent < 0.5 * first or recent < 0.5 * slope:
        out["pattern"] = "levelling"
    elif fit >= MEM_MIN_FIT:
        out["pattern"] = "steady"
    else:
        out["pattern"] = "irregular"
    return out


def memory_trends(conn, now: float | None = None) -> list[dict[str, Any]]:
    """Monitored hosts whose memory use is rising. Only a steady, straight rise over a week or more (what a leak looks like) gets a date; memory that
    levels off, is given back now and then or moves irregularly gets none, and is mentioned only when it is nearly full.
    Only listed, never announced: a cache that grows is normal until the trend is clear for weeks."""
    now = now if now is not None else time.time()
    store = tsdb.for_conn(conn)
    if store is None:
        return []
    out = []
    rows = conn.execute("SELECT m.device_id, COALESCE(d.custom_name, d.hostname, d.primary_ip) AS name FROM host_monitors m JOIN devices d ON d.id = m.device_id WHERE m.enabled = 1").fetchall()
    known = store.metrics_of_many("device", [r["device_id"] for r in rows])
    for r in rows:
        for s in known.get(r["device_id"], []):
            if s["metric"] != "mem_pct" or s["last"] is None or s["last_ts"] is None or now - s["last_ts"] > FRESH:
                continue
            data = store.query("device", r["device_id"], "mem_pct", s["label"], span=MEM_SPAN, end=int(now), points=300)
            pat = memory_pattern(data["points"])
            item = {"device_id": r["device_id"], "device": r["name"], "current": round(s["last"], 1), "days_to_full": None, "full_on": None, **pat}
            slope = pat["slope_per_day"]
            if pat["pattern"] == "steady":
                days = max(0.0, (100.0 - s["last"]) / slope)
                if days > HORIZON_DAYS:
                    continue
                item.update(days_to_full=round(days, 1), full_on=time.strftime("%Y-%m-%d", time.gmtime(now + days * 86400)))
            elif pat["pattern"] in ("levelling", "irregular", "resets") and slope is not None and slope >= MIN_SLOPE and s["last"] >= MEM_QUIET_ABOVE:
                pass
            else:
                continue
            out.append(item)
    out.sort(key=lambda i: (i["days_to_full"] is None, i["days_to_full"] if i["days_to_full"] is not None else 0))
    return out


_CACHE: dict[str, tuple[float, list]] = {}


def cached(conn, ttl: float = 600.0, now: float | None = None) -> list[dict[str, Any]]:
    """The forecasts, recomputed at most every `ttl` seconds (the summary that Home Assistant polls asks often)."""
    now = now if now is not None else time.time()
    key = tsdb.db_file(conn)
    hit = _CACHE.get(key)
    if hit and now - hit[0] < ttl:
        return hit[1]
    value = forecasts(conn, now)
    _CACHE[key] = (now, value)
    return value


def alert_days(conn) -> int:
    try:
        v = int(get_setting(conn, ALERT_DAYS_KEY) or DEFAULT_ALERT_DAYS)
    except ValueError:
        v = DEFAULT_ALERT_DAYS
    return min(max(v, 1), 180)


def check(conn, now: float | None = None) -> list[str]:
    """Raise `capacity_warning` / `capacity_critical` when a disk is on course to fill within the chosen days.
    An event is raised when the level gets worse, not on every round; a disk that recovers is simply forgotten."""
    from app.hostmetrics import service as hm

    now = now if now is not None else time.time()
    try:
        state = json.loads(get_setting(conn, STATE_KEY) or "{}")
    except ValueError:
        state = {}
    horizon = alert_days(conn)
    new_state: dict[str, str] = {}
    raised: list[str] = []
    stamp = utcnow()
    for f in forecasts(conn, now):
        key = f"{f['device_id']}|{f['label']}"
        days = f["days_to_full"]
        if not f["alerts"] or days is None:
            continue
        crit_limit = hm.rules(conn, f["device_id"]).get("disk_pct", {}).get("crit")
        if crit_limit is not None and f["current"] >= crit_limit:
            continue                                   # already a critical reading of its own
        level = "critical" if days <= CRITICAL_DAYS else "warning" if days <= horizon else None
        if level is None:
            continue
        new_state[key] = level
        before = state.get(key)
        if before == level or (before == "critical" and level == "warning"):
            continue
        where = f" on {f['label']}" if f["label"] else ""
        text = f"{f['device']}: the disk{where} is {f['current']:.0f}% full and will be full in about {max(1, round(days))} day{'s' if round(days) != 1 else ''} (around {f['full_on']})"
        kind = "capacity_critical" if level == "critical" else "capacity_warning"
        add_event(conn, kind, text, device_id=f["device_id"], now=stamp, subject=f"metric:{f['device_id']}:disk_pct:{f['label']}")
        raised.append(kind)
    set_setting(conn, STATE_KEY, json.dumps(new_state))
    conn.commit()
    return raised
