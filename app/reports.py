"""Reports in plain language: a weekly summary for whoever looks after the network, and a monthly availability report.

Both are built from what Netlens already stores (presence checks, service results, events, the health readings, the disk
forecast), so they need nothing new to be measured. The weekly text goes out through the notification channels that ticked
"Weekly report"; the monthly report is a page that can be printed or downloaded as a CSV file.
"""

from __future__ import annotations

import bisect
import calendar
import itertools
import json
import logging
import operator
from datetime import datetime, timedelta, timezone
from typing import Any

from app import checkstats
from app.db import get_setting, set_setting

log = logging.getLogger(__name__)

SETTINGS_KEY = "reports.weekly"
SENT_KEY = "reports.weekly_sent"
DEFAULTS = {"enabled": False, "day": 0, "hour": 8,           # Monday, 08:00 (the time of the server)
            "scope": "all",                                  # all devices, or only the always-on ("core") devices
            "services": True, "new_devices": True, "health": True, "disks": True, "sites": True}     # the parts of the weekly text
SECTIONS = ("services", "new_devices", "health", "disks", "sites")
SCOPES = ("all", "core")
HOURS = ("all", "business")
MONTHLY_KEY = "reports.monthly_sent"
DEFAULTS.update({"max_items": 5,                                       # how many outages, disks ... the weekly text lists
                 "ignore_maintenance": False,                            # leave the time of planned maintenance windows out of the figures
                 "hours": "all", "business_days": [0, 1, 2, 3, 4], "business_start": 8, "business_end": 18,     # "business" = count only these hours (the time of the server)
                 "summary": True, "summary_model": True,                                  # start the weekly text with a short summary, which the language model may word
                 "monthly": False, "monthly_day": 1, "monthly_hour": 8, "monthly_target": None})               # e-mail the report of the last month
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    if seconds < 90:
        return f"{seconds} s"
    if seconds < 5400:
        return f"{round(seconds / 60)} min"
    if seconds < 2 * 86400:
        h, m = divmod(round(seconds / 60), 60)
        return f"{h} h {m:02d} min" if m else f"{h} h"
    return f"{seconds / 86400:.1f} days"


def month_bounds(month: str) -> tuple[datetime, datetime]:
    """'2026-09' -> (start, end) of that calendar month in UTC."""
    try:
        y, m = int(month[:4]), int(month[5:7])
        if not (1 <= m <= 12 and 2000 <= y <= 2100) or month[4] != "-":
            raise ValueError
    except (ValueError, IndexError):
        raise ValueError("the month must look like 2026-09") from None
    start = datetime(y, m, 1, tzinfo=timezone.utc)
    end = datetime(y + (m == 12), 1 if m == 12 else m + 1, 1, tzinfo=timezone.utc)
    return start, end


def months_available(conn, now: datetime | None = None, count: int = 12) -> list[str]:
    """The months to choose from: this one and the previous ones, back to the first check."""
    now = now or datetime.now(timezone.utc)
    row = conn.execute("SELECT MIN(ts) AS t FROM checks").fetchone()
    first = _parse(row["t"]) if row and row["t"] else now
    out, y, m = [], now.year, now.month
    for _ in range(count):
        out.append(f"{y:04d}-{m:02d}")
        if (y, m) <= (first.year, first.month):
            break
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    return out


# ----------------------------------------------------------------------------- the numbers
def _outages(rows, start: datetime, end: datetime) -> tuple[list[dict], float]:
    """Down periods from (ts, up) rows in time order: [{start, end, seconds, ongoing}] and the total seconds."""
    out: list[dict] = []
    down_since: datetime | None = None
    for r in rows:                                   # a timestamp is only parsed where the device goes down or comes back (not for every check)
        up = r["up"]
        if not up and down_since is None:
            down_since = _parse(r["ts"])
        elif up and down_since is not None:
            t = _parse(r["ts"])
            out.append({"start": _fmt(down_since), "end": _fmt(t), "seconds": (t - down_since).total_seconds(), "ongoing": False})
            down_since = None
    if down_since is not None:
        out.append({"start": _fmt(down_since), "end": None, "seconds": (min(end, datetime.now(timezone.utc)) - down_since).total_seconds(), "ongoing": True})
    return out, sum(o["seconds"] for o in out)


class _Spans:
    """Sorted, merged [start, end) time spans as stamp text (the stamps sort like the times), to ask whether a check falls in one."""

    def __init__(self, spans: list[tuple[str, str]]):
        merged: list[list[str]] = []
        for a, b in sorted(spans):
            if merged and a <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        self.starts = [m[0] for m in merged]
        self.ends = [m[1] for m in merged]

    def contains(self, ts: str) -> bool:
        i = bisect.bisect_right(self.starts, ts) - 1
        return i >= 0 and ts < self.ends[i]


def business_spans(start: datetime, end: datetime, business: dict[str, Any]) -> _Spans:
    """The business hours (days and hours of the *server's* clock) between start and end, as UTC spans."""
    spans, day = [], (start - timedelta(days=1)).astimezone().date()
    last = (end + timedelta(days=1)).astimezone().date()
    while day <= last:
        if day.weekday() in business["business_days"]:
            first = datetime(day.year, day.month, day.day).astimezone() + timedelta(hours=business["business_start"])
            spans.append((_fmt(first), _fmt(datetime(day.year, day.month, day.day).astimezone() + timedelta(hours=business["business_end"]))))
        day += timedelta(days=1)
    return _Spans(spans)


def maintenance_spans(conn, start: datetime, end: datetime) -> dict[int, _Spans]:
    """Device id -> the planned maintenance windows that covered it between start and end."""
    from app import maintenance

    per_device: dict[int, list[tuple[str, str]]] = {}
    days_back = int((end - start).total_seconds() // 86400) + 2
    for window in maintenance.load_windows(conn):
        if not window.get("enabled", True):
            continue
        if window["schedule"]["type"] == "once":
            runs = [maintenance._once(window)]
        else:
            runs = list(maintenance._occurrences(window, end, days_back, 1))
        spans = [(_fmt(a), _fmt(b)) for a, b in runs if b > start and a < end]
        if not spans:
            continue
        for device in maintenance.device_ids(conn, window):
            per_device.setdefault(device, []).extend(spans)
    return {d: _Spans(v) for d, v in per_device.items()}


BATCH = 50                       # devices or checks whose rows are fetched in one statement (enough to save round trips, few enough to keep memory small)


def _rows_of(conn, table: str, key: str, columns: str, ids: list[int], a: str, b: str) -> dict[int, list]:
    """{id: [rows oldest first]} for [a, b) from one statement. `table`, `key` and `columns` are fixed names from this module, never user input."""
    out: dict[int, list] = {i: [] for i in ids}
    if ids:
        cur = conn.execute(f"SELECT {key} AS k, {columns} FROM {table} WHERE {key} IN ({','.join('?' * len(ids))}) AND ts >= ? AND ts < ? ORDER BY {key}, ts, id", [*ids, a, b])
        for k, group in itertools.groupby(cur, operator.itemgetter(0)):          # grouping in C: a big report has hundreds of thousands of rows
            out[k] = list(group)
    return out


def _windows_of(conn, windows: list[tuple[int, str, str]]) -> dict[int, list]:
    """{device_id: [checks inside that device's windows, oldest first]}; the windows of one device come in time order."""
    out: dict[int, list] = {}
    for i in range(0, len(windows), 100):
        chunk = windows[i:i + 100]
        cond = " OR ".join("(device_id = ? AND ts >= ? AND ts < ?)" for _ in chunk)
        cur = conn.execute(f"SELECT device_id AS k, ts, up FROM checks WHERE {cond} ORDER BY device_id, ts, id", [x for w in chunk for x in w])
        for k, group in itertools.groupby(cur, operator.itemgetter(0)):
            out.setdefault(k, []).extend(group)
    return out


def availability(conn, start: datetime, end: datetime, scope: str = "all", with_services: bool = True, group_id: int | None = None,
                 only_outages: bool = False, target: float | None = None, hours: str = "all", business: dict[str, Any] | None = None,
                 ignore_maintenance: bool = False) -> dict[str, Any]:
    """Per device and per service: availability in [start, end), and the outages.

    scope "core": only the always-on devices; with_services=False leaves the service checks out; group_id: only the devices of one group; target: an availability
    goal in percent (rows below it are flagged); only_outages: list only what had an outage (the summary still counts everything that was selected).
    hours="business": count only the checks inside the business hours (`business`: business_days, business_start, business_end, on the server's clock);
    ignore_maintenance: leave out the checks that fall in a planned maintenance window of the device. Devices marked "leave out of reports" are never listed.
    """
    a, b = _fmt(start), _fmt(end)
    span = (end - start).total_seconds()
    devices = []
    where, args = ["report_exclude = 0"], []
    inside = business_spans(start, end, {**DEFAULTS, **(business or {})}) if hours == "business" else None
    quiet = maintenance_spans(conn, start, end) if ignore_maintenance else {}
    if scope == "core":
        where.append("always_on = 1")
    if group_id is not None:
        where.append("group_id = ?")
        args.append(group_id)
    totals = checkstats.range_totals(conn, a, b)
    down = checkstats.down_hours(conn, a, b) if totals is not None else {}
    all_devices = conn.execute("SELECT id, COALESCE(custom_name, hostname, primary_ip) AS name, primary_ip AS ip, COALESCE(type_override, device_type) AS type, always_on FROM devices "
                               f"WHERE {' AND '.join(where)} ORDER BY LOWER(COALESCE(custom_name, hostname, primary_ip))", args).fetchall()
    for first in range(0, len(all_devices), BATCH):                      # the checks of a batch of devices come in one statement, not one per device
        batch = all_devices[first:first + BATCH]
        plans: dict[int, Any] = {}
        for d in batch:
            if inside is None and d["id"] not in quiet and totals is not None:
                u, n = totals.get(d["id"], (0, 0, 0, 0))[:2]
                if n == 0:
                    plans[d["id"]] = "none"
                elif u == n:                             # never down this period: there is nothing to look up (the usual device on a healthy network)
                    plans[d["id"]] = "healthy"
                else:                                    # only the hours with a failed check (and the one after) can hold a down period; the counts come from the roll-up
                    mine = down.get(d["id"], [])
                    plans[d["id"]] = ("all" if len(mine) * 2 >= span / 3600 * 0.6 else "windows", checkstats.change_windows(mine, a, b))   # most of the period: read it whole, it is cheaper
            else:
                plans[d["id"]] = "range"
        whole = _rows_of(conn, "checks", "device_id", "ts, up", [i for i, p in plans.items() if p == "range" or (isinstance(p, tuple) and p[0] == "all")], a, b)
        parts = _windows_of(conn, [(i, w0, w1) for i, p in plans.items() if isinstance(p, tuple) and p[0] == "windows" for w0, w1 in p[1]])
        for d in batch:
            plan = plans[d["id"]]
            if plan == "none":
                continue
            if plan == "healthy":
                n = totals[d["id"]][1]
                devices.append({"id": d["id"], "name": d["name"] or d["ip"], "ip": d["ip"], "type": d["type"], "always_on": bool(d["always_on"]), "checks": n,
                                "availability": 100.0, "down_seconds": 0, "down_text": duration(0), "outages": 0, "longest": duration(0), "ongoing": False})
                continue
            if plan == "range":
                rows = whole.get(d["id"], [])
                if inside is not None or d["id"] in quiet:
                    skip = quiet.get(d["id"])
                    rows = [r for r in rows if (inside is None or inside.contains(r["ts"])) and (skip is None or not skip.contains(r["ts"]))]
                if not rows:
                    continue
                count, ups = len(rows), sum(1 for r in rows if r["up"])
            else:
                rows = (whole if plan[0] == "all" else parts).get(d["id"], [])
                count, ups = totals[d["id"]][1], totals[d["id"]][0]
            outs, down_s = _outages(rows, start, end)
            devices.append({"id": d["id"], "name": d["name"] or d["ip"], "ip": d["ip"], "type": d["type"], "always_on": bool(d["always_on"]), "checks": count,
                            "availability": round(ups / count * 100, 2), "down_seconds": round(down_s), "down_text": duration(down_s),
                            "outages": len(outs), "longest": duration(max([o["seconds"] for o in outs], default=0)), "ongoing": any(o["ongoing"] for o in outs)})
    services = []
    checks = conn.execute("SELECT id, name, kind, host, port FROM service_checks WHERE enabled = 1 ORDER BY LOWER(name)").fetchall() if with_services else []
    for first in range(0, len(checks), BATCH):
        batch = checks[first:first + BATCH]
        results = _rows_of(conn, "service_results", "check_id", "ts, up, ms", [c["id"] for c in batch], a, b)
        for s in batch:
            rows = results.get(s["id"], [])
            if inside is not None:
                rows = [r for r in rows if inside.contains(r["ts"])]
            if not rows:
                continue
            up = sum(1 for r in rows if r["up"])
            outs, down_s = _outages(rows, start, end)
            ms = [r["ms"] for r in rows if r["up"] and r["ms"] is not None]
            services.append({"id": s["id"], "name": s["name"], "kind": s["kind"], "target": f"{s['host']}:{s['port']}" if s["port"] else s["host"], "checks": len(rows),
                             "availability": round(up / len(rows) * 100, 3), "down_seconds": round(down_s), "down_text": duration(down_s), "outages": len(outs),
                             "longest": duration(max([o["seconds"] for o in outs], default=0)), "avg_ms": round(sum(ms) / len(ms), 1) if ms else None,
                             "ongoing": any(o["ongoing"] for o in outs)})
    core = [d for d in devices if d["always_on"]]

    def mean(items):
        total = sum(i["checks"] for i in items)
        return round(sum(i["availability"] * i["checks"] for i in items) / total, 2) if total else None

    summary = {"devices": len(devices), "devices_availability": mean(devices), "core_devices": len(core), "core_availability": mean(core),
               "services": len(services), "services_availability": mean(services),
               "with_outages": sum(1 for d in devices if d["outages"]) + sum(1 for s in services if s["outages"]), "scope": scope, "target": target,
               "hours": hours, "ignore_maintenance": bool(ignore_maintenance)}
    if target is not None:
        for row in devices + services:
            row["below_target"] = row["availability"] < target
        summary["below_target"] = sum(1 for row in devices + services if row["below_target"])
    if only_outages:
        devices, services = [d for d in devices if d["outages"]], [s for s in services if s["outages"]]
    return {"start": a, "end": b, "span_days": round(span / 86400, 1), "devices": devices, "services": services, "summary": summary}


def availability_csv(report: dict[str, Any]) -> str:
    def cell(v: Any) -> str:
        t = "" if v is None else str(v)
        if t[:1] in "=+-@":                       # a spreadsheet would run it as a formula
            t = "'" + t
        return '"' + t.replace('"', '""') + '"'

    goal = report["summary"].get("target") is not None
    lines = [",".join(map(cell, ["Type", "Name", "Address", "Always on", "Availability %", "Checks", "Outages", "Longest outage", "Time down (s)", "Average ms"] + (["Below target"] if goal else [])))]
    for d in report["devices"]:
        lines.append(",".join(map(cell, ["Device", d["name"], d["ip"], "yes" if d["always_on"] else "", d["availability"], d["checks"], d["outages"], d["longest"], d["down_seconds"], ""]
                                  + (["yes" if d.get("below_target") else ""] if goal else []))))
    for s in report["services"]:
        lines.append(",".join(map(cell, ["Service", s["name"], s["target"], "", s["availability"], s["checks"], s["outages"], s["longest"], s["down_seconds"], s["avg_ms"]]
                                  + (["yes" if s.get("below_target") else ""] if goal else []))))
    return "\r\n".join(lines) + "\r\n"


# ----------------------------------------------------------------------------- the weekly summary
def weekly(conn, now: datetime | None = None, options: dict[str, Any] | None = None) -> dict[str, Any]:
    """What happened in the last seven days and what needs a look, as data (`weekly_text` writes it out). `options` default to the saved settings
    (scope: all devices or only the always-on ones; which parts to include)."""
    from app import forecast
    from app.hostmetrics import service as hm

    opts = {**get_settings(conn), **(options or {})}
    core = opts["scope"] == "core"
    only = " AND report_exclude = 0" + (" AND always_on = 1" if core else "")
    limit = int(opts["max_items"])
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(days=7)
    # whole hours, so the hourly roll-up can answer (see app/checkstats.py): from the hour in which the week began to the end of the current hour
    hour = timedelta(hours=1)
    first = start.replace(minute=0, second=0, microsecond=0)
    last = now.replace(minute=0, second=0, microsecond=0) + hour
    av = availability(conn, first, last, scope=opts["scope"], with_services=opts["services"], hours=opts["hours"], business=opts,
                      ignore_maintenance=opts["ignore_maintenance"])
    a = _fmt(start)
    counts = {r["kind"]: r["n"] for r in conn.execute("SELECT kind, COUNT(*) AS n FROM events WHERE ts >= ? GROUP BY kind", (a,))}
    total = conn.execute(f"SELECT COUNT(*) FROM devices WHERE 1 = 1{only}").fetchone()[0]
    online = conn.execute(f"SELECT COUNT(*) FROM devices WHERE online = 1{only}").fetchone()[0]
    new = [r["n"] for r in conn.execute(
        "SELECT COALESCE(custom_name, hostname, primary_ip) AS n FROM devices WHERE first_seen >= ? AND report_exclude = 0 ORDER BY first_seen", (a,))] if opts["new_devices"] else []
    core_ids = {r["id"] for r in conn.execute("SELECT id FROM devices WHERE report_exclude = 0" + (" AND always_on = 1" if core else ""))}
    worst = sorted([d for d in av["devices"] if d["outages"]], key=lambda d: -d["down_seconds"])[:limit]
    worst_services = sorted([s for s in av["services"] if s["outages"]], key=lambda s: -s["down_seconds"])[:limit]
    problems = [p for p in hm.problems(conn) if p["device_id"] in core_ids] if opts["health"] else []
    filling = [f for f in forecast.forecasts(conn, now.timestamp()) if f["days_to_full"] is not None and f["device_id"] in core_ids][:limit] if opts["disks"] else []
    sites = []
    try:
        if not opts["sites"]:
            raise LookupError("left out by the settings")
        from app import probes

        for row in conn.execute("SELECT * FROM probes WHERE enabled = 1 ORDER BY LOWER(name)"):
            p = probes.present(conn, row)
            sites.append({"name": p["name"], "state": p["state"], "problems": (p.get("problems") or {}).get("count", 0)})
    except Exception:  # noqa: BLE001 - remote sites are optional
        log.debug("remote sites left out of the weekly report", exc_info=True)
    return {"options": {k: opts[k] for k in ("scope", "hours", "ignore_maintenance", "max_items") + SECTIONS}, "start": a, "end": _fmt(now), "devices": {"total": total, "online": online, "new": new[:10], "new_count": len(new)},
            "availability": av["summary"], "worst_devices": worst, "worst_services": worst_services, "events": counts,
            "problems": [{k: p[k] for k in ("device", "title", "label", "value", "unit", "level", "since")} for p in problems[:max(10, limit)]],
            "filling": [{k: f[k] for k in ("device", "label", "current", "days_to_full", "full_on")} for f in filling], "sites": sites}


def _pct(v: float | None) -> str:
    return "no data" if v is None else f"{v:.2f}%".replace(".00%", "%")


def weekly_text(r: dict[str, Any]) -> tuple[str, str]:
    """(title, body) in plain language."""
    d, av = r["devices"], r["availability"]
    attention = len(r["problems"]) + len(r["filling"]) + sum(1 for s in r["sites"] if s["state"] == "silent")
    title = f"Netlens weekly report: {'everything looks fine' if not attention and not r['worst_devices'] and not r['worst_services'] else f'{attention} thing(s) to look at'}"
    lines = [f"Period: {r['start'][:10]} to {r['end'][:10]}"]
    opts = r.get("options") or {}
    notes = (["only the business hours count"] if opts.get("hours") == "business" else []) + (["time in planned maintenance windows is left out"] if opts.get("ignore_maintenance") else [])
    if notes:
        lines.append("(" + "; ".join(notes) + ")")
    lines.append("")
    core = opts.get("scope") == "core"
    new_part = "" if opts.get("new_devices") is False else (f" {d['new_count']} new device(s) appeared: {', '.join(d['new'][:5])}{'...' if d['new_count'] > 5 else ''}." if d["new_count"] else " No new devices.")
    lines.append(f"Network: {d['online']} of {d['total']} {'always-on ' if core else ''}devices are online now." + new_part)
    if av["core_devices"]:
        lines.append(f"Your always-on devices were reachable {_pct(av['core_availability'])} of the time.")
    elif av["devices"]:
        lines.append(f"Devices were reachable {_pct(av['devices_availability'])} of the time.")
    if av["services"] and opts.get("services", True):
        lines.append(f"Service checks: {_pct(av['services_availability'])} available over {av['services']} check(s).")
    if r["worst_devices"] or (r["worst_services"] and opts.get("services", True)):
        lines += ["", "Outages this week:"]
        for x in r["worst_devices"]:
            lines.append(f"  - {x['name']}: down {x['down_text']} in {x['outages']} outage(s), longest {x['longest']}{' (still down)' if x['ongoing'] else ''}")
        for x in (r["worst_services"] if opts.get("services", True) else []):
            lines.append(f"  - {x['name']} (service): down {x['down_text']} in {x['outages']} outage(s){' (still down)' if x['ongoing'] else ''}")
    else:
        lines += ["", "No device or service had an outage this week."]
    if r["problems"]:
        lines += ["", "Health readings past a limit right now:"]
        for p in r["problems"]:
            shown = f"{p['value']:.0f}{p['unit']}" if p["unit"] else f"{p['value']:g}"
            lines.append(f"  - {p['device']}: {p['title'].lower()}{' on ' + p['label'] if p['label'] else ''} is {shown} ({p['level']})")
    if r["filling"]:
        lines += ["", "Disks filling up:"]
        for f in r["filling"]:
            lines.append(f"  - {f['device']}{' ' + f['label'] if f['label'] else ''}: {f['current']:.0f}% used, full in about {max(1, round(f['days_to_full']))} day(s) (around {f['full_on']})")
    for s in r["sites"]:
        if s["state"] == "silent":
            lines += ["", f"Remote site {s['name']} has stopped reporting."]
    if not (r["problems"] or r["filling"]) and (opts.get("health", True) or opts.get("disks", True)):
        lines += ["", "No health readings are past a limit and no disk is on course to fill up." if opts.get("health", True) and opts.get("disks", True)
                  else "No health readings are past a limit." if opts.get("health", True) else "No disk is on course to fill up."]
    return title, "\n".join(lines)


# ----------------------------------------------------------------------------- schedule
def _int(value: Any, key: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{key} must be a number from {low} to {high}")
    return value


def clean_setting(key: str, value: Any) -> Any:
    """One setting, checked; raises ValueError with a message the user can read."""
    if key in ("enabled", "ignore_maintenance", "monthly", "summary", "summary_model", *SECTIONS):
        if not isinstance(value, bool):
            raise ValueError(f"{key} must be true or false")
        return value
    if key == "scope":
        if value not in SCOPES:
            raise ValueError(f"scope must be one of {', '.join(SCOPES)}")
        return value
    if key == "hours":
        if value not in HOURS:
            raise ValueError(f"hours must be one of {', '.join(HOURS)}")
        return value
    ranges = {"day": (0, 6), "hour": (0, 23), "max_items": (1, 30), "business_start": (0, 23), "business_end": (1, 24), "monthly_day": (1, 28), "monthly_hour": (0, 23)}
    if key in ranges:
        return _int(value, key, *ranges[key])
    if key == "business_days":
        if not isinstance(value, list) or not value or not all(isinstance(d, int) and not isinstance(d, bool) and 0 <= d <= 6 for d in value):
            raise ValueError("business_days must be a list of weekdays (0 = Monday ... 6 = Sunday), at least one")
        return sorted(set(value))
    if key == "monthly_target":
        if value is None or value == "":
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 100:
            raise ValueError("monthly_target must be a percentage from 0 to 100")
        return float(value)
    raise ValueError(f"unknown setting {key!r}")


def get_settings(conn) -> dict[str, Any]:
    try:
        data = json.loads(get_setting(conn, SETTINGS_KEY) or "{}")
    except ValueError:
        data = {}
    out = dict(DEFAULTS)
    if isinstance(data, dict):
        for key in DEFAULTS:
            if key in data:
                try:
                    out[key] = clean_setting(key, data[key])
                except ValueError:
                    pass                                   # a damaged value is replaced by the default
        if "summary" not in data:                                  # the summary switch used to live on the Insights page
            out["summary"] = get_setting(conn, "reports.summary") != "0"
        if out["business_end"] <= out["business_start"]:
            out["business_start"], out["business_end"] = DEFAULTS["business_start"], DEFAULTS["business_end"]
    return out


def save_settings(conn, data: dict[str, Any]) -> dict[str, Any]:
    cur = get_settings(conn)
    for key, value in data.items():
        cur[key] = clean_setting(key, value)
    if cur["business_end"] <= cur["business_start"]:
        raise ValueError("the business hours must end after they start")
    set_setting(conn, SETTINGS_KEY, json.dumps(cur))
    return cur


def due(conn, now: datetime | None = None) -> bool:
    """Is it time for the weekly report: enabled, the chosen weekday and hour reached, and not yet sent this week."""
    s = get_settings(conn)
    if not s["enabled"]:
        return False
    now = (now or datetime.now(timezone.utc)).astimezone()         # the weekday and hour are the time of the server
    scheduled = (now - timedelta(days=(now.weekday() - s["day"]) % 7)).replace(hour=s["hour"], minute=0, second=0, microsecond=0)
    if scheduled > now:
        scheduled -= timedelta(days=7)
    last = get_setting(conn, SENT_KEY)
    return not last or _parse(last) < scheduled.astimezone(timezone.utc)


def mark_sent(conn, now: datetime | None = None) -> None:
    set_setting(conn, SENT_KEY, _fmt(now or datetime.now(timezone.utc)))


async def send_weekly(db_path: str, force: bool = False, poster=None, mailer=None) -> dict[str, Any]:
    """Build the weekly report and send it to the channels that ticked "Weekly report". Returns {"sent", "failed", "errors"}."""
    import asyncio

    from app.db import connect
    from app.notify import channels as ch

    kwargs = {k: v for k, v in (("poster", poster), ("mailer", mailer)) if v is not None}
    conn = connect(db_path)
    try:
        if not force and not due(conn):
            return {"sent": 0, "failed": 0, "errors": [], "skipped": True}
        wanted = [c for c in ch.load_channels(conn) if c["enabled"] and "report_weekly" in c["events"]]
        report = weekly(conn)
        title, body = weekly_text(report)
        try:
            from app import reportsummary

            if reportsummary.enabled(conn):
                body = "In short: " + await asyncio.to_thread(reportsummary.summary, conn, report) + "\n\n" + body
        except Exception:  # noqa: BLE001 - the summary is a nicety; the report goes out without it
            log.debug("the report summary could not be written", exc_info=True)
        result = {"sent": 0, "failed": 0, "errors": [], "channels": len(wanted), "title": title}
        for c in wanted:
            try:
                await asyncio.to_thread(ch.send_channel, c, title, body, [], **kwargs)
                result["sent"] += 1
            except ch.ChannelError as exc:
                result["failed"] += 1
                result["errors"].append(f"{c.get('name') or c['type']}: {exc}")
        if wanted or not force:
            mark_sent(conn)
        return result
    finally:
        conn.close()


# ----------------------------------------------------------------------------- the monthly report by e-mail (or any channel)
def previous_month(now: datetime) -> str:
    first = now.replace(day=1)
    last = first - timedelta(days=1)
    return last.strftime("%Y-%m")


def monthly(conn, month: str | None = None, options: dict[str, Any] | None = None, now: datetime | None = None) -> dict[str, Any]:
    """The availability of one month (default: the last full month) in the shape of `monthly_text`, following the saved report settings."""
    opts = {**get_settings(conn), **(options or {})}
    now = now or datetime.now(timezone.utc)
    month = month or previous_month(now.astimezone())
    start, end = month_bounds(month)
    av = availability(conn, start, end, scope=opts["scope"], with_services=opts["services"], hours=opts["hours"], business=opts, ignore_maintenance=opts["ignore_maintenance"],
                      target=opts["monthly_target"])
    limit = int(opts["max_items"])
    worst = sorted([d for d in av["devices"] if d["outages"]], key=lambda d: -d["down_seconds"])[:limit]
    worst_services = sorted([s for s in av["services"] if s["outages"]], key=lambda s: -s["down_seconds"])[:limit]
    below = sorted([r for r in av["devices"] + av["services"] if r.get("below_target")], key=lambda r: r["availability"])[:max(limit, 10)]
    return {"month": month, "summary": av["summary"], "worst_devices": worst, "worst_services": worst_services, "below_target": below,
            "options": {k: opts[k] for k in ("scope", "hours", "ignore_maintenance", "monthly_target")}}


def monthly_text(r: dict[str, Any]) -> tuple[str, str]:
    """(title, body) in plain language."""
    s, opts = r["summary"], r["options"]
    y, m = r["month"].split("-")
    name = f"{calendar.month_name[int(m)]} {y}"
    core = opts.get("scope") == "core"
    title = f"Netlens availability report for {name}"
    lines = [f"Period: {name}"]
    notes = (["always-on devices only"] if core else []) + (["only the business hours count"] if opts.get("hours") == "business" else []) \
        + (["time in planned maintenance windows is left out"] if opts.get("ignore_maintenance") else [])
    if notes:
        lines.append("(" + "; ".join(notes) + ")")
    lines.append("")
    if s["devices"]:
        lines.append(f"{'Always-on devices' if core else 'Devices'} were reachable {_pct(s['devices_availability'])} of the time ({s['devices']} device(s)).")
    if s["core_devices"] and not core:
        lines.append(f"Your always-on devices: {_pct(s['core_availability'])}.")
    if s["services"]:
        lines.append(f"Service checks: {_pct(s['services_availability'])} available over {s['services']} check(s).")
    if not s["devices"] and not s["services"]:
        lines.append("Netlens has no checks for this month.")
    lines.append(f"{s['with_outages']} device(s) or service(s) had an outage.")
    if opts.get("monthly_target") is not None:
        lines.append(f"Target {opts['monthly_target']:g}%: {s.get('below_target', 0)} below it." if s.get("below_target") else f"Target {opts['monthly_target']:g}%: everything met it.")
    if r["worst_devices"] or r["worst_services"]:
        lines += ["", "Most downtime:"]
        for x in r["worst_devices"]:
            lines.append(f"  - {x['name']}: {_pct(x['availability'])}, down {x['down_text']} in {x['outages']} outage(s), longest {x['longest']}")
        for x in r["worst_services"]:
            lines.append(f"  - {x['name']} (service): {_pct(x['availability'])}, down {x['down_text']} in {x['outages']} outage(s)")
    if r["below_target"]:
        lines += ["", f"Below the {opts['monthly_target']:g}% target:"]
        lines += [f"  - {x['name']}: {_pct(x['availability'])}" for x in r["below_target"]]
    return title, "\n".join(lines)


def monthly_due(conn, now: datetime | None = None) -> bool:
    """Time for the monthly report: switched on, the chosen day and hour of this month reached, and the report of the last month not yet sent."""
    s = get_settings(conn)
    if not s["monthly"]:
        return False
    now = (now or datetime.now(timezone.utc)).astimezone()
    if now < now.replace(day=s["monthly_day"], hour=s["monthly_hour"], minute=0, second=0, microsecond=0):
        return False
    return get_setting(conn, MONTHLY_KEY) != previous_month(now)


async def send_monthly(db_path: str, force: bool = False, poster=None, mailer=None) -> dict[str, Any]:
    """Send the monthly report to the channels that ticked "Monthly report". Returns {"sent", "failed", "errors"}."""
    import asyncio

    from app.db import connect
    from app.notify import channels as ch

    kwargs = {k: v for k, v in (("poster", poster), ("mailer", mailer)) if v is not None}
    conn = connect(db_path)
    try:
        if not force and not monthly_due(conn):
            return {"sent": 0, "failed": 0, "errors": [], "skipped": True}
        wanted = [c for c in ch.load_channels(conn) if c["enabled"] and "report_monthly" in c["events"]]
        title, body = monthly_text(monthly(conn))
        result = {"sent": 0, "failed": 0, "errors": [], "channels": len(wanted), "title": title}
        for c in wanted:
            try:
                await asyncio.to_thread(ch.send_channel, c, title, body, [], **kwargs)
                result["sent"] += 1
            except ch.ChannelError as exc:
                result["failed"] += 1
                result["errors"].append(f"{c.get('name') or c['type']}: {exc}")
        if wanted or not force:
            set_setting(conn, MONTHLY_KEY, previous_month(datetime.now(timezone.utc).astimezone()))
        return result
    finally:
        conn.close()
