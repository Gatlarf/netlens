"""Reports in plain language: a weekly summary for whoever looks after the network, and a monthly availability report.

Both are built from what Netlens already stores (presence checks, service results, events, the health readings, the disk
forecast), so they need nothing new to be measured. The weekly text goes out through the notification channels that ticked
"Weekly report"; the monthly report is a page that can be printed or downloaded as a CSV file.
"""

from __future__ import annotations

import calendar
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from app.db import get_setting, set_setting

log = logging.getLogger(__name__)

SETTINGS_KEY = "reports.weekly"
SENT_KEY = "reports.weekly_sent"
DEFAULTS = {"enabled": False, "day": 0, "hour": 8,           # Monday, 08:00 (the time of the server)
            "scope": "all",                                  # all devices, or only the always-on ("core") devices
            "services": True, "new_devices": True, "health": True, "disks": True, "sites": True}     # the parts of the weekly text
SECTIONS = ("services", "new_devices", "health", "disks", "sites")
SCOPES = ("all", "core")
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


def availability(conn, start: datetime, end: datetime, scope: str = "all", with_services: bool = True, group_id: int | None = None,
                 only_outages: bool = False, target: float | None = None) -> dict[str, Any]:
    """Per device and per service: availability in [start, end), and the outages.

    scope "core": only the always-on devices; with_services=False leaves the service checks out; group_id: only the devices of one group; target: an availability
    goal in percent (rows below it are flagged); only_outages: list only what had an outage (the summary still counts everything that was selected).
    """
    a, b = _fmt(start), _fmt(end)
    span = (end - start).total_seconds()
    devices = []
    where, args = ["1 = 1"], []
    if scope == "core":
        where.append("always_on = 1")
    if group_id is not None:
        where.append("group_id = ?")
        args.append(group_id)
    for d in conn.execute("SELECT id, COALESCE(custom_name, hostname, primary_ip) AS name, primary_ip AS ip, COALESCE(type_override, device_type) AS type, always_on FROM devices "
                          f"WHERE {' AND '.join(where)} ORDER BY name COLLATE NOCASE", args):
        rows = conn.execute("SELECT ts, up FROM checks WHERE device_id = ? AND ts >= ? AND ts < ? ORDER BY ts, id", (d["id"], a, b)).fetchall()
        if not rows:
            continue
        up = sum(1 for r in rows if r["up"])
        outs, down_s = _outages(rows, start, end)
        devices.append({"id": d["id"], "name": d["name"] or d["ip"], "ip": d["ip"], "type": d["type"], "always_on": bool(d["always_on"]), "checks": len(rows),
                        "availability": round(up / len(rows) * 100, 2), "down_seconds": round(down_s), "down_text": duration(down_s),
                        "outages": len(outs), "longest": duration(max([o["seconds"] for o in outs], default=0)), "ongoing": any(o["ongoing"] for o in outs)})
    services = []
    for s in conn.execute("SELECT id, name, kind, host, port FROM service_checks WHERE enabled = 1 ORDER BY name COLLATE NOCASE") if with_services else []:
        rows = conn.execute("SELECT ts, up, ms FROM service_results WHERE check_id = ? AND ts >= ? AND ts < ? ORDER BY ts, id", (s["id"], a, b)).fetchall()
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
               "with_outages": sum(1 for d in devices if d["outages"]) + sum(1 for s in services if s["outages"]), "scope": scope, "target": target}
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
    only = " AND always_on = 1" if core else ""
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(days=7)
    av = availability(conn, start, now + timedelta(seconds=1), scope=opts["scope"], with_services=opts["services"])
    a = _fmt(start)
    counts = {r["kind"]: r["n"] for r in conn.execute("SELECT kind, COUNT(*) AS n FROM events WHERE ts >= ? GROUP BY kind", (a,))}
    total = conn.execute(f"SELECT COUNT(*) FROM devices WHERE 1 = 1{only}").fetchone()[0]
    online = conn.execute(f"SELECT COUNT(*) FROM devices WHERE online = 1{only}").fetchone()[0]
    new = [r["n"] for r in conn.execute(
        "SELECT COALESCE(custom_name, hostname, primary_ip) AS n FROM devices WHERE first_seen >= ? ORDER BY first_seen", (a,))] if opts["new_devices"] else []
    core_ids = {r["id"] for r in conn.execute("SELECT id FROM devices WHERE always_on = 1")} if core else None
    worst = sorted([d for d in av["devices"] if d["outages"]], key=lambda d: -d["down_seconds"])[:5]
    worst_services = sorted([s for s in av["services"] if s["outages"]], key=lambda s: -s["down_seconds"])[:5]
    problems = [p for p in hm.problems(conn) if core_ids is None or p["device_id"] in core_ids] if opts["health"] else []
    filling = [f for f in forecast.forecasts(conn, now.timestamp()) if f["days_to_full"] is not None and (core_ids is None or f["device_id"] in core_ids)][:5] if opts["disks"] else []
    sites = []
    try:
        if not opts["sites"]:
            raise LookupError("left out by the settings")
        from app import probes

        for row in conn.execute("SELECT * FROM probes WHERE enabled = 1 ORDER BY name COLLATE NOCASE"):
            p = probes.present(conn, row)
            sites.append({"name": p["name"], "state": p["state"], "problems": (p.get("problems") or {}).get("count", 0)})
    except Exception:  # noqa: BLE001 - remote sites are optional
        log.debug("remote sites left out of the weekly report", exc_info=True)
    return {"options": {k: opts[k] for k in ("scope",) + SECTIONS}, "start": a, "end": _fmt(now), "devices": {"total": total, "online": online, "new": new[:10], "new_count": len(new)},
            "availability": av["summary"], "worst_devices": worst, "worst_services": worst_services, "events": counts,
            "problems": [{k: p[k] for k in ("device", "title", "label", "value", "unit", "level", "since")} for p in problems[:10]],
            "filling": [{k: f[k] for k in ("device", "label", "current", "days_to_full", "full_on")} for f in filling], "sites": sites}


def _pct(v: float | None) -> str:
    return "no data" if v is None else f"{v:.2f}%".replace(".00%", "%")


def weekly_text(r: dict[str, Any]) -> tuple[str, str]:
    """(title, body) in plain language."""
    d, av = r["devices"], r["availability"]
    attention = len(r["problems"]) + len(r["filling"]) + sum(1 for s in r["sites"] if s["state"] == "silent")
    title = f"Netlens weekly report: {'everything looks fine' if not attention and not r['worst_devices'] and not r['worst_services'] else f'{attention} thing(s) to look at'}"
    lines = [f"Period: {r['start'][:10]} to {r['end'][:10]}", ""]
    opts = r.get("options") or {}
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
def get_settings(conn) -> dict[str, Any]:
    try:
        data = json.loads(get_setting(conn, SETTINGS_KEY) or "{}")
    except ValueError:
        data = {}
    out = dict(DEFAULTS)
    if isinstance(data, dict):
        if isinstance(data.get("enabled"), bool):
            out["enabled"] = data["enabled"]
        for k, hi in (("day", 6), ("hour", 23)):
            v = data.get(k)
            if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= hi:
                out[k] = v
        if data.get("scope") in SCOPES:
            out["scope"] = data["scope"]
        for k in SECTIONS:
            if isinstance(data.get(k), bool):
                out[k] = data[k]
    return out


def save_settings(conn, data: dict[str, Any]) -> dict[str, Any]:
    cur = get_settings(conn)
    for k, hi in (("day", 6), ("hour", 23)):
        if k in data:
            v = data[k]
            if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= hi:
                raise ValueError(f"{k} must be a number from 0 to {hi}")
            cur[k] = v
    if "enabled" in data:
        cur["enabled"] = bool(data["enabled"])
    if "scope" in data:
        if data["scope"] not in SCOPES:
            raise ValueError(f"scope must be one of {', '.join(SCOPES)}")
        cur["scope"] = data["scope"]
    for k in SECTIONS:
        if k in data:
            if not isinstance(data[k], bool):
                raise ValueError(f"{k} must be true or false")
            cur[k] = data[k]
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
        title, body = weekly_text(weekly(conn))
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
