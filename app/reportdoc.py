"""The report document: built from the network's data for one template and one period, then written as a PDF or as a web page.

`build` makes a plain document, a list of blocks (headings, figures, tables, bars, a line chart, a score), so what is in a report can be tested without drawing it.
`render_pdf` and `render_html` draw that document. A section that cannot be made (a feature that is not set up, a failure) says so in the report instead of
failing it: a report that arrives with one note is better than none.
"""

from __future__ import annotations

import base64
import calendar
import html as htmllib
import logging
import math
from datetime import datetime, timedelta, timezone
from typing import Any

from app import pdf as pdflib
from app import pdfimage, reports
from app.reporttemplates import PERIODS, SECTIONS

log = logging.getLogger(__name__)
TONES = {"ok": "#16a34a", "warn": "#d97706", "bad": "#dc2626", "": "#6b7280"}


# ----------------------------------------------------------------------------- the period and the subject
def bounds(period: str, now: datetime, month: str | None = None) -> tuple[datetime, datetime, str]:
    """(start, end, words) for a named period: the last 7 or 30 days (to the end of this hour), or a calendar month (the last full one by default, or "YYYY-MM")."""
    if month or period == "month":
        month = month or reports.previous_month(now.astimezone())
        start, end = reports.month_bounds(month)
        y, m = month.split("-")
        return start, end, f"{calendar.month_name[int(m)]} {y}"
    days = 30 if period == "30d" else 7
    end = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    start = end - timedelta(days=days)
    return start, end, f"{start.astimezone():%d %b %Y} to {(end - timedelta(seconds=1)).astimezone():%d %b %Y}"


def scope_ids(conn, tpl: dict) -> set[int] | None:
    """The devices a report is about: None for everything, or the devices of the chosen groups."""
    if tpl["scope"]["type"] != "group":
        return None
    marks = ",".join("?" for _ in tpl["scope"]["ids"])
    return {r[0] for r in conn.execute(f"SELECT id FROM devices WHERE group_id IN ({marks})", tpl["scope"]["ids"])}


def _pct(value: float | None) -> str:
    return "–" if value is None else f"{value:.2f}".rstrip("0").rstrip(".") + "%"


def _tone(pct: float | None, good: float = 99.0, fair: float = 95.0) -> str:
    return "" if pct is None else "ok" if pct >= good else "warn" if pct >= fair else "bad"


def _day(ts: str) -> str:
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).astimezone().strftime("%d %b %H:%M")
    except (ValueError, TypeError):
        return ts or ""


# ----------------------------------------------------------------------------- the sections
class Ctx:
    def __init__(self, conn, tpl: dict, start: datetime, end: datetime, now: datetime):
        self.conn, self.tpl, self.start, self.end, self.now = conn, tpl, start, end, now
        self.ids = scope_ids(conn, tpl)
        self._availability: dict | None = None

    def keep(self, device_id: int | None) -> bool:
        return self.ids is None or (device_id is not None and device_id in self.ids)

    def availability(self) -> dict:
        if self._availability is None:
            opts = reports.get_settings(self.conn)
            av = reports.availability(self.conn, self.start, self.end, scope=opts["scope"], with_services=True, hours=opts["hours"], business=opts, ignore_maintenance=opts["ignore_maintenance"],
                                      target=opts["monthly_target"])
            if self.ids is not None:                                  # a report for some groups: only their devices, and the checks of those devices
                allowed_checks = {r[0] for r in self.conn.execute("SELECT id FROM service_checks WHERE device_id IN ({})".format(",".join(str(int(i)) for i in self.ids) or "NULL"))}
                av["devices"] = [d for d in av["devices"] if d["id"] in self.ids]
                av["services"] = [s for s in av["services"] if s["id"] in allowed_checks]
                av["summary"] = _resummarise(av)
            self._availability = av
        return self._availability


def _resummarise(av: dict) -> dict:
    def mean(items):
        total = sum(i["checks"] for i in items)
        return round(sum(i["availability"] * i["checks"] for i in items) / total, 2) if total else None

    core = [d for d in av["devices"] if d["always_on"]]
    s = dict(av["summary"])
    s.update(devices=len(av["devices"]), devices_availability=mean(av["devices"]), core_devices=len(core), core_availability=mean(core), services=len(av["services"]),
             services_availability=mean(av["services"]), with_outages=sum(1 for d in av["devices"] if d["outages"]) + sum(1 for x in av["services"] if x["outages"]))
    return s


def _summary(c: Ctx) -> list[dict]:
    from app import healthscore

    blocks: list[dict] = [{"type": "heading", "text": "At a glance"}]
    av = c.availability()["summary"]
    tiles = []
    total = c.conn.execute("SELECT COUNT(*) FROM devices WHERE same_host_id IS NULL AND report_exclude = 0" + (" AND id IN ({})".format(",".join(str(int(i)) for i in c.ids) or "NULL") if c.ids is not None else "")).fetchone()[0]
    online = c.conn.execute("SELECT COUNT(*) FROM devices WHERE same_host_id IS NULL AND report_exclude = 0 AND online = 1" + (" AND id IN ({})".format(",".join(str(int(i)) for i in c.ids) or "NULL") if c.ids is not None else "")).fetchone()[0]
    tiles.append({"value": f"{online} / {total}", "label": "devices online now", "tone": "ok" if online == total else "warn" if total and online / total >= 0.9 else "bad"})
    tiles.append({"value": _pct(av["devices_availability"]), "label": "devices reachable", "tone": _tone(av["devices_availability"])})
    if av["services"]:
        tiles.append({"value": _pct(av["services_availability"]), "label": "services available", "tone": _tone(av["services_availability"])})
    tiles.append({"value": str(av["with_outages"]), "label": "had an outage", "tone": "" if av["with_outages"] == 0 else "warn"})
    if c.ids is None:                                                   # the score is about the whole network
        try:
            from app import stats

            score = stats.summary(c.conn, scan_running=False)["score"]
            if score and score.get("score") is not None:
                text = score.get("why") or "Nothing holds the score back."
                trend = score.get("trend")
                blocks.append({"type": "score", "value": score["score"], "label": score["label"], "text": text,
                               "trend": (f"{'+' if trend['delta'] > 0 else '−' if trend['delta'] < 0 else ''}{abs(trend['delta'])} since {trend['since']}" if trend and trend["delta"] else None)})
            hist = healthscore.history(c.conn, c.start.strftime("%Y-%m-%d"), (c.end - timedelta(seconds=1)).strftime("%Y-%m-%d"))
            if len(hist) >= 3:
                blocks.append({"type": "line", "title": "Network health score by day", "unit": "", "min": 0, "max": 100, "points": [{"x": h["day"][5:], "y": h["score"]} for h in hist]})
        except Exception:  # noqa: BLE001 - the score is an extra
            log.debug("the score is left out of the report", exc_info=True)
    blocks.insert(1, {"type": "tiles", "items": tiles})
    return blocks


def _availability(c: Ctx) -> list[dict]:
    av = c.availability()
    s = av["summary"]
    blocks: list[dict] = [{"type": "heading", "text": "Availability"}]
    notes = (["always-on devices only"] if s["scope"] == "core" else []) + (["only the business hours count"] if s["hours"] == "business" else []) + (["planned maintenance is left out"] if s["ignore_maintenance"] else [])
    if notes:
        blocks.append({"type": "text", "text": "Counted: " + "; ".join(notes) + ".", "muted": True})
    if not s["devices"] and not s["services"]:
        blocks.append({"type": "text", "text": "Netlens has no checks for this period."})
        return blocks
    tiles = [{"value": _pct(s["devices_availability"]), "label": f"{s['devices']} devices", "tone": _tone(s["devices_availability"])}]
    if s["core_devices"] and s["scope"] != "core":
        tiles.append({"value": _pct(s["core_availability"]), "label": f"{s['core_devices']} always-on devices", "tone": _tone(s["core_availability"])})
    if s["services"]:
        tiles.append({"value": _pct(s["services_availability"]), "label": f"{s['services']} service checks", "tone": _tone(s["services_availability"])})
    blocks.append({"type": "tiles", "items": tiles})
    worst = sorted([d for d in av["devices"] if d["outages"]], key=lambda d: -d["down_seconds"])[:10]
    if worst:
        blocks.append({"type": "table", "title": "Devices with the most downtime", "columns": [{"key": "name", "label": "Device", "w": 3}, {"key": "a", "label": "Available", "w": 1.2, "align": "right"},
                       {"key": "down", "label": "Down", "w": 1.2, "align": "right"}, {"key": "n", "label": "Outages", "w": 1, "align": "right"}, {"key": "l", "label": "Longest", "w": 1.2, "align": "right"}],
                       "rows": [{"name": d["name"], "a": _pct(d["availability"]), "down": d["down_text"], "n": str(d["outages"]), "l": d["longest"], "_tone": _tone(d["availability"])} for d in worst]})
    else:
        blocks.append({"type": "text", "text": "No device had an outage in this period."})
    wservices = sorted([x for x in av["services"] if x["outages"]], key=lambda x: -x["down_seconds"])[:8]
    if wservices:
        blocks.append({"type": "table", "title": "Services with the most downtime", "columns": [{"key": "name", "label": "Service", "w": 3}, {"key": "a", "label": "Available", "w": 1.2, "align": "right"},
                       {"key": "down", "label": "Down", "w": 1.2, "align": "right"}, {"key": "n", "label": "Outages", "w": 1, "align": "right"}],
                       "rows": [{"name": x["name"], "a": _pct(x["availability"]), "down": x["down_text"], "n": str(x["outages"]), "_tone": _tone(x["availability"], 99.5, 98)} for x in wservices]})
    below = [r for r in av["devices"] + av["services"] if r.get("below_target")]
    if s.get("target") is not None:
        blocks.append({"type": "text", "text": f"Target {s['target']:g}%: " + (f"{len(below)} below it." if below else "everything met it."), "muted": True})
    return blocks


def _incidents(c: Ctx) -> list[dict]:
    from app import incidents

    days = max(1, math.ceil((c.end - c.start).total_seconds() / 86400))
    found = [i for i in incidents.incidents(c.conn, days=days + 1, now=c.end) if c.start.strftime("%Y-%m-%dT%H:%M:%SZ") <= i["start"] < c.end.strftime("%Y-%m-%dT%H:%M:%SZ")]
    if c.ids is not None:
        found = [i for i in found if any(d in c.ids for d in i["device_ids"])]
    blocks: list[dict] = [{"type": "heading", "text": "Incidents"}]
    if not found:
        blocks.append({"type": "text", "text": "No incidents in this period."})
        return blocks
    ongoing = sum(1 for i in found if i["ongoing"])
    blocks.append({"type": "text", "text": f"{len(found)} incident{'s' if len(found) != 1 else ''}" + (f", {ongoing} still going on." if ongoing else ", all over.")})
    rows = []
    for i in found[:15]:
        seconds = (datetime.strptime(i["end"], "%Y-%m-%dT%H:%M:%SZ") - datetime.strptime(i["start"], "%Y-%m-%dT%H:%M:%SZ")).total_seconds()
        rows.append({"when": _day(i["start"]), "what": i["title"], "dur": reports.duration(seconds) if seconds else "moments", "state": "ongoing" if i["ongoing"] else "over", "_tone": "bad" if i["ongoing"] else ""})
    blocks.append({"type": "table", "columns": [{"key": "when", "label": "Started", "w": 1.4}, {"key": "what", "label": "What happened", "w": 4}, {"key": "dur", "label": "Lasted", "w": 1.1, "align": "right"},
                                                {"key": "state", "label": "State", "w": 0.9}], "rows": rows})
    if len(found) > 15:
        blocks.append({"type": "text", "text": f"{len(found) - 15} more incidents are not listed.", "muted": True})
    return blocks


def _changes(c: Ctx) -> list[dict]:
    from app import changes

    span = (c.end - c.start).total_seconds() / 3600
    period = "24h" if span <= 24 else "7d" if span <= 168 else "30d"
    only = c.ids
    got = changes.timeline(c.conn, period=period, include_audit=True, limit=1000, now=c.end, only=only)
    items = [i for i in got["items"] if c.start.strftime("%Y-%m-%dT%H:%M:%SZ") <= i["ts"] < c.end.strftime("%Y-%m-%dT%H:%M:%SZ") and i["category"] != "availability"]
    blocks: list[dict] = [{"type": "heading", "text": "What changed"}]
    if not items:
        blocks.append({"type": "text", "text": "Nothing notable changed in this period."})
        return blocks
    counts: dict[str, int] = {}
    for i in items:
        counts[i["category"]] = counts.get(i["category"], 0) + 1
    top = max(counts.values())
    blocks.append({"type": "bars", "title": "By kind", "items": [{"label": got["categories"].get(k, k), "value": v, "max": top, "text": str(v)} for k, v in sorted(counts.items(), key=lambda kv: -kv[1])]})
    rows = [{"when": _day(i["ts"]), "what": (f"{i['device']}: " if i.get("device") else "") + i["text"], "kind": got["categories"].get(i["category"], i["category"])} for i in items[:15]]
    blocks.append({"type": "table", "title": "The latest", "columns": [{"key": "when", "label": "When", "w": 1.4}, {"key": "what", "label": "What", "w": 4.5}, {"key": "kind", "label": "Kind", "w": 1.3}], "rows": rows})
    return blocks


def _capacity(c: Ctx) -> list[dict]:
    from app import forecast

    items = [f for f in forecast.forecasts(c.conn, c.now.timestamp()) if f["days_to_full"] is not None and c.keep(f["device_id"])]
    blocks: list[dict] = [{"type": "heading", "text": "Capacity"}]
    if not items:
        blocks.append({"type": "text", "text": "No monitored disk is on course to fill up."})
        return blocks
    rows = [{"dev": f["device"], "disk": f["label"] or "disk", "now": f"{f['current']:g}%", "days": f"{f['days_to_full']:g} days", "on": f.get("full_on") or "", "_tone": "bad" if f["days_to_full"] <= 14 else "warn" if f["days_to_full"] <= 60 else ""} for f in items[:12]]
    blocks.append({"type": "table", "columns": [{"key": "dev", "label": "Device", "w": 3}, {"key": "disk", "label": "Disk", "w": 1.6}, {"key": "now", "label": "Used now", "w": 1.1, "align": "right"},
                                                {"key": "days", "label": "Full in", "w": 1.2, "align": "right"}, {"key": "on", "label": "On", "w": 1.4}], "rows": rows})
    return blocks


def _health(c: Ctx) -> list[dict]:
    from app.hostmetrics import service as hm

    items = [p for p in hm.problems(c.conn) if c.keep(p["device_id"])]
    blocks: list[dict] = [{"type": "heading", "text": "Problems now"}]
    if not items:
        blocks.append({"type": "text", "text": "No health reading is past its limit."})
        return blocks
    rows = [{"dev": p["device"], "what": p["title"] + (f" · {p['label']}" if p["label"] else ""), "val": (f"{p['value']:.0f}{p['unit']}" if p["unit"] else f"{p['value']:g}"), "since": _day(p["since"]) if p.get("since") else "",
             "_tone": "bad" if p["level"] == "critical" else "warn"} for p in items[:15]]
    blocks.append({"type": "table", "columns": [{"key": "dev", "label": "Device", "w": 3}, {"key": "what", "label": "Reading", "w": 3}, {"key": "val", "label": "Now", "w": 1, "align": "right"}, {"key": "since", "label": "Since", "w": 1.4}], "rows": rows})
    return blocks


def _vulnerabilities(c: Ctx) -> list[dict]:
    from app import licence, vulns

    blocks: list[dict] = [{"type": "heading", "text": "Vulnerabilities"}]
    if not licence.allows(c.conn, "vulnerabilities") or not vulns.summary(c.conn)["configured"]:
        blocks.append({"type": "text", "text": "No vulnerability scanner is connected.", "muted": True})
        return blocks
    rows = [f for f in vulns.findings(c.conn, limit=1000) if c.keep(f["device_id"])]
    sev: dict[str, int] = {}
    for f in rows:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    blocks.append({"type": "tiles", "items": [{"value": str(sev.get(k, 0)), "label": k, "tone": "bad" if k in ("critical", "high") and sev.get(k) else ""} for k in ("critical", "high", "medium", "low")]})
    worst = [f for f in rows if f["severity"] in ("critical", "high")][:10]
    if worst:
        blocks.append({"type": "table", "title": "The most serious", "columns": [{"key": "dev", "label": "Device", "w": 2.4}, {"key": "t", "label": "Finding", "w": 4}, {"key": "s", "label": "Severity", "w": 1, "align": "right"},
                                                                              {"key": "x", "label": "Exploited", "w": 1, "align": "right"}],
                       "rows": [{"dev": f["device"] or f["host_ip"] or "", "t": f["title"], "s": f["severity"], "x": "yes" if f["exploited"] else "", "_tone": "bad" if f["exploited"] else ""} for f in worst]})
    return blocks


def _network(c: Ctx) -> list[dict]:
    blocks: list[dict] = [{"type": "heading", "text": "Wi-Fi and internet connections"}]
    names = {r["id"]: (r["custom_name"] or r["hostname"] or r["primary_ip"] or f"device {r['id']}") for r in c.conn.execute("SELECT id, custom_name, hostname, primary_ip FROM devices")}
    from app import airspace

    rows = []
    for r in c.conn.execute("SELECT device_id FROM wifi_radios GROUP BY device_id"):
        if not c.keep(r["device_id"]):
            continue
        for radio in airspace.for_device(c.conn, r["device_id"])["radios"]:
            advice = radio["advice"]
            rows.append({"ap": names.get(r["device_id"], ""), "radio": f"{radio['band'] or ''} ch {radio['channel'] or '?'}", "cl": "" if radio["clients"] is None else str(radio["clients"]),
                         "air": "" if radio["utilization_pct"] is None else f"{radio['utilization_pct']:.0f}%", "sh": "" if advice["networks"] is None else str(advice["networks"]),
                         "tip": f"channel {advice['suggest']['channel']} is quieter" if advice["suggest"] else "", "_tone": "warn" if advice["suggest"] else ""})
    if rows:
        blocks.append({"type": "table", "title": "Access points", "columns": [{"key": "ap", "label": "Access point", "w": 2.6}, {"key": "radio", "label": "Radio", "w": 1.6}, {"key": "cl", "label": "Clients", "w": 0.9, "align": "right"},
                       {"key": "air", "label": "Airtime", "w": 0.9, "align": "right"}, {"key": "sh", "label": "Neighbours", "w": 1.1, "align": "right"}, {"key": "tip", "label": "", "w": 2.4}], "rows": rows[:20]})
    wan = []
    for r in c.conn.execute("SELECT device_id, name, up, active, ip FROM node_uplinks ORDER BY device_id, priority IS NULL, priority, name"):
        if c.keep(r["device_id"]):
            wan.append({"gw": names.get(r["device_id"], ""), "name": r["name"], "state": "down" if r["up"] == 0 else "in use" if r["active"] else "standby" if r["up"] else "unknown", "ip": r["ip"] or "", "_tone": "bad" if r["up"] == 0 else ""})
    if wan:
        blocks.append({"type": "table", "title": "Internet connections", "columns": [{"key": "gw", "label": "Gateway", "w": 2.6}, {"key": "name", "label": "Connection", "w": 2}, {"key": "state", "label": "State", "w": 1.2}, {"key": "ip", "label": "Address", "w": 1.8}], "rows": wan})
    if not rows and not wan:
        blocks.append({"type": "text", "text": "No router or access point reports its Wi-Fi channels or internet connections yet.", "muted": True})
    return blocks


def _devices(c: Ctx) -> list[dict]:
    where = "same_host_id IS NULL AND report_exclude = 0" + (" AND id IN ({})".format(",".join(str(int(i)) for i in c.ids) or "NULL") if c.ids is not None else "")
    blocks: list[dict] = [{"type": "heading", "text": "Devices"}]
    types: dict[str, int] = {}
    for r in c.conn.execute(f"SELECT COALESCE(type_override, device_type, 'unknown') AS t, COUNT(*) AS n FROM devices WHERE {where} GROUP BY t ORDER BY n DESC"):
        types[r["t"]] = r["n"]
    if types:
        top = max(types.values())
        blocks.append({"type": "bars", "title": "By type", "items": [{"label": k.replace("_", " ").capitalize(), "value": v, "max": top, "text": str(v)} for k, v in list(types.items())[:8]]})
    new = c.conn.execute(f"SELECT COALESCE(custom_name, hostname, primary_ip) AS n, COALESCE(type_override, device_type, 'unknown') AS t, first_seen FROM devices WHERE {where} AND first_seen >= ? AND first_seen < ? ORDER BY first_seen",
                         (c.start.strftime("%Y-%m-%dT%H:%M:%SZ"), c.end.strftime("%Y-%m-%dT%H:%M:%SZ"))).fetchall()
    if new:
        blocks.append({"type": "table", "title": f"New in this period ({len(new)})", "columns": [{"key": "n", "label": "Device", "w": 3}, {"key": "t", "label": "Type", "w": 1.5}, {"key": "f", "label": "First seen", "w": 1.5}],
                       "rows": [{"n": r["n"], "t": r["t"].replace("_", " "), "f": _day(r["first_seen"])} for r in new[:12]]})
    off = c.conn.execute(f"SELECT COALESCE(custom_name, hostname, primary_ip) AS n, always_on, last_seen FROM devices WHERE {where} AND online = 0 ORDER BY always_on DESC, last_seen DESC LIMIT 12").fetchall()
    if off:
        blocks.append({"type": "table", "title": "Offline now", "columns": [{"key": "n", "label": "Device", "w": 3}, {"key": "a", "label": "Always on", "w": 1.2}, {"key": "l", "label": "Last seen", "w": 1.5}],
                       "rows": [{"n": r["n"], "a": "yes" if r["always_on"] else "", "l": _day(r["last_seen"]), "_tone": "warn" if r["always_on"] else ""} for r in off]})
    return blocks


BUILDERS = {"summary": _summary, "availability": _availability, "incidents": _incidents, "changes": _changes, "capacity": _capacity, "health": _health,
            "vulnerabilities": _vulnerabilities, "network": _network, "devices": _devices}


def build(conn, tpl: dict, now: datetime | None = None, period: str | None = None, month: str | None = None, logo: tuple[bytes, str] | None = None) -> dict:
    """The document: {"meta": {...}, "blocks": [...]}. `period` and `month` override the template's period (for "make one now")."""
    now = now or datetime.now(timezone.utc)
    start, end, words = bounds(period or tpl["period"], now, month)
    ctx = Ctx(conn, tpl, start, end, now)
    blocks: list[dict] = []
    for key in tpl["sections"]:
        try:
            blocks.extend(BUILDERS[key](ctx))
        except Exception:  # noqa: BLE001 - one section failing must not cost the whole report
            log.exception("the %s section of a report failed", key)
            blocks.extend([{"type": "heading", "text": SECTIONS[key].split(" (")[0]}, {"type": "text", "text": "This part could not be made this time.", "muted": True}])
    meta = {"title": tpl["title"], "subtitle": tpl["subtitle"], "prepared_for": tpl["prepared_for"], "period": words, "generated": now.astimezone().strftime("%d %b %Y %H:%M"), "accent": tpl["accent"],
            "footer": tpl["footer"], "show_netlens": tpl["show_netlens"], "logo": logo, "scope": "the selected groups" if tpl["scope"]["type"] == "group" else "the whole network",
            "start": start.strftime("%Y-%m-%dT%H:%M:%SZ"), "end": end.strftime("%Y-%m-%dT%H:%M:%SZ")}
    return {"meta": meta, "blocks": blocks}


def text_summary(doc: dict) -> str:
    """A few plain lines for the body of the e-mail that carries the PDF."""
    m = doc["meta"]
    lines = [f"{m['title']}", f"Period: {m['period']}", ""]
    for b in doc["blocks"]:
        if b["type"] == "score":
            lines.append(f"Network health: {b['value']} of 100 ({b['label']})" + (f", {b['trend']}" if b.get("trend") else ""))
        elif b["type"] == "tiles":
            lines.append(", ".join(f"{t['label']}: {t['value']}" for t in b["items"]))
        elif b["type"] == "text" and not b.get("muted") and len(lines) < 14:
            lines.append(b["text"])
    return "\n".join(lines)


# ----------------------------------------------------------------------------- the web page
def render_html(doc: dict) -> str:
    esc = htmllib.escape
    m = doc["meta"]
    accent = m["accent"]
    logo = ""
    if m.get("logo"):
        data, kind = m["logo"]
        logo = f'<img class="logo" alt="" src="data:{esc(kind)};base64,{base64.b64encode(data).decode()}">'
    out = [f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{esc(m['title'])} - {esc(m['period'])}</title>
<style>
:root {{ --accent: {accent}; --ok: {TONES['ok']}; --warn: {TONES['warn']}; --bad: {TONES['bad']}; --muted: #6b7280; --line: #e5e7eb; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: #f3f4f6; color: #1c1f24; font: 14px/1.5 -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; }}
.page {{ max-width: 860px; margin: 24px auto; background: #fff; padding: 36px 44px; box-shadow: 0 1px 8px rgba(0,0,0,.12); }}
.head {{ display: flex; gap: 20px; align-items: center; border-bottom: 4px solid var(--accent); padding-bottom: 16px; margin-bottom: 8px; }}
.logo {{ max-height: 64px; max-width: 200px; }}
h1 {{ margin: 0; font-size: 26px; }} .sub {{ color: var(--muted); margin: 2px 0 0; }}
.meta {{ color: var(--muted); font-size: 12px; margin: 0 0 12px; }}
h2 {{ margin: 28px 0 8px; font-size: 18px; color: var(--accent); border-bottom: 1px solid var(--line); padding-bottom: 4px; }}
h3 {{ margin: 16px 0 6px; font-size: 14px; }}
.muted {{ color: var(--muted); }}
.tiles {{ display: flex; flex-wrap: wrap; gap: 10px; margin: 10px 0; }}
.tile {{ flex: 1 1 140px; border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; }}
.tile b {{ display: block; font-size: 22px; }} .tile span {{ color: var(--muted); font-size: 12px; }}
.ok {{ color: var(--ok); }} .warn {{ color: var(--warn); }} .bad {{ color: var(--bad); }}
table {{ width: 100%; border-collapse: collapse; margin: 6px 0 12px; font-size: 13px; }}
th {{ background: var(--accent); color: #fff; text-align: left; padding: 5px 8px; font-weight: 600; }}
td {{ padding: 5px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }} tr:nth-child(even) td {{ background: #f9fafb; }}
.r {{ text-align: right; white-space: nowrap; }}
.bar {{ display: grid; grid-template-columns: 30% 1fr 12%; gap: 8px; align-items: center; margin: 3px 0; }}
.track {{ background: var(--line); border-radius: 4px; height: 10px; }} .fill {{ background: var(--accent); height: 10px; border-radius: 4px; }}
.score {{ display: flex; gap: 20px; align-items: center; margin: 10px 0; }} .score svg {{ flex: none; }}
.foot {{ margin-top: 32px; padding-top: 10px; border-top: 1px solid var(--line); color: var(--muted); font-size: 12px; display: flex; justify-content: space-between; gap: 12px; }}
@media print {{ body {{ background: #fff; }} .page {{ box-shadow: none; margin: 0; max-width: none; padding: 0; }} h2, table, .tile {{ break-inside: avoid; }} * {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }} }}
</style></head><body><div class="page">
<div class="head">{logo}<div><h1>{esc(m['title'])}</h1>{f'<p class="sub">{esc(m["subtitle"])}</p>' if m['subtitle'] else ''}</div></div>
<p class="meta">{esc(m['period'])} · {esc(m['scope'])}{(' · prepared for ' + esc(m['prepared_for'])) if m['prepared_for'] else ''} · made {esc(m['generated'])}</p>"""]
    for b in doc["blocks"]:
        t = b["type"]
        if t == "heading":
            out.append(f"<h2>{esc(b['text'])}</h2>")
        elif t == "text":
            out.append(f"<p class=\"{'muted' if b.get('muted') else ''}\">{esc(b['text'])}</p>")
        elif t == "tiles":
            out.append('<div class="tiles">' + "".join(f'<div class="tile"><b class="{esc(i["tone"])}">{esc(i["value"])}</b><span>{esc(i["label"])}</span></div>' for i in b["items"]) + "</div>")
        elif t == "score":
            tone = "ok" if b["value"] >= 80 else "warn" if b["value"] >= 50 else "bad"
            circ = 2 * math.pi * 40
            out.append(f'<div class="score"><svg width="100" height="100" viewBox="0 0 100 100" role="img" aria-label="Health score {b["value"]}"><circle cx="50" cy="50" r="40" fill="none" stroke="#e5e7eb" stroke-width="10"/>'
                       f'<circle cx="50" cy="50" r="40" fill="none" stroke="{TONES[tone]}" stroke-width="10" stroke-linecap="round" stroke-dasharray="{circ * b["value"] / 100:.1f} {circ:.1f}" transform="rotate(-90 50 50)"/>'
                       f'<text x="50" y="58" text-anchor="middle" font-size="26" font-weight="700" fill="#1c1f24">{b["value"]}</text></svg>'
                       f'<div><b class="{tone}">Health is {esc(b["label"])}</b>{(" <span class=muted>(" + esc(b["trend"]) + ")</span>") if b.get("trend") else ""}<br><span class="muted">{esc(b["text"])}</span></div></div>')
        elif t == "table":
            if b.get("title"):
                out.append(f"<h3>{esc(b['title'])}</h3>")
            head = "".join(f'<th class="{"r" if c.get("align") == "right" else ""}">{esc(c["label"])}</th>' for c in b["columns"])
            body = "".join("<tr>" + "".join(f'<td class="{"r" if c.get("align") == "right" else ""} {esc(r.get("_tone", "")) if c["key"] == b["columns"][0]["key"] else ""}">{esc(str(r.get(c["key"], "")))}</td>' for c in b["columns"]) + "</tr>" for r in b["rows"])
            out.append(f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>")
        elif t == "bars":
            if b.get("title"):
                out.append(f"<h3>{esc(b['title'])}</h3>")
            for i in b["items"]:
                out.append(f'<div class="bar"><span>{esc(i["label"])}</span><div class="track"><div class="fill" style="width:{max(2, 100 * i["value"] / (i["max"] or 1)):.0f}%"></div></div><span class="r">{esc(i["text"])}</span></div>')
        elif t == "line":
            out.append(f"<h3>{esc(b['title'])}</h3>" + _svg_line(b))
    foot_right = "Made with Netlens" if m["show_netlens"] else ""
    out.append(f'<div class="foot"><span>{esc(m["footer"])}</span><span>{foot_right}</span></div></div></body></html>')
    return "".join(out)


def _svg_line(b: dict) -> str:
    pts = b["points"]
    w, h_, pl, pr, pt, pb = 760, 150, 34, 8, 8, 22
    lo, hi = b.get("min", min(p["y"] for p in pts)), b.get("max", max(p["y"] for p in pts))
    hi = hi if hi > lo else lo + 1
    x = lambda i: pl + i * (w - pl - pr) / max(1, len(pts) - 1)
    y = lambda v: pt + (1 - (v - lo) / (hi - lo)) * (h_ - pt - pb)
    grid = "".join(f'<line x1="{pl}" x2="{w - pr}" y1="{y(v):.1f}" y2="{y(v):.1f}" stroke="#e5e7eb"/><text x="{pl - 4}" y="{y(v) + 3:.1f}" text-anchor="end" font-size="10" fill="#6b7280">{v:g}</text>' for v in (lo, (lo + hi) / 2, hi))
    labels = "".join(f'<text x="{x(i):.1f}" y="{h_ - 6}" text-anchor="{a}" font-size="10" fill="#6b7280">{htmllib.escape(pts[i]["x"])}</text>' for i, a in ((0, "start"), (len(pts) // 2, "middle"), (len(pts) - 1, "end")))
    line = " ".join(f"{x(i):.1f},{y(p['y']):.1f}" for i, p in enumerate(pts))
    return f'<svg viewBox="0 0 {w} {h_}" width="100%" role="img">{grid}{labels}<polyline points="{line}" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linejoin="round"/></svg>'


# ----------------------------------------------------------------------------- the PDF
M = 44.0                                                         # page margin
LEAD = 1.28


class _Flow:
    """Lays blocks down the pages: a block that does not fit starts a new page, a table carries its heading row over."""

    def __init__(self, doc: dict):
        self.doc = doc
        self.meta = doc["meta"]
        self.pdf = pdflib.Pdf(title=f"{self.meta['title']} - {self.meta['period']}", author=self.meta.get("prepared_for") or "Netlens", subject=self.meta["period"])
        self.accent = self.meta["accent"]
        self.logo = None
        if self.meta.get("logo"):
            try:
                self.logo = pdfimage.load(self.meta["logo"][0])
            except pdfimage.ImageError:
                self.logo = None
        self.page: pdflib.Page | None = None
        self.y = 0.0
        self.w = pdflib.A4[0] - 2 * M
        self.bottom = pdflib.A4[1] - 52

    def new_page(self, first: bool = False) -> None:
        self.page = self.pdf.add_page()
        if first:
            self.y = M
            self._cover()
        else:
            self.page.text(M, 30, fit(self.meta["title"], self.w - 120, 8.5), 8.5, color="#6b7280")
            self.page.text(M, 30, self.meta["period"], 8.5, color="#6b7280", align="right", width=self.w)
            self.page.line(M, 36, M + self.w, 36, "#e5e7eb")
            self.y = 54

    def _cover(self) -> None:
        p = self.page
        p.rect(0, 0, pdflib.A4[0], 8, fill=self.accent)
        x = M
        top = M + 6
        if self.logo:
            h = 46.0
            w = min(150.0, self.logo["width"] * h / self.logo["height"])
            h = w * self.logo["height"] / self.logo["width"]
            p.image(self.logo, M, top, w, h)
            x = M + w + 16
        p.text(x, top + 20, fit(self.meta["title"], self.w - (x - M), 22, True), 22, True)
        if self.meta["subtitle"]:
            p.text(x, top + 38, fit(self.meta["subtitle"], self.w - (x - M), 11), 11, color="#6b7280")
        info = f"{self.meta['period']}  ·  {self.meta['scope']}" + (f"  ·  prepared for {self.meta['prepared_for']}" if self.meta["prepared_for"] else "")
        p.line(M, top + 62, M + self.w, top + 62, self.accent, 1.5)
        p.text(M, top + 78, fit(info, self.w, 9), 9, color="#6b7280")
        p.text(M, top + 90, f"Made {self.meta['generated']}", 8, color="#9ca3af")
        self.y = top + 112

    def need(self, height: float) -> None:
        if self.y + height > self.bottom:
            self.new_page()

    # --- blocks
    def heading(self, text: str) -> None:
        self.need(110)                                          # a heading is never left alone at the bottom of a page
        self.y += 10
        self.page.text(M, self.y + 12, text, 14, True, self.accent)
        self.page.line(M, self.y + 18, M + self.w, self.y + 18, "#e5e7eb")
        self.y += 30

    def text(self, text: str, muted: bool = False, size: float = 9.5) -> None:
        for line in pdflib.wrap(text, self.w, size):
            self.need(size * LEAD)
            self.page.text(M, self.y + size, line, size, color="#6b7280" if muted else "#1c1f24")
            self.y += size * LEAD
        self.y += 4

    def tiles(self, items: list[dict]) -> None:
        per = min(4, max(1, len(items)))
        gap, h = 8.0, 54.0
        tw = (self.w - gap * (per - 1)) / per
        for start in range(0, len(items), per):
            self.need(h + 6)
            for i, t in enumerate(items[start:start + per]):
                x = M + i * (tw + gap)
                self.page.rounded(x, self.y, tw, h, 6, fill="#f9fafb", stroke="#e5e7eb")
                self.page.text(x + 10, self.y + 26, fit(t["value"], tw - 20, 18, True), 18, True, TONES.get(t["tone"], TONES[""]) if t["tone"] else "#1c1f24")
                self.page.text(x + 10, self.y + 42, fit(t["label"], tw - 20, 8.5), 8.5, color="#6b7280")
            self.y += h + 8

    def score(self, b: dict) -> None:
        self.need(100)
        cx, cy, r = M + 40, self.y + 44, 30
        tone = "ok" if b["value"] >= 80 else "warn" if b["value"] >= 50 else "bad"
        self.page.arc(cx, cy, r, 0, 360, "#e5e7eb", 9)
        self.page.arc(cx, cy, r, 0, 3.6 * max(1, b["value"]) if b["value"] < 100 else 359.9, TONES[tone], 9)
        self.page.text(cx - 40, cy + 8, str(b["value"]), 22, True, align="center", width=80)
        x = M + 96
        self.page.text(x, self.y + 30, f"Health is {b['label']}", 13, True, TONES[tone])
        if b.get("trend"):
            self.page.text(x + pdflib.text_width(f"Health is {b['label']}", 13, True) + 8, self.y + 30, b["trend"], 9, color="#6b7280")
        for k, line in enumerate(pdflib.wrap(b["text"], self.w - 100, 9.5)[:3]):
            self.page.text(x, self.y + 46 + k * 12, line, 9.5, color="#4b5563")
        self.y += 96

    def bars(self, b: dict) -> None:
        if b.get("title"):
            self.need(40)
            self.page.text(M, self.y + 11, b["title"], 10.5, True)
            self.y += 20
        lw, tw = self.w * 0.3, self.w * 0.55
        for i in b["items"]:
            self.need(18)
            self.page.text(M, self.y + 10, fit(i["label"], lw - 6, 9), 9)
            self.page.rounded(M + lw, self.y + 2, tw, 9, 3, fill="#e5e7eb")
            self.page.rounded(M + lw, self.y + 2, max(4.0, tw * i["value"] / (i["max"] or 1)), 9, 3, fill=self.accent)
            self.page.text(M + lw + tw + 6, self.y + 10, i["text"], 9, align="left")
            self.y += 17
        self.y += 6

    def line_chart(self, b: dict) -> None:
        self.need(150)
        self.page.text(M, self.y + 11, b["title"], 10.5, True)
        self.y += 18
        pl, pr, pt, pb = 30.0, 6.0, 6.0, 16.0
        h = 100.0
        x0, x1, y0, y1 = M + pl, M + self.w - pr, self.y + pt, self.y + h - pb
        pts = b["points"]
        lo, hi = b.get("min", min(p["y"] for p in pts)), b.get("max", max(p["y"] for p in pts))
        hi = hi if hi > lo else lo + 1
        for v in (lo, (lo + hi) / 2, hi):
            yy = y1 - (v - lo) / (hi - lo) * (y1 - y0)
            self.page.line(x0, yy, x1, yy, "#e5e7eb", 0.5)
            self.page.text(M, yy + 3, f"{v:g}", 7.5, color="#6b7280", align="right", width=pl - 4)
        xs = [x0 + i * (x1 - x0) / max(1, len(pts) - 1) for i in range(len(pts))]
        self.page.polyline([(xs[i], y1 - (p["y"] - lo) / (hi - lo) * (y1 - y0)) for i, p in enumerate(pts)], self.accent, 1.6)
        for i, align in ((0, "left"), (len(pts) // 2, "center"), (len(pts) - 1, "right")):
            w = 60
            self.page.text(xs[i] - (0 if align == "left" else w if align == "right" else w / 2), self.y + h - 4, pts[i]["x"], 7.5, color="#6b7280", align=align, width=w if align != "left" else None)
        self.y += h + 10

    def table(self, b: dict) -> None:
        cols = b["columns"]
        total = sum(c["w"] for c in cols)
        widths = [self.w * c["w"] / total for c in cols]
        size, pad = 8.5, 5.0
        if b.get("title"):
            self.need(50)
            self.page.text(M, self.y + 11, b["title"], 10.5, True)
            self.y += 18

        def header() -> None:
            self.need(22)
            self.page.rect(M, self.y, self.w, 17, fill=self.accent)
            x = M
            for c, w in zip(cols, widths):
                self.page.text(x + pad, self.y + 12, fit(c["label"], w - 2 * pad, size, True), size, True, "#ffffff", align="right" if c.get("align") == "right" else "left", width=w - 2 * pad)
                x += w
            self.y += 17

        header()
        for n, row in enumerate(b["rows"]):
            cells = [pdflib.wrap(str(row.get(c["key"], "")), w - 2 * pad, size) for c, w in zip(cols, widths)]
            height = max(len(lines) for lines in cells) * size * LEAD + 6
            if self.y + height > self.bottom:
                self.new_page()
                header()
            if n % 2:
                self.page.rect(M, self.y, self.w, height, fill="#f9fafb")
            x = M
            for ci, (c, w, lines) in enumerate(zip(cols, widths, cells)):
                colour = TONES[row["_tone"]] if row.get("_tone") and ci == 0 and row["_tone"] in TONES and row["_tone"] else "#1c1f24"
                for k, line in enumerate(lines):
                    self.page.text(x + pad, self.y + 3 + size + k * size * LEAD, line, size, color=colour, align="right" if c.get("align") == "right" else "left", width=w - 2 * pad)
                x += w
            self.page.line(M, self.y + height, M + self.w, self.y + height, "#e5e7eb", 0.4)
            self.y += height
        self.y += 10


def fit(text: str, width: float, size: float, bold: bool = False) -> str:
    return pdflib.fit(text, width, size, bold)


def render_pdf(doc: dict) -> bytes:
    flow = _Flow(doc)
    flow.new_page(first=True)
    for b in doc["blocks"]:
        t = b["type"]
        if t == "heading":
            flow.heading(b["text"])
        elif t == "text":
            flow.text(b["text"], b.get("muted", False))
        elif t == "tiles":
            flow.tiles(b["items"])
        elif t == "score":
            flow.score(b)
        elif t == "table":
            flow.table(b)
        elif t == "bars":
            flow.bars(b)
        elif t == "line":
            flow.line_chart(b)
    total = len(flow.pdf.pages)
    for n, page in enumerate(flow.pdf.pages, 1):                  # the footer of every page: the footer text, then "Page n of N"
        page.line(M, pdflib.A4[1] - 40, M + flow.w, pdflib.A4[1] - 40, "#e5e7eb", 0.5)
        left = flow.meta["footer"] or ("Made with Netlens" if flow.meta["show_netlens"] else "")
        page.text(M, pdflib.A4[1] - 27, fit(left, flow.w - 90, 8), 8, color="#9ca3af")
        page.text(M, pdflib.A4[1] - 27, f"Page {n} of {total}", 8, color="#9ca3af", align="right", width=flow.w)
    return flow.pdf.bytes()
