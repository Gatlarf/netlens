"""Ask your network: questions answered from Netlens's own data (a paid feature, see app/insights.py).

Without a language model a question is matched to one of the ready-made questions by its words, and the answer is written from the numbers.
With one, the model chooses among the same read-only tools (it cannot run anything else and cannot change any data), looks at what they return and
writes the answer. Names and addresses reach the model as placeholders and come back as the real ones.
"""

from __future__ import annotations

import contextvars
import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from app import engineer, forecast, incidents, insights, anomaly, relevance, reports
from app.insights import complete  # noqa: F401 - re-exported for the tests

STAMP = "%Y-%m-%dT%H:%M:%SZ"
MAX_STEPS = 4
MAX_RESULT = 3500
LIMIT = 15


# Which devices count. A phone going offline is not news: by default the answers are about the devices that are meant to be on
# (marked always-on, or of an infrastructure kind) and about network problems. `scope="all"` brings everything back.
_SCOPE: contextvars.ContextVar[str] = contextvars.ContextVar("ask_scope", default="all")
_FOR_MODEL: contextvars.ContextVar[bool] = contextvars.ContextVar("ask_for_model", default=False)       # the result of a tool goes to a language model: no file or folder names


def for_model() -> bool:
    return _FOR_MODEL.get()


def important_ids(conn) -> set[int] | None:
    """The ids of the devices that matter, or None when every device counts (scope "all", or none of them is marked)."""
    return None if _SCOPE.get() == "all" else relevance.important_ids(conn)


def _days(value: Any, default: int = 7) -> int:
    try:
        return max(1, min(int(value), 30))
    except (TypeError, ValueError):
        return default


def _name(row) -> str:
    return row["custom_name"] or row["hostname"] or row["primary_ip"] or f"device {row['id']}"


def _since(days: int, now: datetime | None) -> str:
    return ((now or datetime.now(timezone.utc)) - timedelta(days=days)).strftime(STAMP)


# ----------------------------------------------------------------------------- the tools (read only)
def t_overview(conn, args, now=None) -> dict:
    keep = important_ids(conn)
    rows = [r for r in conn.execute("SELECT id, custom_name, hostname, primary_ip, online FROM devices ORDER BY last_seen DESC") if keep is None or r["id"] in keep]
    down = [_name(r) for r in rows if not r["online"]][:LIMIT]
    services = [r["name"] for r in conn.execute("SELECT name FROM service_checks WHERE enabled = 1 AND last_up = 0 LIMIT ?", (LIMIT,))]
    from app import dashboard

    needs_attention = [{"level": i["level"], "text": i["text"]} for i in dashboard.current_problems(conn)][:LIMIT * 2]       # the same list as the dashboard
    return {"devices": len(rows), "online": sum(1 for r in rows if r["online"]), "offline_devices": down, "services_down": services, "needs_attention": needs_attention}


def t_offline_now(conn, args, now=None) -> dict:
    keep = important_ids(conn)
    rows = [r for r in conn.execute("SELECT id, custom_name, hostname, primary_ip, last_seen, always_on FROM devices WHERE online = 0 ORDER BY always_on DESC, last_seen DESC LIMIT 400") if keep is None or r["id"] in keep][:LIMIT * 2]
    return {"offline": [{"name": _name(r), "last_seen": r["last_seen"], "always_on": bool(r["always_on"])} for r in rows]}


def t_events(conn, args, now=None) -> dict:
    days, kind, text = _days(args.get("days"), 1), str(args.get("kind") or ""), str(args.get("device") or "").lower()
    names = {r["id"]: _name(r) for r in conn.execute("SELECT id, custom_name, hostname, primary_ip FROM devices")}
    out = []
    keep = important_ids(conn)
    for r in conn.execute("SELECT ts, kind, device_id, detail FROM events WHERE ts >= ? ORDER BY id DESC LIMIT 400", (_since(days, now),)):
        if kind and r["kind"] != kind:
            continue
        if keep is not None and r["device_id"] is not None and r["device_id"] not in keep and not text:
            continue
        if text and text not in (names.get(r["device_id"]) or "").lower() and text not in (r["detail"] or "").lower():
            continue
        out.append({"at": r["ts"], "kind": r["kind"], "device": names.get(r["device_id"]), "detail": (r["detail"] or "")[:160]})
        if len(out) >= LIMIT:
            break
    return {"days": days, "events": out}


def t_availability(conn, args, now=None) -> dict:
    days = _days(args.get("days"), 7)
    end = now or datetime.now(timezone.utc)
    rep = reports.availability(conn, end - timedelta(days=days), end, with_services=True)
    keep = important_ids(conn)
    worst = sorted([d for d in rep["devices"] if d["outages"] and (keep is None or d["id"] in keep)], key=lambda d: d["availability"])[:LIMIT]
    return {"days": days, "summary": {k: rep["summary"][k] for k in ("devices", "devices_availability", "core_availability", "with_outages")},
            "least_available": [{"name": d["name"], "availability_pct": d["availability"], "outages": d["outages"], "down": d["down_text"]} for d in worst],
            "services_with_outages": [{"name": s["name"], "availability_pct": s["availability"], "down": s["down_text"]} for s in rep["services"] if s["outages"]][:LIMIT]}


def t_response_times(conn, args, now=None) -> dict:
    days = _days(args.get("days"), 7)
    fastest = str(args.get("order") or "").lower() in ("fastest", "lowest", "asc")
    since = _since(days, now)
    direction = "ASC" if fastest else "DESC"
    keep = important_ids(conn)
    devices = conn.execute(f"SELECT c.device_id AS id, COALESCE(d.custom_name, d.hostname, d.primary_ip) AS name, ROUND(AVG(c.rtt_ms), 1) AS avg_ms, ROUND(MAX(c.rtt_ms), 1) AS max_ms, COUNT(*) AS n "
                           f"FROM checks c JOIN devices d ON d.id = c.device_id WHERE c.ts >= ? AND c.up = 1 AND c.rtt_ms IS NOT NULL GROUP BY c.device_id HAVING n >= 3 ORDER BY avg_ms {direction} LIMIT 200", (since,)).fetchall()
    devices = [r for r in devices if keep is None or r["id"] in keep][:10]
    services = conn.execute(f"SELECT s.name AS name, ROUND(AVG(r.ms), 1) AS avg_ms, ROUND(MAX(r.ms), 1) AS max_ms, COUNT(*) AS n FROM service_results r JOIN service_checks s ON s.id = r.check_id "
                            f"WHERE r.ts >= ? AND r.up = 1 AND r.ms IS NOT NULL GROUP BY r.check_id HAVING n >= 3 ORDER BY avg_ms {direction} LIMIT ?", (since, 5)).fetchall()
    return {"days": days, "order": "fastest" if fastest else "slowest", "devices": [{k: r[k] for k in ("name", "avg_ms", "max_ms", "n")} for r in devices], "services": [dict(r) for r in services]}


def t_new_devices(conn, args, now=None) -> dict:
    days = _days(args.get("days"), 7)
    rows = conn.execute("SELECT id, custom_name, hostname, primary_ip, vendor, first_seen, online FROM devices WHERE first_seen >= ? ORDER BY first_seen DESC LIMIT ?", (_since(days, now), LIMIT)).fetchall()
    return {"days": days, "new_devices": [{"name": _name(r), "vendor": r["vendor"], "first_seen": r["first_seen"], "online": bool(r["online"])} for r in rows]}


def t_incidents(conn, args, now=None) -> dict:
    found = incidents.incidents(conn, _days(args.get("days"), 7), now, only=important_ids(conn))[:LIMIT]
    return {"incidents": [{"start": i["start"], "title": i["title"], "summary": i["summary"], "resolved": i["resolved"]} for i in found]}


def t_anomalies(conn, args, now=None) -> dict:
    keep = important_ids(conn)
    return {"unusual_now": [anomaly.describe(a) for a in anomaly.scan(conn) if keep is None or a.get("device_id") is None or a["device_id"] in keep][:LIMIT]}


def t_disks(conn, args, now=None) -> dict:
    items = [f for f in forecast.cached(conn) if f.get("days_to_full") is not None][:LIMIT]
    leaks = forecast.memory_trends(conn)[:LIMIT]
    return {"filling_up": [{"device": f["device"], "disk": f["label"], "used_pct": f["current"], "full_in_days": f["days_to_full"]} for f in items], "checked": len(forecast.cached(conn)),
            "memory_rising": [{"device": m["device"], "used_pct": m["current"], "pattern": m["pattern"], "out_of_memory_in_days": m["days_to_full"]} for m in leaks]}


HEALTH_METRICS = {"memory": "mem_pct", "ram": "mem_pct", "cpu": "cpu_pct", "processor": "cpu_pct", "disk": "disk_pct", "storage": "disk_pct", "temperature": "temp_c", "temp": "temp_c",
                  "battery": "battery_pct", "ups": "battery_pct"}
LOW_IS_BAD = {"battery_pct"}


def t_health(conn, args, now=None) -> dict:
    """The newest reading of one kind from every monitored host (Settings → Host monitoring), the most worrying first."""
    from app import tsdb
    from app.hostmetrics import service as hm

    metric = HEALTH_METRICS.get(str(args.get("metric") or "memory").lower(), "mem_pct")
    store = tsdb.for_conn(conn)
    t = (now or datetime.now(timezone.utc)).timestamp()
    rows = []
    monitored = conn.execute("SELECT m.device_id, COALESCE(d.custom_name, d.hostname, d.primary_ip) AS name FROM host_monitors m JOIN devices d ON d.id = m.device_id WHERE m.enabled = 1").fetchall()
    known = store.metrics_of_many("device", [r["device_id"] for r in monitored]) if store else {}
    for r in monitored:
        for s in known.get(r["device_id"], []):
            if s["metric"] == metric and s["last"] is not None and s["last_ts"] is not None and t - s["last_ts"] < 3 * 3600:
                rows.append({"device": r["name"], "label": s["label"], "value": round(s["last"], 1), "unit": s["unit"]})
    rows.sort(key=lambda x: x["value"], reverse=metric not in LOW_IS_BAD)
    limits = [{"device": p["device"], "reading": p["title"], "value": p["value"], "level": p["level"]} for p in hm.problems(conn) if p["metric"] == metric]
    return {"metric": metric, "monitored_hosts": len(monitored), "readings": rows[:12], "past_their_limit": limits[:12]}


def t_fixes(conn, args, now=None) -> dict:
    from app import remediation

    return {"runs": [{"rule": r["rule_name"], "device": r["device"], "state": r["state"], "result": (r["result"] or "")[:120], "recovered": bool(r.get("recovered")), "at": r["created"]}
                     for r in remediation.recent_runs(conn, 30)[:LIMIT]]}


def t_services(conn, args, now=None) -> dict:
    rows = conn.execute("SELECT name, kind, last_up, last_ms, last_detail FROM service_checks WHERE enabled = 1 ORDER BY last_up IS NULL, last_up, LOWER(name) LIMIT 60").fetchall()
    items = [{"name": r["name"], "kind": r["kind"], "state": "unknown" if r["last_up"] is None else "up" if r["last_up"] else "down", "response_ms": r["last_ms"], "detail": (r["last_detail"] or "")[:80] if r["last_up"] == 0 else ""} for r in rows]
    return {"total": len(items), "down": [i["name"] for i in items if i["state"] == "down"], "services": items[:30]}


def t_plugins(conn, args, now=None) -> dict:
    """How the syncs of the plugins went (the integrations with Proxmox, Home Assistant ...): failures, the last error and how long a sync takes."""
    days = _days(args.get("days"), 1)
    out = []
    for r in conn.execute("SELECT plugin_id, COUNT(*) AS n, SUM(ok) AS good, ROUND(AVG(ms), 0) AS avg_ms, ROUND(MAX(ms), 0) AS max_ms, MAX(ts) AS last_ts FROM plugin_runs WHERE ts >= ? GROUP BY plugin_id ORDER BY (n - good) DESC, plugin_id LIMIT ?",
                          (_since(days, now), LIMIT)):
        err = conn.execute("SELECT ts, detail FROM plugin_runs WHERE plugin_id = ? AND ok = 0 AND ts >= ? ORDER BY id DESC LIMIT 1", (r["plugin_id"], _since(days, now))).fetchone()
        out.append({"plugin": r["plugin_id"], "syncs": r["n"], "failed": r["n"] - (r["good"] or 0), "avg_sync_ms": r["avg_ms"], "slowest_sync_ms": r["max_ms"], "last_sync": r["last_ts"],
                    "last_error": (err["detail"] or "")[:160] if err else ""})
    return {"days": days, "plugins": out}


def _type_word(needle: str) -> str | None:
    for word in (needle, needle.rstrip("s"), needle.rstrip("es")):
        if word in TYPE_WORDS:
            return word
    return None


def t_device(conn, args, now=None) -> dict:
    needle = str(args.get("name") or "").strip().lower()
    if not needle:
        return {"error": "give a name or address"}
    kind = _type_word(needle)
    if kind:                                           # "the printers", "the switch": every device of that type
        end = now or datetime.now(timezone.utc)
        rep = {d["id"]: d for d in reports.availability(conn, end - timedelta(days=7), end, with_services=False)["devices"]}
        rows = conn.execute("SELECT * FROM devices WHERE COALESCE(type_override, device_type) = ? ORDER BY online, last_seen DESC LIMIT ?", (kind, LIMIT)).fetchall()
        if rows:
            return {"type": kind, "devices": [{"name": _name(r), "online": bool(r["online"]), "last_seen": r["last_seen"], "availability_7d_pct": rep[r["id"]]["availability"] if r["id"] in rep else None,
                                               "outages_7d": rep[r["id"]]["outages"] if r["id"] in rep else None} for r in rows]}
    rows = [r for r in conn.execute("SELECT * FROM devices") if needle in (_name(r) or "").lower() or needle == (r["primary_ip"] or "")]
    if not rows:
        found = ask_more.TOOLS["site"][0](conn, {"name": needle}, now)       # not a device: perhaps a website or a service ("why is example.com down")
        if not found.get("error"):
            return found
        return {"error": f"no device matches {needle!r}"}
    r = rows[0]
    end = now or datetime.now(timezone.utc)
    rep = reports.availability(conn, end - timedelta(days=7), end, with_services=False)
    mine = next((d for d in rep["devices"] if d["id"] == r["id"]), None)
    events = conn.execute("SELECT ts, kind, detail FROM events WHERE device_id = ? ORDER BY id DESC LIMIT 8", (r["id"],)).fetchall()
    services = [{"name": s["name"], "up": None if s["last_up"] is None else bool(s["last_up"])} for s in conn.execute("SELECT name, last_up FROM service_checks WHERE enabled = 1 AND device_id = ?", (r["id"],))]
    return {"name": _name(r), "type": r["type_override"] or r["device_type"], "vendor": r["vendor"], "online": bool(r["online"]), "first_seen": r["first_seen"], "last_seen": r["last_seen"],
            "availability_7d_pct": mine["availability"] if mine else None, "outages_7d": mine["outages"] if mine else None, "services": services,
            "recent_events": [{"at": e["ts"], "kind": e["kind"], "detail": (e["detail"] or "")[:120]} for e in events], "other_matches": len(rows) - 1}


TYPE_WORDS = ("router", "switch", "tablet", "tv", "speaker", "console", "appliance", "printer", "iot", "camera", "nas", "phone", "server", "pc")

TOOLS: dict[str, tuple[Callable, str]] = {
    "overview": (t_overview, "how many devices are online, which are offline and which services are down right now, plus everything else the dashboard lists under needs attention (full or filling disks, hot or busy hosts, restarting containers, failed backups, failing plugins, expiring certificates ...). args: none"),
    "offline_now": (t_offline_now, "the devices that are offline now with the time they were last seen. args: none"),
    "events": (t_events, "recent events (devices going offline or online, services, alerts). args: days (1-30), kind (optional event kind such as device_offline), device (optional name text)"),
    "availability": (t_availability, "availability percentages and outages of devices and services over a period. args: days (1-30)"),
    "response_times": (t_response_times, "average response time (ping for devices, answer time for services) over a period, slowest first. args: days (1-30), order (slowest or fastest)"),
    "new_devices": (t_new_devices, "devices first seen in a period. args: days (1-30)"),
    "incidents": (t_incidents, "incidents (grouped problems with a probable cause) of a period. args: days (1-30)"),
    "anomalies": (t_anomalies, "readings that are unusual right now for the time of day. args: none"),
    "health": (t_health, "CURRENT readings of the monitored hosts: memory (RAM), cpu (processor), disk (usage), temperature, battery. Most worrying first. args: metric (memory, cpu, disk, temperature or battery)"),
    "disks": (t_disks, "FORECAST only, not current usage: disks that will fill up and memory use that keeps rising, with the days left. For current usage use health. args: none"),
    "fixes": (t_fixes, "recent automatic fixes (auto-remediation) and whether they worked. args: none"),
    "services": (t_services, "all service checks (websites, ports, DNS) with their state and response time. args: none"),
    "plugins": (t_plugins, "how the syncs of the plugins (integrations such as Proxmox, Home Assistant, UniFi) went: failures, the last error, how long a sync takes. args: days (1-30)"),
    "device": (t_device, "details of one device, or of every device of a kind. args: name (a device name, host name or address, or a kind: printer, switch, nas, camera, router, tv, phone, server, pc ...)"),
}

# ----------------------------------------------------------------------------- without a model
PRESETS = [
    {"id": "now", "text": "What is wrong right now?", "tool": "overview", "args": {}},
    {"id": "changed", "text": "What happened in the last 24 hours?", "tool": "incidents", "args": {"days": 1}},
    {"id": "week", "text": "Which devices were least available this week?", "tool": "availability", "args": {"days": 7}},
    {"id": "new", "text": "Which new devices appeared this week?", "tool": "new_devices", "args": {"days": 7}},
    {"id": "unusual", "text": "Is anything behaving unusually?", "tool": "anomalies", "args": {}},
    {"id": "disks", "text": "Which disks are filling up?", "tool": "disks", "args": {}},
    {"id": "fixes", "text": "What did the automatic fixes do?", "tool": "fixes", "args": {}},
]
KEYWORDS = [
    ("plugins", r"\bplugins?\b|integrations?"),
    ("disks", r"fill up|filling|run out|will be full|when will|predict|forecast|leak"),
    ("health", r"\bram\b|memory|\bcpu\b|processor|temperature|\bhot\b|\bbusy\b|battery|\bups\b|\bdisks?\b|storage|disk space|\bfull\b|\bload\b"),
    ("response_times", r"response|latenc|\bping|\bslow|\bfast|\brtt\b|\blag"), ("services", r"\bservices?\b|website|\bsites?\b|checks? (is|are)"), ("anomalies", r"unusual|anomal|strange|weird|odd|abnormal"), ("fixes", r"\bfix|remediat|restart|reset|repair"),
    ("new_devices", r"\bnew\b|unknown|appeared|joined|stranger|first seen"), ("availability", r"uptime|availab|reliab|worst|least|outage|stable|flaky"),
    ("incidents", r"happen|changed|incident|yesterday|last night|summar|recap|what.?s new"), ("offline_now", r"\boffline|\bdown\b|not working|unreachable|dead"),
    ("overview", r"wrong|problem|issue|status|health|\bok\b|\bfine\b|right now|going on"),
]


def route(question: str, known_names: list[str], conn=None) -> tuple[str, dict]:
    """(tool, args) for a question, by its words: a device name wins, then the first keyword group that matches."""
    q = question.lower()
    if conn is not None:
        extra = ask_extra.route(q, known_names)
        if extra:
            return extra
        more = ask_more.route(conn, q, known_names)
        if more:
            return more
    days = 1 if re.search(r"today|24 ?h|yesterday|last night|day\b", q) else 30 if "month" in q else 7
    if conn is not None and re.search(r"\b(why|how come|reason)\b", q):         # "why is example.com offline": a website, which may be switched off on the proxy
        for needle in ask_more.site_needles(q):
            if "." in needle and not ask_more.TOOLS["site"][0](conn, {"name": needle}).get("error"):
                return "site", {"name": needle}
    for name in sorted(known_names, key=len, reverse=True):
        if len(name) > 2 and re.search(r"(?<![\w.-])" + re.escape(name.lower()) + r"(?![\w-])", q):
            return "device", {"name": name}
    comparative = re.search(r"\bwhich\b|\bmost\b|\bleast\b|worst|highest|lowest|slowest|fastest|\bbest\b", q)
    if not comparative:
        for word in TYPE_WORDS:
            if re.search(rf"\b{word}(e?s)?\b", q):
                return "device", {"name": word}
    for tool, pattern in KEYWORDS:
        if re.search(pattern, q):
            args = {"days": days} if tool in ("availability", "new_devices", "incidents", "events", "response_times", "plugins") else {}
            if tool == "health":
                args = {"metric": next((m for w, m in (("ram", "memory"), ("memory", "memory"), ("cpu", "cpu"), ("processor", "cpu"), ("temp", "temperature"), ("hot", "temperature"), ("battery", "battery"), ("ups", "battery"),
                                                      ("busy", "cpu"), ("load", "cpu")) if re.search(rf"\b{w}", q)), "disk")}
            if tool == "response_times" and re.search(r"fastest|lowest|best|quickest|least", q):
                args["order"] = "fastest"
            return tool, args
    return "", {}


MEMORY_PATTERNS = {"levelling": "the rise is slowing down, like a cache that has filled", "resets": "memory is given back now and then", "irregular": "it moves up and down"}
RENDERERS: dict[str, Callable[[dict], str]] = {}


def render(tool: str, r: dict) -> str:
    if r.get("error"):
        return r["error"]
    if tool in RENDERERS:
        return RENDERERS[tool](r)
    if tool == "overview":
        lines = [f"{r['online']} of {r['devices']} devices are online."]
        lines.append("Offline: " + ", ".join(r["offline_devices"]) + "." if r["offline_devices"] else "No device is offline.")
        lines.append("Services down: " + ", ".join(r["services_down"]) + "." if r["services_down"] else "All service checks are up.")
        if r.get("needs_attention"):
            lines.append("Needs attention: " + "; ".join(i["text"] for i in r["needs_attention"]) + ".")
        return " ".join(lines)
    if tool == "offline_now":
        return "Offline now: " + "; ".join(f"{d['name']} (last seen {d['last_seen']})" for d in r["offline"]) + "." if r["offline"] else "No device is offline."
    if tool == "availability":
        rows = r["least_available"]
        head = f"Over the last {r['days']} days the devices were up {r['summary']['devices_availability']}% of the time."
        return head + (" Least available: " + "; ".join(f"{d['name']} {d['availability_pct']}% ({d['outages']} outage{'s' if d['outages'] != 1 else ''}, down {d['down']})" for d in rows[:6]) + "." if rows else " No device had an outage.")
    if tool == "response_times":
        if not r["devices"] and not r["services"]:
            return f"There are not enough response time measurements from the last {r['days']} days yet."
        lines = [f"{'Fastest' if r['order'] == 'fastest' else 'Slowest'} average response over the last {r['days']} days:"]
        lines += [f"{d['name']}: {d['avg_ms']} ms on average (worst {d['max_ms']} ms)" for d in r["devices"][:6]]
        lines += [f"{s['name']} (service): {s['avg_ms']} ms on average (worst {s['max_ms']} ms)" for s in r["services"][:3]]
        return "\n".join(lines)
    if tool == "new_devices":
        return (f"{len(r['new_devices'])} new device(s) in the last {r['days']} days: " + "; ".join(f"{d['name']}" + (f" ({d['vendor']})" if d["vendor"] else "") for d in r["new_devices"]) + ".") if r["new_devices"] else f"No new devices in the last {r['days']} days."
    if tool == "incidents":
        return "\n".join(f"{i['start'][:16].replace('T', ' ')} UTC: {i['title']}. {i['summary']}" for i in r["incidents"][:8]) or "No incidents in that period."
    if tool == "anomalies":
        return "\n".join(r["unusual_now"]) or "Nothing is behaving unusually right now."
    if tool == "disks":
        lines = [f"{d['device']} {d['disk']}: {d['used_pct']}% used, full in about {d['full_in_days']} days" for d in r["filling_up"]]
        lines += [(f"{m['device']}: memory use has risen in a steady line ({m['used_pct']}% now); at that pace it would run out in about {m['out_of_memory_in_days']} days, which is what a leak looks like"
                   if m["out_of_memory_in_days"] is not None else f"{m['device']}: memory is nearly full ({m['used_pct']}%) but does not follow a straight line ({MEMORY_PATTERNS.get(m.get('pattern'), 'irregular')}), so there is no date")
                  for m in r.get("memory_rising", [])]
        return "\n".join(lines) or f"No disk is on course to fill up ({r['checked']} checked) and no memory use keeps rising."
    if tool == "fixes":
        return "\n".join(f"{x['at'][:16].replace('T', ' ')} {x['rule']} on {x['device']}: {x['state']}" + (" (the problem went away)" if x["recovered"] else "") for x in r["runs"][:8]) or "No automatic fixes have run."
    if tool == "health":
        names = {"mem_pct": "Memory in use", "cpu_pct": "Processor busy", "disk_pct": "Disk usage", "temp_c": "Temperature", "battery_pct": "Battery"}
        if not r["readings"]:
            return f"No recent {names.get(r['metric'], r['metric']).lower()} readings: {r['monitored_hosts']} host(s) are monitored (Settings → Host monitoring)." if r["monitored_hosts"] else "No host is monitored yet, so there are no memory, processor, disk or temperature readings (device page → Monitor)."
        lines = [f"{names.get(r['metric'], r['metric'])}, most worrying first:"]
        lines += [f"{x['device']}{' ' + x['label'] if x['label'] else ''}: {x['value']:g}{x['unit'] or ''}" for x in r["readings"][:8]]
        if r["past_their_limit"]:
            lines.append("Past their limit: " + "; ".join(f"{p['device']} ({p['level']})" for p in r["past_their_limit"][:6]) + ".")
        return "\n".join(lines)
    if tool == "plugins":
        if not r["plugins"]:
            return f"No plugin has synced in the last {r['days']} day(s)."
        bad = [p for p in r["plugins"] if p["failed"]]
        head = f"{len(r['plugins'])} plugin(s) synced in the last {r['days']} day(s)" + (f"; {len(bad)} had failures." if bad else ", all without failures.")
        lines = [f"{p['plugin']}: {p['failed']} of {p['syncs']} syncs failed" + (f" (last error: {p['last_error']})" if p["last_error"] else "") + (f", a sync takes about {p['avg_sync_ms']:g} ms" if p["avg_sync_ms"] else "") for p in bad[:6]]
        slow = sorted((p for p in r["plugins"] if p["avg_sync_ms"]), key=lambda p: -p["avg_sync_ms"])[:3]
        return "\n".join([head] + lines + (["Slowest syncs: " + "; ".join(f"{p['plugin']} {p['avg_sync_ms']:g} ms" for p in slow)] if slow else []))
    if tool == "services":
        if not r["total"]:
            return "There are no service checks."
        return f"{r['total']} service checks. " + ("Down: " + ", ".join(r["down"]) + "." if r["down"] else "All of them are up.")
    if tool == "device" and "proxy_sites" in r:                # a website, found through the device tool
        return RENDERERS["site"](r)
    if tool == "device" and "devices" in r:
        return "\n".join(f"{d['name']}: {'online' if d['online'] else 'offline (last seen ' + d['last_seen'] + ')'}" + (f", up {d['availability_7d_pct']}% over 7 days with {d['outages_7d']} outage(s)" if d["availability_7d_pct"] is not None else "") for d in r["devices"])
    if tool == "device":
        parts = [f"{r['name']} is {'online' if r['online'] else 'offline'} (last seen {r['last_seen']})."]
        if r.get("availability_7d_pct") is not None:
            parts.append(f"Over the last 7 days it was up {r['availability_7d_pct']}% of the time with {r['outages_7d']} outage(s).")
        if r["services"]:
            parts.append("Services: " + ", ".join(f"{s['name']} {'up' if s['up'] else 'down' if s['up'] is False else '?'}" for s in r["services"]) + ".")
        if r["recent_events"]:
            parts.append("Latest: " + "; ".join(f"{e['kind'].replace('_', ' ')} {e['at'][:16].replace('T', ' ')}" for e in r["recent_events"][:3]) + ".")
        return " ".join(parts)
    if tool == "events":
        return "\n".join(f"{e['at'][:16].replace('T', ' ')} {e['device'] or ''} {e['kind']}" for e in r["events"]) or "No events."
    return json.dumps(r)[:600]


# ----------------------------------------------------------------------------- with a model
EXAMPLES = [
    ("Which device responds slowest?", "response_times", {"days": 7, "order": "slowest"}), ("Is the printer up?", "device", {"name": "printer"}), ("What happened yesterday?", "incidents", {"days": 1}),
    ("Which machines are low on RAM?", "health", {"metric": "memory"}), ("How many printers do I have?", "search_devices", {"type": "printer"}), ("Which Apple devices are offline?", "search_devices", {"vendor": "apple", "online": False}),
    ("Which devices have SSH open?", "ports", {"port": 22, "service": "ssh"}), ("Which virtual machines are stopped?", "guests", {"status": "stopped"}), ("Are my backups healthy?", "backups", {}),
    ("When does my certificate expire?", "certificates", {}), ("How fast is my internet?", "speedtest", {"days": 30}), ("What is the NAS connected to?", "connections", {"device": "nas"}),
    ("Who changed settings this week?", "audit", {"days": 7}), ("Is anything suspicious going on?", "security", {"days": 7}), ("Which smart-home batteries are low?", "smart_home", {}),
    ("How many devices are there per type?", "counts", {"by": "type"}), ("Which version of Netlens is this?", "system", {}),
]


def system_prompt() -> str:
    return ("You answer questions about the user's own computer network using tools that read Netlens's data.\n"
            "Reply with ONE JSON object and nothing else (no markdown, no text around it).\n"
            'To look at data: {"tool": "<name>", "args": {...}}\n'
            'To answer: {"answer": "<a few plain sentences>"}\n'
            "Rules:\n"
            "- Always look at the data with a tool first. Never answer about the network from memory.\n"
            "- Use at most four tool calls. Pick the tool that fits the question. If the first result does not help, you may try one other tool that fits.\n"
            "- For a list or a count of devices with some property (a kind, a manufacturer, an operating system, online or offline, an open port) use search_devices or ports. For one named device use device. For a kind of device (printer, switch, nas, camera ...) use search_devices with type, or device with that word.\n"
            "- For a website or domain (example.com) use site, also for 'why is it down': it shows whether the site is disabled on the reverse proxy, which is often the real reason; say so plainly when it is.\n"
            "- Current readings (memory, processor, disk, temperature, battery) are in health. Forecasts (a disk that will fill up) are in disks.\n"
            "- Copy names and numbers exactly as they appear in the results. If a result is a list, mention every item that matters; say \"only\" only when the list has one item. Round long numbers to one decimal.\n"
            "- The user cares about problems that matter: always-on devices (servers, routers, switches, NAS, cameras ...), services and network faults. The tools already leave out phones, tablets and other devices that come and go; never bring them up yourself.\n"
            "- Answer in the language of the question, in a few plain sentences.\n"
            '- If the data does not contain the answer, answer exactly: {"answer": "The data does not tell."}\n'
            "- Names such as <device1> or <ip2> are placeholders: write them exactly as they are.\n"
            "Examples:\n" + "\n".join(f"Question: {q} -> {json.dumps({'tool': t, 'args': a})}" for q, t, a in EXAMPLES) + "\n"
            "Tools:\n" + "\n".join(f"- {n}: {d}" for n, (_f, d) in TOOLS.items()))


def _restore_args(args: Any, redact: engineer.Redactor | None) -> dict:
    if not isinstance(args, dict):
        return {}
    return {k: (redact.restore(v) if redact and isinstance(v, str) else v) for k, v in list(args.items())[:6]}


def _parse_reply(reply: str) -> dict | None:
    match = re.search(r"\{.*\}", reply or "", re.S)
    try:
        doc = json.loads(match.group(0)) if match else None
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def _ask_model(conn, question: str, names: list[str], now, ask) -> dict | None:
    """The model's answer through the tools, or None when it cannot be used (then the plain version answers).
    A model that does not reply in JSON, or answers without looking at the data, is told once; after that the plain version takes over."""
    redact = engineer.Redactor(names) if engineer.settings(conn)["redact"] else None
    hide = redact or (lambda t: t)
    messages = [{"role": "system", "content": system_prompt()}, {"role": "user", "content": hide(question)}]
    used: list[str] = []
    nudged = {"json": False, "tool": False}
    for _ in range(MAX_STEPS + 3):
        try:
            reply = (ask or (lambda m: engineer.chat(conn, m)))(messages)
        except Exception:  # noqa: BLE001
            return None
        doc = _parse_reply(reply)
        if doc is None:
            if nudged["json"]:
                return None
            nudged["json"] = True
            messages += [{"role": "assistant", "content": (reply or "")[:500]}, {"role": "user", "content": 'Reply with one JSON object only: {"tool": ..., "args": ...} or {"answer": ...}.'}]
            continue
        if isinstance(doc.get("answer"), str) and doc["answer"].strip():
            if not used and not nudged["tool"]:
                nudged["tool"] = True
                messages += [{"role": "assistant", "content": json.dumps(doc)}, {"role": "user", "content": 'Look at the data first: call one of the tools. If none of them can tell, answer {"answer": "The data does not tell."}.'}]
                continue
            text = doc["answer"].strip()[:2000]
            return {"answer": redact.restore(text) if redact else text, "source": "model", "tools": used}
        tool = doc.get("tool")
        if tool not in TOOLS or len(used) >= MAX_STEPS:
            return None
        used.append(tool)
        token = _FOR_MODEL.set(True)
        try:
            result = TOOLS[tool][0](conn, _restore_args(doc.get("args"), redact), now)
        finally:
            _FOR_MODEL.reset(token)
        text = hide(json.dumps(result, default=str))[:MAX_RESULT]
        messages += [{"role": "assistant", "content": json.dumps({"tool": tool, "args": doc.get("args") or {}})}, {"role": "user", "content": "Result of " + tool + ":\n" + text}]
    return None


def answer(conn: sqlite3.Connection, question: str, now: datetime | None = None, ask=None, mode: str = "auto", scope: str = "all") -> dict[str, Any]:
    """`scope`: "important" (only the always-on and infrastructure devices, and network problems) or "all" (every device).
    `mode`: "auto" (the language model when one is connected, else the built-in logic), "rules" (the built-in logic only) or "model" (the language model, with the built-in logic as the fallback)."""
    token = _SCOPE.set("important" if scope == "important" else "all")
    try:
        got = _answer(conn, question, now, ask, mode)
    finally:
        _SCOPE.reset(token)
    got["scope"] = scope
    return got


def _answer(conn, question: str, now, ask, mode: str) -> dict[str, Any]:
    question = (question or "").strip()[:500]
    if not question:
        return {"answer": "Ask a question, or pick one of the ready-made ones.", "source": "rules", "tools": []}
    names = [_name(r) for r in conn.execute("SELECT id, custom_name, hostname, primary_ip FROM devices")] + [r["name"] for r in conn.execute("SELECT name FROM service_checks")]
    fell_back = False
    if mode == "model" and ask is None and not insights.llm_ready(conn):
        return {"answer": "No language model is connected or it is switched off for insights (Settings → AI, and the switch below). Switch to the built-in logic or connect a model.", "source": "rules", "tools": [], "understood": False}
    if ask is not None or (mode != "rules" and insights.llm_ready(conn)):
        got = _ask_model(conn, question, names, now, ask)
        if got:
            return got
        fell_back = True
    tool, args = route(question, [n for n in names if n], conn)
    if not tool:
        return {"answer": "The built-in logic cannot answer that: it understands questions about what is wrong now, what happened, availability, response times, current readings (memory, processor, disks, temperature), "
                          "devices by kind, manufacturer, operating system or open port, virtual machines and containers, backups, certificates, speed tests, remote sites, smart home, security, Wi-Fi, "
                          "who changed what, what is connected to what, maintenance, versions and updates, or one device by name. Pick one below, or connect a language model for free-form questions.",
                "source": "rules", "tools": [], "understood": False, "fell_back": fell_back}
    result = TOOLS[tool][0](conn, args, now)
    return {"answer": render(tool, result), "source": "rules", "tools": [tool], "fell_back": fell_back}


from app import ask_extra, ask_more  # noqa: E402 - the other questions register themselves into the tables above

ask_more.register()
ask_extra.register()
