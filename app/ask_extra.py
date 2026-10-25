"""More questions for "Ask your network": vulnerabilities, traffic, who is told about what, who is on call, the application's own log and the
investigation of an incident. Same shape as app/ask_more.py: a read-only tool, the sentence that writes it out and the words that pick it."""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app import ask
from app.ask import LIMIT, _days
from app.db import main_file


def t_vulnerabilities(conn, args, now=None) -> dict:
    from app import licence, vulns

    if not licence.allows(conn, "vulnerabilities"):
        return {"error": "Vulnerability findings are part of a paid edition (Settings → Licence)."}
    s = vulns.summary(conn)
    if not s["configured"]:
        return {"error": "No vulnerability scanner plugin (Greenbone, Tenable, Rapid7 ...) has reported yet."}
    return {"counts": s["counts"], "devices_with_serious_findings": s["devices"], "known_exploited": s["exploited"], "last_scan": s["last_scan"],
            "worst_devices": [{"device": d["device"], "critical": d["critical"], "high": d["high"], "exploited": d["exploited"]} for d in vulns.top_devices(conn, 6)],
            "critical": [{"device": f["device"], "title": f["title"][:90], "cve": f["cve"][:2], "exploited": f["exploited"]} for f in vulns.findings(conn, severity="critical", limit=8)]}


def r_vulnerabilities(r: dict) -> str:
    c = r["counts"]
    text = f"{c.get('critical', 0)} critical, {c.get('high', 0)} high, {c.get('medium', 0)} medium and {c.get('low', 0)} low findings (last scan {r['last_scan'] or 'unknown'})."
    if r["known_exploited"]:
        text += f" {r['known_exploited']} are known to be exploited."
    if r["worst_devices"]:
        text += " Worst: " + "; ".join(f"{d['device']} ({d['critical']} critical, {d['high']} high)" for d in r["worst_devices"][:4]) + "."
    if r["critical"]:
        text += " Critical: " + "; ".join(f"{f['device']}: {f['title']}" for f in r["critical"][:3]) + "."
    return text


def _mbps(point) -> float | None:
    return None if not point else round(point[1] / 1e6, 2) if isinstance(point, (list, tuple)) else None


def t_traffic(conn, args, now=None) -> dict:
    from app import interface_settings, traffic

    range_key = args.get("range") if args.get("range") in traffic.RANGES else "1h"
    chosen = interface_settings.get(conn)["wan"]
    wan = (int(chosen.split("|", 1)[0]), chosen.split("|", 1)[1]) if chosen else None
    t = traffic.build(conn, range_key, wan, mode="endpoints")
    out: dict[str, Any] = {"range": range_key, "devices": None, "internet": None}
    d = t["devices"]
    if d.get("now"):
        peak = lambda pts: max((p[1] for p in pts), default=0)
        out["devices"] = {"count": d["count"], "in_mbps_now": _mbps(d["now"]["rx"]), "out_mbps_now": _mbps(d["now"]["tx"]), "in_mbps_peak": round(peak(d["rx"]) / 1e6, 2), "out_mbps_peak": round(peak(d["tx"]) / 1e6, 2)}
    w = t.get("wan")
    if w:
        out["internet"] = {"device": w["device"], "interface": w["label"], "in_mbps_now": _mbps(w["now"]["rx"]), "out_mbps_now": _mbps(w["now"]["tx"]),
                           "in_mbps_peak": round(max((p[1] for p in w["rx"]), default=0) / 1e6, 2), "out_mbps_peak": round(max((p[1] for p in w["tx"]), default=0) / 1e6, 2)}
    if not out["devices"] and not out["internet"]:
        out["error"] = "No traffic is measured yet: add health monitors (Settings → Host monitoring) or a router plugin that reports its interfaces."
    return out


def r_traffic(r: dict) -> str:
    parts = []
    if r["internet"]:
        i = r["internet"]
        parts.append(f"Internet ({i['device']} {i['interface']}): {i['in_mbps_now']} Mbit/s in and {i['out_mbps_now']} out now; peaks {i['in_mbps_peak']} in and {i['out_mbps_peak']} out over {r['range']}.")
    if r["devices"]:
        d = r["devices"]
        parts.append(f"The {d['count']} monitored devices together: {d['in_mbps_now']} Mbit/s in and {d['out_mbps_now']} out now; peaks {d['in_mbps_peak']} and {d['out_mbps_peak']} over {r['range']}.")
    return " ".join(parts)


def t_notifications(conn, args, now=None) -> dict:
    from app.notify import channels as ch

    chans = ch.load_channels(conn)
    cov = ch.coverage(conn)
    return {"channels": [{"name": c.get("name") or c.get("type"), "type": c.get("type"), "enabled": bool(c.get("enabled")), "events": len(c.get("events") or []),
                          "minimum_severity": (c.get("filters") or {}).get("min_severity")} for c in chans],
            "nobody_would_hear_about": [{"what": g["label"], "why": g["why"]} for g in cov["gaps"]], "all_covered": cov["ok"]}


def r_notifications(r: dict) -> str:
    on = [c for c in r["channels"] if c["enabled"]]
    if not on:
        return "No notification channel is switched on, so nobody is told about anything (Settings → Notifications → Channels)."
    text = "Channels on: " + ", ".join(f"{c['name']} ({c['events']} kinds of event)" for c in on) + "."
    if r["nobody_would_hear_about"]:
        text += " Nobody would hear about: " + "; ".join(g["what"] for g in r["nobody_would_hear_about"]) + "."
    else:
        text += " Every important kind of event reaches at least one channel."
    return text


def t_oncall(conn, args, now=None) -> dict:
    from app import oncall

    cur = oncall.on_call(conn)
    return {"people": [p.get("name") for p in cur["people"]], "shift": cur["source"], "until": cur["until"], "upcoming": [str(x)[:100] for x in oncall.timeline(conn)[:6]]}


def r_oncall(r: dict) -> str:
    if not r["people"]:
        return "Nobody is on call right now (no schedule, or a gap in it)."
    return f"On call now: {', '.join(r['people'])} ({r['shift']}{', until ' + r['until'] if r['until'] else ''})."


def t_system_log(conn, args, now=None) -> dict:
    from app import syslog

    level = args.get("level") if args.get("level") in ("warning", "error") else "warning"
    got = syslog.entries(Path(main_file(conn)).parent, level=level, limit=40)
    lines = [f"{e['ts']} {e['level']} {e['logger']}: {e['message'][:160]}" for e in got["entries"][:12]]
    return {"level": level, "lines": lines, "shown": len(lines)}


def r_system_log(r: dict) -> str:
    return "Recent " + r["level"] + "s and worse in Netlens' own log:\n" + "\n".join(r["lines"]) if r["lines"] else f"The log holds no {r['level']}s."


def t_investigate(conn, args, now=None) -> dict:
    from app import incidents, investigate, licence

    if not licence.allows(conn, "insights"):
        return {"error": "Investigating incidents is part of the Insights feature (Settings → Licence)."}
    found = incidents.incidents(conn, _days(args.get("days"), 3), now)
    name = str(args.get("device") or "").lower()
    pick = None
    for i in found:                                    # newest first: the incident of the named device, else the latest
        report = investigate.investigate(conn, i["id"], now=now)
        if report and (not name or any(name in (d["name"] or "").lower() for d in report["devices"])):
            pick = report
            break
    if not pick:
        return {"error": "No incident in that period" + (f" involves {name}." if name else ".")}
    return {"title": pick["title"], "start": pick["start"], "resolved": pick["resolved"], "devices": [d["name"] for d in pick["devices"]],
            "left_out": [f"{u['name']} ({u['why']})" for u in pick["unrelated"]], "findings": [f["text"] for f in pick["findings"][:10]]}


def r_investigate(r: dict) -> str:
    return f"{r['title']} (from {r['start']}, {'over' if r['resolved'] else 'still going'}). " + " ".join(r["findings"])


TOOLS = {
    "vulnerabilities": (t_vulnerabilities, "security weaknesses found by the vulnerability scanners (Greenbone, Tenable ...): counts by severity, known-exploited ones, the worst devices and the critical findings. args: none"),
    "traffic": (t_traffic, "network traffic: bandwidth in and out now and the peak, of the internet line and of the monitored devices together. args: range (1h, 6h, 24h or 7d)"),
    "notifications": (t_notifications, "who is told about what: the alert channels (e-mail, Telegram ...) and the kinds of event that nobody would hear about. args: none"),
    "oncall": (t_oncall, "who is on call now and the coming shifts. args: none"),
    "system_log": (t_system_log, "warnings and errors in Netlens' own log (why a sync, a monitor or a notification failed). args: level (warning or error)"),
    "investigate": (t_investigate, "ROOT CAUSE of the latest incident (or of one device's): what started it, which device moved first, what was running at the time, what else broke, whether anybody was told. args: device (optional name), days (1-30)"),
}
RENDERERS = {"vulnerabilities": r_vulnerabilities, "traffic": r_traffic, "notifications": r_notifications, "oncall": r_oncall, "system_log": r_system_log, "investigate": r_investigate}
PRESETS = [
    {"id": "vulns", "text": "Which vulnerabilities do I have?", "tool": "vulnerabilities", "args": {}},
    {"id": "traffic", "text": "How much traffic is going through my network?", "tool": "traffic", "args": {}},
    {"id": "told", "text": "Would I be told if something broke?", "tool": "notifications", "args": {}},
    {"id": "cause", "text": "What caused the latest incident?", "tool": "investigate", "args": {}},
    {"id": "log", "text": "Are there errors in the Netlens log?", "tool": "system_log", "args": {"level": "error"}},
]
RULES = [
    ("investigate", r"root cause|investigat|what caused|cause of|post-?mortem|what went wrong|why did .{0,40}(stop|fail|crash|go down|go offline|jump|spike|slow)|why was .{0,40}(slow|full|overloaded|busy)"),
    ("vulnerabilities", r"vulnerab|\bcves?\b|exploit|greenbone|openvas|nessus|unpatched|security (hole|weakness)"),
    ("notifications", r"notification|alert channel|who (is|gets|would get) (told|alerted|notified)|would i (get|be) (a |told|alerted|warned|notified)|was i (told|warned|alerted|notified)|e-?mail alerts?|quiet hours|nobody (is |was )?told"),
    ("oncall", r"on[- ]?call"),
    ("traffic", r"\btraffic\b|throughput|top talkers?|how much (data|bandwidth)|bandwidth (use|usage|is being)|wan (load|usage)"),
    ("system_log", r"system log|netlens log|error log|errors? in (the )?log|log (says|shows)|exceptions?"),
]


def route(q: str, names: list[str]) -> tuple[str, dict] | None:
    for tool, pattern in RULES:
        if re.search(pattern, q):
            args: dict[str, Any] = {}
            if tool == "investigate":
                name = next((n for n in sorted(names, key=len, reverse=True) if len(n) > 2 and n.lower() in q), "")
                args = {"device": name} if name else {}
            elif tool == "traffic":
                args = {"range": next((r for r, p in (("7d", r"week|7 ?d"), ("24h", r"today|24 ?h|day"), ("6h", r"6 ?h")) if re.search(p, q)), "1h")}
            elif tool == "system_log":
                args = {"level": "error" if re.search(r"error|exception", q) else "warning"}
            return tool, args
    return None


def register() -> None:
    ask.TOOLS.update(TOOLS)
    ask.RENDERERS.update(RENDERERS)
    ask.PRESETS.extend(p for p in PRESETS if p["id"] not in {x["id"] for x in ask.PRESETS})
