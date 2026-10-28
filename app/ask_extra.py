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


def _mbps(bits) -> float | None:
    return None if bits is None else round(bits / 1e6, 2)


def t_traffic(conn, args, now=None) -> dict:
    from app import interface_settings, traffic

    range_key = args.get("range") if args.get("range") in traffic.RANGES else "1h"
    chosen = interface_settings.get(conn)["wan"]
    wan = (int(chosen.split("|", 1)[0]), chosen.split("|", 1)[1]) if chosen else None
    t = traffic.build(conn, range_key, wan, now=now.timestamp() if now else None, mode="endpoints")
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


def t_coverage(conn, args, now=None) -> dict:
    from app import hosts

    rows = hosts.overview(conn)
    reachable = [h for h in rows if h["can_monitor"]]
    return {"hosts": len(rows), "reachable": len(reachable),
            "not_monitored": [h["name"] for h in reachable if not h["monitor"]][:15],
            "cannot_log_in": [h["name"] for h in rows if h["monitor"] and h["monitor"].get("ok") is False][:15],
            "probes_on": [h["name"] for h in rows if h["probes"]["enabled"]][:15],
            "old_probe": [h["name"] for h in rows if h["probes"]["update_available"]][:15]}


def r_coverage(r: dict) -> str:
    parts = [f"{r['reachable']} of {r['hosts']} devices can be monitored over SSH or WinRM."]
    parts.append(("Not monitored yet: " + ", ".join(r["not_monitored"]) + ".") if r["not_monitored"] else "Every reachable host has a health monitor.")
    if r["cannot_log_in"]:
        parts.append("The monitor cannot log in on: " + ", ".join(r["cannot_log_in"]) + ".")
    parts.append(("Read-only probes are on for: " + ", ".join(r["probes_on"]) + ".") if r["probes_on"] else "The read-only probes are not on for any host.")
    if r["old_probe"]:
        parts.append("An older probe script runs on: " + ", ".join(r["old_probe"]) + " (Settings → Hosts updates them).")
    return " ".join(parts)


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


def t_storage_use(conn, args, now=None) -> dict:
    """What uses the disk space of a host, from its storage snapshots (Settings → Host probes)."""
    from app.hostprobe import parse, service as probes

    name = str(args.get("device") or "").strip().lower()
    rows = conn.execute("SELECT id, COALESCE(custom_name, hostname, primary_ip) AS n FROM devices").fetchall()
    enabled = [r for r in rows if device_enabled(conn, r["id"])]
    pick = next((r for r in rows if name and name in (r["n"] or "").lower()), None)
    if pick is None and not name:
        from app.hostmetrics import service as hm

        bad = {p["device_id"] for p in hm.problems(conn) if p["metric"] == "disk_pct"}
        pick = next((r for r in enabled if r["id"] in bad), enabled[0] if enabled else None)
    if pick is None:
        return {"error": "No host is being inspected yet: switch it on for a device (device page → Storage inspection)." if not name else f"I don't know a device called {name}."}
    last = probes.latest_ok(conn, pick["id"])
    if not last:
        return {"error": f"No storage snapshot of {pick['n']} yet" + ("" if device_enabled(conn, pick["id"]) else ": switch on Storage inspection on its device page") + "."}
    data = last["data"]
    mounts = []
    for m in data["mounts"][:3]:
        top = [d for d in m["dirs"] if d["path"] != m["mount"]][:6]
        mounts.append({"mount": m["mount"], "used_pct": round(100 * m["used"] / m["size"]) if m["size"] else None, "used": parse.nice_bytes(m["used"]),
                       "biggest": [{"path": d["path"], "size": parse.nice_bytes(d["bytes"])} for d in top], "big_files": [{"path": f["path"], "size": parse.nice_bytes(f["bytes"])} for f in m["files"][:4]]})
    docker = [{"container": c["name"], "log": parse.nice_bytes(c["log_bytes"]), "layer": parse.nice_bytes(c["layer_bytes"])} for c in sorted(data["docker"]["containers"], key=lambda c: -(c["log_bytes"] + c["layer_bytes"]))[:4]]
    first = probes.snapshots(conn, pick["id"], 40)
    grew = None
    older = next((x for x in first[1:] if x["ok"]), None)
    if older:
        prev = probes.latest_ok(conn, pick["id"], before=older["taken"])
        grew = parse.compare(prev["data"], data, min_bytes=100 * 1024 ** 2) if prev else None
    hidden = [parse.describe_unaccounted(u) for u in parse.unaccounted(data)]
    return {"device": pick["n"], "not_in_any_folder": hidden, "taken": last["taken"], "mode": last["mode"], "partial": data.get("partial"), "disks": mounts, "docker": docker,
            "docker_total": [{"type": u["type"], "size": parse.nice_bytes(u["bytes"]), "reclaimable": parse.nice_bytes(u["reclaimable"])} for u in data["docker"]["usage"]],
            "deleted_but_open": [{"path": d["path"], "size": parse.nice_bytes(d["bytes"]), "process": d["process"]} for d in data["deleted"][:3]],
            "grew_since_previous": [{"path": g["path"], "grew": parse.nice_bytes(g["bytes"]), "kind": g["kind"]} for g in (grew or {"growth": []})["growth"][:4]]}


def t_analysis(conn, args, now=None) -> dict:
    """An analysis report by its id (AR-12) or the analysis of an incident by its id (INC-345), or the newest one."""
    from app import analysis

    ref = str(args.get("ref") or "")
    doc = None
    m = analysis.REPORT_RE.search(ref)
    if m:
        doc = analysis.get(conn, int(m.group(1)))
    else:
        m = analysis.INCIDENT_RE.search(ref)
        if m:
            doc = analysis.latest_for_incident(conn, int(m.group(1))) or analysis.create_for_incident(conn, int(m.group(1)), "ask", now)
        else:
            rows = analysis.listing(conn, 1)
            doc = analysis.get(conn, rows[0]["report_id"]) if rows else None
    if doc is None:
        return {"error": f"No analysis found for {ref or 'that'}. Reports have ids like AR-12; incidents INC-345."}
    hide = ask.for_model() and not __import__("app.hostprobe.service", fromlist=["x"])._load(conn)["names_to_llm"]
    show = lambda f: (f.get("llm_text") or "A finding with names was withheld.") if f.get("private") and hide else f["text"]
    cause = next((show(f) for f in doc["findings"] if f["text"] == doc.get("probable_cause")), doc.get("probable_cause") if not hide else "A cause with names was withheld.")
    return {"report": doc["report_ref"], "incident": doc.get("incident_ref"), "title": doc["title"], "created": doc["created"], "probable_cause": cause,
            "findings": [show(f) for f in doc["findings"]][:10], "ruled_out": doc.get("ruled_out"), "read_only_note": "Information only: nothing was changed on any host."}


def r_analysis(r: dict) -> str:
    text = f"{r['report']}" + (f" ({r['incident']})" if r.get("incident") else "") + f": {r['title']}. "
    text += ("Probable cause: " + r["probable_cause"].removeprefix("Probable cause: ") + " ") if r.get("probable_cause") else "No single cause stands out. "
    rest = [f for f in r["findings"] if f != r.get("probable_cause")][:4]
    return (text + " ".join(rest) + " " + r["read_only_note"]).strip()


def _device_pick(conn, name: str):
    rows = conn.execute("SELECT id, COALESCE(custom_name, hostname, primary_ip) AS n FROM devices").fetchall()
    return next((r for r in rows if name and name in (r["n"] or "").lower()), None)


def t_host_activity(conn, args, now=None) -> dict:
    """What the host probes saw on one host (processor, memory, network, applications, changes, scheduled jobs, hardware, security) and the probable cause."""
    from app.hostprobe import diagnose, service as probes

    name = str(args.get("device") or "").strip().lower()
    symptom = str(args.get("symptom") or "").strip()
    pick = _device_pick(conn, name) if name else None
    if pick is None:
        enabled = [r for r in conn.execute("SELECT id, COALESCE(custom_name, hostname, primary_ip) AS n FROM devices") if device_enabled(conn, r["id"])]
        if name:
            return {"error": f"I don't know a device called {name}."}
        if not enabled:
            return {"error": "No host is being inspected yet: switch it on for a device (device page → Host probes)."}
        pick = enabled[0]
    if not device_enabled(conn, pick["id"]):
        return {"error": f"Host probes are not switched on for {pick['n']} (device page → Host probes)."}
    rep = diagnose.diagnose(conn, pick["id"], symptom or None, now.timestamp() if now else None)
    if not rep["taken"]:
        return {"error": f"No probe has looked at {pick['n']} yet" + ("" if not rep["missing"] else f" (missing: {', '.join(rep['missing'])})") + ". Use Diagnose now on its device page."}
    model = for_model_view()
    from app.hostprobe import service as svc

    allow = svc._load(conn)["names_to_llm"]
    hide = model and not allow
    pick_text = lambda f: (f.get("llm_text") or "A finding with names was withheld.") if f.get("private") and hide else f["text"]
    return {"device": rep["device"], "looked_at": rep["taken"], "not_yet_looked_at": rep["missing"], "probable_cause": [(c.get("llm_text") or "A cause with names was withheld.") if c["private"] and hide else c["text"] for c in rep["chains"]],
            "findings": [{"level": f["level"], "text": pick_text(f)} for f in rep["findings"]]}


def t_interface_errors(conn, args, now=None) -> dict:
    """Errors and dropped packets on network interfaces, of every host at once: the counters of the read-only host probes (a Linux or Windows host)
    and the error rate of switch ports and SNMP interfaces. Answers "which systems have errors on eth0" without naming a host."""
    import json as _json

    from app import tsdb
    from app.hostprobe import service as probes

    wanted = str(args.get("interface") or "").strip().lower()
    only = str(args.get("device") or "").strip().lower()
    keep = ask.important_ids(conn)
    names = {r["id"]: r["n"] for r in conn.execute("SELECT id, COALESCE(custom_name, hostname, primary_ip) AS n FROM devices")}
    found: list[dict] = []
    looked: set[int] = set()
    for did, name in names.items():
        if (keep is not None and did not in keep) or (only and only not in (name or "").lower()):
            continue
        snap = probes.latest_ok(conn, did, probe="network")
        for n in ((snap or {}).get("data") or {}).get("interfaces", []):
            looked.add(did)
            if wanted and wanted not in n["name"].lower():
                continue
            bad = n["rx_err_total"] + n["tx_err_total"] + n["rx_drop_total"] + n["tx_drop_total"]
            pk = n["rx_pkts_total"] + n["tx_pkts_total"]
            if bad:
                found.append({"device": name, "interface": n["name"], "errors": n["rx_err_total"] + n["tx_err_total"], "dropped": n["rx_drop_total"] + n["tx_drop_total"],
                              "percent_of_packets": round(100 * bad / pk, 2) if pk else None, "since_boot": True, "source": "host probe", "seen": snap["taken"]})
    store = tsdb.for_conn(conn)
    stamp = int((now or datetime.now(timezone.utc)).timestamp())
    for did, series in (store.metrics_of_many("device", [i for i in names if keep is None or i in keep]) if store else {}).items():
        if only and only not in (names.get(did) or "").lower():
            continue
        for m in series:
            if m["metric"] != "if_err_ps" or (wanted and wanted not in (m["label"] or "").lower()) or stamp - (m["last_ts"] or 0) > 86400:
                continue
            looked.add(did)
            if (m["last"] or 0) > 0:
                found.append({"device": names.get(did), "interface": m["label"], "errors_per_second": round(m["last"], 3), "since_boot": False, "source": "port or interface monitor"})
    found.sort(key=lambda f: -(f.get("errors", 0) + f.get("dropped", 0) + 1000 * (f.get("errors_per_second") or 0)))
    return {"interface_filter": wanted or None, "hosts_with_interface_data": len(looked), "with_errors_or_drops": found[:20],
            "note": "Counters from a host probe count since the host started; errors_per_second is the current rate. An empty list with hosts_with_interface_data above 0 means none of them has any."}


def r_interface_errors(r: dict) -> str:
    rows = r["with_errors_or_drops"]
    where = f" on {r['interface_filter']}" if r["interface_filter"] else ""
    if not r["hosts_with_interface_data"]:
        return "No host or port reports interface counters yet: switch on the Host probes (network) for a host, or add a port monitor."
    if not rows:
        return f"None of the {r['hosts_with_interface_data']} systems that report interface counters has errors or dropped packets{where}."
    parts = []
    for f in rows[:8]:
        if "errors_per_second" in f:
            parts.append(f"{f['device']} {f['interface']}: {f['errors_per_second']} errors/s now")
        else:
            parts.append(f"{f['device']} {f['interface']}: {f['errors']} errors, {f['dropped']} dropped" + (f" ({f['percent_of_packets']}% of packets)" if f["percent_of_packets"] is not None else "") + " since the host started")
    return f"{len(rows)} of {r['hosts_with_interface_data']} systems have errors or dropped packets{where}: " + "; ".join(parts) + "."


def for_model_view() -> bool:
    return ask.for_model()


def r_host_activity(r: dict) -> str:
    text = f"{r['device']}: "
    if r["probable_cause"]:
        text += "probable cause: " + " ".join(r["probable_cause"][:2]) + " "
    rest = [f["text"] for f in r["findings"] if not f["text"].startswith("Probable cause")][:6]
    text += (" ".join(rest) if rest else "nothing unusual in what the probes saw.")
    if r["not_yet_looked_at"]:
        text += f" (Not looked at yet: {', '.join(r['not_yet_looked_at'])}.)"
    return text.strip()


def device_enabled(conn, device_id: int) -> bool:
    from app.hostprobe import service as probes

    return probes.device_config(conn, device_id)["enabled"]


def r_storage_use(r: dict) -> str:
    text = f"{r['device']} (snapshot {r['taken']})."
    for m in r["disks"][:2]:
        text += f" {m['mount']} is {m['used_pct']}% full ({m['used']}); biggest: " + ", ".join(f"{d['path']} {d['size']}" for d in m["biggest"][:4]) + "."
        if m["big_files"]:
            text += " Big files: " + ", ".join(f"{f['path']} {f['size']}" for f in m["big_files"][:3]) + "."
    if r.get("not_in_any_folder"):
        text += " Note: " + "; ".join(r["not_in_any_folder"]) + "."
    if r["grew_since_previous"]:
        text += " Grew since the previous snapshot: " + ", ".join(f"{g['path']} +{g['grew']}" for g in r["grew_since_previous"]) + "."
    if r["docker"]:
        text += " Docker (logs/layers): " + ", ".join(f"{c['container']} {c['log']}/{c['layer']}" for c in r["docker"][:3]) + "."
    if r["deleted_but_open"]:
        text += " Deleted but still open: " + ", ".join(f"{d['path']} {d['size']} ({d['process']})" for d in r["deleted_but_open"]) + "."
    return text


TOOLS = {
    "interface_errors": (t_interface_errors, "ERRORS AND DROPPED PACKETS on network interfaces of ALL hosts at once (host probes, switch ports, SNMP). Use for 'which systems have errors or drops on eth0', 'any bad cable or port', 'packet loss on the network cards'. args: interface (optional, such as eth0), device (optional name)"),
    "vulnerabilities": (t_vulnerabilities, "security weaknesses found by the vulnerability scanners (Greenbone, Tenable ...): counts by severity, known-exploited ones, the worst devices and the critical findings. args: none"),
    "traffic": (t_traffic, "network traffic: bandwidth in and out now and the peak, of the internet line and of the monitored devices together. args: range (1h, 6h, 24h or 7d)"),
    "notifications": (t_notifications, "who is told about what: the alert channels (e-mail, Telegram ...) and the kinds of event that nobody would hear about. args: none"),
    "coverage": (t_coverage, "which hosts are monitored and how: which can be reached over SSH or WinRM but have no health monitor, which monitors cannot log in, where the read-only probes are on and where their script is old. args: none"),
    "oncall": (t_oncall, "who is on call now and the coming shifts. args: none"),
    "system_log": (t_system_log, "warnings and errors in Netlens' own log (why a sync, a monitor or a notification failed). args: level (warning or error)"),
    "storage_use": (t_storage_use, "WHAT USES the disk space of a host (needs Storage inspection on that device): the biggest directories and files, Docker logs and layers, files deleted but still open, and what grew since the previous snapshot. args: device (name, optional)"),
    "analysis": (t_analysis, "an ANALYSIS REPORT of the digital engineer by id (AR-12), or the analysis of an incident by its id (INC-345), or the newest one: probable cause, findings, what was ruled out. Information only. args: ref (AR-12, INC-345 or empty)"),
    "host_activity": (t_host_activity, "WHAT IS GOING ON on one host according to the read-only host probes: what uses the processor, memory and network, which applications or containers are failing or restarting, what changed or was scheduled lately, hardware and security state, chained into a probable cause. Use for 'why is X slow', 'what is using the CPU/memory/network on X', 'why did X restart'. args: device (name), symptom (optional words such as slow, memory, network, restart)"),
    "investigate": (t_investigate, "ROOT CAUSE of the latest incident (or of one device's): what started it, which device moved first, what was running at the time, what else broke, whether anybody was told. args: device (optional name), days (1-30)"),
}
RENDERERS = {"interface_errors": r_interface_errors, "analysis": r_analysis, "host_activity": r_host_activity, "storage_use": r_storage_use, "vulnerabilities": r_vulnerabilities, "traffic": r_traffic, "notifications": r_notifications, "oncall": r_oncall, "coverage": r_coverage, "system_log": r_system_log, "investigate": r_investigate}
PRESETS = [
    {"id": "nicerrors", "text": "Which systems have errors or dropped packets on their network interface?", "tool": "interface_errors", "args": {}},
    {"id": "coverage", "text": "Which hosts are not monitored yet?", "tool": "coverage", "args": {}},
    {"id": "vulns", "text": "Which vulnerabilities do I have?", "tool": "vulnerabilities", "args": {}},
    {"id": "traffic", "text": "How much traffic is going through my network?", "tool": "traffic", "args": {}},
    {"id": "told", "text": "Would I be told if something broke?", "tool": "notifications", "args": {}},
    {"id": "slow", "text": "Why is my server slow?", "tool": "host_activity", "args": {"symptom": "slow"}},
    {"id": "space", "text": "What is using the disk space?", "tool": "storage_use", "args": {}},
    {"id": "cause", "text": "What caused the latest incident?", "tool": "investigate", "args": {}},
    {"id": "log", "text": "Are there errors in the Netlens log?", "tool": "system_log", "args": {"level": "error"}},
]
RULES = [
    ("interface_errors", r"(errors?|dropped|drops?|discards?|collisions?|packet loss).{0,50}(interfaces?|nics?|network cards?|\beth\d|\bens\d+|\benp\w+|ports?)\b|(interfaces?|nics?|\beth\d|\bens\d+|\benp\w+|ports?).{0,40}(errors?|drop(s|ped|ping)?|discards?|packet loss)|dropped packets|bad cable"),
    ("analysis", r"\b(inc|ar)-\d+\b|analysis report|latest analysis|the report of (the )?incident"),
    ("host_activity", r"why is .{0,40}(slow|sluggish|laggy|unresponsive|hanging|overloaded|busy)|what('s| is| are) (using|eating|hogging|consuming|taking) .{0,20}(cpu|processor|memory|ram|bandwidth|network)|what('s| is) (going on|wrong|happening) (on|with) |why did .{0,40}(restart|reboot|crash)|what('s| is| are) (killing|crashing)|(cpu|memory|ram|network) (usage|hog|hogs|spike)|who is using the (cpu|memory|network|bandwidth)|diagnos"),
    ("storage_use", r"what (is|are|was|has been) (using|taking|eating|filling|consuming|hogging)\b.{0,30}(space|disk|storage)|where (did|does|is) (the |my )?(disk|space|storage).{0,20}(go|going|gone)|what filled|(biggest|largest) (files?|folders?|directories|dirs?)|disk space (is )?(used|taken|used up) by|what.{0,12}(uses|using) (the )?(disk|space)"),
    ("investigate", r"root cause|investigat|what caused|cause of|post-?mortem|what went wrong|why did .{0,40}(stop|fail|crash|go down|go offline|jump|spike|slow)|why was .{0,40}(slow|full|overloaded|busy)"),
    ("vulnerabilities", r"vulnerab|\bcves?\b|exploit|greenbone|openvas|nessus|unpatched|security (hole|weakness)"),
    ("notifications", r"notification|alert channel|who (is|gets|would get) (told|alerted|notified)|would i (get|be) (a |told|alerted|warned|notified)|was i (told|warned|alerted|notified)|e-?mail alerts?|quiet hours|nobody (is |was )?told"),
    ("oncall", r"on[- ]?call"),
    ("coverage", r"(which|what) (hosts?|servers?|devices?|machines?).{0,30}(not |un)?monitored|monitoring coverage|(not|isn'?t|aren'?t|un)monitored|without monitoring|(is|are) .{0,30}(being )?monitored|probes? (installed|on|enabled)|where (are|is) the probes?"),
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
            elif tool == "analysis":
                m = re.search(r"\b(inc|ar)-\d+\b", q)
                args = {"ref": m.group(0).upper()} if m else {}
            elif tool == "host_activity":
                name = next((n for n in sorted(names, key=len, reverse=True) if len(n) > 2 and n.lower() in q), "")
                symptom = next((w for w, pat in (("memory", r"memory|ram|oom"), ("cpu", r"cpu|processor|slow|sluggish|busy|overload"), ("network", r"network|bandwidth|latency|connect"), ("restart", r"restart|reboot|crash|die|stop|go down|killing")) if re.search(pat, q)), "")
                args = {k: v for k, v in (("device", name), ("symptom", symptom)) if v}
            elif tool == "interface_errors":
                m = re.search(r"\b(eth\d+|ens\d+\w*|enp\w+|wlan\d|eno\d+|bond\d+)\b", q)
                name = next((n for n in sorted(names, key=len, reverse=True) if len(n) > 2 and n.lower() in q), "")
                args = {k: v for k, v in (("interface", m.group(1) if m else ""), ("device", name)) if v}
            elif tool == "storage_use":
                name = next((n for n in sorted(names, key=len, reverse=True) if len(n) > 2 and n.lower() in q), "")
                args = {"device": name} if name else {}
            elif tool == "system_log":
                args = {"level": "error" if re.search(r"error|exception", q) else "warning"}
            return tool, args
    return None


def register() -> None:
    ask.TOOLS.update(TOOLS)
    ask.RENDERERS.update(RENDERERS)
    ask.PRESETS.extend(p for p in PRESETS if p["id"] not in {x["id"] for x in ask.PRESETS})
