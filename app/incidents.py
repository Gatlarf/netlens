"""Incidents: the events of a few minutes that belong together, in one story (a paid feature, see app/insights.py).

Ten alerts after a switch fails are one incident. Events are grouped when they follow each other within ten minutes (a recovery joins the
incident of its problem, however much later it comes); the device that sits above the others in the network hierarchy and went wrong first is the
probable cause. The sentence is written from the facts by Netlens; a language model, when one is set up, may only rewrite it.
"""

from __future__ import annotations

import sqlite3

from app.db import Error as db_Error
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from app import insights
from app.hierarchy import ancestors, device_name, load_hierarchy
from app.remediation import RECOVERY

STAMP = "%Y-%m-%dT%H:%M:%SZ"
GAP = timedelta(minutes=10)
PROBLEMS = set(RECOVERY) | {"anomaly", "capacity_warning", "capacity_critical", "container_unhealthy", "container_restarting", "container_stopped", "backup_failed", "dhcp_rogue",
                            "gateway_changed", "cert_expiring", "guest_backup_late", "guest_backup_failed", "storage_degraded",
                            "vuln_critical", "port_unexpected", "firewall_ha", "firewall_licence", "dns_failed", "host_timeout", "plugin_update_failed", "inventory_battery_low", "agent_silent", "ingest_cert_expiring"}
RECOVERS = {v: k for k, v in RECOVERY.items()}
RECOVERS["storage_recovered"] = "storage_degraded"
RECOVERS["agent_back"] = "agent_silent"
REMEDIATION = {"remediation_pending", "remediation_ran", "remediation_failed", "remediation_recovered"}
WORDS = {"agent_silent": "a host agent stopped sending data", "ingest_cert_expiring": "the certificate of a host agent is about to end", "device_offline": "went offline", "service_down": "a service went down", "metric_critical": "a health reading went critical", "metric_warning": "a health reading went past its warning limit",
         "anomaly": "a reading was unusual", "capacity_warning": "a disk is filling up", "capacity_critical": "a disk is almost full", "remote_offline": "a remote device went offline",
         "probe_offline": "a remote site went silent", "central_unreachable": "the central Netlens could not be reached", "guest_backup_failed": "a backup failed", "storage_degraded": "a storage system had a problem", "backup_failed": "a backup failed", "container_unhealthy": "a container was unhealthy",
         "container_restarting": "a container kept restarting", "container_stopped": "a container stopped", "inventory_unavailable": "a smart-home device became unavailable",
         "vuln_critical": "a critical vulnerability was found", "port_unexpected": "an unexpected port opened", "firewall_ha": "a firewall cluster changed state", "firewall_licence": "a firewall licence needs attention",
         "dns_failed": "a DNS check failed", "host_timeout": "a monitored host stopped answering its health check", "plugin_update_failed": "a plugin update failed", "inventory_battery_low": "a smart-home battery is low"}
SYSTEM = ("You write one short paragraph (at most four sentences) for the administrator of a home or small-business network about an incident. "
          "Use only the facts in the JSON. Say what happened, the probable cause if one is given, whether it is over and whether an automatic fix ran. "
          "Do not invent causes, times or devices, and give no advice. Plain language.")


def _ts(text: str) -> datetime:
    return datetime.strptime(text, STAMP).replace(tzinfo=timezone.utc)


def _span(seconds: float) -> str:
    minutes = round(seconds / 60)
    if minutes < 1:
        return "less than a minute"
    if minutes < 90:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    hours = minutes / 60
    return f"{hours:.1f} hours" if hours < 48 else f"{hours / 24:.1f} days"


def incidents(conn: sqlite3.Connection, days: int = 7, now: datetime | None = None, only: set[int] | None = None) -> list[dict[str, Any]]:
    """The incidents of the last `days` days, the newest first. `only`: the ids of the devices that count (see app/relevance.py); what happened to the other devices is left out."""
    now = now or datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=days)).strftime(STAMP)
    kinds = PROBLEMS | set(RECOVERS) | REMEDIATION
    rows = [dict(r) for r in conn.execute("SELECT id, ts, device_id, kind, detail FROM events WHERE ts >= ? AND maintenance IS NULL ORDER BY id", (cutoff,)) if r["kind"] in kinds and (only is None or r["device_id"] is None or r["device_id"] in only)]
    clusters: list[dict] = []
    open_by_key: dict[tuple, dict] = {}
    for e in rows:
        when = _ts(e["ts"])
        if e["kind"] in PROBLEMS:
            key = (e["device_id"], e["kind"])
            c = open_by_key.get(key)
            if c is None:
                c = clusters[-1] if clusters and when - clusters[-1]["_last"] <= GAP else None
            if c is None:
                c = {"events": [], "problems": [], "remediation": [], "_last": when, "_open": set()}
                clusters.append(c)
            c["events"].append(e)
            c["problems"].append(e)
            c["_last"] = max(c["_last"], when)
            if e["device_id"] is not None:
                open_by_key[key] = c
                c["_open"].add(key)
        elif e["kind"] in RECOVERS:
            key = (e["device_id"], RECOVERS[e["kind"]])
            c = open_by_key.pop(key, None)
            if c is not None:
                c["events"].append(e)
                c["_open"].discard(key)
                c["_last"] = max(c["_last"], when)
        else:                                            # a remediation step: joins the incident of its device that is the newest
            mine = [c for c in clusters if any(p["device_id"] == e["device_id"] for p in c["problems"])] if e["device_id"] is not None else []
            c = mine[-1] if mine else (clusters[-1] if clusters and when - clusters[-1]["_last"] <= GAP else None)
            if c is not None:
                c["events"].append(e)
                c["remediation"].append(e)
                c["_last"] = max(c["_last"], when)
    try:
        devices, hierarchy = load_hierarchy(conn)
    except db_Error:
        devices, hierarchy = {}, {}
    out = [_describe(c, devices, hierarchy, now) for c in clusters if c["problems"]]
    out.sort(key=lambda i: i["start"], reverse=True)
    return out


def _describe(c: dict, devices: dict, hierarchy: dict, now: datetime) -> dict[str, Any]:
    problems = c["problems"]
    start, end = _ts(c["events"][0]["ts"]), _ts(c["events"][-1]["ts"])
    ids = sorted({p["device_id"] for p in problems if p["device_id"] is not None})
    names = [device_name(devices[i]) for i in ids if i in devices]
    cause = None
    for p in problems:                                   # the first device that went wrong and has the other affected ones below it
        if p["device_id"] is None:
            continue
        below = [i for i in ids if i != p["device_id"] and p["device_id"] in ancestors(hierarchy, i)]
        if below and p["device_id"] in devices:
            cause = {"device_id": p["device_id"], "name": device_name(devices[p["device_id"]]), "behind": len(below)}
            break
    ongoing = bool(c["_open"]) or any(p["device_id"] is None for p in problems) and (now - end) < timedelta(hours=1)
    resolved = not c["_open"] and all(p["device_id"] is not None for p in problems) if problems else True
    kinds = Counter(p["kind"] for p in problems)
    notes = list(dict.fromkeys((p["detail"] or "").strip()[:120] for p in problems if (p["detail"] or "").strip()))[:3]       # what the alerts said: the only names a service or site alert has
    fixes = [{"text": r["detail"] or "", "ok": r["kind"] in ("remediation_ran", "remediation_recovered")} for r in c["remediation"] if r["kind"] != "remediation_pending"]
    facts = {"start": c["events"][0]["ts"], "end": c["events"][-1]["ts"], "problems": sum(kinds.values()), "devices": names[:12], "device_count": len(ids), "kinds": [WORDS.get(k, k) for k in kinds],
             "probable_cause": cause, "alerts_said": notes, "over": resolved, "automatic_fixes": [f["text"] for f in fixes][:4]}
    title = (f"{cause['name']} went wrong and {cause['behind']} device{'s' if cause['behind'] != 1 else ''} behind it were affected" if cause
             else f"{names[0]}: {WORDS.get(problems[0]['kind'], problems[0]['kind'])}" if len(ids) == 1 and names
             else f"{len(ids)} devices had problems" if len(ids) > 1 else WORDS.get(problems[0]["kind"], problems[0]["kind"]).capitalize())
    parts = [f"{sum(kinds.values())} alert{'s' if sum(kinds.values()) != 1 else ''}"
             + (f" on {len(ids)} device{'s' if len(ids) != 1 else ''}" if ids else "") + f" within {_span((end - start).total_seconds())}."]
    if cause:
        parts.append(f"Probable cause: {cause['name']} ({cause['behind']} device{'s' if cause['behind'] != 1 else ''} behind it could not be reached).")
    elif len(kinds) == 1 and ids:
        parts.append(f"Everything was of one kind: {WORDS.get(next(iter(kinds)), next(iter(kinds)))}.")
    parts.append(f"It lasted {_span((end - start).total_seconds())} and is over." if resolved and end > start else "It is over." if resolved else "It may still be going on.")
    if fixes:
        parts.append("Automatic fix: " + "; ".join(f["text"] for f in fixes[:2]) + ".")
    return {"id": c["events"][0]["id"], "ref": f"INC-{c['events'][0]['id']}", "event_ids": [e["id"] for e in c["events"]][:200], "start": c["events"][0]["ts"], "end": c["events"][-1]["ts"], "title": title[:140], "summary": " ".join(parts), "devices": names[:20],
            "device_count": len(ids), "device_ids": ids, "notes": notes, "events": len(c["events"]), "resolved": resolved, "ongoing": ongoing and not resolved, "cause": cause, "facts": facts}


def narrate(conn: sqlite3.Connection, incident: dict, ask=None) -> str | None:
    """The same story in nicer words from the language model, or None (then the plain summary stands)."""
    import json

    return insights.complete(conn, SYSTEM, json.dumps(incident["facts"], indent=1), names=incident["devices"], ask=ask)


def incident_of(conn: sqlite3.Connection, event_id: int, days: int = 30, now: datetime | None = None) -> dict[str, Any] | None:
    """The incident that contains an event (by the event's id), or None."""
    for inc in incidents(conn, days, now):
        if event_id in inc.get("event_ids", []):
            return inc
    return None
