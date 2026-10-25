"""Investigate an incident: what happened, how it built up, and why you did (not) hear about it (a paid feature, see app/insights.py).

The findings come from the facts Netlens already holds, with plain rules:

  * the timeline of every affected device (repeated events are counted, not listed),
  * the shape of each reading that went wrong (a slow climb or a sudden step, from what to what, how fast),
  * what else happened in the hours before (a container that kept restarting, a new device, a port that opened),
  * how long it took before the first alert, and whether anybody was told: which channels include the alert, quiet hours that held it back.

A language model, when one is set up, may only put the same facts into better words; it never decides anything.
"""

from __future__ import annotations

import json
import re
import sqlite3
import statistics
from datetime import datetime, timedelta, timezone
from typing import Any

from app import incidents, insights, tsdb
from app.notify import channels as ch

STAMP = "%Y-%m-%dT%H:%M:%SZ"
BEFORE = timedelta(hours=3)             # what happened before the first alert counts as "the lead-up"
LOOKBACK = 48 * 3600                    # how far back a reading is examined
MAX_DEVICES = 6
FLAP = {"device_offline", "device_online", "wifi_roamed", "ip_changed", "device_new"}      # a device that only did this is background noise, not part of the story
HEALTH_METRICS = ("cpu_pct", "mem_pct", "disk_pct", "net_tx_bps", "net_rx_bps")
LEAD_KINDS = {"container_restarting", "container_unhealthy", "container_stopped", "service_down", "anomaly", "metric_warning", "capacity_warning", "backup_failed", "firmware_update",
              "port_opened", "port_unexpected", "device_new", "gateway_changed", "dhcp_rogue", "cert_expiring"}
UNITS = {"cpu_pct": "%", "mem_pct": "%", "disk_pct": "%", "temp_c": " °C", "battery_pct": "%", "net_tx_bps": " bit/s", "net_rx_bps": " bit/s"}
WORDS = {"disk_pct": "disk use", "cpu_pct": "processor use", "mem_pct": "memory use", "temp_c": "temperature", "net_tx_bps": "outgoing traffic", "net_rx_bps": "incoming traffic"}
SYSTEM = ("You write a short report (at most six plain sentences) for the administrator of a home or small-business network about one incident that has been investigated. "
          "Use only the facts in the JSON, in this order: what happened and to which device, the probable cause and the evidence for it, what was affected as a result, "
          "and, last and in one short sentence, whether the administrator was warned. Leave out the devices listed as unrelated. "
          "Invent no causes, times, numbers or devices; if the facts name no cause, say that none stands out.")


def _ts(text: str) -> datetime:
    return datetime.strptime(text, STAMP).replace(tzinfo=timezone.utc)


def _clock(when: datetime) -> str:
    return when.strftime("%d %b %H:%M UTC")


def _minutes(seconds: float) -> str:
    m = round(seconds / 60)
    return "a few minutes" if m < 2 else f"{m} minutes" if m < 90 else f"{m / 60:.1f} hours" if m < 2880 else f"{m / 1440:.1f} days"


def shape(points: list[list[float]], unit: str = "%") -> dict[str, Any] | None:
    """How a reading moved: [[t, avg, lo, hi], ...] oldest first -> a step (the biggest rise within an hour is most of the change), a climb, or steady."""
    pts = [(p[0], p[1]) for p in points if p[1] is not None]
    if len(pts) < 4:
        return None
    first, last = pts[0][1], pts[-1][1]
    peak = max(v for _, v in pts)
    best = (0.0, 0, 0)                          # the biggest rise within an hour: (rise, from index, to index)
    for j in range(len(pts)):
        for i in range(j - 1, -1, -1):
            if pts[j][0] - pts[i][0] > 3600:
                break
            if pts[j][1] - pts[i][1] > best[0]:
                best = (pts[j][1] - pts[i][1], i, j)
    total = peak - min(v for _, v in pts[: pts.index(max(pts, key=lambda p: p[1])) + 1])
    out: dict[str, Any] = {"first": round(first, 1), "last": round(last, 1), "peak": round(peak, 1)}
    if best[0] >= 8 and total > 0 and best[0] >= 0.5 * total:
        a, b = pts[best[1]], pts[best[2]]
        out.update(kind="step", from_value=round(a[1], 1), to_value=round(b[1], 1), at=int(a[0]), seconds=int(b[0] - a[0]))
        before = [v for t, v in pts if t < a[0] - 3600]
        if len(before) >= 6:
            days = (a[0] - pts[0][0]) / 86400
            out["slope_before_per_day"] = round((before[-1] - before[0]) / days, 2) if days >= 0.5 else None
    elif peak - first >= 3:
        out.update(kind="climb", from_value=round(first, 1), to_value=round(peak, 1), per_day=round((peak - first) / max(1e-9, (pts[-1][0] - pts[0][0]) / 86400), 1))
    else:
        out["kind"] = "steady"
    return out


def surge(points: list[list[float]]) -> dict[str, Any] | None:
    """A reading that is not a percentage (traffic): it counts as a surge when it rises to five times its usual level and by at least 1 Mbit/s."""
    pts = [(p[0], p[1]) for p in points if p[1] is not None]
    if len(pts) < 6:
        return None
    base = statistics.median(v for _, v in pts[: max(3, len(pts) // 2)])
    peak = max(pts, key=lambda p: p[1])
    if peak[1] - base < 1e6 or peak[1] < 5 * max(base, 1.0):
        return {"kind": "steady", "first": round(base), "last": round(pts[-1][1]), "peak": round(peak[1])}
    onset = next(t for t, v in pts if v > base + (peak[1] - base) / 3)
    return {"kind": "surge", "from_value": round(base), "to_value": round(peak[1]), "at": int(onset), "seconds": int(peak[0] - onset), "first": round(base), "last": round(pts[-1][1]), "peak": round(peak[1])}


def _timeline(conn: sqlite3.Connection, device_id: int, since: str, until: str) -> list[dict[str, Any]]:
    """The device's events in the window, a kind that repeats is one line with a count."""
    rows = conn.execute("SELECT id, ts, kind, detail FROM events WHERE device_id = ? AND ts >= ? AND ts <= ? ORDER BY id", (device_id, since, until)).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        if out and out[-1]["kind"] == r["kind"] and (_ts(r["ts"]) - _ts(out[-1]["last"])).total_seconds() < 4 * 3600:
            out[-1]["count"] += 1
            out[-1]["last"] = r["ts"]
            out[-1]["text"] = (r["detail"] or "")[:160]
            continue
        out.append({"ts": r["ts"], "last": r["ts"], "kind": r["kind"], "count": 1, "text": (r["detail"] or "")[:160]})
    return out[:40]


def _noise(conn: sqlite3.Connection, device_id: int, timeline: list[dict], start: datetime) -> str | None:
    """Why a device that only went offline and online again is not part of the story (None when it is)."""
    if any(t["kind"] not in FLAP for t in timeline):
        return None
    for t in timeline:
        m = re.search(r"maintenance '([^']+)'", t["text"])
        if m:
            return f"it went offline during the maintenance window '{m.group(1)}'"
    day = conn.execute("SELECT COUNT(*) FROM events WHERE device_id = ? AND kind IN ('device_offline', 'device_online', 'wifi_roamed', 'ip_changed') AND ts >= ? AND ts < ?",
                       (device_id, (start - timedelta(hours=24)).strftime(STAMP), start.strftime(STAMP))).fetchone()[0]
    changes = sum(t["count"] for t in timeline)
    if day >= 3 or changes >= 4:
        return f"it keeps going offline and online ({changes} times in these hours, {day} in the day before) and nothing else about it changed"
    return None


def _readings(conn: sqlite3.Connection, device_id: int, start: datetime, end: datetime, now: datetime) -> list[dict[str, Any]]:
    """How the processor, memory, disk and network traffic of this device moved around the incident; only what changed is returned."""
    store = tsdb.for_conn(conn)
    if store is None:
        return []
    states = {(r["metric"], r["label"] or ""): r for r in conn.execute(
        "SELECT s.metric, s.label, s.level, s.value FROM metric_state s JOIN host_monitors m ON m.id = s.monitor_id WHERE m.device_id = ?", (device_id,))}
    out = []
    e = int(min(now, end + timedelta(hours=2)).timestamp())
    for series in store.metrics_of("device", device_id):
        metric, label = series["metric"], series["label"] or ""
        if metric not in HEALTH_METRICS:
            continue
        got = store.query("device", device_id, metric, label, span=min(LOOKBACK, max(6 * 3600, e - int(start.timestamp()) + 36 * 3600)), end=e, points=400)
        sh = surge(got["points"]) if metric.startswith("net_") else shape(got["points"])
        if not sh or sh["kind"] == "steady":
            continue
        if sh["kind"] in ("step", "surge") and not (start - timedelta(hours=4)).timestamp() <= sh["at"] <= (end + timedelta(hours=1)).timestamp():
            continue                                  # it moved, but at another time: not part of this story
        st = states.get((metric, label))
        out.append({"metric": metric, "label": label, "level": st["level"] if st else "ok", "now": round(st["value"], 1) if st and st["value"] is not None else sh.get("last"), "unit": UNITS[metric], "shape": sh})
    return out[:8]


def _bits(value: float) -> str:
    return f"{value / 1e6:.0f} Mbit/s" if value >= 1e6 else f"{value / 1e3:.0f} kbit/s"


def _suspects(conn: sqlite3.Connection, device_ids: list[int], onset: datetime, end: datetime, now: datetime) -> list[dict[str, Any]]:
    """What else was going on at the same time on the same machine: a scan, a (re)started container, a backup, a maintenance window."""
    out = []
    lo, hi = (onset - timedelta(minutes=45)).strftime(STAMP), (max(end, onset) + timedelta(hours=2)).strftime(STAMP)
    guests = [dict(r) for r in conn.execute("SELECT plugin_id, name, host_device_id, device_id, details FROM hypervisor_guests WHERE host_device_id IN (%s)" % ",".join("?" * len(device_ids)), device_ids)] if device_ids else []
    # a vulnerability scanner that reported during the incident; it runs here when its containers are guests of the affected machine
    for srv in conn.execute("SELECT plugin_id, server_id, name FROM vuln_servers"):
        row = conn.execute("SELECT MIN(last_seen) a, MAX(last_seen) b, COUNT(*) n, COUNT(DISTINCT host_ip) hosts FROM vuln_findings WHERE plugin_id = ? AND server_id = ? AND last_seen >= ? AND last_seen <= ?",
                           (srv["plugin_id"], srv["server_id"], lo, hi)).fetchone()
        if not row or not row["n"]:
            continue
        here = [g for g in guests if srv["plugin_id"].lower() in g["name"].lower() or srv["name"].lower() in g["name"].lower()]
        text = f"{srv['name']} (a vulnerability scanner) reported findings from {_clock(_ts(row['a']))[:-4]} to {_clock(_ts(row['b']))[:-4]} UTC on {row['hosts']} host{'s' if row['hosts'] != 1 else ''}: a scan was running while this happened"
        if here:
            text += f". It runs on the affected machine ({len(here)} of its containers, such as {here[0]['name']}), and a scan loads the processor and memory heavily"
        if here:                                       # a scanner elsewhere loads the network, not this machine; it is only mentioned when it runs here
            out.append({"score": 90, "text": text + "."})
    # containers of the affected machines that (re)started right around the onset
    for g in guests:
        try:
            details = json.loads(g["details"] or "{}")
        except ValueError:
            continue
        started = details.get("started")
        if started and started[:19] + "Z" >= (onset - timedelta(minutes=20)).strftime(STAMP) and started[:19] + "Z" <= (onset + timedelta(minutes=20)).strftime(STAMP):
            out.append({"score": 70, "text": f"The container {g['name']} (re)started at {started[11:16]} UTC, right at the start."})
    # other scheduled or administrative work around the onset
    for r in conn.execute("SELECT ts, kind, detail FROM events WHERE ts >= ? AND ts <= ? AND kind IN ('backup_failed', 'guest_backup_failed', 'guest_backup_late', 'remediation_ran', 'firmware_update', 'image_update') ORDER BY id LIMIT 3",
                          ((onset - timedelta(hours=1)).strftime(STAMP), (onset + timedelta(minutes=30)).strftime(STAMP))):
        out.append({"score": 50, "text": f"At {r['ts'][11:16]} UTC: {(r['detail'] or r['kind'])[:120]}."})
    try:
        from app import maintenance

        for w in maintenance.load_windows(conn):
            if w.get("enabled", True) and any(d in device_ids for d in (w.get("scope") or {}).get("devices", [])) and maintenance.is_active(w, onset):
                out.append({"score": 60, "text": f"The maintenance window '{w.get('name')}' covered the start."})
    except (ImportError, AttributeError):
        pass
    out.sort(key=lambda x: -x["score"])
    return out[:4]


def _told(conn: sqlite3.Connection, kind: str, when: datetime) -> dict[str, Any]:
    """Which channels include this kind, and whether quiet hours held it back at that time."""
    channels = [c for c in ch.load_channels(conn) if c["enabled"]]
    rank = {s: i for i, s in enumerate(ch.SEVERITIES)}
    include = [c for c in channels if kind in c["events"]]
    passing = [c for c in include if rank[ch.severity_of(kind)] >= rank[(c.get("filters") or {}).get("min_severity", "info")]]
    quiet = ch.load_quiet(conn)
    held = ch.in_quiet_hours(when, quiet) and not (quiet.get("bypass_critical") and kind in ch.CRITICAL)
    return {"kind": kind, "label": ch.EVENT_LABELS.get(kind, kind), "channels": [c["name"] for c in passing], "enabled_channels": len(channels), "held_by_quiet_hours": bool(passing) and held,
            "excluded_by_severity": len(include) - len(passing)}


def investigate(conn: sqlite3.Connection, incident_id: int, now: datetime | None = None) -> dict[str, Any] | None:
    now = now or datetime.now(timezone.utc)
    found = next((i for i in incidents.incidents(conn, 30, now=now) if i["id"] == incident_id), None)
    if found is None:
        return None
    start, end = _ts(found["start"]), _ts(found["end"])
    lead_from = (start - BEFORE).strftime(STAMP)
    until = (min(now, end + timedelta(hours=6))).strftime(STAMP)
    names = {r["id"]: r["n"] for r in conn.execute("SELECT id, COALESCE(custom_name, hostname, primary_ip) AS n FROM devices")}
    host_of = {r["device_id"]: r["host_device_id"] for r in conn.execute("SELECT device_id, host_device_id FROM hypervisor_guests WHERE device_id IS NOT NULL AND host_device_id IS NOT NULL")}

    # 1. who is part of the story and who is only background noise
    core, unrelated = [], []
    for device_id in found["device_ids"][:MAX_DEVICES]:
        timeline = _timeline(conn, device_id, lead_from, until)
        why = _noise(conn, device_id, timeline, start)
        entry = {"id": device_id, "name": names.get(device_id, f"device {device_id}"), "timeline": timeline}
        (unrelated if why else core).append({**entry, "why": why} if why else entry)
    if not core:                                   # nothing but flapping: then that is the story
        core, unrelated = [{k: v for k, v in u.items() if k != "why"} for u in unrelated], []
    for d in core:
        d["readings"] = _readings(conn, d["id"], start, end, now)

    # 2. what moved first: the earliest jump of a reading, and the machine that hosts the other one
    onsets = {d["id"]: min((datetime.fromtimestamp(r["shape"]["at"], timezone.utc) for r in d["readings"] if r["shape"]["kind"] in ("step", "surge") and r["metric"] != "disk_pct"), default=None) for d in core}
    onset = min((o for o in onsets.values() if o), default=None)
    findings: list[dict[str, str]] = []
    for d in core:
        for rd in d["readings"]:
            sh = rd["shape"]
            what = f"{WORDS.get(rd['metric'], rd['metric'])}{' on ' + rd['label'] if rd['label'] else ''} of {d['name']}"
            if sh["kind"] == "step":
                at = datetime.fromtimestamp(sh["at"], timezone.utc)
                findings.append({"level": "fact", "text": f"The {what} jumped from {sh['from_value']}{rd['unit']} to {sh['to_value']}{rd['unit']} in {_minutes(sh['seconds'])}, starting {_clock(at)}."})
                slope = sh.get("slope_before_per_day")
                warned = conn.execute("SELECT 1 FROM events WHERE device_id = ? AND kind IN ('capacity_warning', 'capacity_critical') AND ts < ? LIMIT 1", (d["id"], found["start"])).fetchone()
                if rd["metric"] == "disk_pct" and slope is not None and slope > 0.2:
                    days = (100 - sh["from_value"]) / slope
                    findings.append({"level": "fact", "text": f"Before the jump it was growing about {slope} points a day" + (f", which would have filled it in about {days:.0f} days" if days < 60 else "") + "."
                                     + (" The disk forecast did not warn: it fits a straight line through 30 days and smooths out a recent change." if days < 14 and not warned else "")})
                first = conn.execute("SELECT MIN(ts) FROM events WHERE device_id = ? AND kind IN ('metric_warning', 'metric_critical', 'anomaly', 'capacity_warning', 'capacity_critical') AND ts >= ?", (d["id"], (at - timedelta(hours=1)).strftime(STAMP))).fetchone()[0]
                if first and _ts(first) > at:
                    findings.append({"level": "fact", "text": f"The first alert about {d['name']} came {_minutes((_ts(first) - at).total_seconds())} after the jump began."})
            elif sh["kind"] == "surge":
                at = datetime.fromtimestamp(sh["at"], timezone.utc)
                findings.append({"level": "fact", "text": f"The {what} rose from {_bits(sh['from_value'])} to {_bits(sh['to_value'])} from {_clock(at)}."})
            elif sh["kind"] == "climb":
                findings.append({"level": "fact", "text": f"The {what} climbed from {sh['from_value']}{rd['unit']} to {sh['to_value']}{rd['unit']}, about {sh['per_day']} points a day."})
            if rd["level"] in ("warning", "critical"):
                findings.append({"level": "warn", "text": f"The {what} is still {rd['level']} ({rd['now']}{rd['unit']})."})
    # host and guest: the one that moved first is the origin, the other one shows the load
    try:
        from app.hierarchy import ancestors, load_hierarchy

        _, hierarchy = load_hierarchy(conn)
    except Exception:  # noqa: BLE001 - without a hierarchy only the hypervisor links are used
        hierarchy, ancestors = {}, None
    for d in core:
        host = host_of.get(d["id"]) or next((a for a in (ancestors(hierarchy, d["id"]) if ancestors else []) if any(x["id"] == a for x in core)), None)
        mine = next((x for x in core if x["id"] == host), None)
        if mine is None:
            continue
        a, b = onsets.get(d["id"]), onsets.get(mine["id"])
        if a and b and a < b:
            findings.append({"level": "cause", "text": f"{mine['name']} is the host of {d['name']} and its load followed {_minutes((b - a).total_seconds())} later: the problem started inside {d['name']} and shows through on {mine['name']}, not the other way round."})
        elif a and not b:
            findings.append({"level": "cause", "text": f"{mine['name']} is the host of {d['name']}; its own alerts are the load of {d['name']} showing through, not a separate problem."})
        elif b and a and b < a:
            findings.append({"level": "cause", "text": f"{mine['name']}, the host, moved first ({_minutes((a - b).total_seconds())} before {d['name']}): look at the host itself."})

    # 3. suspects: what else happened on that machine at the same time
    suspects = _suspects(conn, [d["id"] for d in core], onset or start, end, now) if (onset or core) else []
    for sp in suspects[:3]:
        findings.append({"level": "cause", "text": ("Probable cause: " if sp is suspects[0] and sp["score"] >= 60 else "Also at that time: ") + sp["text"]})
    if not suspects and not any(f["level"] == "cause" for f in findings):
        findings.append({"level": "fact", "text": "Nothing Netlens knows about explains the start: no scan, backup, restart or maintenance window at that time. Look at what runs on the machine."})
    # restart loops on the same devices
    for d in core:
        for t in sorted(d["timeline"], key=lambda t: -t["count"]):
            if t["kind"] in ("container_restarting", "container_unhealthy", "container_stopped") and t["count"] >= 2:
                findings.append({"level": "cause", "text": f"Probable cause: {t['text'] or t['kind']} ({t['count']} alerts on {d['name']} between {_clock(_ts(t['ts']))} and {_clock(_ts(t['last']))}). A container in a restart loop is a common reason for a disk to fill or a host to slow down."})
                break

    # 4. what it did to the rest: services that failed meanwhile
    if onset:
        down = [r for r in conn.execute("SELECT ts, detail FROM events WHERE kind = 'service_down' AND ts >= ? AND ts <= ? ORDER BY id", (onset.strftime(STAMP), (end + timedelta(minutes=30)).strftime(STAMP)))]
        if down:
            findings.append({"level": "impact", "text": "Service checks that failed meanwhile: " + "; ".join(f"{(r['detail'] or '')[:70]} at {r['ts'][11:16]}" for r in down[:4]) + ". They may be a result of the overload."})
    for d in core:
        slow = conn.execute("SELECT detail FROM events WHERE kind = 'anomaly' AND ts >= ? AND ts <= ? AND device_id != ? AND detail LIKE '%response time%' ORDER BY id LIMIT 1", ((onset or start).strftime(STAMP), until, d["id"])).fetchone()
        if slow:
            findings.append({"level": "impact", "text": f"Elsewhere: {slow['detail'][:140]}."})
            break
    if unrelated:
        findings.append({"level": "noise", "text": "Left out as unrelated: " + "; ".join(f"{u['name']} ({u['why']})" for u in unrelated) + "."})

    # 5. was anybody told: one line, at the end
    told = []
    kinds = list(dict.fromkeys(p["kind"] for d in core for p in d["timeline"] if p["kind"] in incidents.PROBLEMS))[:6]
    silent, held = [], []
    for kind in kinds:
        when = min((_ts(p["ts"]) for d in core for p in d["timeline"] if p["kind"] == kind), default=start)
        t = _told(conn, kind, when)
        told.append(t)
        if not t["channels"]:
            silent.append(t["label"])
        elif t["held_by_quiet_hours"]:
            held.append(t["label"])
    if told and not told[0]["enabled_channels"]:
        findings.append({"level": "notify", "text": "Nobody was told: no notification channel is switched on."})
    elif silent:
        findings.append({"level": "notify", "text": f"These alerts reached nobody, because no channel includes them: {'; '.join(silent)} (Settings → Notifications → Channels)."})
    for label in held:
        findings.append({"level": "notify", "text": f"\"{label}\" came during quiet hours, so it was held until they ended."})
    if not found["resolved"]:
        findings.append({"level": "warn", "text": "The incident is not over."})
    order = {"cause": 0, "fact": 1, "warn": 2, "impact": 3, "noise": 4, "notify": 5}
    findings.sort(key=lambda f: order[f["level"]])
    names_core = [d["name"] for d in core]
    changed = sorted({WORDS.get(r["metric"], r["metric"]) for d in core for r in d["readings"] if r["shape"]["kind"] in ("step", "surge")})
    title = f"{', '.join(names_core[:2])}: {' and '.join(changed[:3])} jumped" if changed else found["title"]
    facts = {"title": title, "start": found["start"], "end": found["end"], "over": found["resolved"], "devices": names_core, "unrelated_devices": [u["name"] for u in unrelated],
             "findings": [f["text"] for f in findings if f["level"] != "noise"][:12]}
    return {"id": found["id"], "title": title, "start": found["start"], "end": found["end"], "resolved": found["resolved"], "devices": core, "unrelated": [{"id": u["id"], "name": u["name"], "why": u["why"]} for u in unrelated],
            "notifications": told, "findings": findings, "facts": facts}


def narrate(conn: sqlite3.Connection, report: dict, ask=None) -> str | None:
    return insights.complete(conn, SYSTEM, json.dumps(report["facts"], indent=1), names=report["facts"]["devices"] + report["facts"]["unrelated_devices"], ask=ask)
