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
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from app import incidents, insights, tsdb
from app.notify import channels as ch

STAMP = "%Y-%m-%dT%H:%M:%SZ"
BEFORE = timedelta(hours=3)             # what happened before the first alert counts as "the lead-up"
LOOKBACK = 48 * 3600                    # how far back a reading is examined
MAX_DEVICES = 6
LEAD_KINDS = {"container_restarting", "container_unhealthy", "container_stopped", "service_down", "anomaly", "metric_warning", "capacity_warning", "backup_failed", "firmware_update",
              "port_opened", "port_unexpected", "device_new", "gateway_changed", "dhcp_rogue", "cert_expiring"}
UNITS = {"cpu_pct": "%", "mem_pct": "%", "disk_pct": "%", "temp_c": " °C", "battery_pct": "%"}
WORDS = {"disk_pct": "disk use", "cpu_pct": "processor use", "mem_pct": "memory use", "temp_c": "temperature"}
SYSTEM = ("You write a short report (at most six plain sentences) for the administrator of a home or small-business network about one incident that has been investigated. "
          "Use only the facts in the JSON: what happened, how it built up, the probable source if one is given, and why the administrator was or was not warned. "
          "Invent no causes, times, numbers or devices. Finish with what to look at first, but only if the facts say so.")


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


def _readings(conn: sqlite3.Connection, device_id: int, start: datetime, end: datetime, now: datetime) -> list[dict[str, Any]]:
    """The readings of this device that went wrong during the incident (or are wrong now), with the shape of each."""
    store = tsdb.for_conn(conn)
    out = []
    rows = conn.execute("SELECT s.metric, s.label, s.level, s.since, s.value FROM metric_state s JOIN host_monitors m ON m.id = s.monitor_id WHERE m.device_id = ?", (device_id,)).fetchall()
    for r in rows:
        if r["metric"] not in UNITS or not (r["level"] != "ok" or (r["since"] or "") >= (start - timedelta(hours=1)).strftime(STAMP)):
            continue
        item: dict[str, Any] = {"metric": r["metric"], "label": r["label"] or "", "level": r["level"], "now": round(r["value"], 1) if r["value"] is not None else None, "unit": UNITS[r["metric"]]}
        if store is not None:
            e = int(min(now, end + timedelta(hours=2)).timestamp())
            got = store.query("device", device_id, r["metric"], r["label"] or "", span=min(LOOKBACK, max(7200, e - int(start.timestamp()) + 36 * 3600)), end=e, points=400)
            item["shape"] = shape(got["points"])
        out.append(item)
    return out[:6]


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
    findings: list[dict[str, str]] = []
    devices = []
    first_alert: dict[int, datetime] = {}
    for device_id in found["device_ids"][:MAX_DEVICES]:
        name = names.get(device_id, f"device {device_id}")
        timeline = _timeline(conn, device_id, lead_from, until)
        readings = _readings(conn, device_id, start, end, now)
        devices.append({"id": device_id, "name": name, "timeline": timeline, "readings": readings})
        problem = next((t for t in timeline if t["kind"] in incidents.PROBLEMS and t["ts"] >= found["start"]), None)
        if problem:
            first_alert[device_id] = _ts(problem["ts"])
        for rd in readings:
            sh = rd.get("shape")
            what = f"{WORDS.get(rd['metric'], rd['metric'])}{' on ' + rd['label'] if rd['label'] else ''} of {name}"
            if sh and sh["kind"] == "step":
                at = datetime.fromtimestamp(sh["at"], timezone.utc)
                findings.append({"level": "info", "text": f"The {what} did not creep up, it jumped: from {sh['from_value']}{rd['unit']} to {sh['to_value']}{rd['unit']} in {_minutes(sh['seconds'])}, starting {_clock(at)}."
                                  + (f" Before that it grew about {sh['slope_before_per_day']} points a day, so a trend forecast could not see it coming." if sh.get("slope_before_per_day") is not None and abs(sh["slope_before_per_day"]) < 5 else "")})
                lag = first_alert.get(device_id)
                if lag and lag > at:
                    findings.append({"level": "info", "text": f"The first alert for {name} came {_minutes((lag - at).total_seconds())} after the jump began."})
            elif sh and sh["kind"] == "climb":
                findings.append({"level": "info", "text": f"The {what} climbed from {sh['from_value']}{rd['unit']} to {sh['to_value']}{rd['unit']}, about {sh['per_day']} points a day."})
            if rd.get("level") in ("warning", "critical"):
                findings.append({"level": "warn", "text": f"The {what} is still {rd['level']} ({rd['now']}{rd['unit']})."})
        # the lead-up: what the same device did in the hours before the first alert, and what changed elsewhere
        for t in sorted(timeline, key=lambda t: -t["count"]):
            if t["kind"] in ("container_restarting", "container_unhealthy", "container_stopped") and t["count"] >= 2:
                findings.append({"level": "cause", "text": f"Probable source: {t['text'] or t['kind']} ({t['count']} alerts on {name} between {_clock(_ts(t['ts']))} and {_clock(_ts(t['last']))}). A container in a restart loop is a common reason for a disk to fill or a host to slow down."})
                break
    before = []
    for r in conn.execute("SELECT ts, device_id, kind, detail FROM events WHERE ts >= ? AND ts < ? ORDER BY id", (lead_from, found["start"])):
        if r["kind"] in LEAD_KINDS and r["device_id"] not in found["device_ids"][:MAX_DEVICES]:
            before.append({"ts": r["ts"], "device": names.get(r["device_id"]), "kind": r["kind"], "text": (r["detail"] or "")[:140]})
    if before:
        findings.append({"level": "info", "text": f"{len(before)} other thing{'s' if len(before) != 1 else ''} happened elsewhere in the three hours before, such as: {before[0]['text']}"})
    # who was told
    told = []
    kinds = list(dict.fromkeys(p["kind"] for d in devices for p in d["timeline"] if p["kind"] in incidents.PROBLEMS))[:6]
    for kind in kinds:
        when = min((_ts(p["ts"]) for d in devices for p in d["timeline"] if p["kind"] == kind), default=start)
        t = _told(conn, kind, when)
        told.append(t)
        if not t["enabled_channels"]:
            findings.append({"level": "warn", "text": f"Nobody was told: no notification channel is switched on ({t['label'].lower()})."})
        elif not t["channels"]:
            reason = "its minimum severity lets only more serious events through" if t["excluded_by_severity"] else "no channel includes it"
            findings.append({"level": "warn", "text": f"Nobody was told about \"{t['label']}\": {reason}. Settings → Notifications → Channels."})
        elif t["held_by_quiet_hours"]:
            findings.append({"level": "info", "text": f"\"{t['label']}\" came during quiet hours, so it was held until they ended."})
    if not found["resolved"]:
        findings.append({"level": "warn", "text": "The incident is not over."})
    order = {"cause": 0, "warn": 1, "info": 2}
    findings.sort(key=lambda f: order[f["level"]])
    facts = {"title": found["title"], "start": found["start"], "end": found["end"], "over": found["resolved"], "devices": [d["name"] for d in devices],
             "findings": [f["text"] for f in findings][:10]}
    return {"id": found["id"], "title": found["title"], "start": found["start"], "end": found["end"], "resolved": found["resolved"], "devices": devices, "before": before[:10], "notifications": told,
            "findings": findings, "facts": facts}


def narrate(conn: sqlite3.Connection, report: dict, ask=None) -> str | None:
    return insights.complete(conn, SYSTEM, json.dumps(report["facts"], indent=1), names=report["facts"]["devices"], ask=ask)
