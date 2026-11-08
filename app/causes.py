"""What changed before it broke, and what breaks if it goes away (a paid feature, see app/insights.py).

Two questions an administrator asks about a device, answered from facts Netlens already holds; nothing new is stored.

  * ``before``: the things that changed on or near the device in the hours before an outage (a port that opened, a firmware or image update,
    a container that stopped, the device above it that went away, a setting somebody changed). Each is scored by how close in time it was and
    how related it is to the device. It is a list of suspects, not a verdict: the words say "changed shortly before", never "caused".
  * ``impact``: everything that depends on a device through the network hierarchy (devices, containers, service checks), level by level,
    for "is it safe to reboot this?".
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from app.hierarchy import ancestors, children_map, device_name, load_hierarchy

STAMP = "%Y-%m-%dT%H:%M:%SZ"
MAX_HOURS = 72
SUSPECTS = 8

# Events that are a change (not a symptom), with how suspicious such a change is. A symptom (the device going offline, an alert) never appears here.
CHANGES: dict[str, float] = {
    "firmware_update": 2.5, "os_changed": 2.0, "plugin_updated": 1.5,
    "port_opened": 2.0, "port_closed": 1.5, "port_unexpected": 2.0, "port_missing": 1.5,
    "guest_started": 2.0, "guest_stopped": 2.0, "container_stopped": 1.5,
    "ip_changed": 1.5, "ip_reused": 2.0, "device_new": 1.0, "device_deleted": 1.0,
    "gateway_changed": 2.5, "dhcp_rogue": 2.5, "dns_removed": 1.0,
    "link_down": 2.0, "link_up": 1.0, "link_degraded": 2.0, "storage_degraded": 2.0,
    "remediation_ran": 2.5,
}
ABOVE_ONLY = {"device_offline": (2.0, "went offline"), "device_online": (1.5, "came back")}      # the device above it going away is a change for the one below
NETWORK_WIDE = {"gateway_changed", "dhcp_rogue"}
# Requests that are not a change of anything (a test, a run, a heartbeat of the audit chain)
NOT_A_CHANGE = re.compile(r"/(run|ping|trace|wake|scan|scans|login|logout|anchor|verify|test|ask|model-check|probe|decide)(/|$)|^/api/insights|/audit/")
DEVICE_PATH = re.compile(r"^/api/devices/(\d+)(?:/|$)")


def _ts(text: str) -> datetime:
    return datetime.strptime(text, STAMP).replace(tzinfo=timezone.utc)


def _before(minutes: float) -> str:
    minutes = max(0, round(minutes))
    if minutes < 2:
        return "a minute before"
    if minutes < 90:
        return f"{minutes} minutes before"
    hours = minutes / 60
    return f"{hours:.1f} hours before" if hours < 48 else f"{hours / 24:.1f} days before"


def outages(conn: sqlite3.Connection, device_id: int, limit: int = 10, days: int = 30, now: datetime | None = None) -> list[str]:
    """When the device went offline (a stamp each), newest first."""
    now = now or datetime.now(timezone.utc)
    since = (now - timedelta(days=days)).strftime(STAMP)
    return [r[0] for r in conn.execute("SELECT ts FROM events WHERE device_id = ? AND kind = 'device_offline' AND ts >= ? ORDER BY id DESC LIMIT ?", (device_id, since, limit))]


def before(conn: sqlite3.Connection, device_id: int, at: str | None = None, hours: float = 6, now: datetime | None = None) -> dict[str, Any] | None:
    """The suspects for an outage of `device_id` at `at` (a stamp; the latest outage when None). None when the device does not exist."""
    now = now or datetime.now(timezone.utc)
    devices, tree = load_hierarchy(conn)
    if device_id not in devices:
        return None
    hours = min(max(float(hours), 0.5), MAX_HOURS)
    known = outages(conn, device_id, now=now)
    when = _ts(at) if at else _ts(known[0]) if known else now
    basis = "the outage you chose" if at else "the latest outage" if known else "now (this device has not gone offline in the last 30 days)"
    since = (when - timedelta(hours=hours)).strftime(STAMP)
    until = when.strftime(STAMP)
    above = ancestors(tree, device_id)
    rank = {device_id: (0, "this device")}
    for i, a in enumerate(above):
        rank[a] = (i + 1, "above it" if i == 0 else "further up")
    found: list[dict[str, Any]] = []

    def add(ts: str, device: int | None, kind: str, text: str, weight: float, relation: str, closeness: float, who: str | None = None) -> None:
        minutes = (when - _ts(ts)).total_seconds() / 60
        score = weight * closeness / (1 + minutes / 60)
        found.append({"ts": ts, "minutes_before": round(minutes), "when": _before(minutes), "device_id": device, "device": device_name(devices[device]) if device in devices else None,
                      "kind": kind, "text": text, "relation": relation, "who": who, "score": round(score, 3)})

    for r in conn.execute("SELECT ts, device_id, kind, detail FROM events WHERE ts >= ? AND ts < ? AND maintenance IS NULL ORDER BY id DESC LIMIT 3000", (since, until)):
        dev, kind = r["device_id"], r["kind"]
        text = (r["detail"] or kind.replace("_", " ")).strip()[:200]
        if dev in rank:
            distance, relation = rank[dev]
            if dev != device_id and kind in ABOVE_ONLY:
                weight, verb = ABOVE_ONLY[kind]
                add(r["ts"], dev, kind, f"{device_name(devices[dev])} {verb}", weight, relation, 0.9 ** distance)
            elif kind in CHANGES:
                add(r["ts"], dev, kind, text, CHANGES[kind], relation, 1.0 if dev == device_id else 0.9 ** distance)
        elif dev is None and kind in NETWORK_WIDE:
            add(r["ts"], None, kind, text, CHANGES[kind], "the whole network", 0.7)
    mine = {device_id, *above}
    for r in conn.execute("SELECT ts, user, method, path, action FROM audit_log WHERE ts >= ? AND ts < ? AND status < 400 AND method != 'GET' ORDER BY id DESC LIMIT 1500", (since, until)):
        if NOT_A_CHANGE.search(r["path"]):
            continue
        m = DEVICE_PATH.match(r["path"])
        if m and int(m.group(1)) in mine:
            dev = int(m.group(1))
            add(r["ts"], dev, "setting_changed", r["action"] or "a setting was changed", 3.0, rank[dev][1], 1.0 if dev == device_id else 0.9, r["user"] or None)
        elif not m:
            add(r["ts"], None, "setting_changed", r["action"] or "a setting was changed", 1.0, "a setting", 0.6, r["user"] or None)
    # the same thing many times (a port that flaps, a setting saved again and again) is one line with a count
    merged: dict[tuple, dict[str, Any]] = {}
    for item in sorted(found, key=lambda x: x["minutes_before"]):
        key = (item["kind"], item["device_id"], item["text"])
        if key in merged:
            merged[key]["times"] += 1
            merged[key]["score"] = max(merged[key]["score"], item["score"])
        else:
            merged[key] = {**item, "times": 1}
    items = sorted(merged.values(), key=lambda x: (-x["score"], x["minutes_before"]))[:SUSPECTS]
    return {"device_id": device_id, "device": device_name(devices[device_id]), "at": when.strftime(STAMP), "basis": basis, "window_hours": hours, "outages": known,
            "suspects": items, "considered": len(found),
            "note": "These are changes that happened shortly before, ranked by how close in time and how related they are. They are suspects, not proof."}


def _kind(row: sqlite3.Row) -> str:
    return (row["type_override"] or row["device_type"] or "device")


def impact(conn: sqlite3.Connection, device_id: int, now: datetime | None = None) -> dict[str, Any] | None:
    """What depends on a device: the devices below it level by level, the containers it hosts and the service checks on all of them. None when it does not exist."""
    devices, tree = load_hierarchy(conn)
    if device_id not in devices:
        return None
    kids = children_map(tree)
    info = {r["id"]: r for r in conn.execute("SELECT id, device_type, type_override, always_on, online FROM devices")}
    levels: list[list[dict[str, Any]]] = []
    seen = {device_id}
    frontier = [device_id]
    while frontier:
        nxt: list[int] = []
        for parent in frontier:
            for child in kids.get(parent, []):
                if child not in seen:
                    seen.add(child)
                    nxt.append(child)
        if not nxt:
            break
        levels.append([{"id": i, "name": device_name(devices[i]), "type": _kind(info[i]) if i in info else "device", "online": bool(devices[i]["online"]),
                        "always_on": bool(info[i]["always_on"]) if i in info else False, "children": len(kids.get(i, []))}
                       for i in sorted(nxt, key=lambda i: device_name(devices[i]).lower())])
        frontier = nxt
    below = seen - {device_id}
    hosts = seen
    marks = ",".join("?" * len(hosts))
    guests = [{"name": r["name"], "kind": r["kind"], "state": r["status"], "host": device_name(devices[r["host_device_id"]])}
              for r in conn.execute(f"SELECT name, kind, status, host_device_id FROM hypervisor_guests WHERE device_id IS NULL AND host_device_id IN ({marks}) AND kind NOT IN ('qemu', 'vm') ORDER BY LOWER(name)", tuple(hosts))]
    services = [{"name": r["name"], "device": device_name(devices[r["device_id"]]), "up": None if r["last_up"] is None else bool(r["last_up"])}
                for r in conn.execute(f"SELECT name, device_id, last_up FROM service_checks WHERE enabled = 1 AND device_id IN ({marks}) ORDER BY LOWER(name)", tuple(hosts))]
    flat = [d for level in levels for d in level]
    core = [d for d in flat if d["always_on"]]
    parent = tree.get(device_id)
    summary = _summary(device_name(devices[device_id]), len(flat), len(levels), core, guests, services)
    return {"device_id": device_id, "device": device_name(devices[device_id]), "type": _kind(info[device_id]) if device_id in info else "device",
            "plugged_into": device_name(devices[parent.parent_id]) if parent and parent.parent_id in devices else None,
            "total": len(flat), "depth": len(levels), "levels": levels, "guests": guests, "services": services, "always_on_count": len(core),
            "already_offline": sum(1 for d in flat if not d["online"]), "risk": "none" if not (flat or guests or services) else "high" if len(core) >= 3 or len(flat) >= 10 else "medium" if core or len(flat) >= 3 else "low",
            "summary": summary, "note": "Worked out from the network layout as Netlens knows it today; a device with a second way to the network may stay reachable."}


def _summary(name: str, devices: int, depth: int, core: list, guests: list, services: list) -> str:
    if not (devices or guests or services):
        return f"Nothing is known to depend on {name}: taking it offline should not affect another device."
    parts = []
    if devices:
        parts.append(f"{devices} device{'s' if devices != 1 else ''}" + (f" in {depth} level{'s' if depth != 1 else ''}" if depth > 1 else ""))
    if guests:
        parts.append(f"{len(guests)} container{'s' if len(guests) != 1 else ''} or app{'s' if len(guests) != 1 else ''}")
    if services:
        parts.append(f"{len(services)} service check{'s' if len(services) != 1 else ''}")
    text = f"If {name} goes down, " + ", ".join(parts[:-1]) + (" and " if len(parts) > 1 else "") + parts[-1] + " depend on it."
    if core:
        text += f" {len(core)} of the devices {'are' if len(core) != 1 else 'is'} marked always-on."
    return text
