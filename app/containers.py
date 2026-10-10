"""What plugins report about their guests (VMs, containers, apps): events when something changes, and the numbers for
Statistics / Prometheus / Home Assistant.

A guest has a kind (qemu, lxc, container, app), a status and `details` (health, restarts, published ports, resources, update
available ...), see app/plugins/contract.py. Events are raised on a *change* between two syncs, so a guest that stays unhealthy
is reported once. Containers get health events; every other guest gets started / stopped / update events.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

RESTART_JUMP = 3          # this many restarts between two syncs = a restart loop
STOPPED = ("exited", "dead")
GONE = ("stopped", "shutoff", "off", "shutdown", "exited", "dead", "crashed")   # a guest that is no longer running
OLD_IMAGE_DAYS = 365
KIND_NAMES = {"qemu": "virtual machine", "vm": "virtual machine", "lxc": "container (LXC)", "container": "container", "app": "app"}


def _details(raw: Any) -> dict:
    try:
        value = json.loads(raw or "{}") if isinstance(raw, str) else raw
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def previous_state(conn: sqlite3.Connection, plugin_id: str) -> dict[str, dict]:
    """What the last sync knew: guest id -> {status, health, restarts}."""
    out = {}
    for r in conn.execute("SELECT guest_id, status, details FROM hypervisor_guests WHERE plugin_id = ?", (plugin_id,)):
        d = _details(r["details"])
        out[r["guest_id"]] = {"status": r["status"], "health": d.get("health"), "restarts": d.get("restarts"), "update": bool(d.get("update_available"))}
    return out


def changes(previous: dict[str, dict], guests: list[dict], host_names: dict[str, str]) -> list[tuple[str, str, int | None]]:
    """(event kind, text, device id) for every container that got worse since the last sync. Nothing on the first sync."""
    if not previous:
        return []
    out = []
    for g in guests:
        if g["id"] not in previous:
            continue
        before, d = previous[g["id"]], g.get("details") or {}
        where = f"{g['name']} on {host_names.get(g.get('host_id'), g.get('host_id') or 'its host')}"
        device = g.get("device_id") or g.get("host_device_id")
        if g.get("kind") != "container":
            noun = KIND_NAMES.get(g.get("kind"), "guest")
            if before["status"] == "running" and g["status"] in GONE:
                out.append(("guest_stopped", f"The {noun} {where} stopped", device))
            elif before["status"] != "running" and g["status"] == "running" and before["status"] in GONE:
                out.append(("guest_started", f"The {noun} {where} started", device))
            if d.get("update_available") and not before.get("update"):
                out.append(("guest_update_available", f"An update is available for the {noun} {where}" + (f" ({d['version']})" if d.get("version") else ""), device))
            continue
        if d.get("health") == "unhealthy" and before.get("health") != "unhealthy":
            out.append(("container_unhealthy", f"{where}: the health check is failing", device))
        jumped = (d.get("restarts") or 0) - (before.get("restarts") or 0) >= RESTART_JUMP
        if (g["status"] == "restarting" and before["status"] != "restarting") or jumped:
            n = d.get("restarts")
            out.append(("container_restarting", f"{where} keeps restarting" + (f" ({n} restarts)" if n else ""), device))
        elif before["status"] == "running" and g["status"] in STOPPED and d.get("exit_code") not in (0, None):
            out.append(("container_stopped", f"{where} stopped with exit code {d['exit_code']}", device))
    return out


def summary(conn: sqlite3.Connection) -> dict[str, Any]:
    """Container numbers over every plugin that reports containers."""
    total = running = stopped = restarting = unhealthy = exposed = 0
    hosts: set[tuple[str, str]] = set()
    problems = []
    for r in conn.execute(
        "SELECT g.plugin_id, g.guest_id, g.name, g.status, g.host_name, g.details, g.device_id, g.host_device_id FROM hypervisor_guests g WHERE g.kind = 'container' ORDER BY g.name"
    ):
        d = _details(r["details"])
        total += 1
        hosts.add((r["plugin_id"], r["host_name"]))
        if r["status"] == "running":
            running += 1
            exposed += 1 if d.get("exposed") else 0
        elif r["status"] == "restarting":
            restarting += 1
        elif r["status"] in STOPPED or r["status"] in ("created", "paused"):
            stopped += 1
        sick = []
        if r["status"] == "restarting":
            sick.append("restarting")
        if d.get("health") == "unhealthy":
            unhealthy += 1
            sick.append("unhealthy")
        if sick:
            problems.append({"name": r["name"], "host": r["host_name"], "problem": ", ".join(sick), "restarts": d.get("restarts"), "device_id": r["device_id"] or r["host_device_id"]})
    return {"total": total, "running": running, "stopped": stopped, "restarting": restarting, "unhealthy": unhealthy, "exposed": exposed,
            "hosts": len(hosts), "problems": problems[:20]}


def _age_days(iso: str | None, now: float | None = None) -> int | None:
    import calendar
    import time
    from datetime import datetime
    try:
        then = calendar.timegm(datetime.strptime(iso or "", "%Y-%m-%dT%H:%M:%SZ").timetuple())
    except ValueError:
        return None
    return int(((now if now is not None else time.time()) - then) // 86400)


def guest_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    """Every guest over every plugin: counts by kind, updates available, old container images, and what needs attention."""
    by_kind: dict[str, dict[str, int]] = {}
    total = running = stopped = updates = old = 0
    hosts: set[tuple[str, str]] = set()
    attention = []
    for r in conn.execute("SELECT plugin_id, name, kind, status, host_name, details, device_id, host_device_id FROM hypervisor_guests ORDER BY name"):
        d = _details(r["details"])
        kind = "vm" if r["kind"] in ("qemu", "vm") else r["kind"]
        k = by_kind.setdefault(kind, {"total": 0, "running": 0})
        k["total"] += 1
        total += 1
        hosts.add((r["plugin_id"], r["host_name"]))
        if r["status"] == "running":
            running += 1
            k["running"] += 1
        elif r["status"] in GONE or r["status"] in ("created", "paused"):
            stopped += 1
        link = r["device_id"] or r["host_device_id"]
        if d.get("update_available"):
            updates += 1
            attention.append({"name": r["name"], "host": r["host_name"], "why": "update available" + (f" ({d['version']})" if d.get("version") else ""), "device_id": link})
        days = _age_days(d.get("image_created"))
        if days is not None and days > OLD_IMAGE_DAYS and r["status"] == "running":
            old += 1
            attention.append({"name": r["name"], "host": r["host_name"], "why": f"image built {days // 365} year(s) ago", "device_id": link})
    return {"total": total, "running": running, "stopped": stopped, "hosts": len(hosts), "by_kind": by_kind,
            "update_available": updates, "old_images": old, "attention": attention[:30]}
