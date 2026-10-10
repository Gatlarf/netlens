"""Containers reported by a plugin (the Docker plugin): events when one gets sick, and the numbers for Statistics / Prometheus / Home Assistant.

A plugin reports containers as guests of kind "container" with `details` (health, restarts, published ports ...), see
app/plugins/contract.py. Events are raised on a *change* between two syncs, so a container that stays unhealthy is reported once.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

RESTART_JUMP = 3          # this many restarts between two syncs = a restart loop
STOPPED = ("exited", "dead")


def _details(raw: Any) -> dict:
    try:
        value = json.loads(raw or "{}") if isinstance(raw, str) else raw
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def previous_state(conn: sqlite3.Connection, plugin_id: str) -> dict[str, dict]:
    """What the last sync knew: guest id -> {status, health, restarts}."""
    out = {}
    for r in conn.execute("SELECT guest_id, status, details FROM hypervisor_guests WHERE plugin_id = ? AND kind = 'container'", (plugin_id,)):
        d = _details(r["details"])
        out[r["guest_id"]] = {"status": r["status"], "health": d.get("health"), "restarts": d.get("restarts")}
    return out


def changes(previous: dict[str, dict], guests: list[dict], host_names: dict[str, str]) -> list[tuple[str, str, int | None]]:
    """(event kind, text, device id) for every container that got worse since the last sync. Nothing on the first sync."""
    if not previous:
        return []
    out = []
    for g in guests:
        if g.get("kind") != "container" or g["id"] not in previous:
            continue
        before, d = previous[g["id"]], g.get("details") or {}
        where = f"{g['name']} on {host_names.get(g.get('host_id'), g.get('host_id') or 'its host')}"
        device = g.get("device_id") or g.get("host_device_id")
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
