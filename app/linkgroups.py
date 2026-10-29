"""Link groups: the switch ports that carry one bond (NIC teaming, LACP) of a host.

A bond shows up as one MAC address on one address, so a scan cannot see that one of its links went down: the host stays online with less
redundancy. The owner tells Netlens which ports of a switch belong to the host's bond; the state of those ports comes from the switch plugin
(`switch_ports`), and Netlens raises `link_degraded` when a member goes down (or all of them) and `link_recovered` when all are up again.

Status: `ok` (every member has a link), `degraded` (some have), `down` (none has), `unknown` (a port is not reported any more, or the switch
has not reported for a while: nothing is claimed).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from app.db import add_event, insert_id, utcnow

MIN_PORTS = 2
MAX_PORTS = 16
STALE = timedelta(minutes=30)          # the switch has not reported for this long: the state of its ports is not known
RANK = {"ok": 0, "degraded": 1, "down": 2}


class LinkGroupError(ValueError):
    """A sentence for the person who set the group up."""


def _ts(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _ports(raw: str | None) -> list[int]:
    try:
        return [int(p) for p in json.loads(raw or "[]")]
    except (ValueError, TypeError):
        return []


def members(conn: sqlite3.Connection, group: sqlite3.Row, now: str | None = None) -> list[dict[str, Any]]:
    limit = _ts(now or utcnow()) - STALE
    out = []
    for number in _ports(group["ports"]):
        r = conn.execute("SELECT name, enabled, up, speed_mbps, updated FROM switch_ports WHERE device_id = ? AND port = ?", (group["switch_device_id"], number)).fetchone()
        if r is None:
            out.append({"port": number, "name": None, "known": False, "up": False, "enabled": None, "speed_mbps": None})
        else:
            out.append({"port": number, "name": r["name"], "known": _ts(r["updated"]) >= limit, "up": bool(r["up"]), "enabled": bool(r["enabled"]), "speed_mbps": r["speed_mbps"]})
    return out


def status_of(member_list: list[dict[str, Any]]) -> str:
    if not member_list or not all(m["known"] for m in member_list):
        return "unknown"
    up = sum(1 for m in member_list if m["up"])
    return "ok" if up == len(member_list) else "down" if up == 0 else "degraded"


def _label(m: dict[str, Any]) -> str:
    return f"port {m['port']}" + (f" ({m['name']})" if m.get("name") else "")


def describe(group: sqlite3.Row, member_list: list[dict[str, Any]], status: str) -> str:
    up = [m for m in member_list if m["up"]]
    down = [_label(m) for m in member_list if not m["up"]]
    if status == "down":
        return f"{group['name']}: no link on any of its {len(member_list)} ports ({', '.join(down)})"
    return f"{group['name']}: {len(up)} of {len(member_list)} links up; no link on {', '.join(down)}"


def evaluate(conn: sqlite3.Connection, now: str | None = None) -> int:
    """Work out every group's status after the switch ports were updated; returns the number of events raised."""
    now = now or utcnow()
    raised = 0
    for g in conn.execute("SELECT * FROM link_groups").fetchall():
        member_list = members(conn, g, now)
        status = status_of(member_list)
        before = g["status"]
        if status == before:
            continue
        conn.execute("UPDATE link_groups SET status = ?, status_since = ? WHERE id = ?", (status, now, g["id"]))
        if status in RANK and before in RANK:                               # unknown on either side: nothing was claimed before or can be now
            subject = f"linkgroup:{g['id']}"
            if RANK[status] > RANK[before]:
                add_event(conn, "link_degraded", describe(g, member_list, status), device_id=g["host_device_id"], now=now, subject=subject)
                raised += 1
            elif status == "ok":
                add_event(conn, "link_recovered", f"{g['name']}: all {len(member_list)} links are up again", device_id=g["host_device_id"], now=now, subject=subject)
                raised += 1
    conn.commit()
    return raised


def _names(conn: sqlite3.Connection) -> dict[int, str]:
    return {r["id"]: r["custom_name"] or r["hostname"] or r["primary_ip"] or f"device {r['id']}" for r in conn.execute("SELECT id, custom_name, hostname, primary_ip FROM devices")}


def listing(conn: sqlite3.Connection, device_id: int | None = None, now: str | None = None) -> list[dict[str, Any]]:
    """The groups with the live state of their members; `device_id` limits it to the groups a device is the host or the switch of."""
    names, now = _names(conn), now or utcnow()
    out = []
    for g in conn.execute("SELECT * FROM link_groups ORDER BY LOWER(name), id").fetchall():
        if device_id is not None and device_id not in (g["host_device_id"], g["switch_device_id"]):
            continue
        member_list = members(conn, g, now)
        status = status_of(member_list)
        out.append({"id": g["id"], "name": g["name"], "host_device_id": g["host_device_id"], "host": names.get(g["host_device_id"]),
                    "switch_device_id": g["switch_device_id"], "switch": names.get(g["switch_device_id"]), "ports": member_list, "status": status,
                    "up": sum(1 for m in member_list if m["up"]), "total": len(member_list), "since": g["status_since"]})
    return out


def _check(conn: sqlite3.Connection, host_id: int, switch_id: int, ports: list[int], ignore: int | None = None) -> list[int]:
    if conn.execute("SELECT 1 FROM devices WHERE id = ?", (host_id,)).fetchone() is None:
        raise LinkGroupError("no such host")
    if host_id == switch_id:
        raise LinkGroupError("the host and the switch must be different devices")
    unique = sorted(set(int(p) for p in ports))
    if not MIN_PORTS <= len(unique) <= MAX_PORTS:
        raise LinkGroupError(f"a bond has {MIN_PORTS} to {MAX_PORTS} ports")
    known = {r["port"] for r in conn.execute("SELECT port FROM switch_ports WHERE device_id = ?", (switch_id,))}
    if not known:
        raise LinkGroupError("this device reports no switch ports (a switch plugin has to read it first)")
    missing = [p for p in unique if p not in known]
    if missing:
        raise LinkGroupError(f"the switch does not report port {', '.join(str(p) for p in missing)}")
    for g in conn.execute("SELECT id, name, ports FROM link_groups WHERE switch_device_id = ?", (switch_id,)):
        if g["id"] != ignore and set(_ports(g["ports"])) & set(unique):
            raise LinkGroupError(f"a port in this list already belongs to {g['name']!r}")
    return unique


def _name(text: str) -> str:
    name = " ".join((text or "").split())
    if not name or len(name) > 60:
        raise LinkGroupError("give the group a name of 1 to 60 characters")
    return name


def create(conn: sqlite3.Connection, name: str, host_id: int, switch_id: int, ports: list[int]) -> int:
    name, unique = _name(name), _check(conn, host_id, switch_id, ports)
    group_id = insert_id(conn, "INSERT INTO link_groups (name, host_device_id, switch_device_id, ports, created) VALUES (?, ?, ?, ?, ?)",
                         (name, host_id, switch_id, json.dumps(unique), utcnow()))
    conn.commit()
    evaluate(conn)                       # the first reading, which never raises an event
    return int(group_id)


def update(conn: sqlite3.Connection, group_id: int, name: str | None = None, ports: list[int] | None = None) -> None:
    g = conn.execute("SELECT * FROM link_groups WHERE id = ?", (group_id,)).fetchone()
    if g is None:
        raise LinkGroupError("no such group")
    if name is not None:
        conn.execute("UPDATE link_groups SET name = ? WHERE id = ?", (_name(name), group_id))
    if ports is not None:
        unique = _check(conn, g["host_device_id"], g["switch_device_id"], ports, ignore=group_id)
        conn.execute("UPDATE link_groups SET ports = ?, status = NULL, status_since = NULL WHERE id = ?", (json.dumps(unique), group_id))
    conn.commit()
    evaluate(conn)


def delete(conn: sqlite3.Connection, group_id: int) -> bool:
    cur = conn.execute("DELETE FROM link_groups WHERE id = ?", (group_id,))
    conn.commit()
    return cur.rowcount > 0


def summary(conn: sqlite3.Connection, now: str | None = None) -> dict[str, Any]:
    """The few numbers of the dashboard (cheap: one pass over the groups)."""
    counts = {"groups": 0, "degraded": 0, "down": 0}
    first = None
    for g in conn.execute("SELECT * FROM link_groups").fetchall():
        counts["groups"] += 1
        status = status_of(members(conn, g, now))
        if status in ("degraded", "down"):
            counts[status] += 1
            first = first if first is not None else g["host_device_id"]
    counts["first_host"] = first
    return counts
