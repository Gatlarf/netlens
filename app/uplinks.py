"""The internet connections of a gateway (multi-WAN): which exist, which are up, which carries the traffic, how the load is shared.

A topology plugin reports them per gateway (`uplinks`). Netlens keeps the latest state and tells what changes between two syncs: a connection that
goes down or comes back (`uplink_down`, `uplink_up`) and the traffic that moves to another connection (`uplink_failover`). Read-only.
"""
from __future__ import annotations

import sqlite3

from app.db import add_event, utcnow
from app.hierarchy import device_name
from app.plugins.enrich import device_lookup

MODE_TEXT = {"failover": "Failover: one connection carries the traffic, the others wait", "balance": "Load balancing: the traffic is shared over the connections", "single": "One connection"}


def record(conn: sqlite3.Connection, plugin_id: str, data: dict, now: str | None = None) -> dict:
    now = now or utcnow()
    by_mac, by_ip = device_lookup(conn)
    stored = events = 0
    for node in data.get("nodes", []):
        up = node.get("uplinks")
        device_id = next((by_mac[m] for m in node["macs"] if m in by_mac), None) or by_ip.get(node.get("ip") or "")
        if not up or device_id is None:
            continue
        before = {r["name"]: dict(r) for r in conn.execute("SELECT * FROM node_uplinks WHERE device_id = ? AND plugin_id = ?", (device_id, plugin_id))}
        conn.execute("DELETE FROM node_uplinks WHERE device_id = ? AND plugin_id = ?", (device_id, plugin_id))
        for c in up["connections"]:
            conn.execute("INSERT INTO node_uplinks (device_id, name, plugin_id, mode, interface, up, active, ip, gateway, weight, priority, latency_ms, loss_pct, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                         (device_id, c["name"], plugin_id, up["mode"], c["interface"], None if c["up"] is None else int(c["up"]), None if c["active"] is None else int(c["active"]),
                          c["ip"], c["gateway"], c["weight"], c["priority"], c["latency_ms"], c["loss_pct"], now))
            stored += 1
        if not before:
            continue                                   # the first sync tells nothing about a change
        who = node.get("name") or device_name({"id": device_id})
        for c in up["connections"]:
            old = before.get(c["name"])
            if old is None or c["up"] is None or old["up"] is None or bool(old["up"]) == c["up"]:
                continue
            add_event(conn, "uplink_up" if c["up"] else "uplink_down", f"{who}: {c['name']} {'is back' if c['up'] else 'went down'}", device_id=device_id, now=now, subject=f"uplink:{device_id}:{c['name']}")
            events += 1
        was = next((n for n, r in before.items() if r["active"]), None)
        now_active = next((c["name"] for c in up["connections"] if c["active"]), None)
        if up["mode"] != "balance" and was and now_active and was != now_active:
            add_event(conn, "uplink_failover", f"{who}: the traffic moved from {was} to {now_active}", device_id=device_id, now=now, subject=f"uplink:{device_id}")
            events += 1
    conn.commit()
    return {"connections": stored, "events": events}


def _shape(rows: list[dict]) -> dict:
    for r in rows:
        for k in ("up", "active"):
            r[k] = None if r[k] is None else bool(r[k])
    mode = next((r["mode"] for r in rows if r["mode"]), None)
    return {"mode": mode, "mode_text": MODE_TEXT.get(mode), "connections": rows}


def for_device(conn: sqlite3.Connection, device_id: int) -> dict:
    return _shape([dict(r) for r in conn.execute("SELECT * FROM node_uplinks WHERE device_id = ? ORDER BY priority IS NULL, priority, name", (device_id,))])


def attention(conn: sqlite3.Connection) -> list[dict]:
    """A connection that is down while the gateway has more than one, and the traffic running on a backup. Two queries, however many gateways there are."""
    grouped: dict[int, list[dict]] = {}
    for r in conn.execute("SELECT * FROM node_uplinks ORDER BY device_id, priority IS NULL, priority, name"):
        grouped.setdefault(r["device_id"], []).append(dict(r))
    if not grouped:
        return []
    names = {r["id"]: device_name(dict(r)) for r in conn.execute("SELECT id, custom_name, hostname, primary_ip FROM devices")}
    out = []
    for device_id, found in grouped.items():
        info = _shape(found)
        rows = info["connections"]
        if len(rows) < 2:
            continue
        name = names.get(device_id, f"device {device_id}")
        href = f"#/device/{device_id}/network/uplinks"
        down = [r["name"] for r in rows if r["up"] is False]
        if down:
            left = sum(1 for r in rows if r["up"])
            out.append({"level": "bad" if not left else "warn", "text": f"{name}: internet connection {', '.join(down)} is down" + (f" ({left} of {len(rows)} still up)" if left else " (no connection left)"), "href": href})
        elif info["mode"] == "failover":
            priorities = [x["priority"] for x in rows if x["priority"] is not None]
            backup = [r["name"] for r in rows if r["active"] and r["priority"] is not None and r["priority"] > min(priorities)]
            if backup:
                out.append({"level": "warn", "text": f"{name}: the traffic runs over the backup connection {backup[0]}", "href": href})
    return out
