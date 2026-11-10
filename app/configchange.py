"""Configuration change control: what changed in the settings of a router, firewall or controller between two syncs.

A topology plugin may report a node's settings as flat key/value pairs (output field `config`, see PLUGINS.md). Netlens keeps the latest set per device, and when a sync brings a
different one it stores the difference and raises `config_changed`. The first set is only a baseline. Read-only: Netlens never writes to a router, and a plugin sends no secrets
(the contract drops keys that look like one). A section the plugin could not read this time (`config_failed`) keeps its old values, so a failed read is not a change.
"""

from __future__ import annotations

import json
import logging
import sqlite3

from app.db import add_event, utcnow

log = logging.getLogger(__name__)

KEEP_CHANGES = 300                  # per device
KEEP_DAYS = 400
SHOWN_IN_EVENT = 4


def diff(old: dict[str, str], new: dict[str, str]) -> dict[str, list]:
    return {
        "added": [{"key": k, "value": new[k]} for k in sorted(new.keys() - old.keys())],
        "removed": [{"key": k, "value": old[k]} for k in sorted(old.keys() - new.keys())],
        "changed": [{"key": k, "before": old[k], "after": new[k]} for k in sorted(old.keys() & new.keys()) if old[k] != new[k]],
    }


def summary_of(name: str, d: dict[str, list]) -> str:
    parts = [f"{len(d[k])} {k}" for k in ("changed", "added", "removed") if d[k]]
    keys = [c["key"] for c in d["changed"]] + [c["key"] for c in d["added"]] + [c["key"] for c in d["removed"]]
    shown = ", ".join(keys[:SHOWN_IN_EVENT]) + (f" and {len(keys) - SHOWN_IN_EVENT} more" if len(keys) > SHOWN_IN_EVENT else "")
    return f"Configuration of {name} changed ({', '.join(parts)}): {shown}"


def _carry(old: dict[str, str], new: dict[str, str], failed: list[str]) -> dict[str, str]:
    """A section that could not be read keeps what it had: its keys start with the section name and a dot."""
    if not failed:
        return new
    keep = {k: v for k, v in old.items() if any(k == s or k.startswith(s + ".") for s in failed)}
    return {**{k: v for k, v in new.items() if k not in keep}, **keep}


def record(conn: sqlite3.Connection, plugin_id: str, data: dict, now: str | None = None) -> dict:
    """Store the settings a topology result carries and raise `config_changed` for each device whose settings differ from the last sync. Returns the counts."""
    from app.plugins.enrich import device_lookup

    now = now or utcnow()
    by_mac, by_ip = device_lookup(conn)
    out = {"devices": 0, "changed": 0}
    for node in data.get("nodes", []):
        items = node.get("config")
        if not items:
            continue
        device_id = next((by_mac[m] for m in node["macs"] if m in by_mac), None) or by_ip.get(node.get("ip") or "")
        if device_id is None:
            continue
        new = {i["key"]: i["value"] for i in items}
        row = conn.execute("SELECT items FROM config_state WHERE device_id = ?", (device_id,)).fetchone()
        try:
            old = json.loads(row["items"]) if row else None
        except ValueError:
            old = None
        if isinstance(old, dict):
            new = _carry(old, new, node.get("config_failed") or [])
            d = diff(old, new)
            if any(d.values()):
                name = node.get("name") or node["mac"]
                text = summary_of(name, d)
                conn.execute("INSERT INTO config_changes (device_id, ts, plugin_id, summary, changes) VALUES (?, ?, ?, ?, ?)", (device_id, now, plugin_id, text, json.dumps(d)))
                add_event(conn, "config_changed", text[:400], device_id=device_id, now=now)
                out["changed"] += 1
        conn.execute(
            "INSERT INTO config_state (device_id, plugin_id, items, updated) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(device_id) DO UPDATE SET plugin_id = excluded.plugin_id, items = excluded.items, updated = excluded.updated",
            (device_id, plugin_id, json.dumps(new), now),
        )
        conn.execute("DELETE FROM config_changes WHERE device_id = ? AND id NOT IN (SELECT id FROM config_changes WHERE device_id = ? ORDER BY id DESC LIMIT ?)", (device_id, device_id, KEEP_CHANGES))
        out["devices"] += 1
    conn.execute("DELETE FROM config_changes WHERE ts < ?", (_ago(now, KEEP_DAYS),))
    conn.commit()
    return out


def _ago(now: str, days: int) -> str:
    from datetime import datetime, timedelta

    return (datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ") - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def for_device(conn: sqlite3.Connection, device_id: int, limit: int = 50) -> dict | None:
    """What Netlens knows about a device's settings: when they were last read, how many there are and the latest changes. None when no plugin reports them."""
    row = conn.execute("SELECT plugin_id, items, updated FROM config_state WHERE device_id = ?", (device_id,)).fetchone()
    if not row:
        return None
    try:
        count = len(json.loads(row["items"]))
    except ValueError:
        count = 0
    changes = []
    for r in conn.execute("SELECT id, ts, plugin_id, summary, changes FROM config_changes WHERE device_id = ? ORDER BY id DESC LIMIT ?", (device_id, max(1, min(200, limit)))):
        try:
            detail = json.loads(r["changes"])
        except ValueError:
            detail = {}
        changes.append({"id": r["id"], "ts": r["ts"], "plugin": r["plugin_id"], "summary": r["summary"], **detail})
    return {"plugin": row["plugin_id"], "updated": row["updated"], "items": count, "changes": changes}


def recent(conn: sqlite3.Connection, days: int = 7, limit: int = 30) -> list[dict]:
    """The latest changes on every device, for Ask and the MCP tool."""
    since = _ago(utcnow(), max(1, min(400, days)))
    return [{"device_id": r["device_id"], "ts": r["ts"], "summary": r["summary"]}
            for r in conn.execute("SELECT device_id, ts, summary FROM config_changes WHERE ts >= ? ORDER BY id DESC LIMIT ?", (since, max(1, min(100, limit))))]
