"""Host readings from a metrics store (plugin kind "metrics": Prometheus, VictoriaMetrics, Mimir ...).

A customer who already runs a metrics stack does not need a second agent on every host: the plugin asks the store for what it already has, and Netlens treats the
answer like the readings of any monitored host: graphs, limits, alerts, the dashboard, reports, Ask, the assistant and MCP. The plugin only reads; Netlens sends
nothing to the hosts. A reading may carry `samples` (the store's own history since the last sync), so the graphs are as dense as the store's, not as sparse as the
sync interval; a sample that is already stored is simply overwritten, so a repeated window does no harm.

A host is matched to a device by IP address, then MAC, then name. A device that is monitored another way (SNMP, SSH, WinRM, an agent, another plugin) is left alone:
two sources must not write the same readings.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any

from app import tsdb
from app.db import utcnow
from app.plugins.enrich import device_lookup, norm_mac

DEFAULT_INTERVAL_S = 300


def _names(conn: sqlite3.Connection) -> dict[str, int | None]:
    """device id by (short) host name; None for a name that two devices share, so it is never guessed."""
    found: dict[str, int | None] = {}
    for row in conn.execute("SELECT id, hostname, custom_name FROM devices ORDER BY id"):
        for raw in (row["hostname"], row["custom_name"]):
            name = (raw or "").strip().lower()
            for key in {name, name.split(".")[0]} - {""}:
                found[key] = row["id"] if key not in found or found[key] == row["id"] else None
    return found


def apply_metrics(conn: sqlite3.Connection, plugin_id: str, data: dict, config: dict[str, Any] | None = None) -> dict[str, int]:
    """Record the readings of every host the plugin reported. Returns {"hosts", "matched", "readings", "samples", "skipped", "unmatched"}."""
    from app.hostmetrics import service as hm

    now = utcnow()
    stamp = int(datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
    by_mac, by_ip = device_lookup(conn)
    by_name = _names(conn)
    store = tsdb.for_conn(conn)
    summary = {"hosts": len(data.get("hosts", [])), "matched": 0, "readings": 0, "samples": 0, "skipped": 0, "unmatched": 0}
    claimed: set[int] = set()
    for host in data.get("hosts", []):
        device_id = by_ip.get(host.get("ip") or "")
        if device_id is None:
            device_id = next((by_mac[m] for m in (norm_mac(x) for x in host.get("macs", [])) if m in by_mac), None)
        if device_id is None:
            for key in (host["name"].strip().lower(), host["name"].strip().lower().split(".")[0]):
                if by_name.get(key) is not None:
                    device_id = by_name[key]
                    break
        if device_id is None:
            summary["unmatched"] += 1
            continue
        if device_id in claimed:
            continue                                       # two entries of the store for one device: the first wins
        claimed.add(device_id)
        row = hm.get_monitor(conn, device_id)
        if row is not None and not (row["method"] == "plugin" and row["source"] == plugin_id):
            summary["skipped"] += 1                        # monitored another way: not mixed
            continue
        points: list[tuple] = []
        bulk: list[tuple] = []
        for r in host["readings"]:
            for ts, value in r["samples"]:
                bulk.append((ts, "device", device_id, r["metric"], value, r["label"], r["unit"]))
            latest = r["value"] if r["value"] is not None else r["samples"][-1][1]
            if r["value"] is not None:
                bulk.append((stamp, "device", device_id, r["metric"], r["value"], r["label"], r["unit"]))
            points.append((r["metric"], r["label"], latest, r["unit"]))
        if not points:
            continue
        if row is None:
            conn.execute("INSERT INTO host_monitors (device_id, method, address, port, credential, interval_s, groups, alerts, enabled, created, source) "
                         "VALUES (?, 'plugin', ?, 0, '', ?, '[]', 1, 1, ?, ?)", (device_id, host.get("ip") or "", DEFAULT_INTERVAL_S, now, plugin_id))
            row = hm.get_monitor(conn, device_id)
        if store is not None and bulk:
            store.record_bulk(bulk)
        conn.execute("UPDATE host_monitors SET last_ts = ?, last_ok = 1, last_error = NULL, since = COALESCE(since, ?) WHERE id = ?", (now, now, row["id"]))
        if row["alerts"]:
            name = conn.execute("SELECT COALESCE(custom_name, hostname, primary_ip) AS n FROM devices WHERE id = ?", (device_id,)).fetchone()
            hm.evaluate(conn, row["id"], device_id, name["n"] if name and name["n"] else f"device {device_id}", points, now)
        summary["matched"] += 1
        summary["readings"] += len(points)
        summary["samples"] += len(bulk)
    conn.commit()
    return summary
