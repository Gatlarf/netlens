"""Should a Wi-Fi device that does not move be locked to one access point? (advice only: Netlens never changes a controller.)

A device that stays where it is but keeps hopping between access points usually sits between two of them and drops out at every hop. From the signal
history (``wifi_samples``) and the outages Netlens saw, this names the access point that served it best and says so when the device looks fixed in place.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

STAMP = "%Y-%m-%dT%H:%M:%SZ"
FIXED = {"server", "nas", "printer", "tv", "camera", "iot", "speaker", "console", "appliance", "router", "switch", "ap", "access_point", "hub"}
MIN_SAMPLES = 10          # per access point, before its average means something
MIN_GAIN_DB = 4           # how much better the best access point must be than the one it is compared with
MIN_ROAMS = 2


def advice(conn: sqlite3.Connection, device_id: int, days: int = 7, now: datetime | None = None) -> dict[str, Any] | None:
    """None when there is nothing to say (not a Wi-Fi device, one access point only, or no real difference between them)."""
    now = now or datetime.now(timezone.utc)
    since = (now - timedelta(days=days)).strftime(STAMP)
    dev = conn.execute("SELECT COALESCE(type_override, device_type) AS kind, always_on FROM devices WHERE id = ?", (device_id,)).fetchone()
    if dev is None:
        return None
    samples = conn.execute("SELECT ts, node, band, rssi FROM wifi_samples WHERE device_id = ? AND ts >= ? AND node IS NOT NULL ORDER BY id", (device_id, since)).fetchall()
    nodes: dict[str, dict[str, Any]] = {}
    for s in samples:
        n = nodes.setdefault(s["node"], {"node": s["node"], "samples": 0, "rssi": [], "bands": {}, "outages": 0})
        n["samples"] += 1
        if s["rssi"] is not None:
            n["rssi"].append(s["rssi"])
        if s["band"]:
            n["bands"][s["band"]] = n["bands"].get(s["band"], 0) + 1
    if len(nodes) < 2:
        return None
    roams = conn.execute("SELECT COUNT(*) FROM events WHERE device_id = ? AND kind = 'wifi_roamed' AND ts >= ?", (device_id, since)).fetchone()[0]
    # an outage belongs to the access point the device was last seen on
    for r in conn.execute("SELECT ts FROM events WHERE device_id = ? AND kind = 'device_offline' AND ts >= ?", (device_id, since)):
        before = [s for s in samples if s["ts"] <= r["ts"]]
        if before and before[-1]["node"] in nodes:
            nodes[before[-1]["node"]]["outages"] += 1
    total = sum(n["samples"] for n in nodes.values())
    rows = []
    for n in nodes.values():
        avg = round(sum(n["rssi"]) / len(n["rssi"])) if n["rssi"] else None
        band = max(n["bands"], key=n["bands"].get) if n["bands"] else None
        rows.append({"node": n["node"], "share_percent": round(100 * n["samples"] / total), "samples": n["samples"], "average_dbm": avg, "band": band, "outages": n["outages"]})
    rows.sort(key=lambda r: -r["share_percent"])
    fixed = bool(dev["always_on"]) or (dev["kind"] or "") in FIXED
    out: dict[str, Any] = {"looks_fixed": fixed, "moves_between_access_points": roams, "access_points": rows, "days": days, "suggestion": None}
    solid = [r for r in rows if r["average_dbm"] is not None and r["samples"] >= MIN_SAMPLES]
    if not fixed or roams < MIN_ROAMS or len(solid) < 2:
        return out if roams >= MIN_ROAMS else None
    best = max(solid, key=lambda r: r["average_dbm"])
    worst = min((r for r in solid if r is not best), key=lambda r: r["average_dbm"])
    if best["average_dbm"] - worst["average_dbm"] < MIN_GAIN_DB:
        return out
    where = f" on {best['band']}" if best["band"] else ""
    out["best"] = best["node"]
    out["suggestion"] = (f"It moved between access points {roams} times in {days} days although it looks like it stays in place. Its signal was best on {best['node']}{where} "
                         f"({best['average_dbm']} dBm on average, against {worst['average_dbm']} dBm on {worst['node']}). Consider locking it to {best['node']} in the Wi-Fi controller, "
                         f"if the device is physically nearest to it. Netlens only advises; it does not change the controller.")
    return out
