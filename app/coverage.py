"""Monitoring coverage: which of the devices that matter have no eyes on them.

A device marked always-on or critical should be watched in more than one way: a quick check (every always-on device gets one), a service check on what it
offers (a web page, a port), a health monitor (processor, memory, disks) when it can be read, and a backup when it is a virtual machine or container.
This lists, per such device, what is missing, so a gap is found before an outage finds it. Nothing here changes anything.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

# kinds of devices a health monitor can read over SNMP or SSH, and a backup applies to guests only
HEALTH_TYPES = ("router", "switch", "ap", "server", "nas", "pc", "vm", "appliance", "ups")


def build(conn: sqlite3.Connection) -> dict[str, Any]:
    conn.row_factory = sqlite3.Row
    services = {r[0]: r[1] for r in conn.execute("SELECT device_id, COUNT(*) FROM service_checks WHERE enabled = 1 AND device_id IS NOT NULL GROUP BY device_id")}
    health = {r[0] for r in conn.execute("SELECT device_id FROM host_monitors")}
    guests = {r[0] for r in conn.execute("SELECT device_id FROM hypervisor_guests WHERE device_id IS NOT NULL AND kind IN ('qemu', 'vm', 'lxc', 'ct')")}
    backed = {r[0] for r in conn.execute("SELECT device_id FROM backup_targets WHERE device_id IS NOT NULL")}
    have_backup_plugin = conn.execute("SELECT COUNT(*) FROM backup_servers").fetchone()[0] > 0
    channels = 0
    try:
        from app.notify.channels import load_channels

        channels = sum(1 for c in load_channels(conn) if c.get("enabled", True))
    except Exception:  # noqa: BLE001 - the channel list is an extra
        channels = 0
    rows = []
    for d in conn.execute("SELECT id, COALESCE(custom_name, hostname, primary_ip) AS name, primary_ip, COALESCE(type_override, device_type, 'unknown') AS type, always_on, tier, notify_offline, online "
                          "FROM devices WHERE (always_on = 1 OR tier = 'critical') AND tier != 'low' ORDER BY LOWER(COALESCE(custom_name, hostname, primary_ip))"):
        missing: list[dict[str, str]] = []
        if not d["always_on"]:
            missing.append({"what": "quick check", "fix": "Mark it always-on (its Settings tab) so it gets a check every minute."})
        if d["id"] not in services:
            missing.append({"what": "service check", "fix": "Add a service check for what it offers (a web page or port) under Services."})
        if d["id"] not in health and d["type"] in HEALTH_TYPES:
            missing.append({"what": "health monitor", "fix": "Set up health monitoring on its page (SNMP or SSH) to watch processor, memory and disks."})
        if d["id"] in guests and have_backup_plugin and d["id"] not in backed:
            missing.append({"what": "backup", "fix": "No backup is known for this virtual machine or container: check the backup jobs."})
        if not d["notify_offline"]:
            missing.append({"what": "alert", "fix": "Alerts for this device going offline are switched off (its Settings tab)."})
        rows.append({"id": d["id"], "name": d["name"], "ip": d["primary_ip"], "type": d["type"], "tier": d["tier"], "missing": missing})
    gaps = [r for r in rows if r["missing"]]
    totals: dict[str, int] = {}
    for r in gaps:
        for m in r["missing"]:
            totals[m["what"]] = totals.get(m["what"], 0) + 1
    return {"watching": len(rows), "with_gaps": len(gaps), "complete": len(rows) - len(gaps), "gaps_by_kind": totals, "channels": channels,
            "no_channel": channels == 0, "devices": sorted(gaps, key=lambda r: (-(r["tier"] == "critical"), -len(r["missing"]), (r["name"] or "").lower()))}
