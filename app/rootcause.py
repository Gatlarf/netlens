"""Find the one cause behind many alerts: when a device is down, the devices that sit behind it are unreachable, not broken.

A switch that fails takes every device plugged into it with it, a hypervisor takes its guests. Netlens knows which device
depends on which (the network hierarchy), so a message can say "sw-garden is offline; 4 devices behind it cannot be
reached" instead of listing five offline devices as separate problems. Only the messages are grouped: every event is still
recorded, and Home Assistant and the Prometheus numbers see the individual devices.
"""

from __future__ import annotations

import sqlite3

from app.db import Error as db_Error

from app.hierarchy import ancestors, device_name, load_hierarchy

FOLLOWS = {"device_offline", "service_down", "metric_warning", "metric_critical"}
SHOWN_NAMES = 5


def collapse(conn: sqlite3.Connection, events: list[dict]) -> list[dict]:
    """The events to announce: the ones that are a cause, plus one summary line per offline device that hides others."""
    candidates = [e for e in events if e["kind"] in FOLLOWS and e.get("device_id") is not None]
    if not candidates:
        return events
    try:
        devices, hierarchy = load_hierarchy(conn)
    except db_Error:
        return events
    hidden: dict[int, list[dict]] = {}
    kept_ids = set()
    for e in candidates:
        chain = ancestors(hierarchy, e["device_id"])
        root = None
        for parent in reversed(chain):       # the highest device on the way up that is offline is the cause
            d = devices.get(parent)
            if d is not None and not d["online"]:
                root = parent
                break
        if root is not None:
            hidden.setdefault(root, []).append(e)
        else:
            kept_ids.add(e["id"])
    if not hidden:
        return events
    hidden_ids = {e["id"] for group in hidden.values() for e in group}
    out = [e for e in events if e["id"] not in hidden_ids]
    for root, group in hidden.items():
        names = sorted({device_name(devices[e["device_id"]]) for e in group})
        shown = ", ".join(names[:SHOWN_NAMES]) + (f" and {len(names) - SHOWN_NAMES} more" if len(names) > SHOWN_NAMES else "")
        parent = devices[root]
        out.append({
            "id": max(e["id"] for e in group), "ts": group[-1]["ts"], "kind": "unreachable", "device_id": root, "detail": None, "maintenance": None,
            "name": device_name(parent), "ip": parent.get("primary_ip"), "mac": parent.get("mac"), "vendor": parent.get("vendor"), "trusted": 1, "notify_offline": 1,
            "hidden_names": names, "text": f"{device_name(parent)} is offline, so {len(names)} device{'s' if len(names) != 1 else ''} behind it cannot be reached: {shown}",
        })
    return sorted(out, key=lambda e: e["id"])


def unreachable(conn: sqlite3.Connection) -> dict[int, int]:
    """Offline devices that sit behind another offline device: {device id: id of the highest offline device above it}. They are unreachable, not broken."""
    try:
        devices, hierarchy = load_hierarchy(conn)
    except db_Error:
        return {}
    out: dict[int, int] = {}
    for did, d in devices.items():
        if d["online"]:
            continue
        for parent in reversed(ancestors(hierarchy, did)):
            p = devices.get(parent)
            if p is not None and not p["online"]:
                out[did] = parent
                break
    return out
