"""Network hierarchy: which device sits below which.

Every device gets at most one parent. The parent comes from, in order of priority:

  manual    the user chose it on the device page (or chose "no parent")
  hypervisor  the guest runs on this host (exact, reported by a hypervisor plugin such as Proxmox)
  uplink    a switch / mesh node the device is connected to (reported by a topology plugin such as the ASUS router)
  guess     a heuristic "probably runs on this hypervisor" (only when exactly one hypervisor exists)
  route     the next router on the traceroute path to the device
  gateway   the default gateway

Relations point from the dependent device (src) to the device it depends on (dst), so the parent
of a device is the dst of its strongest outgoing relation. The result is always a forest: an
assignment that would create a loop is skipped in favour of the next candidate.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any, Iterable

# lower number = stronger
SOURCE_RANK = {"manual": 0, "hypervisor": 1, "uplink": 2, "guess": 3, "route": 4, "gateway": 5}

SOURCE_TEXT = {
    "manual": "Set manually",
    "hypervisor": "Runs on this hypervisor host",
    "uplink": "Connected to this network device",
    "route": "Next router on the path (traceroute)",
    "gateway": "Default gateway",
    "guess": "Probably the hypervisor it runs on (guess)",
}


@dataclass(frozen=True)
class Parent:
    parent_id: int | None
    source: str  # key of SOURCE_RANK, or "none" when there is no parent
    reason: str
    locked: bool = False  # True when the user decided (including "no parent")


def _classify(rel: dict) -> tuple[str, str] | None:
    """(source, reason) of a relation as a parent link, or None if it is not hierarchical."""
    kind, source = rel["kind"], rel.get("source")
    plugin = source[len("plugin:"):] if isinstance(source, str) and source.startswith("plugin:") else None
    if kind == "host-of":
        if plugin:
            return "hypervisor", f"{SOURCE_TEXT['hypervisor']} ({plugin})"
        return "guess", SOURCE_TEXT["guess"]
    if kind == "uplink":
        label = plugin or source
        return "uplink", f"{SOURCE_TEXT['uplink']} ({label})" if label else SOURCE_TEXT["uplink"]
    if kind == "route":
        return "route", SOURCE_TEXT["route"]
    if kind == "gateway":
        reason = SOURCE_TEXT["gateway"] + (" (guessed)" if source == "heuristic" else "")
        return "gateway", reason
    return None  # manual links and services say nothing about who depends on whom


def build_hierarchy(devices: Iterable[dict], relations: Iterable[dict]) -> dict[int, Parent]:
    """Choose the parent of every device.

    devices:   dicts with id, parent_mode ('auto'|'none'|'device') and parent_device_id
    relations: dicts with src_id, dst_id, kind, source, confidence (hidden/deleted ones excluded)
    """
    devs = {d["id"]: d for d in devices}
    result: dict[int, Parent] = {}
    parent_of: dict[int, int] = {}  # accepted assignments, used for loop checks

    def creates_loop(child: int, parent: int) -> bool:
        seen = set()
        node: int | None = parent
        while node is not None and node not in seen:
            if node == child:
                return True
            seen.add(node)
            node = parent_of.get(node)
        return False

    # 1. what the user decided is final
    for dev_id, d in devs.items():
        mode = d.get("parent_mode") or "auto"
        if mode == "none":
            result[dev_id] = Parent(None, "manual", "Top level (set manually)", locked=True)
        elif mode == "device":
            pid = d.get("parent_device_id")
            if pid in devs and pid != dev_id and not creates_loop(dev_id, pid):
                parent_of[dev_id] = pid
                result[dev_id] = Parent(pid, "manual", SOURCE_TEXT["manual"], locked=True)
            # a chosen parent that no longer exists falls back to automatic

    # 2. derived candidates, strongest first
    candidates: dict[int, list[tuple[int, float, int, str, str]]] = {}
    for rel in relations:
        child, parent = rel["src_id"], rel["dst_id"]
        if child == parent or child not in devs or parent not in devs or child in result:
            continue
        classified = _classify(rel)
        if classified is None:
            continue
        source, reason = classified
        candidates.setdefault(child, []).append(
            (SOURCE_RANK[source], -float(rel.get("confidence") or 0), parent, source, reason)
        )
    for options in candidates.values():
        options.sort()

    # children whose best candidate is strongest are placed first, so strong links win loop conflicts
    for child in sorted(candidates, key=lambda c: (candidates[c][0][0], c)):
        for _, _, parent, source, reason in candidates[child]:
            if not creates_loop(child, parent):
                parent_of[child] = parent
                result[child] = Parent(parent, source, reason)
                break

    for dev_id in devs:
        result.setdefault(dev_id, Parent(None, "none", "No parent known"))
    return result


def children_map(hierarchy: dict[int, Parent]) -> dict[int, list[int]]:
    out: dict[int, list[int]] = {}
    for dev_id, info in sorted(hierarchy.items()):
        if info.parent_id is not None:
            out.setdefault(info.parent_id, []).append(dev_id)
    return out


def ancestors(hierarchy: dict[int, Parent], dev_id: int) -> list[int]:
    """Parents from the nearest to the top."""
    chain: list[int] = []
    seen = {dev_id}
    node = hierarchy.get(dev_id)
    while node is not None and node.parent_id is not None and node.parent_id not in seen:
        chain.append(node.parent_id)
        seen.add(node.parent_id)
        node = hierarchy.get(node.parent_id)
    return chain


def descendants(hierarchy: dict[int, Parent], dev_id: int) -> set[int]:
    kids = children_map(hierarchy)
    found: set[int] = set()
    stack = list(kids.get(dev_id, []))
    while stack:
        node = stack.pop()
        if node in found:
            continue
        found.add(node)
        stack.extend(kids.get(node, []))
    return found


def would_loop(hierarchy: dict[int, Parent], dev_id: int, new_parent: int) -> bool:
    """True if making `new_parent` the parent of `dev_id` would put a device below itself."""
    return new_parent == dev_id or dev_id in ancestors(hierarchy, new_parent)


# ---- database loading --------------------------------------------------------------------

def load_inputs(conn: sqlite3.Connection) -> tuple[list[dict], list[dict]]:
    conn.row_factory = sqlite3.Row
    devices = [
        dict(r)
        for r in conn.execute(
            "SELECT id, mac, primary_ip, hostname, custom_name, vendor, device_type, type_override, online, "
            "parent_mode, parent_device_id FROM devices ORDER BY id"
        )
    ]
    relations = [
        dict(r)
        for r in conn.execute(
            "SELECT src_id, dst_id, kind, source, confidence FROM relations WHERE manual >= 0"
        )
    ]
    return devices, relations


def device_name(d: dict) -> str:
    return d.get("custom_name") or d.get("hostname") or d.get("primary_ip") or f"device {d['id']}"


def load_hierarchy(conn: sqlite3.Connection) -> tuple[dict[int, dict], dict[int, Parent]]:
    """(devices by id, parent of every device)"""
    devices, relations = load_inputs(conn)
    return {d["id"]: d for d in devices}, build_hierarchy(devices, relations)


def hierarchy_payload(conn: sqlite3.Connection) -> dict[str, Any]:
    """Flat node list for the UI (it builds the tree from parent_id)."""
    devs, hierarchy = load_hierarchy(conn)
    kids = children_map(hierarchy)

    def depth(dev_id: int) -> int:
        return len(ancestors(hierarchy, dev_id))

    nodes = []
    for dev_id, d in sorted(devs.items(), key=lambda kv: device_name(kv[1]).lower()):
        info = hierarchy[dev_id]
        nodes.append({
            "id": dev_id,
            "name": device_name(d),
            "ip": d["primary_ip"],
            "type": d["type_override"] or d["device_type"] or "unknown",
            "online": bool(d["online"]),
            "parent_id": info.parent_id,
            "source": info.source,
            "reason": info.reason,
            "locked": info.locked,
            "children": len(kids.get(dev_id, [])),
            "descendants": len(descendants(hierarchy, dev_id)),
            "depth": depth(dev_id),
        })
    roots = [n["id"] for n in nodes if n["parent_id"] is None]
    return {
        "nodes": nodes,
        "roots": roots,
        "stats": {
            "devices": len(nodes),
            "with_parent": len(nodes) - len(roots),
            "manual": sum(1 for n in nodes if n["source"] == "manual"),
            "max_depth": max((n["depth"] for n in nodes), default=0),
        },
        "sources": SOURCE_TEXT,
    }
