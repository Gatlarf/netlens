"""Traffic of the whole network in one picture: the in and out bandwidth of all monitored devices combined, and the traffic of the internet connection (WAN)
on a line of its own.

The numbers come from the health monitors (SNMP, SSH, WinRM and plugins record the speed of every network interface in the graph store).
Two ways to add them up (`mode`):
  * "all" (the default): every interface of every monitored device, as recorded. Traffic that passes through a switch, a bridge or a router is counted on
    each interface it crosses, so this is the total of what all the interfaces carry, not the amount of data that exists on the network.
  * "endpoints": the same without counting the same traffic twice:
  * switches, routers and access points are left out: their ports carry other devices' traffic, so every frame would count again;
  * virtual interfaces (loopback, veth, tap, docker, firewall links, Hyper-V adapters) are left out;
  * a host with a bridge (a Proxmox host's vmbr0) counts its bridge, which is the host's own traffic: the physical card also carries the traffic of its guests,
    and the guests are monitored and counted themselves;
  * when nothing is left, the device counts with all its interfaces.
The WAN line is one interface of the router: the one chosen under Settings → Interface, otherwise the interface of a router named like a WAN port.
"""

from __future__ import annotations

import re
import sqlite3
import time
from typing import Any

from app import tsdb

RANGES = {"1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400}
GEAR = {"router", "switch", "ap"}
VIRTUAL = re.compile(r"^(lo\d*$|veth|tap|fwbr|fwln|fwpr|docker|br-|virbr|vnet|flannel|cni|cali|tun\d|tailscale|zt)|loopback|virtual|vethernet|isatap|teredo", re.I)
BRIDGE = re.compile(r"^(vmbr|br\d|bridge)", re.I)
WAN_NAME = re.compile(r"wan|ppp|internet|uplink|pppoe|ge-?0$", re.I)
FRESH = 3600


def _fresh(s: dict, now: float) -> bool:
    return s["last"] is not None and s["last_ts"] is not None and now - s["last_ts"] <= FRESH


def interfaces_to_count(labels: set[str]) -> set[str]:
    """Which interfaces of a host count towards the total (see the module text)."""
    real = {l for l in labels if not VIRTUAL.search(l)}
    if not real:
        return set(labels)
    bridges = {l for l in real if BRIDGE.search(l)}
    return bridges or real


def _sum(parts: list[dict]) -> list[list[float]]:
    total: dict[int, float] = {}
    for p in parts:
        for t, avg, _lo, _hi in p["points"]:
            if avg is not None:
                total[int(t)] = total.get(int(t), 0.0) + avg
    return [[t, round(total[t])] for t in sorted(total)]


def _newest(points: list[list[float]]) -> float | None:
    return points[-1][1] if points else None


def wan_candidates(conn: sqlite3.Connection, series: dict[int, list[dict]], now: float) -> list[dict]:
    """The interfaces that could be the internet connection: those of routers, and any interface named like a WAN port."""
    out = []
    for r in conn.execute("SELECT id, COALESCE(NULLIF(type_override, ''), device_type) AS type, COALESCE(custom_name, hostname, primary_ip) AS name FROM devices"):
        pairs: dict[str, dict] = {}
        for s in series.get(r["id"], []):
            if s["metric"] in ("net_rx_bps", "net_tx_bps") and _fresh(s, now):
                pairs.setdefault(s["label"], {})[s["metric"]] = s["last"]
        for label, v in pairs.items():
            if r["type"] == "router" or WAN_NAME.search(label):
                out.append({"device_id": r["id"], "device": r["name"], "label": label, "rx": v.get("net_rx_bps"), "tx": v.get("net_tx_bps"), "named_wan": bool(WAN_NAME.search(label))})
    return out


def build(conn: sqlite3.Connection, range_key: str = "1h", wan: tuple[int, str] | None = None, now: float | None = None, mode: str = "all") -> dict[str, Any]:
    """The combined traffic of the devices and the WAN line, as points [t, bits per second]. mode "all": every interface; "endpoints": without double counting."""
    span = RANGES.get(range_key, 3600)
    now = now if now is not None else time.time()
    store = tsdb.for_conn(conn)
    out: dict[str, Any] = {"range": range_key, "mode": mode, "start": int(now - span), "end": int(now), "devices": {"count": 0, "rx": [], "tx": [], "now": None},
                           "wan": None, "candidates": []}
    if store is None:
        return out
    series = store.metrics_of_many("device")
    types = {r["id"]: r["type"] for r in conn.execute("SELECT id, COALESCE(NULLIF(type_override, ''), device_type) AS type FROM devices")}
    rx_parts: list[dict] = []
    tx_parts: list[dict] = []
    counted = interfaces = 0
    for device_id, ss in series.items():
        if device_id not in types or (mode == "endpoints" and types[device_id] in GEAR):
            continue
        labels = {s["label"] for s in ss if s["metric"] in ("net_rx_bps", "net_tx_bps") and _fresh(s, now)}
        if not labels:
            continue
        counted += 1
        chosen_labels = labels if mode == "all" else interfaces_to_count(labels)
        interfaces += len(chosen_labels)
        for label in chosen_labels:
            rx_parts.append(store.query("device", device_id, "net_rx_bps", label, span=span, end=int(now), points=120))
            tx_parts.append(store.query("device", device_id, "net_tx_bps", label, span=span, end=int(now), points=120))
    rx, tx = _sum(rx_parts), _sum(tx_parts)
    out["devices"] = {"count": counted, "interfaces": interfaces, "rx": rx, "tx": tx, "now": {"rx": _newest(rx), "tx": _newest(tx)} if counted else None}

    candidates = wan_candidates(conn, series, now)
    out["candidates"] = candidates
    chosen = None
    if wan:
        chosen = next((c for c in candidates if c["device_id"] == wan[0] and c["label"] == wan[1]), None) or (
            {"device_id": wan[0], "label": wan[1], "device": ""} if store.latest("device", wan[0], "net_rx_bps", wan[1]) else None)
    if chosen is None:
        routers = [c for c in candidates if c["named_wan"]] or ([c for c in candidates if len([x for x in candidates if x["device_id"] == c["device_id"]]) == 1])
        chosen = routers[0] if routers else None
    if chosen:
        a = store.query("device", chosen["device_id"], "net_rx_bps", chosen["label"], span=span, end=int(now), points=120)
        b = store.query("device", chosen["device_id"], "net_tx_bps", chosen["label"], span=span, end=int(now), points=120)
        a_points, b_points = _sum([a]), _sum([b])
        name = chosen.get("device") or next((r["name"] for r in conn.execute("SELECT COALESCE(custom_name, hostname, primary_ip) AS name FROM devices WHERE id = ?", (chosen["device_id"],))), "")
        out["wan"] = {"device_id": chosen["device_id"], "device": name, "label": chosen["label"], "rx": a_points, "tx": b_points, "now": {"rx": _newest(a_points), "tx": _newest(b_points)}}
    return out
