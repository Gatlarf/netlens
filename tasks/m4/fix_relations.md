Fix the defects below and output the COMPLETE corrected file. Keep everything else identical.

DEFECTS:
A device whose IP address appears in ANY hops list (it is a router in a traceroute chain) must NOT receive a gateway edge; the route edges already connect it. Compute the set of hop IPs over all hops lists first and skip gateway edges for devices whose primary_ip is in that set. Everything else unchanged.

CURRENT FILE:
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Edge:
    src_id: int
    dst_id: int
    kind: str
    source: str
    confidence: float


def infer_relations(
    devices: list[dict],
    hops: Optional[dict[str, list[str]]] = None,
    gateway_ip: Optional[str] = None,
) -> list[Edge]:
    """Infer relations between devices based on network topology and heuristics."""

    # Build ip_to_id mapping
    ip_to_id: dict[str, int] = {}
    for device in devices:
        primary_ip = device.get("primary_ip")
        if primary_ip:
            ip_to_id[primary_ip] = device["id"]

    # Determine gateway device
    gw_id: Optional[int] = None
    gw_source: str = "default-route"
    gw_confidence: float = 1.0

    if gateway_ip:
        gw_id = ip_to_id.get(gateway_ip)
    else:
        # Heuristic: if exactly one device has type "router", use it
        router_devices = [d for d in devices if d.get("type") == "router"]
        if len(router_devices) == 1:
            gw_id = router_devices[0]["id"]
            gw_source = "heuristic"
            gw_confidence = 0.5

    edges: list[Edge] = []
    seen: set[tuple[int, int, str]] = set()

    def add_edge(src_id: int, dst_id: int, kind: str, source: str, confidence: float) -> None:
        key = (src_id, dst_id, kind)
        if key in seen:
            return
        seen.add(key)
        edges.append(Edge(src_id=src_id, dst_id=dst_id, kind=kind, source=source, confidence=confidence))

    # Gateway edges
    if gw_id is not None:
        for device in devices:
            device_id = device["id"]
            if device_id == gw_id:
                continue

            # Check if device has usable hops
            device_ip = device.get("primary_ip")
            device_hops = hops.get(device_ip) if hops else None

            has_usable_hops = False
            if device_hops:
                for hop_ip in device_hops:
                    if hop_ip in ip_to_id:
                        has_usable_hops = True
                        break

            if not has_usable_hops:
                add_edge(device_id, gw_id, "gateway", gw_source, gw_confidence)

    # Route edges
    if hops:
        for device in devices:
            device_id = device["id"]
            device_ip = device.get("primary_ip")
            device_hops = hops.get(device_ip)

            if not device_hops:
                continue

            # Filter hops that exist in ip_to_id, in order, drop duplicates and the device itself
            known: list[int] = []
            seen_hops: set[int] = set()
            for hop_ip in device_hops:
                if hop_ip == device_ip:
                    continue
                hop_id = ip_to_id.get(hop_ip)
                if hop_id is None:
                    continue
                if hop_id in seen_hops:
                    continue
                seen_hops.add(hop_id)
                known.append(hop_id)

            if not known:
                continue

            # known is ordered nearest-to-scanner first = [r1, r2, ..., rn]
            n = len(known)

            # Edge(device, rn) - device attaches to the last known hop (closest to device)
            add_edge(device_id, known[-1], "route", "traceroute", 0.9)

            # Chain consecutive pairs: Edge(r_i, r_{i-1}) for i from n down to 2
            for i in range(n, 1, -1):
                add_edge(known[i - 1], known[i - 2], "route", "traceroute", 0.9)

            # Edge(r1, gw_id) if gw_id is known and r1 != gw
            if gw_id is not None and known[0] != gw_id:
                add_edge(known[0], gw_id, "route", "traceroute", 0.9)

    # Host-of edges
    vm_devices = [d for d in devices if d.get("type") == "vm"]
    hypervisor_keywords = {"proxmox", "esxi", "vmware", "hyper-v", "hypervisor", "libvirt", "kvm", "xen"}

    candidates: list[dict] = []
    for device in devices:
        if device.get("type") == "vm":
            continue

        ports = device.get("ports", [])
        if 8006 in ports:
            candidates.append(device)
            continue

        hostname = (device.get("hostname") or "").lower()
        vendor = (device.get("vendor") or "").lower()

        if any(keyword in hostname or keyword in vendor for keyword in hypervisor_keywords):
            candidates.append(device)

    if len(candidates) == 1:
        candidate = candidates[0]
        for vm in vm_devices:
            add_edge(vm["id"], candidate["id"], "host-of", "heuristic", 0.5)

    # Sort by (kind, src_id, dst_id)
    edges.sort(key=lambda e: (e.kind, e.src_id, e.dst_id))

    return edges