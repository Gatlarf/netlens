"""Match what a plugin reports (hosts, guests, nodes, clients) to the devices Netlens has scanned."""

from __future__ import annotations

from typing import Optional


def norm_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    return mac.lower().replace("-", ":").strip()


def match_hypervisor(output: dict, devices: list[dict]) -> dict:
    """devices: [{id, mac, ips: [..]}]. Returns {"hosts": {host id: device id | None}, "guests": [guest + device_id + host_device_id]}.

    A host is found by its IP (then MAC); a guest by MAC first, then by IP. A device is never claimed twice and
    a host is never taken for a guest.
    """
    hosts: dict[str, Optional[int]] = {}
    host_device_ids: set[int] = set()

    for host in output.get("hosts", []):
        device_id = None
        if host.get("ip"):
            candidates = [d for d in devices if host["ip"] in d.get("ips", [])]
            if candidates:
                device_id = min(c["id"] for c in candidates)
        if device_id is None and host.get("mac"):
            candidates = [d for d in devices if norm_mac(d.get("mac")) == norm_mac(host["mac"])]
            if candidates:
                device_id = min(c["id"] for c in candidates)
        hosts[host["id"]] = device_id
        if device_id is not None:
            host_device_ids.add(device_id)

    guests = output.get("guests", [])
    ordered = sorted(guests, key=lambda g: (len(g["id"]), g["id"]))
    claimed: set[int] = set()
    matched: dict[str, Optional[int]] = {}

    for guest in ordered:  # pass 1: MAC
        guest_macs = {norm_mac(m) for m in guest.get("macs", []) if norm_mac(m)}
        if not guest_macs:
            continue
        candidates = [
            d for d in devices
            if d["id"] not in host_device_ids and d["id"] not in claimed and norm_mac(d.get("mac")) in guest_macs
        ]
        if candidates:
            device_id = min(c["id"] for c in candidates)
            claimed.add(device_id)
            matched[guest["id"]] = device_id

    host_ips = {h["ip"] for h in output.get("hosts", []) if h.get("ip")}
    for guest in ordered:  # pass 2: IP
        if matched.get(guest["id"]) is not None:
            continue
        guest_ips = set(guest.get("ips", []))
        candidates = [
            d for d in devices
            if d["id"] not in host_device_ids and d["id"] not in claimed
            and any(ip in guest_ips and ip not in host_ips for ip in d.get("ips", []))
        ]
        if candidates:
            device_id = min(c["id"] for c in candidates)
            claimed.add(device_id)
            matched[guest["id"]] = device_id

    result = []
    for guest in guests:
        item = dict(guest)
        item["device_id"] = matched.get(guest["id"])
        item["host_device_id"] = hosts.get(guest["host_id"]) if guest.get("host_id") else None
        result.append(item)
    return {"hosts": hosts, "guests": result}


def topology_links(output: dict, by_mac: dict[str, int], by_ip: dict[str, int]) -> list[tuple[int, int, str]]:
    """[(child device id, parent device id, how)] for a topology plugin's output.

    A node hangs below its parent_mac (or below the gateway when it names none); a client below the node it is
    connected to (or below the gateway when none is named). Nodes and clients are matched by MAC, then IP.
    """
    nodes = output.get("nodes", [])
    gateway = next((n for n in nodes if n["role"] == "gateway"), None)

    def device_of_node(node: dict) -> Optional[int]:
        for mac in node["macs"]:
            if mac in by_mac:
                return by_mac[mac]
        return by_ip.get(node.get("ip") or "")

    node_by_mac = {m: n for n in nodes for m in n["macs"]}
    dev_of = {n["mac"]: device_of_node(n) for n in nodes}
    node_devices = {d for d in dev_of.values() if d is not None}
    links: dict[int, tuple[int, str]] = {}

    for node in nodes:
        child = dev_of[node["mac"]]
        if child is None or node is gateway:
            continue
        parent_node = node_by_mac.get(node["parent_mac"]) if node["parent_mac"] else gateway
        parent = dev_of.get(parent_node["mac"]) if parent_node else None
        if parent is not None and parent != child:
            links[child] = (parent, "node")

    for client in output.get("clients", []):
        child = by_mac.get(client["mac"])
        if child is None:
            child = by_ip.get(client.get("ip") or "")
        if child is None or child in node_devices:
            continue
        node = node_by_mac.get(client["node_mac"]) if client["node_mac"] else gateway
        parent = dev_of.get(node["mac"]) if node else None
        if parent is None or parent == child:
            continue
        how = "wired" if client["medium"] == "wired" else ("wifi " + client["band"]) if client.get("band") else client["medium"]
        links[child] = (parent, how)
    return [(c, p, how) for c, (p, how) in links.items()]
