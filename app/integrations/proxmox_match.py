from typing import Optional


def norm_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    return mac.lower().replace("-", ":").strip()


def match_inventory(inventory: dict, devices: list[dict]) -> dict:
    hosts: dict[str, Optional[int]] = {}
    host_device_ids: set[int] = set()

    # Pass 0: Hosts
    for node in inventory.get("nodes", []):
        node_name = node["name"]
        node_ip = node.get("ip")
        device_id = None
        if node_ip:
            candidates = [d for d in devices if node_ip in d.get("ips", [])]
            if candidates:
                device_id = min(c["id"] for c in candidates)
        hosts[node_name] = device_id
        if device_id is not None:
            host_device_ids.add(device_id)

    # Pass 1: MAC matching
    guests = inventory.get("guests", [])
    sorted_guests = sorted(guests, key=lambda g: g["vmid"])
    claimed_devices: set[int] = set()
    guest_device_map: dict[int, Optional[int]] = {}

    for guest in sorted_guests:
        guest_macs = {norm_mac(m) for m in guest.get("macs", []) if norm_mac(m)}
        if not guest_macs:
            continue
        candidates = [
            d for d in devices
            if d["id"] not in host_device_ids
            and d["id"] not in claimed_devices
            and norm_mac(d.get("mac")) in guest_macs
        ]
        if candidates:
            device_id = min(c["id"] for c in candidates)
            claimed_devices.add(device_id)
            guest_device_map[guest["vmid"]] = device_id
        else:
            guest_device_map[guest["vmid"]] = None

    # Pass 2: IP matching
    node_ips = {node.get("ip") for node in inventory.get("nodes", []) if node.get("ip")}

    for guest in sorted_guests:
        if guest_device_map.get(guest["vmid"]) is not None:
            continue
        guest_ips = set(guest.get("ips", []))
        candidates = [
            d for d in devices
            if d["id"] not in host_device_ids
            and d["id"] not in claimed_devices
            and any(ip in guest_ips and ip not in node_ips for ip in d.get("ips", []))
        ]
        if candidates:
            device_id = min(c["id"] for c in candidates)
            claimed_devices.add(device_id)
            guest_device_map[guest["vmid"]] = device_id
        else:
            guest_device_map[guest["vmid"]] = None

    # Build output
    result_guests = []
    for guest in guests:
        copy = dict(guest)
        copy["device_id"] = guest_device_map.get(guest["vmid"])
        copy["host_device_id"] = hosts.get(guest["node"])
        result_guests.append(copy)

    return {"hosts": hosts, "guests": result_guests}