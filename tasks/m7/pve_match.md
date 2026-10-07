
TASK: write app/integrations/proxmox_match.py (full file, under 90 lines). No imports except typing/standard library. Pure functions, no database access.

def norm_mac(mac: str | None) -> str | None
  - lowercase, replace "-" with ":", strip; None or empty -> None.

def match_inventory(inventory: dict, devices: list[dict]) -> dict
  Input `inventory` (from a Proxmox sync): {"nodes": [{"name": "pve1", "ip": "192.168.0.180"}, ...], "guests": [{"vmid": 100, "name": "web", "kind": "qemu" or "lxc", "node": "pve1", "status": "running", "macs": ["bc:24:11:aa:bb:cc"], "ips": ["192.168.0.50"]}, ...]}  (node ip may be None; macs/ips may be empty lists)
  Input `devices`: [{"id": 7, "mac": "BC:24:11:AA:BB:CC" or None, "ips": ["192.168.0.50", ...]}]  (ips = every IPv4 address known for the device)
  Output: {"hosts": {node_name: device_id or None}, "guests": [guest dicts]} where each guest dict is a COPY of the input guest plus the keys "device_id" (int or None) and "host_device_id" (int or None). Guests keep the input order.
  Rules:
  1. Hosts: for each node, device_id = id of the device whose "ips" contains node["ip"] (lowest id if several), else None.
  2. The devices that are Proxmox hosts (the non-None values of "hosts") must never be matched to a guest.
  3. Pass 1 (MAC): process guests sorted by vmid; a guest matches the device whose normalised mac equals one of the guest's normalised macs; each device can be claimed by only one guest (the lowest vmid wins) and by MAC before IP.
  4. Pass 2 (IP): for guests still unmatched, sorted by vmid, match the unclaimed device (lowest id first) whose ips intersect the guest's ips. Ignore device ips equal to a node ip.
  5. host_device_id = hosts.get(guest["node"]).
