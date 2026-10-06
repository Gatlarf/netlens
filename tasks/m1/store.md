Create app/scanner/store.py. It imports from app.db: get_or_create_device, utcnow (module app.db, sqlite3 connections with row_factory=sqlite3.Row), and ScanHost/ScanPort from app.scanner.nmap_parser (ScanHost fields: ip, mac, vendor, hostnames: list[tuple[str,str]] of (name, type), ports: list[ScanPort(proto, port, state, service, product, version, extrainfo)], os_name, os_accuracy, os_type, ttl, via). Existing tables: devices(id, mac, primary_ip, hostname, vendor, os_name, os_confidence, device_type, type_override, custom_name, notes, tags, online, first_seen, last_seen, ...), device_names(device_id, name, source, first_seen, last_seen, UNIQUE(device_id,name,source)), ports(device_id, proto, port, state, service, product, version, updated, UNIQUE(device_id,proto,port)).

def save_scan_results(conn, hosts: list[ScanHost], kind: str, now: str | None = None) -> dict:
- now defaults to utcnow(). kind is "quick" or "deep" (else ValueError).
- For each host: device_id = get_or_create_device(conn, host.mac, host.ip, now). Remember whether the device already existed (count new vs updated; you can detect it by checking whether a row with that id existed before the call, e.g. compare max(id) before and after, or look for the device before calling).
- UPDATE devices: vendor = host.vendor only if not None; os_name and os_confidence only if host.os_name is not None; hostname = the first name of type "PTR" if any, else the first name of any type, else leave unchanged.
- device_names: upsert every (name, type.lower()) with first_seen/last_seen = now (on conflict update last_seen).
- ports: upsert every port (proto, port, state, service, product, version, updated=now). When kind == "deep", additionally delete the device's ports that are not in this result (compare by (proto, port)). For "quick" never delete.
- Single commit at the end. Return {"new": int, "updated": int, "device_ids": list[int]} (device_ids in input order).
- Use parameterised SQL only.
