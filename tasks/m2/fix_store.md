Fix the defects below and output the COMPLETE corrected file. Keep everything else identical.

DEFECTS:
host.mac can be None (hosts without a MAC address). Every use of host.mac.lower() must be guarded: compute mac = host.mac.lower() if host.mac is not None else None once per host, use it in the snapshot lookup branch 'if mac is not None' and pass mac to classify_device (which accepts None).

CURRENT FILE:
from dataclasses import replace
from typing import Any, Optional

from app.db import add_event, get_or_create_device, utcnow
from app.scanner.classify import classify_device
from app.scanner.nmap_parser import ScanHost


def save_scan_results(
    conn: Any,
    hosts: list[ScanHost],
    kind: str,
    now: str | None = None,
    extra_names: dict[str, list[tuple[str, str]]] | None = None,
) -> dict[str, Any]:
    if kind not in ("quick", "deep"):
        raise ValueError("kind must be 'quick' or 'deep'")

    if now is None:
        now = utcnow()

    # Apply extra names to hosts without mutating input
    processed_hosts: list[ScanHost] = []
    for host in hosts:
        if extra_names and host.ip in extra_names:
            existing_names = {name for name, _ in host.hostnames}
            new_names = []
            for name, source in extra_names[host.ip]:
                if name not in existing_names:
                    new_names.append((name, source))
            if new_names:
                processed_hosts.append(replace(host, hostnames=host.hostnames + new_names))
            else:
                processed_hosts.append(host)
        else:
            processed_hosts.append(host)

    new_count = 0
    updated_count = 0
    device_ids: list[int] = []

    for host in processed_hosts:
        # Snapshot existing device state before get_or_create_device
        if host.mac is not None:
            row = conn.execute(
                "SELECT id, primary_ip, online, os_name FROM devices WHERE mac = ?",
                (host.mac.lower(),),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT id, primary_ip, online, os_name FROM devices WHERE mac IS NULL AND primary_ip = ?",
                (host.ip,),
            ).fetchone()

        existing_device_id = row["id"] if row else None
        old_primary_ip = row["primary_ip"] if row else None
        old_online = row["online"] if row else None
        old_os_name = row["os_name"] if row else None

        # Get existing ports for this device
        existing_ports: set[tuple[str, int]] = set()
        if existing_device_id is not None:
            port_rows = conn.execute(
                "SELECT proto, port FROM ports WHERE device_id = ?",
                (existing_device_id,),
            ).fetchall()
            existing_ports = {(r["proto"], r["port"]) for r in port_rows}

        # Read prev_max inside the loop immediately before get_or_create_device
        prev_max = conn.execute("SELECT COALESCE(MAX(id), 0) FROM devices").fetchone()[0]

        # Create or update device
        device_id = get_or_create_device(conn, host.mac, host.ip, now)
        device_ids.append(device_id)

        is_new = device_id > prev_max
        if is_new:
            new_count += 1
            add_event(conn, "device_new", f"{host.ip} {host.vendor or ''}".strip(), device_id=device_id, now=now)
        else:
            updated_count += 1
            # Events for existing devices
            if old_online == 0:
                add_event(conn, "device_online", None, device_id=device_id, now=now)
            if old_primary_ip is not None and old_primary_ip != host.ip:
                add_event(conn, "ip_changed", f"{old_primary_ip} -> {host.ip}", device_id=device_id, now=now)
            if old_os_name is not None and host.os_name is not None and old_os_name != host.os_name:
                add_event(conn, "os_changed", f"{old_os_name} -> {host.os_name}", device_id=device_id, now=now)

        # Update vendor if not None
        if host.vendor is not None:
            conn.execute(
                "UPDATE devices SET vendor = ? WHERE id = ?",
                (host.vendor, device_id),
            )

        # Update os_name and os_confidence if host.os_name is not None
        if host.os_name is not None:
            conn.execute(
                "UPDATE devices SET os_name = ?, os_confidence = ? WHERE id = ?",
                (host.os_name, host.os_accuracy, device_id),
            )

        # Determine hostname: first PTR name else first name else unchanged
        hostname = None
        for name, source in host.hostnames:
            if source.lower() == "ptr":
                hostname = name
                break
        if hostname is None and host.hostnames:
            hostname = host.hostnames[0][0]
        if hostname is not None:
            conn.execute(
                "UPDATE devices SET hostname = ? WHERE id = ?",
                (hostname, device_id),
            )

        # Upsert device_names
        for name, source in host.hostnames:
            conn.execute(
                """
                INSERT INTO device_names (device_id, name, source, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(device_id, name, source) DO UPDATE SET last_seen = excluded.last_seen
                """,
                (device_id, name, source.lower(), now, now),
            )

        # Upsert ports
        for port in host.ports:
            conn.execute(
                """
                INSERT INTO ports (device_id, proto, port, state, service, product, version, updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id, proto, port) DO UPDATE SET
                    state = excluded.state,
                    service = excluded.service,
                    product = excluded.product,
                    version = excluded.version,
                    updated = excluded.updated
                """,
                (device_id, port.proto, port.port, port.state, port.service, port.product, port.version, now),
            )

            # Port opened event for existing devices only
            if not is_new and (port.proto, port.port) not in existing_ports:
                detail = f"{port.proto}/{port.port} {port.service or ''}".strip()
                add_event(conn, "port_opened", detail, device_id=device_id, now=now)

        # For deep scans, delete ports not in the result
        if kind == "deep":
            result_ports = {(p.proto, p.port) for p in host.ports}
            existing_port_ids = conn.execute(
                "SELECT id, proto, port FROM ports WHERE device_id = ?",
                (device_id,),
            ).fetchall()
            for pr in existing_port_ids:
                if (pr["proto"], pr["port"]) not in result_ports:
                    conn.execute("DELETE FROM ports WHERE id = ?", (pr["id"],))

        # Classification
        # Get open ports for classification
        open_ports_rows = conn.execute(
            "SELECT proto, port, service FROM ports WHERE device_id = ? AND state LIKE 'open%'",
            (device_id,),
        ).fetchall()
        open_ports = [r["port"] for r in open_ports_rows]
        services = [r["service"] for r in open_ports_rows if r["service"]]

        # Get all names from device_names
        name_rows = conn.execute(
            "SELECT name FROM device_names WHERE device_id = ?",
            (device_id,),
        ).fetchall()
        names = [r["name"] for r in name_rows]

        # Get current device values for classification
        dev_row = conn.execute(
            "SELECT vendor, os_name, type_override FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone()

        device_type = classify_device(
            vendor=dev_row["vendor"],
            os_name=dev_row["os_name"],
            os_type=host.os_type,
            open_ports=open_ports,
            services=services,
            hostnames=names,
            mac=host.mac.lower(),
        )
        conn.execute(
            "UPDATE devices SET device_type = ? WHERE id = ?",
            (device_type, device_id),
        )

    conn.commit()

    return {"new": new_count, "updated": updated_count, "device_ids": device_ids}