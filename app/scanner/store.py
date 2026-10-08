import json
from dataclasses import replace
from typing import Any, Optional

from app.db import add_event, get_or_create_device, utcnow
from app.plugins.enrich import refresh_hostname
from app.scanner.classify import classify_device
from app.scanner.nmap_parser import ScanHost


MAX_HINTS = 40  # discovery hints kept per device


def _hours_before(ts: str, hours: int) -> str:
    from datetime import datetime, timedelta, timezone

    return (datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


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

    # Devices the user chose to ignore are not stored again
    ignored_macs = {r["mac"] for r in conn.execute("SELECT mac FROM ignored_devices WHERE mac IS NOT NULL")}
    ignored_ips = {r["ip"] for r in conn.execute("SELECT ip FROM ignored_devices WHERE mac IS NULL")}

    def is_ignored(host: ScanHost) -> bool:
        if host.mac is not None:
            return host.mac.lower() in ignored_macs
        return host.ip in ignored_ips

    # Apply extra names to hosts without mutating input
    processed_hosts: list[ScanHost] = []
    for host in hosts:
        if is_ignored(host):
            continue
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
    rtts: dict[int, float] = {}

    for host in processed_hosts:
        mac = host.mac.lower() if host.mac is not None else None

        # Snapshot existing device state before get_or_create_device
        if mac is not None:
            row = conn.execute(
                "SELECT id, primary_ip, online, os_name FROM devices WHERE mac = ?",
                (mac,),
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

        # Another device held this IP until now (seen within a day): worth a note, it explains odd history
        holder = conn.execute(
            "SELECT id, mac, hostname, custom_name, last_seen FROM devices WHERE primary_ip = ? AND id != ? AND last_seen >= ?",
            (host.ip, existing_device_id or -1, _hours_before(now, 24)),
        ).fetchone()

        # Create or update device
        device_id = get_or_create_device(conn, host.mac, host.ip, now)
        if holder is not None and holder["mac"] != mac:
            detail = f"{host.ip} is now used by {mac or 'a device without MAC'}; it was {holder['custom_name'] or holder['hostname'] or holder['mac'] or 'another device'} ({holder['mac'] or 'no MAC'})"
            if conn.execute("SELECT 1 FROM events WHERE kind = 'ip_reused' AND device_id = ? AND detail = ?", (device_id, detail)).fetchone() is None:
                add_event(conn, "ip_reused", detail, device_id=device_id, now=now)
        device_ids.append(device_id)
        if host.rtt_ms is not None:
            rtts[device_id] = host.rtt_ms

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

        # Discovery hints are kept on the device (they are not names); everything else is a name
        named = [(n, src) for n, src in host.hostnames if src.lower() != "hint"]
        new_hints = [n for n, src in host.hostnames if src.lower() == "hint"]
        if new_hints:
            try:
                kept = json.loads(conn.execute("SELECT hints FROM devices WHERE id = ?", (device_id,)).fetchone()["hints"] or "[]")
            except ValueError:
                kept = []
            merged_hints = (kept + [h for h in new_hints if h not in kept])[-MAX_HINTS:]
            conn.execute("UPDATE devices SET hints = ? WHERE id = ?", (json.dumps(merged_hints), device_id))

        # Determine hostname: the PTR name, else the first real name (an SSDP product token such as "Linux" is not a
        # name), else unchanged; a device that still has none takes its best alias
        hostname = None
        for name, source in named:
            if source.lower() == "ptr":
                hostname = name
                break
        if hostname is None:
            hostname = next((name for name, source in named if source.lower() != "ssdp"), None)
        if hostname is not None:
            conn.execute(
                "UPDATE devices SET hostname = ? WHERE id = ?",
                (hostname, device_id),
            )

        # Upsert device_names
        for name, source in named:
            conn.execute(
                """
                INSERT INTO device_names (device_id, name, source, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(device_id, name, source) DO UPDATE SET last_seen = excluded.last_seen
                """,
                (device_id, name, source.lower(), now, now),
            )
        refresh_hostname(conn, device_id)

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

        if host.timed_out:
            add_event(
                conn,
                "host_timeout",
                f"{host.ip}: nmap gave up on this host (host timeout); its ports were not refreshed",
                device_id=device_id,
                now=now,
            )

        # For deep scans, delete ports not in the result. A host nmap gave up on has an incomplete
        # (usually empty) result, so it keeps the ports it had.
        if kind == "deep" and not host.timed_out:
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
            "SELECT vendor, os_name, type_override, hints FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone()
        try:
            stored_hints = json.loads(dev_row["hints"] or "[]")
        except ValueError:
            stored_hints = []

        device_type = classify_device(
            vendor=dev_row["vendor"],
            os_name=dev_row["os_name"],
            os_type=host.os_type,
            open_ports=open_ports,
            services=services,
            hostnames=names,
            mac=mac,
            hints=stored_hints,
        )
        conn.execute(
            "UPDATE devices SET device_type = ? WHERE id = ?",
            (device_type, device_id),
        )

    conn.commit()

    return {"new": new_count, "updated": updated_count, "device_ids": device_ids, "rtts": rtts}