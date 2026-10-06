Fix the defects below and output the COMPLETE corrected file. Keep everything else identical.

DEFECTS:
New-vs-existing detection is wrong. The pre-check 'SELECT id FROM devices WHERE mac = ? AND primary_ip = ?' never matches when mac is NULL (NULL = NULL is not true in SQL) and miscounts a known device whose IP changed as new. Remove that pre-check. Instead: before the loop-iteration's call read prev_max = SELECT COALESCE(MAX(id), 0) FROM devices; always call get_or_create_device(conn, host.mac, host.ip, now); the device is new if the returned id > prev_max, else updated.

CURRENT FILE:
from __future__ import annotations

import sqlite3
from typing import Any

from app.db import get_or_create_device, utcnow
from app.scanner.nmap_parser import ScanHost, ScanPort


def save_scan_results(
    conn: sqlite3.Connection,
    hosts: list[ScanHost],
    kind: str,
    now: str | None = None,
) -> dict[str, Any]:
    if kind not in ("quick", "deep"):
        raise ValueError(f"kind must be 'quick' or 'deep', got {kind!r}")

    if now is None:
        now = utcnow()

    new_count = 0
    updated_count = 0
    device_ids: list[int] = []

    for host in hosts:
        # Determine if device already exists before calling get_or_create_device
        row = conn.execute(
            "SELECT id FROM devices WHERE mac = ? AND primary_ip = ?",
            (host.mac, host.ip),
        ).fetchone()

        if row is not None:
            device_id = row["id"]
            updated_count += 1
        else:
            device_id = get_or_create_device(conn, host.mac, host.ip, now)
            new_count += 1

        device_ids.append(device_id)

        # Update devices table
        updates: list[str] = []
        params: list[Any] = []

        if host.vendor is not None:
            updates.append("vendor = ?")
            params.append(host.vendor)

        if host.os_name is not None:
            updates.append("os_name = ?")
            params.append(host.os_name)
            updates.append("os_confidence = ?")
            params.append(host.os_accuracy)

        # Determine hostname
        hostname = None
        ptr_names = [name for name, typ in host.hostnames if typ == "PTR"]
        if ptr_names:
            hostname = ptr_names[0]
        elif host.hostnames:
            hostname = host.hostnames[0][0]

        if hostname is not None:
            updates.append("hostname = ?")
            params.append(hostname)

        if updates:
            params.append(device_id)
            conn.execute(
                f"UPDATE devices SET {', '.join(updates)} WHERE id = ?",
                params,
            )

        # Upsert device_names
        for name, typ in host.hostnames:
            source = typ.lower()
            conn.execute(
                """
                INSERT INTO device_names (device_id, name, source, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(device_id, name, source) DO UPDATE SET last_seen = ?
                """,
                (device_id, name, source, now, now, now),
            )

        # Upsert ports
        for port in host.ports:
            conn.execute(
                """
                INSERT INTO ports (device_id, proto, port, state, service, product, version, updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id, proto, port) DO UPDATE SET
                    state = ?, service = ?, product = ?, version = ?, updated = ?
                """,
                (
                    device_id,
                    port.proto,
                    port.port,
                    port.state,
                    port.service,
                    port.product,
                    port.version,
                    now,
                    port.state,
                    port.service,
                    port.product,
                    port.version,
                    now,
                ),
            )

        # For deep scans, delete ports not in this result
        if kind == "deep":
            existing_ports = conn.execute(
                "SELECT proto, port FROM ports WHERE device_id = ?",
                (device_id,),
            ).fetchall()

            result_keys = {(p.proto, p.port) for p in host.ports}

            for row in existing_ports:
                if (row["proto"], row["port"]) not in result_keys:
                    conn.execute(
                        "DELETE FROM ports WHERE device_id = ? AND proto = ? AND port = ?",
                        (device_id, row["proto"], row["port"]),
                    )

    conn.commit()

    return {
        "new": new_count,
        "updated": updated_count,
        "device_ids": device_ids,
    }