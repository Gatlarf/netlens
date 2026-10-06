import sqlite3
import ipaddress
from typing import Any

from app.db import add_event, utcnow


def mark_offline(
    conn: sqlite3.Connection,
    seen_ids: set[int] | list[int] | tuple[int, ...],
    ranges: list[str],
    now: str | None = None,
) -> list[int]:
    if not ranges:
        return []

    seen_set = set(seen_ids)
    networks = [ipaddress.ip_network(r, strict=False) for r in ranges]

    rows = conn.execute(
        "SELECT id, primary_ip FROM devices WHERE online = 1 AND id NOT IN ({})".format(
            ",".join("?" for _ in seen_set)
        ),
        tuple(seen_set),
    ).fetchall()

    offline_ids: list[int] = []
    for row in rows:
        device_id = row["id"]
        primary_ip = row["primary_ip"]
        if primary_ip is None:
            continue
        try:
            addr = ipaddress.ip_address(primary_ip)
        except ValueError:
            continue

        if any(addr in net for net in networks):
            conn.execute("UPDATE devices SET online = 0 WHERE id = ?", (device_id,))
            add_event(conn, "device_offline", primary_ip, device_id=device_id, now=now)
            offline_ids.append(device_id)

    conn.commit()
    offline_ids.sort()
    return offline_ids