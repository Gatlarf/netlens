"""Port baselines: the open ports a device is expected to have.

A device with a baseline reports a new port as `port_unexpected` (instead of the plain `port_opened`) and a
vanished baseline port as `port_missing`. Devices without a baseline are not judged.
"""

import sqlite3
from typing import Iterable

from app.db import utcnow

OPEN = "state LIKE 'open%'"


def open_ports(conn: sqlite3.Connection, device_id: int) -> set[tuple[str, int]]:
    rows = conn.execute(f"SELECT proto, port FROM ports WHERE device_id = ? AND {OPEN}", (device_id,)).fetchall()
    return {(r["proto"], r["port"]) for r in rows}


def baseline_ports(conn: sqlite3.Connection, device_id: int) -> set[tuple[str, int]] | None:
    """The expected ports, or None when the device has no baseline."""
    if conn.execute("SELECT baseline_at FROM devices WHERE id = ?", (device_id,)).fetchone()["baseline_at"] is None:
        return None
    rows = conn.execute("SELECT proto, port FROM port_baselines WHERE device_id = ?", (device_id,)).fetchall()
    return {(r["proto"], r["port"]) for r in rows}


def accept(conn: sqlite3.Connection, device_ids: Iterable[int] | None = None, now: str | None = None) -> int:
    """Take the current open ports as normal. `None` = every device. Returns how many devices got a baseline."""
    now = now or utcnow()
    if device_ids is None:
        ids = [r["id"] for r in conn.execute("SELECT id FROM devices")]
    else:
        ids = [r["id"] for r in conn.execute("SELECT id FROM devices WHERE id IN (%s)" % (",".join("?" for _ in device_ids) or "NULL"), tuple(device_ids))]
    for device_id in ids:
        conn.execute("DELETE FROM port_baselines WHERE device_id = ?", (device_id,))
        for proto, port in open_ports(conn, device_id):
            conn.execute("INSERT INTO port_baselines (device_id, proto, port) VALUES (?, ?, ?)", (device_id, proto, port))
        conn.execute("UPDATE devices SET baseline_at = ? WHERE id = ?", (now, device_id))
    conn.commit()
    return len(ids)


def clear(conn: sqlite3.Connection, device_ids: Iterable[int] | None = None) -> int:
    where, params = ("", ()) if device_ids is None else (" WHERE id IN (%s)" % (",".join("?" for _ in device_ids) or "NULL"), tuple(device_ids))
    ids = [r["id"] for r in conn.execute("SELECT id FROM devices" + where, params)]
    for device_id in ids:
        conn.execute("DELETE FROM port_baselines WHERE device_id = ?", (device_id,))
        conn.execute("UPDATE devices SET baseline_at = NULL WHERE id = ?", (device_id,))
    conn.commit()
    return len(ids)


def _label(ports: set[tuple[str, int]]) -> list[str]:
    return [f"{proto}/{port}" for proto, port in sorted(ports, key=lambda p: (p[1], p[0]))]


def drift(conn: sqlite3.Connection, device_id: int) -> dict | None:
    """{"at", "expected", "unexpected", "missing"} for a device with a baseline, else None."""
    expected = baseline_ports(conn, device_id)
    if expected is None:
        return None
    at = conn.execute("SELECT baseline_at FROM devices WHERE id = ?", (device_id,)).fetchone()["baseline_at"]
    now_open = open_ports(conn, device_id)
    return {"at": at, "expected": _label(expected), "unexpected": _label(now_open - expected), "missing": _label(expected - now_open)}


def drift_counts(conn: sqlite3.Connection) -> dict[int, dict]:
    """device id -> {"unexpected": n, "missing": n} for every device with a baseline (one pass, for the device list)."""
    out: dict[int, dict] = {r["id"]: {"unexpected": 0, "missing": 0} for r in conn.execute("SELECT id FROM devices WHERE baseline_at IS NOT NULL")}
    if not out:
        return out
    expected: dict[int, set] = {i: set() for i in out}
    for r in conn.execute("SELECT device_id, proto, port FROM port_baselines"):
        if r["device_id"] in expected:
            expected[r["device_id"]].add((r["proto"], r["port"]))
    seen: dict[int, set] = {i: set() for i in out}
    for r in conn.execute(f"SELECT device_id, proto, port FROM ports WHERE {OPEN}"):
        if r["device_id"] in seen:
            seen[r["device_id"]].add((r["proto"], r["port"]))
    for i in out:
        out[i] = {"unexpected": len(seen[i] - expected[i]), "missing": len(expected[i] - seen[i])}
    return out
