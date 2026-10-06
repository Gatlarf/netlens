Fix the defects below and output the COMPLETE corrected file. Keep everything else identical.

DEFECTS:
FastAPI runs sync dependencies and endpoints in different worker threads, so a connection opened by a dependency is used from another thread and fails with sqlite3.ProgrammingError: SQLite objects created in a thread can only be used in that same thread. Open every file connection with sqlite3.connect(path, check_same_thread=False) (each request uses its own connection, so this is safe).

CURRENT FILE:
"""Database layer for Netlens using only the standard library sqlite3."""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


def utcnow() -> str:
    """Return current UTC time as ISO-8601 with seconds precision and trailing 'Z'."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(path: str | os.PathLike) -> sqlite3.Connection:
    """Open a SQLite connection with sensible defaults for Netlens."""
    # Create parent directory for file paths before connecting.
    # Skip for in-memory databases or empty paths.
    if isinstance(path, os.PathLike) or isinstance(path, str):
        p = Path(path)
        if p.parent and p.parent != Path(".") and not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row

    # Enable foreign keys.
    conn.execute("PRAGMA foreign_keys=ON")

    # WAL journal mode; ignore failure for in-memory databases.
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.OperationalError:
        pass

    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Idempotently create the schema and record the schema version."""
    cur = conn.cursor()

    # schema_version table with one row.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER
        )
        """
    )
    cur.execute("SELECT version FROM schema_version LIMIT 1")
    row = cur.fetchone()
    if row is None:
        cur.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))
    else:
        # Ensure stored version matches expected version.
        if row["version"] != SCHEMA_VERSION:
            cur.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION,))

    # devices
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY,
            mac TEXT UNIQUE,
            primary_ip TEXT,
            hostname TEXT,
            vendor TEXT,
            os_name TEXT,
            os_confidence INTEGER,
            device_type TEXT,
            type_override TEXT,
            custom_name TEXT,
            notes TEXT,
            tags TEXT,
            online INTEGER NOT NULL DEFAULT 1,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            pos_x REAL,
            pos_y REAL,
            raw_xml TEXT
        )
        """
    )

    # device_ips
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS device_ips (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            ip TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(device_id, ip)
        )
        """
    )

    # device_names
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS device_names (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(device_id, name, source)
        )
        """
    )

    # ports
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            proto TEXT NOT NULL,
            port INTEGER NOT NULL,
            state TEXT NOT NULL,
            service TEXT,
            product TEXT,
            version TEXT,
            updated TEXT NOT NULL,
            UNIQUE(device_id, proto, port)
        )
        """
    )

    # scans
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY,
            kind TEXT NOT NULL,
            status TEXT NOT NULL,
            started TEXT NOT NULL,
            finished TEXT,
            hosts_found INTEGER NOT NULL DEFAULT 0,
            error TEXT
        )
        """
    )

    # events
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            kind TEXT NOT NULL,
            detail TEXT
        )
        """
    )

    # relations
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS relations (
            id INTEGER PRIMARY KEY,
            src_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            dst_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 1.0,
            manual INTEGER NOT NULL DEFAULT 0,
            UNIQUE(src_id, dst_id, kind)
        )
        """
    )

    # settings
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )

    # host_keys
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS host_keys (
            device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
            fingerprint TEXT NOT NULL,
            first_seen TEXT NOT NULL
        )
        """
    )

    # Indexes
    cur.execute("CREATE INDEX IF NOT EXISTS idx_device_ips_ip ON device_ips(ip)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ports_device_id ON ports(device_id)")

    conn.commit()


def _normalize_mac(mac: str | None) -> str | None:
    """Normalize MAC to lowercase colon-separated form."""
    if mac is None:
        return None
    # Accept formats like "AA-BB-CC-DD-EE-FF" or "AA:BB:CC:DD:EE:FF"
    cleaned = mac.strip().lower()
    # Replace dashes with colons
    cleaned = cleaned.replace("-", ":")
    # Ensure only colons remain as separators
    # If already colon-separated, keep as is
    return cleaned


def get_or_create_device(
    conn: sqlite3.Connection,
    mac: str | None,
    ip: str,
    now: str | None = None,
) -> int:
    """Find or create a device by MAC or IP, update last_seen, upsert device_ips."""
    if now is None:
        now = utcnow()

    normalized_mac = _normalize_mac(mac)
    cur = conn.cursor()

    device_id: int | None = None

    if normalized_mac is not None:
        # Find by MAC
        cur.execute("SELECT id FROM devices WHERE mac = ?", (normalized_mac,))
        row = cur.fetchone()
        if row is not None:
            device_id = row["id"]
        else:
            # Create new device with MAC
            cur.execute(
                """
                INSERT INTO devices (mac, primary_ip, first_seen, last_seen, online)
                VALUES (?, ?, ?, ?, 1)
                """,
                (normalized_mac, ip, now, now),
            )
            device_id = cur.lastrowid
    else:
        # Find device with mac IS NULL and primary_ip == ip
        cur.execute(
            "SELECT id FROM devices WHERE mac IS NULL AND primary_ip = ?",
            (ip,),
        )
        row = cur.fetchone()
        if row is not None:
            device_id = row["id"]
        else:
            # Create new device without MAC
            cur.execute(
                """
                INSERT INTO devices (mac, primary_ip, first_seen, last_seen, online)
                VALUES (?, ?, ?, ?, 1)
                """,
                (None, ip, now, now),
            )
            device_id = cur.lastrowid

    # Update last_seen, primary_ip, online
    cur.execute(
        """
        UPDATE devices
        SET last_seen = ?, primary_ip = ?, online = 1
        WHERE id = ?
        """,
        (now, ip, device_id),
    )

    # Upsert device_ips row
    cur.execute(
        """
        INSERT INTO device_ips (device_id, ip, first_seen, last_seen)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(device_id, ip) DO UPDATE SET last_seen = ?
        """,
        (device_id, ip, now, now, now),
    )

    conn.commit()
    return device_id


def add_event(
    conn: sqlite3.Connection,
    kind: str,
    detail: str | None = None,
    device_id: int | None = None,
    now: str | None = None,
) -> int:
    """Insert an event, commit, and return the event id."""
    if now is None:
        now = utcnow()

    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO events (ts, device_id, kind, detail)
        VALUES (?, ?, ?, ?)
        """,
        (now, device_id, kind, detail),
    )
    conn.commit()
    return cur.lastrowid


def list_devices(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Return all devices as plain dicts, ordered by primary_ip string then id."""
    cur = conn.cursor()
    cur.execute(
        """
        SELECT * FROM devices
        ORDER BY primary_ip, id
        """
    )
    rows = cur.fetchall()
    return [dict(row) for row in rows]