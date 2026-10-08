"""Database layer for Netlens using only the standard library sqlite3."""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 7


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

    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    # Enable foreign keys.
    conn.execute("PRAGMA foreign_keys=ON")

    # WAL journal mode; ignore failure for in-memory databases.
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.OperationalError:
        pass

    return conn



def _add_column_if_missing(conn: sqlite3.Connection, table: str, column: str, decl: str) -> bool:
    """Add the column when it is not there yet; returns True when it was added."""
    cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
        return True
    return False


def _migrate_to_plugins(conn: sqlite3.Connection) -> None:
    """Schema v5: the Proxmox and ASUS connectors became plugins. Move their guests, settings and links over.

    Runs on every start but only does something while old data exists. Nothing is lost if it is interrupted:
    old rows are removed only after the new ones are written.
    """
    import json

    def setting(key):
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def put(key, value):
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value if isinstance(value, str) else json.dumps(value)),
        )

    def load(key):
        raw = setting(key)
        try:
            data = json.loads(raw) if raw else None
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if "proxmox_guests" in tables:
        conn.execute(
            """
            INSERT OR IGNORE INTO hypervisor_guests
                (plugin_id, guest_id, name, kind, host_name, status, macs, ips, device_id, host_device_id, updated)
            SELECT 'proxmox', CAST(vmid AS TEXT), name, kind, node, status, macs, ips, device_id, host_device_id, updated
            FROM proxmox_guests
            """
        )
        conn.execute("DROP TABLE proxmox_guests")

    old = load("proxmox")
    if old is not None and setting("plugin.proxmox") is None:
        keys = ("url", "verify_tls", "username", "password", "token_id", "token_secret")
        put("plugin.proxmox", {"enabled": bool(old.get("enabled")), "config": {k: old[k] for k in keys if k in old}})
        status = load("proxmox_status")
        if status is not None:
            put("plugin.proxmox.status", status)
    if old is not None or setting("proxmox_status") is not None:
        conn.execute("DELETE FROM settings WHERE key IN ('proxmox', 'proxmox_status')")

    old = load("asus")
    if old is not None and setting("plugin.asus") is None:
        keys = ("url", "verify_tls", "username", "password")
        put("plugin.asus", {"enabled": bool(old.get("enabled")), "config": {k: old[k] for k in keys if k in old}})
        status = load("asus_status")
        if status is not None:
            put("plugin.asus.status", status)
        snapshot = load("asus_snapshot")
        if snapshot is not None:
            try:
                from app.plugins.builtin.asus.plugin import to_topology

                put("plugin.asus.data", to_topology(snapshot))
            except Exception:  # noqa: BLE001 - the next sync rebuilds it
                pass
    for key in ("asus", "asus_status", "asus_snapshot"):
        conn.execute("DELETE FROM settings WHERE key = ?", (key,))

    # relations created by the connectors carry the plugin id as their source
    conn.execute("UPDATE relations SET source = 'plugin:proxmox' WHERE source = 'proxmox'")
    conn.execute("UPDATE relations SET source = 'plugin:asus' WHERE source = 'asus-mesh'")
    conn.commit()


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

    # --- schema v2 -------------------------------------------------------
    _add_column_if_missing(conn, "devices", "notify_offline", "INTEGER NOT NULL DEFAULT 1")

    # --- schema v4: single-host scans and ignored devices -----------------
    _add_column_if_missing(conn, "scans", "target", "TEXT")  # the host of a "full" scan, else NULL
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ignored_devices (
            id INTEGER PRIMARY KEY,
            mac TEXT,
            ip TEXT,
            label TEXT NOT NULL,
            added TEXT NOT NULL
        )
        """
    )
    # a device is ignored by MAC when it has one, otherwise by IP (routed hosts have no MAC)
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_ignored_mac ON ignored_devices(mac) WHERE mac IS NOT NULL")
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_ignored_ip ON ignored_devices(ip) WHERE mac IS NULL")

    # --- schema v3: user-chosen parent in the network hierarchy -----------
    # parent_mode: 'auto' (derived from Proxmox/route/gateway), 'none' (top level on purpose)
    # or 'device' (parent_device_id is the chosen parent)
    _add_column_if_missing(conn, "devices", "parent_mode", "TEXT NOT NULL DEFAULT 'auto'")
    _add_column_if_missing(conn, "devices", "parent_device_id", "INTEGER REFERENCES devices(id) ON DELETE SET NULL")

    # uptime heartbeats: one row per device per completed scan covering it
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            ts TEXT NOT NULL,
            up INTEGER NOT NULL,
            rtt_ms REAL
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_checks_device_ts ON checks(device_id, ts)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_checks_ts ON checks(ts)")

    # --- schema v5: guests reported by hypervisor plugins (replaces proxmox_guests) ---------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS hypervisor_guests (
            plugin_id TEXT NOT NULL,
            guest_id TEXT NOT NULL,
            name TEXT NOT NULL,
            kind TEXT NOT NULL,
            host_name TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL,
            macs TEXT NOT NULL DEFAULT '[]',
            ips TEXT NOT NULL DEFAULT '[]',
            device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            host_device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            updated TEXT NOT NULL,
            PRIMARY KEY (plugin_id, guest_id)
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hv_guests_device ON hypervisor_guests(device_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hv_guests_host ON hypervisor_guests(host_device_id)")
    _migrate_to_plugins(conn)

    # --- schema v7: trusted devices, identification hints, Wi-Fi samples, service checks ---------
    # trusted: 1 = a device the user knows. Devices that already exist when this column appears are all trusted, so an
    # upgrade does not turn the whole network into "unknown devices"; devices found later start untrusted.
    if _add_column_if_missing(conn, "devices", "trusted", "INTEGER NOT NULL DEFAULT 0"):
        conn.execute("UPDATE devices SET trusted = 1")
    # hints: what discovery told us about the device (mDNS service types, UPnP device types, models), JSON list
    _add_column_if_missing(conn, "devices", "hints", "TEXT NOT NULL DEFAULT '[]'")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS wifi_samples (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            ts TEXT NOT NULL,
            node TEXT,
            band TEXT,
            rssi INTEGER,
            tx_mbps REAL,
            rx_mbps REAL
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_wifi_device_ts ON wifi_samples(device_id, ts)")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS service_checks (
            id INTEGER PRIMARY KEY,
            device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            kind TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER,
            path TEXT NOT NULL DEFAULT '',
            expect TEXT NOT NULL DEFAULT '',
            interval_s INTEGER NOT NULL DEFAULT 60,
            timeout_s INTEGER NOT NULL DEFAULT 5,
            enabled INTEGER NOT NULL DEFAULT 1,
            last_ts TEXT,
            last_up INTEGER,
            last_ms REAL,
            last_detail TEXT,
            since TEXT,
            created TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS service_results (
            id INTEGER PRIMARY KEY,
            check_id INTEGER NOT NULL REFERENCES service_checks(id) ON DELETE CASCADE,
            ts TEXT NOT NULL,
            up INTEGER NOT NULL,
            ms REAL,
            detail TEXT
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_service_results ON service_results(check_id, ts)")

    # --- schema v6: one row per day for the history charts of the Statistics page ---------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS stats_daily (
            day TEXT PRIMARY KEY,
            devices INTEGER NOT NULL,
            online INTEGER NOT NULL,
            new_devices INTEGER NOT NULL DEFAULT 0,
            open_ports INTEGER NOT NULL DEFAULT 0,
            events INTEGER NOT NULL DEFAULT 0,
            scans INTEGER NOT NULL DEFAULT 0
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


def get_setting(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    conn.commit()


def delete_setting(conn: sqlite3.Connection, key: str) -> None:
    conn.execute("DELETE FROM settings WHERE key = ?", (key,))
    conn.commit()
