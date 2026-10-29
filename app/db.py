"""Database layer for Netlens using only the standard library sqlite3."""

from __future__ import annotations

import os
import time
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 36


def utcnow() -> str:
    """Return current UTC time as ISO-8601 with seconds precision and trailing 'Z'."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ago(**delta: float) -> str:
    """The time `delta` (days=, hours=, ...) before now, in the stored format. Use it instead of SQL date functions, which differ between engines."""
    return (datetime.now(timezone.utc) - timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


# What the rest of the application catches. Code outside this module says `except db.Error` / `db.IntegrityError`, never the driver's own classes,
# so a second database driver only has to be added here.
Error = sqlite3.Error
IntegrityError = sqlite3.IntegrityError


class Connection(sqlite3.Connection):
    """A SQLite connection that remembers which file it opened (`file`), so nobody has to ask the database with a PRAGMA each time."""

    file: str = ""


class SlowConnection(Connection):
    """A connection that writes a line to the system log for each statement slower than NETLENS_SLOW_QUERY_MS (see `factory`)."""

    threshold = 0.0

    def _note(self, sql: str, started: float) -> None:
        took = time.perf_counter() - started
        if took < self.threshold:
            return
        import logging
        import traceback

        where = next((f"{f.filename.rsplit('/app/', 1)[-1]}:{f.lineno}" for f in reversed(traceback.extract_stack()) if "/app/" in f.filename and not f.filename.endswith("/db.py")), "?")
        logging.getLogger("netlens.slowquery").warning("%.0f ms at %s: %s", took * 1000, where, " ".join(str(sql).split())[:300])

    def execute(self, sql, *args, **kwargs):
        started = time.perf_counter()
        try:
            return super().execute(sql, *args, **kwargs)
        finally:
            self._note(sql, started)

    def executemany(self, sql, *args, **kwargs):
        started = time.perf_counter()
        try:
            return super().executemany(sql, *args, **kwargs)
        finally:
            self._note(sql, started)


def factory() -> type[Connection]:
    """The connection class to use: the plain one, or, when NETLENS_SLOW_QUERY_MS is a number above 0, the one that logs slow statements."""
    try:
        ms = float(os.environ.get("NETLENS_SLOW_QUERY_MS", "") or 0)
    except ValueError:
        ms = 0.0
    if ms <= 0:
        return Connection
    SlowConnection.threshold = ms / 1000
    return SlowConnection


def insert_id(conn, sql: str, params=()) -> int | None:
    """Run one INSERT and return the id of the new row (None when nothing was inserted, for example ON CONFLICT DO NOTHING).
    RETURNING works on SQLite (3.35 and later) and on PostgreSQL; `cursor.lastrowid` exists only on SQLite."""
    cur = conn.execute(sql.rstrip().rstrip(";") + " RETURNING id", params)
    row = cur.fetchone()
    cur.close()
    return row[0] if row else None


def main_file(conn: sqlite3.Connection) -> str:
    """The file of the main database ("" for an in-memory one). Free for a connection made by connect(); otherwise one PRAGMA."""
    known = getattr(conn, "file", "")
    if known:
        return known
    try:
        for _seq, name, path in conn.execute("PRAGMA database_list"):
            if name == "main":
                return path or ""
    except sqlite3.Error:
        pass
    return ""


def connect(path: str | os.PathLike) -> sqlite3.Connection:
    """Open a SQLite connection with sensible defaults for Netlens."""
    # Create parent directory for file paths before connecting.
    # Skip for in-memory databases or empty paths.
    if isinstance(path, os.PathLike) or isinstance(path, str):
        p = Path(path)
        if p.parent and p.parent != Path(".") and not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(path, check_same_thread=False, factory=factory())
    conn.row_factory = sqlite3.Row
    text = os.fspath(path) if isinstance(path, (str, os.PathLike)) else ""
    if text and text != ":memory:" and not text.startswith("file:"):
        conn.file = str(Path(text).resolve())

    # Enable foreign keys.
    conn.execute("PRAGMA foreign_keys=ON")

    # WAL journal mode; ignore failure for in-memory databases.
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.OperationalError:
        pass

    return conn



class BatchedCommits:
    """A connection that only really commits every `every` times it is asked to. A scan saves hundreds or thousands of devices, and every helper commits
    for itself (a commit is a write to disk: about a millisecond each, so 17,000 of them are 17 seconds for 10,000 devices). Progress is still saved in
    steps, and the caller commits for real at the end."""

    def __init__(self, conn: sqlite3.Connection, every: int = 250) -> None:
        self._conn, self._every, self._asked = conn, every, 0

    def commit(self) -> None:
        self._asked += 1
        if self._asked % self._every == 0:
            self._conn.commit()

    def __getattr__(self, name: str):
        return getattr(self._conn, name)


def _allow_operator_role(conn: sqlite3.Connection) -> None:
    """The users table once only allowed the roles admin and viewer in a CHECK constraint, which SQLite cannot change in place: rebuild the table
    (keeping every row, the id and the foreign keys of sessions and tokens) so that `operator` is accepted too."""
    row = conn.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'").fetchone()
    if row is None or "'operator'" in row[0]:
        return
    sql = row[0]
    new_sql = re.sub(r"\(\s*'admin'\s*,\s*'viewer'\s*\)", "('admin', 'operator', 'viewer')", sql)
    if new_sql == sql:
        return
    new_sql = re.sub(r"CREATE TABLE (IF NOT EXISTS )?users\b", "CREATE TABLE users_new", new_sql, count=1)
    conn.commit()
    conn.execute("PRAGMA foreign_keys = OFF")
    try:
        conn.execute("DROP TABLE IF EXISTS users_new")
        conn.execute(new_sql)
        conn.execute("INSERT INTO users_new SELECT * FROM users")
        conn.execute("DROP TABLE users")
        conn.execute("ALTER TABLE users_new RENAME TO users")
        conn.commit()
    finally:
        conn.execute("PRAGMA foreign_keys = ON")


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
            INSERT INTO hypervisor_guests
                (plugin_id, guest_id, name, kind, host_name, status, macs, ips, device_id, host_device_id, updated)
            SELECT 'proxmox', CAST(vmid AS TEXT), name, kind, node, status, macs, ips, device_id, host_device_id, updated
            FROM proxmox_guests WHERE 1 = 1
            ON CONFLICT DO NOTHING
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

    # smart-home hubs (kind "inventory", see app/inventory.py)
    cur.execute("CREATE TABLE IF NOT EXISTS inventory_servers (plugin_id TEXT NOT NULL, server_id TEXT NOT NULL, name TEXT NOT NULL, ip TEXT, version TEXT, online INTEGER NOT NULL DEFAULT 1, warnings TEXT NOT NULL DEFAULT '[]', PRIMARY KEY (plugin_id, server_id))")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS inventory_devices (
            plugin_id TEXT NOT NULL, dev_id TEXT NOT NULL, server_id TEXT NOT NULL, name TEXT NOT NULL, manufacturer TEXT, model TEXT, area TEXT, sw TEXT, protocol TEXT,
            mac TEXT, ip TEXT, via_id TEXT, available INTEGER NOT NULL DEFAULT 1, battery INTEGER, battery_low INTEGER NOT NULL DEFAULT 0, update_available INTEGER NOT NULL DEFAULT 0,
            url TEXT, entities INTEGER, device_id INTEGER, unavailable_since TEXT, PRIMARY KEY (plugin_id, dev_id)
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_inventory_devices_device ON inventory_devices(device_id)")

    # escalation of unacknowledged alerts (paid, see app/escalation.py)
    cur.execute("CREATE TABLE IF NOT EXISTS escalation_state (event_id INTEGER PRIMARY KEY, level INTEGER NOT NULL DEFAULT 0, sent_at TEXT, acked_by TEXT, acked_at TEXT)")

    # auto-remediation (paid, see app/remediation.py)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS remediation_rules (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, kinds TEXT NOT NULL DEFAULT '[]', device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
            match_text TEXT NOT NULL DEFAULT '', action TEXT NOT NULL, secret TEXT NOT NULL DEFAULT '', mode TEXT NOT NULL DEFAULT 'ask', cooldown_min INTEGER NOT NULL DEFAULT 30,
            max_per_day INTEGER NOT NULL DEFAULT 3, created TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS remediation_runs (
            id INTEGER PRIMARY KEY, rule_id INTEGER, rule_name TEXT NOT NULL, action_type TEXT NOT NULL, event_id INTEGER, device_id INTEGER, kind TEXT, detail TEXT,
            state TEXT NOT NULL, result TEXT, analysis TEXT, created TEXT NOT NULL, decided_by TEXT, decided_at TEXT, finished TEXT, recovered TEXT
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_remediation_runs_rule ON remediation_runs(rule_id, device_id, created)")

    # IPv6 addresses of the devices (optional feature, see app/scanner/ipv6.py)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS device_ipv6 (
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            ip TEXT NOT NULL,
            scope TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(device_id, ip)
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
    # covers the uptime sums and the per-device scans over a time window without reading the table rows (about three times faster); it replaces the plain ts index
    cur.execute("CREATE INDEX IF NOT EXISTS idx_checks_cover ON checks(ts, device_id, up)")
    cur.execute("DROP INDEX IF EXISTS idx_checks_ts")
    # beat = 1: a quick ping between two scans (app/beats.py). Those rows are many (one a minute per device), so they are kept for days only; the hourly roll-up keeps their count for good
    _add_column_if_missing(conn, "checks", "beat", "INTEGER NOT NULL DEFAULT 0")
    # importance of a device / a service check / the event it raised: critical, normal or low (it steers how loudly a problem is reported)
    _add_column_if_missing(conn, "devices", "tier", "TEXT NOT NULL DEFAULT 'normal'")
    _add_column_if_missing(conn, "events", "tier", "TEXT NOT NULL DEFAULT 'normal'")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_checks_beat ON checks(beat, ts)")

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
    # --- schema v8: port baselines (baseline_at NULL = the device has none) ---------------------
    _add_column_if_missing(conn, "devices", "baseline_at", "TEXT")
    _add_column_if_missing(conn, "devices", "gentle", "INTEGER NOT NULL DEFAULT 0")  # v14: scans never probe this device's services
    _add_column_if_missing(conn, "devices", "gentle_off", "INTEGER NOT NULL DEFAULT 0")  # 1 = the owner turned gentle scanning off although its type would have it on
    # --- schema v9: users, login sessions and API tokens ---------------------------------------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
            disabled INTEGER NOT NULL DEFAULT 0,
            created TEXT NOT NULL,
            last_login TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created TEXT NOT NULL,
            expires TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            created TEXT NOT NULL,
            last_used TEXT
        )
        """
    )
    # --- schema v10: read-only share links ---------------------------------------------------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS share_links (
            id INTEGER PRIMARY KEY,
            token TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            mode TEXT NOT NULL CHECK (mode IN ('view', 'status')),
            show_ips INTEGER NOT NULL DEFAULT 0,
            show_macs INTEGER NOT NULL DEFAULT 0,
            created TEXT NOT NULL,
            expires TEXT,
            last_used TEXT,
            views INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    # --- schema v34: share links choose their sections, scope and look, can have a PIN and a start date -----------
    _add_column_if_missing(conn, "share_links", "options", "TEXT NOT NULL DEFAULT '{}'")      # JSON: sections, groups, services, texts, theme (see app/shares.py)
    _add_column_if_missing(conn, "share_links", "pin_hash", "TEXT")                         # optional PIN, asked before any data is sent
    _add_column_if_missing(conn, "share_links", "valid_from", "TEXT")                       # the link works from this moment on
    # --- schema v11: DHCP servers seen on the network (network checks) ----------------------------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS dhcp_servers (
            ip TEXT PRIMARY KEY,
            trusted INTEGER NOT NULL DEFAULT 0,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            router TEXT,
            dns TEXT NOT NULL DEFAULT '[]',
            domain TEXT,
            offered_ip TEXT
        )
        """
    )
    # --- schema v13: nmap's device class ("webcam", "printer", "media device"...) is kept between scans -------
    _add_column_if_missing(conn, "devices", "os_type", "TEXT")
    # --- schema v12: device groups (rooms, floors, owners) ---------------------------------------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS device_groups (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE COLLATE NOCASE,
            color TEXT NOT NULL
        )
        """
    )
    _add_column_if_missing(conn, "devices", "group_id", "INTEGER REFERENCES device_groups(id) ON DELETE SET NULL")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS port_baselines (
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            proto TEXT NOT NULL,
            port INTEGER NOT NULL,
            PRIMARY KEY (device_id, proto, port)
        )
        """
    )
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
    # ports of a switch as a topology plugin reports them (link state, speed, packet counters), the latest state and a history of counter samples
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS switch_ports (
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            port INTEGER NOT NULL,
            plugin_id TEXT NOT NULL,
            name TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            up INTEGER NOT NULL DEFAULT 0,
            speed_mbps REAL,
            duplex TEXT,
            tx_packets BIGINT, rx_packets BIGINT, tx_errors BIGINT, rx_errors BIGINT,
            updated TEXT NOT NULL,
            PRIMARY KEY (device_id, port)
        )
        """
    )
    _add_column_if_missing(conn, "ports", "cpe", "TEXT")          # the CPE name(s) nmap derived from the service banner (for the version-based CVE check)
    cur.execute("CREATE TABLE IF NOT EXISTS cve_cache (cpe TEXT PRIMARY KEY, fetched TEXT NOT NULL, data TEXT NOT NULL)")
    _add_column_if_missing(conn, "switch_ports", "tx_bytes", "BIGINT")
    _add_column_if_missing(conn, "switch_ports", "rx_bytes", "BIGINT")
    # how much traffic each application and each device used on a day, as a router or controller counts it (the latest figure of the day wins)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS app_usage (
            day TEXT NOT NULL,
            source TEXT NOT NULL,
            name TEXT NOT NULL,
            rx_bytes BIGINT NOT NULL DEFAULT 0,
            tx_bytes BIGINT NOT NULL DEFAULT 0,
            updated TEXT NOT NULL,
            PRIMARY KEY (day, source, name)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS client_usage (
            day TEXT NOT NULL,
            source TEXT NOT NULL,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            rx_bytes BIGINT NOT NULL DEFAULT 0,
            tx_bytes BIGINT NOT NULL DEFAULT 0,
            updated TEXT NOT NULL,
            PRIMARY KEY (day, source, device_id)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS client_app_usage (
            day TEXT NOT NULL,
            source TEXT NOT NULL,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            rx_bytes BIGINT NOT NULL DEFAULT 0,
            tx_bytes BIGINT NOT NULL DEFAULT 0,
            updated TEXT NOT NULL,
            PRIMARY KEY (day, source, device_id, name)
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_client_app_usage_device ON client_app_usage (device_id, day)")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS firewall_state (
            device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
            plugin_id TEXT NOT NULL,
            data TEXT NOT NULL,
            updated TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS switch_port_samples (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            port INTEGER NOT NULL,
            ts TEXT NOT NULL,
            up INTEGER NOT NULL DEFAULT 0,
            speed_mbps REAL,
            tx_packets BIGINT, rx_packets BIGINT, tx_errors BIGINT, rx_errors BIGINT
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_switch_port_samples ON switch_port_samples(device_id, port, ts)")
    # --- schema v17: what a plugin reports about a guest (a container's image, health, published ports), JSON ---
    _add_column_if_missing(conn, "hypervisor_guests", "details", "TEXT NOT NULL DEFAULT '{}'")
    # --- schema v16: DNS registration (see app/dns) -------------------------------------------
    _add_column_if_missing(conn, "devices", "dns_mode", "TEXT NOT NULL DEFAULT 'auto'")   # auto | always | never
    _add_column_if_missing(conn, "devices", "dns_name", "TEXT")                           # the user's own DNS name
    # --- schema v31: an API token can be read-only whatever the role of its user ---------------------------------
    _add_column_if_missing(conn, "api_tokens", "readonly", "INTEGER NOT NULL DEFAULT 0")
    _add_column_if_missing(conn, "api_tokens", "assistant", "TEXT")          # NULL = an ordinary token; 'read' or 'change' = a token made for an AI assistant (app/assistant.py)

    # --- schema v30: users that sign in through an identity provider are recognised by its stable subject id -----
    _add_column_if_missing(conn, "users", "oidc_sub", "TEXT")
    # --- schema v33: hourly roll-up of the checks, so availability over weeks stays quick on a big network (see app/checkstats.py) --------
    conn.execute(
        "CREATE TABLE IF NOT EXISTS checks_hourly (device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE, hour TEXT NOT NULL, n INTEGER NOT NULL, up INTEGER NOT NULL, "
        "rtt_sum REAL NOT NULL DEFAULT 0, rtt_n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (device_id, hour)) WITHOUT ROWID")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_checks_hourly_hour ON checks_hourly(hour, device_id)")

    # --- schema v32: the role operator, and a user (a viewer) that can see only some groups ---------------------
    _add_column_if_missing(conn, "users", "scope", "TEXT")          # JSON list of group ids; NULL = everything
    _add_column_if_missing(conn, "users", "site_scope", "TEXT")      # JSON list of remote site ids a viewer may see; NULL = none (see `scope`)
    _allow_operator_role(conn)
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_oidc_sub ON users(oidc_sub) WHERE oidc_sub IS NOT NULL")

    # --- schema v18: events held back by a maintenance window carry the window's name ----------------------
    _add_column_if_missing(conn, "events", "maintenance", "TEXT")

    # --- schema v19: sites published by a reverse proxy plugin (Nginx Proxy Manager ...) -----------------------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS proxy_sites (
            plugin_id TEXT NOT NULL,
            site_id TEXT NOT NULL,
            proxy_id TEXT NOT NULL,
            proxy_name TEXT NOT NULL DEFAULT '',
            proxy_device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            type TEXT NOT NULL,
            domains TEXT NOT NULL DEFAULT '[]',
            enabled INTEGER NOT NULL DEFAULT 1,
            scheme TEXT NOT NULL DEFAULT 'http',
            forward_host TEXT NOT NULL DEFAULT '',
            forward_port INTEGER,
            target_device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            target_plugin_id TEXT,
            target_guest_id TEXT,
            target_name TEXT NOT NULL DEFAULT '',
            target_how TEXT NOT NULL DEFAULT '',
            details TEXT NOT NULL DEFAULT '{}',
            updated TEXT NOT NULL,
            PRIMARY KEY (plugin_id, site_id)
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_proxy_sites_target ON proxy_sites(target_device_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_proxy_sites_proxy ON proxy_sites(proxy_device_id)")

    # --- schema v26: what a vulnerability plugin (Greenbone, Tenable, Rapid7 ...) reports: the scanners and the open findings per host ---------------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS vuln_servers (
            plugin_id TEXT NOT NULL, server_id TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', version TEXT NOT NULL DEFAULT '', online INTEGER NOT NULL DEFAULT 1,
            last_scan TEXT, warnings TEXT NOT NULL DEFAULT '[]', updated TEXT NOT NULL,
            PRIMARY KEY (plugin_id, server_id)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS vuln_findings (
            plugin_id TEXT NOT NULL, finding_id TEXT NOT NULL, server_id TEXT NOT NULL, device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            host_ip TEXT, host_mac TEXT, host_name TEXT NOT NULL DEFAULT '', title TEXT NOT NULL, cves TEXT NOT NULL DEFAULT '[]', severity TEXT NOT NULL,
            score REAL, port INTEGER, proto TEXT NOT NULL DEFAULT 'tcp', first_seen TEXT, last_seen TEXT, exploited INTEGER NOT NULL DEFAULT 0,
            solution TEXT NOT NULL DEFAULT '', url TEXT NOT NULL DEFAULT '', updated TEXT NOT NULL,
            PRIMARY KEY (plugin_id, finding_id)
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_vuln_device ON vuln_findings (device_id)")
    # --- schema v22: what a backup plugin (Proxmox Backup Server ...) reports: servers, stores, what is backed up, recent problems ---------------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS backup_servers (
            plugin_id TEXT NOT NULL, server_id TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', ip TEXT, version TEXT NOT NULL DEFAULT '',
            online INTEGER NOT NULL DEFAULT 1, device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL, warnings TEXT NOT NULL DEFAULT '[]', updated TEXT NOT NULL,
            PRIMARY KEY (plugin_id, server_id)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS backup_stores (
            plugin_id TEXT NOT NULL, store_id TEXT NOT NULL, server_id TEXT NOT NULL, name TEXT NOT NULL DEFAULT '',
            total INTEGER, used INTEGER, avail INTEGER, full TEXT, level TEXT NOT NULL DEFAULT 'ok',
            gc_state TEXT NOT NULL DEFAULT 'none', gc_at TEXT, prune_state TEXT NOT NULL DEFAULT 'none', prune_at TEXT,
            verify_state TEXT NOT NULL DEFAULT 'none', verify_at TEXT, sync_state TEXT NOT NULL DEFAULT 'none', sync_at TEXT, updated TEXT NOT NULL,
            PRIMARY KEY (plugin_id, store_id)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS backup_targets (
            plugin_id TEXT NOT NULL, target_id TEXT NOT NULL, server_id TEXT NOT NULL, store_id TEXT, type TEXT NOT NULL DEFAULT 'other', backup_id TEXT NOT NULL,
            name TEXT NOT NULL DEFAULT '', count INTEGER NOT NULL DEFAULT 0, last_backup TEXT, last_state TEXT NOT NULL DEFAULT 'unknown', last_size INTEGER,
            verify_state TEXT NOT NULL DEFAULT 'none', interval INTEGER, protected INTEGER NOT NULL DEFAULT 0,
            guest_plugin_id TEXT, guest_id TEXT, device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL, stale INTEGER NOT NULL DEFAULT 0, updated TEXT NOT NULL,
            PRIMARY KEY (plugin_id, target_id)
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_backup_targets_device ON backup_targets(device_id)")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS backup_problems (
            plugin_id TEXT NOT NULL, problem_id TEXT NOT NULL, server_id TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'other', state TEXT NOT NULL DEFAULT 'failed',
            at TEXT, text TEXT NOT NULL DEFAULT '', target_id TEXT, PRIMARY KEY (plugin_id, problem_id)
        )
        """
    )

    # --- schema v34: what a storage plugin (NetApp, Dell, Pure, Ceph ...) reports: systems, controllers, pools, volumes, disks, alerts -----------
    for sql in (
        """CREATE TABLE IF NOT EXISTS storage_systems (
            plugin_id TEXT NOT NULL, system_id TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', ip TEXT, vendor TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '',
            version TEXT NOT NULL DEFAULT '', serial TEXT NOT NULL DEFAULT '', online INTEGER NOT NULL DEFAULT 1, health TEXT NOT NULL DEFAULT 'unknown',
            device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL, warnings TEXT NOT NULL DEFAULT '[]', updated TEXT NOT NULL, PRIMARY KEY (plugin_id, system_id))""",
        """CREATE TABLE IF NOT EXISTS storage_controllers (
            plugin_id TEXT NOT NULL, controller_id TEXT NOT NULL, system_id TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', ip TEXT, mac TEXT, online INTEGER NOT NULL DEFAULT 1,
            health TEXT NOT NULL DEFAULT 'unknown', device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL, updated TEXT NOT NULL, PRIMARY KEY (plugin_id, controller_id))""",
        """CREATE TABLE IF NOT EXISTS storage_pools (
            plugin_id TEXT NOT NULL, pool_id TEXT NOT NULL, system_id TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', total INTEGER, used INTEGER, avail INTEGER,
            health TEXT NOT NULL DEFAULT 'unknown', raid TEXT NOT NULL DEFAULT '', level TEXT NOT NULL DEFAULT 'ok', updated TEXT NOT NULL, PRIMARY KEY (plugin_id, pool_id))""",
        """CREATE TABLE IF NOT EXISTS storage_volumes (
            plugin_id TEXT NOT NULL, volume_id TEXT NOT NULL, system_id TEXT NOT NULL, pool_id TEXT, name TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT 'volume',
            protocol TEXT NOT NULL DEFAULT '', size INTEGER, used INTEGER, health TEXT NOT NULL DEFAULT 'unknown', clients TEXT NOT NULL DEFAULT '[]', updated TEXT NOT NULL,
            PRIMARY KEY (plugin_id, volume_id))""",
        """CREATE TABLE IF NOT EXISTS storage_disks (
            plugin_id TEXT NOT NULL, disk_id TEXT NOT NULL, system_id TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', slot TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '',
            size INTEGER, state TEXT NOT NULL DEFAULT 'unknown', updated TEXT NOT NULL, PRIMARY KEY (plugin_id, disk_id))""",
        """CREATE TABLE IF NOT EXISTS storage_alerts (
            plugin_id TEXT NOT NULL, alert_id TEXT NOT NULL, system_id TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'warning', text TEXT NOT NULL DEFAULT '', at TEXT,
            PRIMARY KEY (plugin_id, alert_id))""",
    ):
        cur.execute(sql)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_storage_controllers_device ON storage_controllers(device_id)")

    # --- schema v21: "always on" devices (the core devices the availability can be limited to) ----------------
    _add_column_if_missing(conn, "devices", "always_on", "INTEGER NOT NULL DEFAULT 0")
    # --- schema v23: a device that is left out of the weekly and monthly reports (a test machine, a guest's phone) ---
    _add_column_if_missing(conn, "devices", "report_exclude", "INTEGER NOT NULL DEFAULT 0")

    # --- schema v20: speed tests (internet, iperf3, browser) ----------------------------------------------------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS speedtests (
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            kind TEXT NOT NULL,
            target TEXT NOT NULL DEFAULT '',
            down_mbps REAL,
            up_mbps REAL,
            latency_ms REAL,
            jitter_ms REAL,
            ok INTEGER NOT NULL DEFAULT 1,
            error TEXT,
            detail TEXT NOT NULL DEFAULT '{}'
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_speedtests_kind_ts ON speedtests(kind, ts)")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_state (
            device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
            auto_name TEXT,
            first_missing TEXT,
            state TEXT,
            reason TEXT,
            fqdn TEXT,
            updated TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_records (
            plugin_id TEXT NOT NULL,
            zone TEXT NOT NULL,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            device_id INTEGER,
            created TEXT NOT NULL,
            PRIMARY KEY (plugin_id, zone, name, type, value)
        )
        """
    )
    # --- schema v15: where a client is connected (switch and port), as reported by a topology plugin ---
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS client_links (
            device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
            plugin_id TEXT NOT NULL,
            node_mac TEXT,
            node_name TEXT,
            port TEXT,
            medium TEXT,
            updated TEXT NOT NULL
        )
        """
    )
    # --- port map: a link can be set by hand, and knows which device (switch) it hangs on ---------------------------
    _add_column_if_missing(conn, "client_links", "source", "TEXT NOT NULL DEFAULT 'plugin'")   # 'plugin' | 'manual' (manual is never overwritten)
    _add_column_if_missing(conn, "client_links", "node_device_id", "INTEGER")                   # the switch as a device of its own
    _add_column_if_missing(conn, "client_links", "seen_node", "TEXT")                           # manual links: what a plugin reports instead
    _add_column_if_missing(conn, "client_links", "seen_port", "TEXT")
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
    _add_column_if_missing(conn, "service_checks", "tier", "TEXT NOT NULL DEFAULT 'normal'")       # importance, see devices.tier
    # --- schema v19: checks made by a plugin, and checks that go through a reverse proxy
    _add_column_if_missing(conn, "service_checks", "source", "TEXT")      # who made the check (a plugin), NULL = the user
    _add_column_if_missing(conn, "service_checks", "via", "TEXT")         # connect to this address, but ask for `host` (Host header / SNI)

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

    # --- host probes: what uses the storage of a host (see app/hostprobe), kept as snapshots so a jump can be traced afterwards ---
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS probe_snapshots (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            taken TEXT NOT NULL,
            ok INTEGER NOT NULL,
            mode TEXT,
            error TEXT,
            data TEXT
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_probe_snapshots_device ON probe_snapshots (device_id, taken)")
    _add_column_if_missing(conn, "probe_snapshots", "probe", "TEXT NOT NULL DEFAULT 'storage'")          # which probe took it (storage, cpu, memory ...)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_probe_snapshots_probe ON probe_snapshots (device_id, probe, taken)")
    _add_column_if_missing(conn, "probe_snapshots", "reason", "TEXT NOT NULL DEFAULT 'schedule'")       # why it was taken: schedule, alarm (while a reading was over its limit: not 'normal') or manual
    # --- analysis reports: what the digital engineer concluded, kept under an id so another system can fetch it later (see app/analysis.py) ---
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS analysis_reports (
            id INTEGER PRIMARY KEY,
            kind TEXT NOT NULL,
            incident_id INTEGER,
            device_id INTEGER,
            created TEXT NOT NULL,
            trigger TEXT NOT NULL,
            title TEXT NOT NULL,
            cause TEXT,
            data TEXT NOT NULL
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_analysis_incident ON analysis_reports (incident_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_analysis_created ON analysis_reports (created)")

    # --- agent ingest (Enterprise): hosts that push metrics through a collector, identified by a client certificate (app/ingest) -----------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ingest_agents (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            identity TEXT NOT NULL DEFAULT '',
            state TEXT NOT NULL DEFAULT 'pending',
            token_hash TEXT,
            token_expires TEXT,
            cert_fp TEXT,
            cert_expires TEXT,
            prev_fp TEXT,
            prev_expires TEXT,
            interval_s INTEGER NOT NULL DEFAULT 60,
            last_seen TEXT,
            last_ip TEXT,
            accepted INTEGER NOT NULL DEFAULT 0,
            dropped INTEGER NOT NULL DEFAULT 0,
            rejected INTEGER NOT NULL DEFAULT 0,
            silent INTEGER NOT NULL DEFAULT 0,
            renewed TEXT,
            created TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ingest_targets (
            agent_id INTEGER NOT NULL REFERENCES ingest_agents(id) ON DELETE CASCADE,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            host_name TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (agent_id, device_id)
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ingest_token ON ingest_agents (token_hash)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ingest_fp ON ingest_agents (cert_fp)")

    # --- schema v22: host monitors (health readings over SNMP or SSH) and the level each reading is at ---------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS host_monitors (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL UNIQUE REFERENCES devices(id) ON DELETE CASCADE,
            method TEXT NOT NULL,
            address TEXT NOT NULL,
            port INTEGER NOT NULL,
            credential TEXT NOT NULL DEFAULT '',
            interval_s INTEGER NOT NULL DEFAULT 60,
            groups TEXT NOT NULL DEFAULT '[]',
            alerts INTEGER NOT NULL DEFAULT 1,
            enabled INTEGER NOT NULL DEFAULT 1,
            last_ts TEXT,
            last_ok INTEGER,
            last_error TEXT,
            since TEXT,
            created TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS metric_state (
            monitor_id INTEGER NOT NULL REFERENCES host_monitors(id) ON DELETE CASCADE,
            metric TEXT NOT NULL,
            label TEXT NOT NULL DEFAULT '',
            level TEXT NOT NULL DEFAULT 'ok',
            since TEXT,
            value REAL,
            pending TEXT,
            pending_n INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (monitor_id, metric, label)
        )
        """
    )

    # --- schema v23: remote sites (other Netlens instances that report to this one) --------------------------------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS probes (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            created TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            last_seen TEXT,
            last_ip TEXT,
            version TEXT,
            interval_s INTEGER NOT NULL DEFAULT 60,
            snapshot_ts TEXT,
            offline_notified INTEGER NOT NULL DEFAULT 0,
            summary TEXT NOT NULL DEFAULT '{}'
        )
        """
    )
    _add_column_if_missing(conn, "probes", "customer", "TEXT NOT NULL DEFAULT ''")             # who the site belongs to (an IT-support person looks after several customers)
    _add_column_if_missing(conn, "probes", "keep_days", "INTEGER")                              # how long this site's history is kept here; NULL = the general retention
    _add_column_if_missing(conn, "probes", "alert_mode", "TEXT NOT NULL DEFAULT 'auto'")        # which devices raise offline alerts: auto, core, all, none
    _add_column_if_missing(conn, "probes", "muted", "TEXT NOT NULL DEFAULT '[]'")               # JSON list of device keys that raise no offline alert
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS remote_devices (
            id INTEGER PRIMARY KEY,
            probe_id INTEGER NOT NULL REFERENCES probes(id) ON DELETE CASCADE,
            key TEXT NOT NULL,
            mac TEXT,
            ip TEXT,
            name TEXT NOT NULL,
            vendor TEXT,
            type TEXT,
            os TEXT,
            online INTEGER NOT NULL DEFAULT 1,
            always_on INTEGER NOT NULL DEFAULT 0,
            ports TEXT NOT NULL DEFAULT '[]',
            first_seen TEXT,
            last_seen TEXT,
            UNIQUE (probe_id, key)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS remote_services (
            id INTEGER PRIMARY KEY,
            probe_id INTEGER NOT NULL REFERENCES probes(id) ON DELETE CASCADE,
            key TEXT NOT NULL,
            name TEXT NOT NULL,
            kind TEXT,
            target TEXT,
            state TEXT,
            ms REAL,
            detail TEXT,
            since TEXT,
            checked TEXT,
            UNIQUE (probe_id, key)
        )
        """
    )

    # --- schema v24: a health monitor can be set up by the central Netlens (source = 'central')
    _add_column_if_missing(conn, "host_monitors", "source", "TEXT")
    # --- a second factor for local accounts (TOTP, app/totp.py): the secret is encrypted, the counter makes a code usable once -------------------
    _add_column_if_missing(conn, "users", "totp_secret", "TEXT")
    _add_column_if_missing(conn, "users", "totp_enabled", "INTEGER NOT NULL DEFAULT 0")
    _add_column_if_missing(conn, "users", "totp_counter", "INTEGER NOT NULL DEFAULT 0")
    _add_column_if_missing(conn, "users", "totp_since", "TEXT")
    # --- break-glass accounts and governed API tokens (app/secpolicy.py) -------------------------------------------------------------------------
    _add_column_if_missing(conn, "users", "break_glass", "INTEGER NOT NULL DEFAULT 0")
    _add_column_if_missing(conn, "api_tokens", "expires", "TEXT")
    _add_column_if_missing(conn, "api_tokens", "allowed_ips", "TEXT")
    # --- sessions that can be listed and ended, and limited (app/secpolicy.py) ---------------------------------------------------------------------
    for col in ("last_seen", "ip", "user_agent", "auth_at", "auth_method"):
        _add_column_if_missing(conn, "sessions", col, "TEXT")
    _add_column_if_missing(conn, "sessions", "seq", "INTEGER")          # a running number: "the newest sessions" without relying on a clock that has seconds only
    # --- terminal session recordings (app/recordings.py): metadata here, the encrypted transcript in a file ----------------------------------------
    conn.execute("CREATE TABLE IF NOT EXISTS session_recordings (id INTEGER PRIMARY KEY, user TEXT NOT NULL, device_id INTEGER, device TEXT, proto TEXT, started TEXT NOT NULL, ended TEXT, "
                 "bytes INTEGER NOT NULL DEFAULT 0, chunks INTEGER NOT NULL DEFAULT 0, truncated INTEGER NOT NULL DEFAULT 0, file TEXT NOT NULL DEFAULT '', sha256 TEXT, status TEXT NOT NULL)")
    # --- four-eyes approval (app/approvals.py) ----------------------------------------------------------------------------------------------------
    conn.execute("CREATE TABLE IF NOT EXISTS approvals (id INTEGER PRIMARY KEY, action TEXT NOT NULL, target TEXT NOT NULL, label TEXT, reason TEXT NOT NULL, requester_id INTEGER NOT NULL, "
                 "requester TEXT NOT NULL, created TEXT NOT NULL, status TEXT NOT NULL, decided_by TEXT, decided_at TEXT, comment TEXT, expires TEXT, used_at TEXT)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, requester_id)")
    # --- security keys and passkeys as a second factor (app/webauthn.py): only public keys are kept --------------------------------------------------
    _add_column_if_missing(conn, "users", "webauthn_enabled", "INTEGER NOT NULL DEFAULT 0")
    _add_column_if_missing(conn, "users", "cert_identity", "TEXT")          # who a client certificate must say it is (app/certlogin.py)
    for col, decl in (("scim_managed", "INTEGER NOT NULL DEFAULT 0"), ("scim_external", "TEXT"), ("scim_user_name", "TEXT"), ("scim_email", "TEXT"), ("scim_display", "TEXT")):
        _add_column_if_missing(conn, "users", col, decl)                    # accounts made by the identity provider (app/scim.py)
    _add_column_if_missing(conn, "users", "custom_role", "TEXT")          # a custom role (app/roles.py): `role` stays its base, so every role check keeps denying by default
    conn.execute("CREATE TABLE IF NOT EXISTS user_webauthn (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL, "
                 "credential_id TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0, aaguid TEXT, transports TEXT, created TEXT NOT NULL, last_used TEXT)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_user_webauthn_user ON user_webauthn(user_id)")
    conn.execute("CREATE TABLE IF NOT EXISTS user_recovery_codes (user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, code_hash TEXT NOT NULL, "
                 "created TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (user_id, code_hash))")
    _add_column_if_missing(conn, "ingest_agents", "cert_ca", "TEXT")          # fingerprint of the CA that issued the current certificate (CA rotation)

    # --- schema v26: the outcome of every plugin sync (heartbeats and response time of the plugins) ---------------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS plugin_runs (
            id INTEGER PRIMARY KEY,
            plugin_id TEXT NOT NULL,
            ts TEXT NOT NULL,
            ok INTEGER NOT NULL,
            ms REAL,
            detail TEXT
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_plugin_runs ON plugin_runs(plugin_id, ts)")
    # --- schema v25: audit log (who changed what) -----------------------------------------------------------------
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            user TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT '',
            ip TEXT NOT NULL DEFAULT '',
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            status INTEGER NOT NULL,
            action TEXT NOT NULL
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)")
    _add_column_if_missing(conn, "audit_log", "chain", "TEXT")          # the tamper-evident link (app/auditchain.py); NULL on rows from before it existed

    # Indexes
    cur.execute("CREATE INDEX IF NOT EXISTS idx_device_ips_ip ON device_ips(ip)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_device ON events(device_id)")           # removing a device sets its events to NULL: without this each removal reads every event
    cur.execute("CREATE INDEX IF NOT EXISTS idx_events_kind_ts ON events(kind, ts)")
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
            device_id = insert_id(
                conn,
                """
                INSERT INTO devices (mac, primary_ip, first_seen, last_seen, online)
                VALUES (?, ?, ?, ?, 1)
                """,
                (normalized_mac, ip, now, now),
            )
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
            device_id = insert_id(
                conn,
                """
                INSERT INTO devices (mac, primary_ip, first_seen, last_seen, online)
                VALUES (?, ?, ?, ?, 1)
                """,
                (None, ip, now, now),
            )

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
    subject: str | None = None,
) -> int:
    """Insert an event, commit, and return the event id. `subject` names what the event is about (for snoozes); a device
    that goes offline or comes back is its own subject."""
    if now is None:
        now = utcnow()

    from app.maintenance import tag_for

    try:
        window = tag_for(conn, kind, device_id, now, subject)
    except Exception:  # noqa: BLE001 - a broken window list must never lose an event
        window = None
    if subject is None and device_id is not None and kind in ("device_offline", "device_online"):
        subject = f"device:{device_id}"
    if window is None and subject:
        try:
            from app import snooze

            window = snooze.tag(conn, kind, subject, now)
        except Exception:  # noqa: BLE001 - same: never lose an event over a broken snooze list
            window = None
    tier = "normal"
    try:
        if subject and subject.startswith("service:") and subject[8:].isdigit():
            row = conn.execute("SELECT tier FROM service_checks WHERE id = ?", (int(subject[8:]),)).fetchone()
        elif device_id is not None:
            row = conn.execute("SELECT tier FROM devices WHERE id = ?", (device_id,)).fetchone()
        else:
            row = None
        if row is not None and row[0] in ("critical", "low"):
            tier = row[0]
    except Exception:  # noqa: BLE001 - an event is never lost over a missing column
        tier = "normal"
    new_id = insert_id(
        conn,
        """
        INSERT INTO events (ts, device_id, kind, detail, maintenance, tier)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (now, device_id, kind, detail, window, tier),
    )
    conn.commit()
    return new_id


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
    if not row:
        return None
    value = row["value"]
    if isinstance(value, str) and value.startswith("enc:v1:"):        # a secret setting (see app/vault.py)
        from app import vault

        try:
            return vault.decrypt(conn, value)
        except vault.VaultError:
            vault.note_unreadable(conn, key)
            return None
    return value


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    from app import vault

    if value and vault.is_secret_key(key):                              # passwords and tokens are stored encrypted
        try:
            value = vault.encrypt(conn, value)
        except (OSError, ValueError):                                   # no usable key file: better stored plain than lost
            import logging

            logging.getLogger(__name__).warning("could not encrypt %s: the key file cannot be read or created", key)
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    conn.commit()


def delete_setting(conn: sqlite3.Connection, key: str) -> None:
    conn.execute("DELETE FROM settings WHERE key = ?", (key,))
    conn.commit()
