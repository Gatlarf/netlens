"""Audit log: who changed what, and when.

Every request that changes something (a POST, PUT, PATCH or DELETE that succeeded) is written down with the signed-in user, the
address it came from and a sentence about what it did. Request bodies are never stored (they hold passwords and tokens), only the
path and the sentence. Sign-ins, failed sign-ins and sign-outs are recorded too. Entries are kept for a year.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any

from app.db import ago, utcnow

RETENTION_DAYS = 365
MAX_ROWS = 50000
# what is not worth a line: personal preferences, probes reporting with their token, the browser's own speed test, the terminal protocol
SKIP = re.compile(r"^/api/(login|logout|me/preferences|dashboard/layout|probe/(push|relay)|speedtest/(up|down|ping|browser)|devices/\d+/(ping|trace)|insights/(ask|identify|model-check|incidents/\d+/words)|hostprobe/(ca|settings)$|credentials(/[0-9a-f]+)?$|hosts/(apply|settings)$|devices/\d+/hostprobe/(run|diagnose|install)$|analysis/\d+/send$)")

# (method, path regex, sentence). {0}, {1}... are the groups; a device id becomes the device's name.
PATTERNS: list[tuple[str, str, str]] = [
    ("POST", r"^/api/scans$", "Started a scan"),
    ("DELETE", r"^/api/scans/current$", "Cancelled the running scan"),
    ("POST", r"^/api/devices/(\d+)/scan$", "Started a full scan of {d0}"),
    ("POST", r"^/api/devices/(\d+)/wake$", "Sent a Wake-on-LAN packet to {d0}"),
    ("PATCH", r"^/api/devices/(\d+)$", "Changed the settings of {d0}"),
    ("DELETE", r"^/api/devices/(\d+)$", "Deleted the device {d0}"),
    ("PUT", r"^/api/devices/(\d+)/monitor$", "Set up or changed health monitoring of {d0}"),
    ("DELETE", r"^/api/devices/(\d+)/monitor$", "Removed health monitoring of {d0}"),
    ("PUT", r"^/api/devices/(\d+)/limits$", "Changed the health limits of {d0}"),
    ("PUT", r"^/api/monitoring/limits$", "Changed the general health limits"),
    ("POST", r"^/api/devices/(\d+)/monitor/run$", "Read the health of {d0} now"),
    ("POST", r"^/api/service-checks$", "Added a service check"),
    ("PATCH", r"^/api/service-checks/(\d+)$", "Changed service check {0}"),
    ("DELETE", r"^/api/service-checks/(\d+)$", "Removed service check {0}"),
    ("POST", r"^/api/users$", "Added a user"),
    ("PATCH", r"^/api/users/(\d+)$", "Changed user {0}"),
    ("DELETE", r"^/api/users/(\d+)$", "Removed user {0}"),
    ("POST", r"^/api/users/(\d+)/tokens$", "Made an API token for user {0}"),
    ("POST", r"^/api/tokens", "Made an API token"),
    ("DELETE", r"^/api/tokens/(\d+)$", "Removed an API token"),
    ("PUT", r"^/api/database/retention$", "Changed how long data is kept"),
    ("POST", r"^/api/database/(purge|orphans|optimize|reindex|compact|integrity|tidy)$", "Database maintenance: {0}"),
    ("POST", r"^/api/probes$", "Added a remote site"),
    ("PATCH", r"^/api/probes/(\d+)$", "Changed remote site {0}"),
    ("POST", r"^/api/probes/(\d+)/token$", "Made a new token for remote site {0}"),
    ("PUT", r"^/api/probes/(\d+)/config$", "Changed what is managed at remote site {0}"),
    ("POST", r"^/api/probes/(\d+)/command$", "Sent a command to remote site {0}"),
    ("DELETE", r"^/api/probes/(\d+)$", "Removed remote site {0}"),
    ("PUT", r"^/api/central$", "Changed the report to the central Netlens"),
    ("POST", r"^/api/backup/restore$", "Restored a backup"),
    ("POST", r"^/api/backups/.+/restore$", "Restored a stored backup"),
    ("POST", r"^/api/plugins", "Installed or changed a plugin"),
    ("DELETE", r"^/api/plugins/([A-Za-z0-9_-]+)$", "Removed the plugin {0}"),
    ("PUT", r"^/api/plugins/([A-Za-z0-9_-]+)", "Changed the settings of the plugin {0}"),
    ("POST", r"^/api/snoozes$", "Snoozed a problem"),
    ("DELETE", r"^/api/snoozes$", "Ended a snooze"),
    ("POST", r"^/api/maintenance", "Started or added a maintenance window"),
    ("PUT", r"^/api/maintenance/", "Changed a maintenance window"),
    ("DELETE", r"^/api/maintenance/", "Removed a maintenance window"),
    ("PUT", r"^/api/channels", "Changed the notification channels"),
    ("POST", r"^/api/channels", "Changed the notification channels"),
    ("PUT", r"^/api/reports/weekly/settings$", "Changed the weekly report"),
    ("POST", r"^/api/reports/weekly/send$", "Sent the weekly report now"),
    ("PUT", r"^/api/dashboard/default$", "Set the dashboard for everybody"),
    ("POST", r"^/api/shares", "Made a share link"),
    ("DELETE", r"^/api/shares/", "Removed a share link"),
    ("PUT", r"^/api/config", "Changed the scan settings"),
    ("POST", r"^/api/vault", "Changed the stored-password protection"),
    ("POST", r"^/api/insights/incidents/(\d+)/analysis$", "Made a new analysis of incident INC-{0}"),
    ("PUT", r"^/api/devices/(\d+)/hostprobe$", "Changed the host probes of {d0}"),
    ("PUT", r"^/api/ingest$", "Changed the agent ingest settings"),
    ("POST", r"^/api/ingest/window$", "Opened the enrolment window for agents"),
    ("DELETE", r"^/api/ingest/window$", "Closed the enrolment window for agents"),
    ("PUT", r"^/api/ingest/own-ca$", "Changed the CA certificates trusted for agents"),
    ("PUT", r"^/api/ingest/server-certificate$", "Changed the server certificate of the agent ingest"),
    ("POST", r"^/api/ingest/agents$", "Added an agent and made an enrolment token"),
    ("PUT", r"^/api/ingest/agents/(\d+)$", "Changed agent {0}"),
    ("POST", r"^/api/ingest/agents/(\d+)/token$", "Made a new enrolment token for agent {0} (its old certificate stopped working)"),
    ("POST", r"^/api/ingest/agents/(\d+)/revoke$", "Revoked the certificate of agent {0}"),
    ("POST", r"^/api/ingest/agents/(\d+)/reinstate$", "Allowed agent {0} again"),
    ("DELETE", r"^/api/ingest/agents/(\d+)$", "Deleted agent {0}"),
]
_COMPILED = [(m, re.compile(rx), text) for m, rx, text in PATTERNS]


def _device_name(conn: sqlite3.Connection, ident: str) -> str:
    row = conn.execute("SELECT COALESCE(custom_name, hostname, primary_ip) AS n FROM devices WHERE id = ?", (int(ident),)).fetchone()
    return (row["n"] if row and row["n"] else f"device {ident}")


def describe(conn: sqlite3.Connection, method: str, path: str) -> str:
    """A sentence about a request. Unknown paths still get an honest, generic one."""
    for m, rx, text in _COMPILED:
        if m != method:
            continue
        hit = rx.match(path)
        if hit:
            groups = hit.groups()
            fields: dict[str, Any] = {str(i): g for i, g in enumerate(groups)}
            if groups and "{d0}" in text and groups[0].isdigit():
                fields["d0"] = _device_name(conn, groups[0])
            try:
                return text.format(*groups, **{k: v for k, v in fields.items() if not k.isdigit()})
            except (KeyError, IndexError):
                return text
    verb = {"POST": "Added or ran", "PUT": "Changed", "PATCH": "Changed", "DELETE": "Removed"}.get(method, method)
    parts = [p for p in path.split("/") if p and p != "api"]
    return f"{verb} {' / '.join(parts[:3])}"[:200] if parts else f"{verb} something"


def record(conn: sqlite3.Connection, user: str, role: str, ip: str, method: str, path: str, status: int, action: str) -> None:
    conn.execute("INSERT INTO audit_log (ts, user, role, ip, method, path, status, action) VALUES (?,?,?,?,?,?,?,?)",
                 (utcnow(), (user or "")[:60], (role or "")[:20], (ip or "")[:60], method[:10], path[:200], int(status), action[:300]))
    conn.commit()


def record_system(conn: sqlite3.Connection, action: str, path: str, status: int = 200) -> None:
    """A line for something Netlens did on its own (a scheduled job): no user, no address. Forwarded to the SIEM like the others."""
    record(conn, "netlens", "system", "", "SYSTEM", path, status, action)


def record_by(conn: sqlite3.Connection, principal, ip: str, method: str, path: str, status: int, action: str) -> None:
    """An explicit line written by the code that knows more than the request path (who, on which host, with which login)."""
    record(conn, getattr(principal, "username", "") or "", getattr(principal, "role", "") or "", ip, method, path, status, action)


def record_read(conn: sqlite3.Connection, principal, ip: str, path: str, action: str, quiet_s: int = 600) -> bool:
    """A line for looking at sensitive data (file names of a host). The same user looking at the same thing again within `quiet_s` seconds is one line."""
    user = getattr(principal, "username", "") or ""
    if conn.execute("SELECT 1 FROM audit_log WHERE method = 'GET' AND user = ? AND path = ? AND ts >= ? LIMIT 1", (user, path[:200], ago(seconds=quiet_s))).fetchone():
        return False
    record(conn, user, getattr(principal, "role", "") or "", ip, "GET", path, 200, action)
    return True


def log_request(conn: sqlite3.Connection, principal, ip: str, method: str, path: str, status: int) -> bool:
    """Write the line for a finished request when it is worth one. Returns whether it was written."""
    if method not in ("POST", "PUT", "PATCH", "DELETE") or not path.startswith("/api/") or SKIP.match(path) or not 200 <= status < 300 or principal is None:
        return False
    record(conn, getattr(principal, "username", ""), getattr(principal, "role", ""), ip, method, path, status, describe(conn, method, path))
    return True


def prune(conn: sqlite3.Connection) -> None:
    from app import dbmaint

    conn.execute("DELETE FROM audit_log WHERE ts < ?", (ago(days=dbmaint.days(conn, "audit_days")),))
    conn.execute("DELETE FROM audit_log WHERE id <= (SELECT MAX(id) FROM audit_log) - ?", (MAX_ROWS,))
    conn.commit()


def entries(conn: sqlite3.Connection, limit: int = 100, before: int | None = None, user: str = "", q: str = "") -> list[dict]:
    where, args = [], []
    if before:
        where.append("id < ?")
        args.append(before)
    if user:
        where.append("user = ?")
        args.append(user)
    if q:
        where.append("(LOWER(action) LIKE ? OR LOWER(path) LIKE ?)")
        args += [f"%{q.lower()}%", f"%{q.lower()}%"]
    sql = "SELECT id, ts, user, role, ip, method, path, status, action FROM audit_log" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT ?"
    return [dict(r) for r in conn.execute(sql, (*args, max(1, min(int(limit), 1000))))]
