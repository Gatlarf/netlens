"""Why did a plugin sync fail: is the plugin broken, or is the machine it talks to simply off?

A plugin that cannot reach a host which Netlens itself sees as offline is not failing: the host is down, and the host's own offline handling (importance, always-on,
notifications) already says so. Only a plugin that fails while its host is up (a refused login, a changed API, a closed port, a crash) is a problem.

`classify` looks at the error and at the devices behind the addresses the plugin is set up with; the sync stores the answer in the plugin's status (`reason`).
"""

from __future__ import annotations

import ipaddress
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from app.db import get_setting

HOST_DOWN = "host_down"
FAILED = "failed"

UNREACHABLE_DAYS = 7          # a plugin whose host has not answered for this long gets one quiet hint (maybe it is no longer in use)
RETRY_MINUTES = 60            # while the host is offline the plugin is only tried this often (it is tried at once when the host is back)

# the host does not answer at all: nothing listens, nothing routes there, the name does not resolve. (A certificate or a login problem means the host IS up.)
CONNECT_LEVEL = ("timed out", "timeout", "no route to host", "network is unreachable", "host is down", "host unreachable", "unreachable", "connection refused",
                 "name or service not known", "temporary failure in name resolution", "nodename nor servname", "cannot reach", "could not reach", "connection reset")
HOST_IS_UP = ("certificate", "ssl", "tls", "401", "403", "unauthorized", "forbidden", "login", "password", "authentication", "http 4", "http 5", "status 4", "status 5")

IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
ADDRESS_KEYS = ("host", "url", "address", "base_url", "server", "endpoint", "ip")


def unreachable_days(conn: sqlite3.Connection) -> int:
    try:
        return max(1, min(365, int(get_setting(conn, "plugins.unreachable_days") or UNREACHABLE_DAYS)))
    except (TypeError, ValueError):
        return UNREACHABLE_DAYS


def _hostname(value: Any) -> str:
    """The host part of 'https://host:5986/path', 'host:22' or 'host'."""
    text = str(value or "").strip()
    if not text or len(text) > 300:
        return ""
    parsed = urlparse(text if "//" in text else "//" + text)
    return (parsed.hostname or "").strip().lower()


def configured_hosts(config: Any) -> list[str]:
    """The addresses a plugin is set up to talk to (the `host` column of its servers, and plain address fields)."""
    found: list[str] = []

    def walk(node: Any, key: str = "") -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, str(k).lower())
        elif isinstance(node, list):
            for v in node:
                walk(v, key)
        elif isinstance(node, str) and key in ADDRESS_KEYS:
            host = _hostname(node)
            if host and host not in found:
                found.append(host)

    walk(config)
    return found


def _device_for(conn: sqlite3.Connection, host: str) -> sqlite3.Row | None:
    sql = "SELECT id, online, COALESCE(NULLIF(custom_name, ''), NULLIF(hostname, ''), primary_ip) AS name FROM devices"
    row = conn.execute(sql + " WHERE primary_ip = ? ORDER BY online DESC LIMIT 1", (host,)).fetchone()
    if row is None:
        row = conn.execute(sql + " WHERE id = (SELECT device_id FROM device_ips WHERE ip = ? ORDER BY last_seen DESC LIMIT 1)", (host,)).fetchone()
    if row is None:
        short = host.split(".")[0]
        row = conn.execute(sql + " WHERE lower(hostname) IN (?, ?) OR lower(custom_name) IN (?, ?) LIMIT 1", (host, short, host, short)).fetchone()
    return row


def _private(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def classify(conn: sqlite3.Connection, config: Any, error: str, auth_failed: bool = False) -> dict:
    """{"reason": "host_down"|"failed", "host": address, "device_id": id|None, "device": name|None}.

    host_down: the error says the machine does not answer, and the device behind that address is offline in Netlens (or, with no such device, the address is on a private
    network). Anything else counts as a failure of the plugin, in particular a refused login and any answer that came from a host that is up.
    """
    failed = {"reason": FAILED}
    text = (error or "").lower()
    if auth_failed or not any(w in text for w in CONNECT_LEVEL) or any(w in text for w in HOST_IS_UP):
        return failed
    named = [m for m in IPV4.findall(error or "")]            # the address the plugin says it could not reach is the best evidence
    candidates = named or configured_hosts(config)
    if not candidates:
        return failed
    devices = [(h, _device_for(conn, h)) for h in candidates]
    known = [(h, d) for h, d in devices if d is not None]
    if known:
        if any(d["online"] for _, d in known):
            return failed                                            # the machine is up in Netlens' eyes, so the plugin or the service on it is the problem
        host, device = known[0]
        return {"reason": HOST_DOWN, "host": host, "device_id": device["id"], "device": device["name"]}
    if all(_private(h) for h in candidates):                          # no device to ask: a silent machine on the local network; a cloud address stays a plugin problem
        return {"reason": HOST_DOWN, "host": candidates[0], "device_id": None, "device": None}
    return failed


def host_is_back(conn: sqlite3.Connection, status: dict) -> bool:
    """A plugin that waits for a host: has Netlens seen that host online since?"""
    device = status.get("host_device_id")
    if device is None:
        return False
    row = conn.execute("SELECT online FROM devices WHERE id = ?", (device,)).fetchone()
    return bool(row and row["online"])


def due_again(conn: sqlite3.Connection, status: dict) -> bool:
    """A plugin waiting for an offline host is tried again when the host is back, or after RETRY_MINUTES."""
    if host_is_back(conn, status):
        return True
    try:
        last = datetime.strptime(str(status.get("ts")), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return True
    return datetime.now(timezone.utc) - last >= timedelta(minutes=RETRY_MINUTES)
