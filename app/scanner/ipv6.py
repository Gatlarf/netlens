"""IPv6 addresses of the devices (optional, off by default).

A /64 cannot be swept like an IPv4 range, so Netlens does not scan IPv6. It asks the network instead: a multicast echo to "all nodes"
(ff02::1) makes every IPv6 device on the link answer, which fills the neighbour table of this machine; the table pairs each IPv6 address
with a MAC address, and the MAC address is how Netlens already recognises a device. The addresses are attached to the devices that the
normal scan found. This works on the networks that the machine is directly connected to, so the Docker container needs host networking
(the same as for ARP). Devices seen only over IPv6 are not added in this version.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import sqlite3
from typing import Any

from app.db import get_setting, utcnow
from app.scanner.netinfo import run_ip

log = logging.getLogger(__name__)
SETTING = "ipv6.enabled"
KEEP_DAYS = 30
SKIP_IFACES = ("lo", "veth", "docker", "br-", "virbr", "tun", "tap", "wg", "tailscale", "zt")
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def enabled(conn: sqlite3.Connection) -> bool:
    return get_setting(conn, SETTING) == "1"


def scope_of(address: str) -> str | None:
    """'link' (fe80::/10), 'ula' (fc00::/7), 'global', or None for what is not worth keeping (multicast, loopback, unspecified, bad text)."""
    try:
        ip = ipaddress.IPv6Address(address.split("%")[0])
    except ValueError:
        return None
    if ip.is_multicast or ip.is_loopback or ip.is_unspecified:
        return None
    if ip.is_link_local:
        return "link"
    if ip in ipaddress.IPv6Network("fc00::/7"):
        return "ula"
    return "global"


def parse_neigh(text: str) -> list[dict[str, str]]:
    """Entries of `ip -6 neigh show` that have a MAC address: [{ip, dev, mac, state}]."""
    out = []
    for line in text.splitlines():
        words = line.split()
        if len(words) < 4 or "lladdr" not in words:
            continue
        mac = words[words.index("lladdr") + 1].lower() if words.index("lladdr") + 1 < len(words) else ""
        dev = words[words.index("dev") + 1] if "dev" in words and words.index("dev") + 1 < len(words) else ""
        state = words[-1]
        if not MAC_RE.match(mac) or scope_of(words[0]) is None or state in ("FAILED", "INCOMPLETE"):
            continue
        out.append({"ip": str(ipaddress.IPv6Address(words[0].split("%")[0])), "dev": dev, "mac": mac, "state": state})
    return out


def parse_interfaces(text: str) -> list[str]:
    """Interfaces that have an IPv6 link-local address (from `ip -6 -o addr show scope link`), without virtual ones."""
    names = []
    for line in text.splitlines():
        words = line.split()
        if len(words) > 1:
            name = words[1].rstrip(":")
            if name not in names and not name.startswith(SKIP_IFACES):
                names.append(name)
    return names


async def _echo(interface: str, nmap_path: str = "nmap", timeout: float = 25.0) -> None:
    """Multicast echo to ff02::1 on one interface; the answers end up in the neighbour table."""
    try:
        proc = await asyncio.create_subprocess_exec(
            nmap_path, "-6", "-sn", "-n", "-e", interface, "--script", "targets-ipv6-multicast-echo", "--script-args", f"newtargets,interface={interface}",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
    except FileNotFoundError:
        return
    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass


async def collect(ip_path: str = "ip", nmap_path: str = "nmap") -> list[dict[str, str]]:
    interfaces = parse_interfaces(await run_ip(["-6", "-o", "addr", "show", "scope", "link"], ip_path))
    if interfaces:
        await asyncio.gather(*(_echo(i, nmap_path) for i in interfaces[:6]))
    return parse_neigh(await run_ip(["-6", "neigh", "show"], ip_path))


def apply(conn: sqlite3.Connection, entries: list[dict[str, str]], now: str | None = None) -> dict[str, int]:
    """Attach the addresses to the devices with that MAC address; forget addresses not seen for KEEP_DAYS days."""
    from datetime import datetime, timedelta, timezone

    now = now or utcnow()
    known = {r["mac"].lower(): r["id"] for r in conn.execute("SELECT id, mac FROM devices WHERE mac IS NOT NULL")}
    attached = unknown = 0
    for e in entries:
        device_id = known.get(e["mac"])
        scope = scope_of(e["ip"])
        if device_id is None or scope is None:
            unknown += 1
            continue
        conn.execute(
            "INSERT INTO device_ipv6 (device_id, ip, scope, first_seen, last_seen) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(device_id, ip) DO UPDATE SET last_seen = excluded.last_seen", (device_id, e["ip"], scope, now, now))
        attached += 1
    cutoff = (datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) - timedelta(days=KEEP_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute("DELETE FROM device_ipv6 WHERE last_seen < ?", (cutoff,))
    conn.commit()
    return {"attached": attached, "unknown": unknown}


def for_device(conn: sqlite3.Connection, device_id: int) -> list[dict[str, Any]]:
    order = {"global": 0, "ula": 1, "link": 2}
    rows = [{"ip": r["ip"], "scope": r["scope"], "first_seen": r["first_seen"], "last_seen": r["last_seen"]}
            for r in conn.execute("SELECT ip, scope, first_seen, last_seen FROM device_ipv6 WHERE device_id = ?", (device_id,))]
    return sorted(rows, key=lambda r: (order.get(r["scope"], 3), r["ip"]))


async def after_scan(db_path: str) -> None:
    from app.db import connect

    conn = connect(db_path)
    try:
        if not enabled(conn):
            return
        entries = await collect()
        result = apply(conn, entries)
        set_status(conn, {"ts": utcnow(), "seen": len(entries), **result})
    except Exception:  # noqa: BLE001 - IPv6 is a convenience, never a reason to fail a scan
        log.exception("IPv6 discovery failed")
    finally:
        conn.close()


def set_status(conn: sqlite3.Connection, doc: dict[str, Any]) -> None:
    import json

    from app.db import set_setting

    set_setting(conn, "ipv6.status", json.dumps(doc))
