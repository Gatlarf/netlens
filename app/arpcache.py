"""MAC addresses for hosts that are behind a router.

nmap sees a MAC address only for hosts on its own network segment (ARP). A host on a routed network (another VLAN, a network reached over a VPN) is
found by IP address alone; it has no MAC, so Netlens has to treat its address as its identity: a DHCP lease that changes looks like a new device, and
there is no manufacturer. The router or layer-3 switch that the host is attached to knows the MAC: it is in its ARP table. A health monitor over
SNMP on such a device reads that table (app/hostmetrics/service.py) and keeps it here for an hour; so does the client list of a router or DHCP plugin
(leases and connected clients, app/plugins/enrich.py). A scan then gives a MAC-less host the MAC that they report for its address.

This only fills a gap: a MAC that the scan itself saw is never replaced, and a MAC that would stand for many addresses is not used (a router that
answers ARP for networks behind it, or NAT, shows one MAC for many addresses: that is the router, not the hosts).
"""

from __future__ import annotations

import sqlite3
from collections import Counter
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any

from app.db import utcnow

TTL = timedelta(hours=1)          # an entry older than this is not used any more (the host may have gone, or got another address)
MAX_IPS_PER_MAC = 8               # a MAC that answers for more addresses than this is a router or a NAT, not a host
AUTO_TYPES = ("router", "switch")  # devices whose ARP table is read without being asked


def _ts(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def usable_mac(mac: str) -> bool:
    """A station address: six bytes, not all zero or all one, not a group (multicast) address."""
    try:
        raw = bytes.fromhex(mac.replace(":", ""))
    except ValueError:
        return False
    return len(raw) == 6 and any(raw) and raw != b"\xff" * 6 and not raw[0] & 1


def learn(conn: sqlite3.Connection, device_id: int | None, entries: list[tuple[str, str, int | None]], now: str | None = None, source: str | None = None) -> int:
    """Keep what a router's ARP table (or the client list of a router or DHCP plugin, `source`) says. Returns the number of entries kept."""
    now = now or utcnow()
    kept = 0
    for ip, mac, iface in entries:
        if not usable_mac(mac):
            continue
        conn.execute(
            "INSERT INTO arp_cache (ip, mac, device_id, iface, seen, source) VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(ip) DO UPDATE SET mac = excluded.mac, device_id = excluded.device_id, iface = excluded.iface, seen = excluded.seen, source = excluded.source",
            (ip, mac.lower(), device_id, iface, now, source))
        kept += 1
    conn.execute("DELETE FROM arp_cache WHERE seen < ?", ((_ts(now) - 2 * TTL).strftime("%Y-%m-%dT%H:%M:%SZ"),))
    conn.commit()
    return kept


def fresh(conn: sqlite3.Connection, now: str | None = None) -> dict[str, str]:
    """{ip: mac} of the entries that can be used now."""
    limit = ((_ts(now) if now else datetime.now(timezone.utc)) - TTL).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = {r["ip"]: r["mac"] for r in conn.execute("SELECT ip, mac FROM arp_cache WHERE seen >= ?", (limit,))}
    crowd = Counter(rows.values())
    return {ip: mac for ip, mac in rows.items() if crowd[mac] <= MAX_IPS_PER_MAC}


def fill_macs(conn: sqlite3.Connection, hosts: list[Any], now: str | None = None) -> list[Any]:
    """Give the hosts of a scan that have no MAC the one a router reports for their address. A device that was stored by address alone keeps its history:
    it takes the MAC over (unless another device already has it)."""
    missing = [h for h in hosts if h.mac is None]
    if not missing:
        return hosts
    known = fresh(conn, now)
    if not known:
        return hosts
    out = []
    for h in hosts:
        mac = known.get(h.ip) if h.mac is None else None
        if mac is None:
            out.append(h)
            continue
        conn.execute("UPDATE devices SET mac = ? WHERE mac IS NULL AND primary_ip = ? AND NOT EXISTS (SELECT 1 FROM devices WHERE mac = ?)", (mac, h.ip, mac))
        out.append(replace(h, mac=mac))
    return out


def entries_of(conn: sqlite3.Connection, device_id: int) -> int:
    return conn.execute("SELECT COUNT(*) FROM arp_cache WHERE device_id = ?", (device_id,)).fetchone()[0]
