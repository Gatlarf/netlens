"""Beats: a quick ping of every device between two scans, so an outage shows after minutes instead of after the next scan.

The scans (every 15 minutes by default) are what finds devices and learns about them; they were also the only thing that said whether a
device was up. A beat only asks "are you there?" with one nmap host discovery for all devices at once (ARP on the local network, ICMP and
TCP probes behind a router), every minute by default. The result is recorded like a scan check (marked `beat`), so availability figures,
the bars and the response-time graphs get one measurement a minute, and a device is marked offline after a few missed beats in a row (so one
lost packet is not an outage) and online again at the first answer. Service checks have their own interval and are not part of this.

The rows of beats are kept for a few days (`BEAT_KEEP_DAYS`); the hourly roll-up (app/checkstats.py) keeps what they counted.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import sqlite3
import time
from datetime import datetime, timedelta, timezone

from app import checkstats, tsdb
from app.db import add_event, connect, get_setting, set_setting, utcnow

log = logging.getLogger(__name__)

INTERVAL_KEY, MISSES_KEY, SCOPE_KEY = "presence.interval", "presence.misses", "presence.scope"
DEFAULT_INTERVAL, DEFAULT_MISSES = 60, 3
MIN_INTERVAL, MAX_INTERVAL = 15, 3600                  # 0 switches beats off
MAX_MISSES = 10
BEAT_KEEP_DAYS = 3                                      # raw rows of beats; the roll-up and the graph store keep the history
WATCH_DAYS = 7                                          # a device not seen for this long is left to the scans
CHUNK = 100                                             # addresses per nmap call

_misses: dict[int, int] = {}                            # device id -> missed beats in a row (kept in memory: a restart starts counting again)


def scope(conn: sqlite3.Connection) -> str:
    """"core": only the devices marked always-on (a phone that sleeps is not an outage); "all": every device in the scanned ranges."""
    return "all" if get_setting(conn, SCOPE_KEY) == "all" else "core"


def settings(conn: sqlite3.Connection) -> tuple[int, int]:
    """(seconds between beats, 0 = off; missed beats before a device is offline)."""
    def number(key: str, default: int, low: int, high: int) -> int:
        raw = get_setting(conn, key)
        try:
            value = int(raw) if raw is not None and raw != "" else default
        except ValueError:
            return default
        return value if value == 0 and key == INTERVAL_KEY or low <= value <= high else default

    return number(INTERVAL_KEY, DEFAULT_INTERVAL, MIN_INTERVAL, MAX_INTERVAL), number(MISSES_KEY, DEFAULT_MISSES, 1, MAX_MISSES)


def save_settings(conn: sqlite3.Connection, interval: int | None = None, misses: int | None = None, which: str | None = None) -> None:
    if interval is not None:
        if interval != 0 and not MIN_INTERVAL <= interval <= MAX_INTERVAL:
            raise ValueError(f"the time between quick checks is 0 (off) or {MIN_INTERVAL} to {MAX_INTERVAL} seconds")
        set_setting(conn, INTERVAL_KEY, str(interval))
    if misses is not None:
        if not 1 <= misses <= MAX_MISSES:
            raise ValueError(f"missed checks before a device is offline: 1 to {MAX_MISSES}")
        set_setting(conn, MISSES_KEY, str(misses))
    if which is not None:
        if which not in ("core", "all"):
            raise ValueError("which devices: core or all")
        set_setting(conn, SCOPE_KEY, which)
    conn.commit()


def _inside(ip: str, networks: list) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return address.version == 4 and any(address in n for n in networks)


def targets(conn: sqlite3.Connection, now: str, ranges: list[str]) -> list[sqlite3.Row]:
    """The devices a beat asks: an IPv4 address inside the scanned ranges (outside them a device may be unreachable by ping), seen in the last week, and by default only the always-on ones."""
    networks = []
    for r in ranges:
        try:
            networks.append(ipaddress.ip_network(r, strict=False))
        except ValueError:
            pass
    since = (datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ") - timedelta(days=WATCH_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.row_factory = sqlite3.Row
    only_core = " AND always_on = 1" if scope(conn) == "core" else ""
    return [r for r in conn.execute(f"SELECT id, primary_ip, online FROM devices WHERE primary_ip IS NOT NULL AND last_seen >= ?{only_core} ORDER BY id", (since,)) if _inside(r["primary_ip"], networks)]


def record(conn: sqlite3.Connection, answered: dict[str, float | None], ranges: list[str], now: str | None = None) -> dict:
    """Write the result of one beat. `answered` maps the address of every device that answered to its response time (ms, or None)."""
    now = now or utcnow()
    _interval, limit = settings(conn)
    rows = targets(conn, now, ranges)
    went_offline: list[int] = []
    came_online: list[int] = []
    samples: list[tuple] = []
    for r in rows:
        did, ip = r["id"], r["primary_ip"]
        up = ip in answered
        rtt = answered.get(ip) if up else None
        conn.execute("INSERT INTO checks (device_id, ts, up, rtt_ms, beat) VALUES (?, ?, ?, ?, 1)", (did, now, 1 if up else 0, rtt))
        samples.append(("device", did, "up", 1 if up else 0, "", "state"))
        if rtt is not None:
            samples.append(("device", did, "rtt_ms", rtt, "", "ms"))
        if up:
            _misses.pop(did, None)
            if not r["online"]:
                conn.execute("UPDATE devices SET online = 1, last_seen = ? WHERE id = ?", (now, did))
                add_event(conn, "device_online", None, device_id=did, now=now)
                came_online.append(did)
            else:
                conn.execute("UPDATE devices SET last_seen = ? WHERE id = ?", (now, did))
        else:
            _misses[did] = _misses.get(did, 0) + 1
            if r["online"] and _misses[did] >= limit:
                conn.execute("UPDATE devices SET online = 0 WHERE id = ?", (did,))
                add_event(conn, "device_offline", ip, device_id=did, now=now)
                went_offline.append(did)
    store = tsdb.for_conn(conn)
    if store is not None and samples:
        store.record(samples, ts=int(datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()))
    conn.commit()
    checkstats.fold(conn)
    return {"checked": len(rows), "answered": sum(1 for r in rows if r["primary_ip"] in answered), "offline": went_offline, "online": came_online}


def prune(conn: sqlite3.Connection, now: str | None = None) -> int:
    """Delete the raw rows of beats after BEAT_KEEP_DAYS (their count stays in the hourly roll-up, which is brought up to date first)."""
    now = now or utcnow()
    cutoff = (datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ") - timedelta(days=BEAT_KEEP_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    checkstats.fold(conn)
    cur = conn.execute("DELETE FROM checks WHERE beat = 1 AND ts < ?", (cutoff,))
    conn.commit()
    return cur.rowcount or 0


async def discover(addresses: list[str], runner=None) -> dict[str, float | None]:
    """Which of these addresses answer right now, with their response time (one nmap host discovery per chunk)."""
    from app.actions import ActionError, nmap_output
    from app.scanner.nmap_parser import parse_nmap_xml

    answered: dict[str, float | None] = {}
    for i in range(0, len(addresses), CHUNK):
        part = addresses[i:i + CHUNK]
        try:
            xml = await nmap_output(["-sn", "-n", "--max-retries", "1", "-T4", "-oX", "-", *part], 30 + len(part) // 4, runner)
            for host in parse_nmap_xml(xml):
                answered[host.ip] = host.rtt_ms
        except (ActionError, ValueError) as exc:
            log.warning("a quick check could not run: %s", exc)
            return {}                         # no answer at all is not "everything is down": the beat is skipped by the caller
    return answered


async def run_once(db_path: str, ranges: list[str], runner=None, now: str | None = None) -> dict | None:
    """One beat. None when nothing was done (beats are off, a scan is running, or nmap could not run)."""
    from app.scanner.scans import running_scan

    conn = connect(db_path)
    try:
        interval, _ = settings(conn)
        if interval == 0 or running_scan(conn) is not None:
            return None
        stamp = now or utcnow()
        rows = targets(conn, stamp, ranges)
    finally:
        conn.close()
    if not rows:
        return None
    answered = await discover([r["primary_ip"] for r in rows], runner)
    if not answered and len(rows) > 1:
        return None                          # nothing answered at all: more likely nmap or the network card than every device being down
    conn = connect(db_path)
    try:
        result = await asyncio.to_thread(record, conn, answered, ranges, stamp)
        if result["offline"] or result["online"]:
            from app.notify.channels import process_channels

            await process_channels(db_path)
        return result
    finally:
        conn.close()


async def loop(db_path: str, ranges_provider) -> None:
    """Background task: a beat every `interval` seconds (the setting is read again each round), the old rows tidied hourly."""
    last_prune = 0.0
    await asyncio.sleep(20)                   # the first scan and the startup work go first
    while True:
        wait = DEFAULT_INTERVAL
        try:
            conn = connect(db_path)
            try:
                wait, _ = settings(conn)
                if time.monotonic() - last_prune > 3600:
                    last_prune = time.monotonic()
                    await asyncio.to_thread(prune, conn)
            finally:
                conn.close()
            if wait:
                started = time.monotonic()
                await run_once(db_path, list(await ranges_provider()))
                wait = max(1.0, wait - (time.monotonic() - started))
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - a failing beat must never stop the next one
            log.exception("a quick check failed")
        await asyncio.sleep(wait or 30)       # off: look again in half a minute for the setting
