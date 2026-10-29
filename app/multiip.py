"""A device that answers on more than one address at once (a fixed address next to a DHCP lease, a virtual address, a failover address).

Netlens keeps one entry per MAC address with one primary address, which monitoring, DNS and the device list use. Before this module
the primary address followed whichever address the last host of a scan had, so a device with two live addresses "changed" its address
twice in every scan. The rule now (see `choose_primary`):

* The scan counts the addresses a MAC answers on (`score`: +1 for a scan with two or more, -1 for a scan with one, 0..MAX_SCORE). A device
  is in *multi-address mode* when the score reaches ENTER, when the owner ticked "several addresses on purpose" or pinned an address.
  A lease that is handed over (old and new address answering for a scan or two) never gets there, and keeps behaving as before.
* In that mode the primary address stays where it is while that address still answers (or answered within GRACE), so nothing is
  reported and DNS stays put. When it really stops answering, the primary moves and `ip_changed` is raised as always.
* A pinned address wins as long as it answers (or answered within GRACE). A pinned address that is silent never keeps a dead address
  as primary: the primary follows the device and the device page says the chosen address is not answering.

Outside that mode nothing changes: the last address of the scan is the primary one, as before.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

ENTER = 3            # scans in a row (net) with two or more answering addresses before the device counts as multi-address
MAX_SCORE = 6        # so it takes several single-address scans to leave again: one lost probe never ends the mode
GRACE = timedelta(minutes=15)   # a primary or pinned address that missed a scan is kept this long before the primary moves


def _ts(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def score_scan(conn: Any, device_id: int, answering: int) -> int:
    """Record one scan for the device (call once per device per scan) and return the new score."""
    row = conn.execute("SELECT multi_score FROM devices WHERE id = ?", (device_id,)).fetchone()
    score = row["multi_score"] if row else 0
    score = min(MAX_SCORE, score + 1) if answering >= 2 else max(0, score - 1)
    if row is not None and score != row["multi_score"]:           # most devices stay at 0: no write
        conn.execute("UPDATE devices SET multi_score = ? WHERE id = ?", (score, device_id))
    return score


def state(row: Any) -> dict[str, Any]:
    """What the device row says: `flag` (owner), `pinned`, `auto` (detected) and `multi` (any of them)."""
    pinned = row["pinned_ip"] or None
    flag = bool(row["multi_ip"]) or bool(pinned)
    auto = (row["multi_score"] or 0) >= ENTER
    return {"flag": flag, "pinned": pinned, "auto": auto, "multi": flag or auto}


def choose_primary(conn: Any, device_id: int, old_primary: str | None, scan_ip: str, answering: list[str], now: str) -> str:
    """The primary address after this scan. `old_primary` is the one before this host was stored, `scan_ip` the address of the host being stored (what used to become primary)."""
    row = conn.execute("SELECT multi_ip, pinned_ip, multi_score FROM devices WHERE id = ?", (device_id,)).fetchone()
    mode = state(row)
    if not mode["multi"]:
        return scan_ip
    seen = {r["ip"]: r["last_seen"] for r in conn.execute("SELECT ip, last_seen FROM device_ips WHERE device_id = ?", (device_id,))}
    limit = _ts(now) - GRACE

    def alive(ip: str | None) -> bool:
        if not ip:
            return False
        return ip in answering or (ip in seen and _ts(seen[ip]) >= limit)

    for candidate in (mode["pinned"], old_primary):
        if alive(candidate):
            return candidate
    return sorted(answering, key=lambda ip: (tuple(int(p) if p.isdigit() else 0 for p in ip.split(".")), ip))[0] if answering else scan_ip
