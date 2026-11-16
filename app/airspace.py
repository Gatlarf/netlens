"""The air around the access points: which channel every radio uses, which neighbouring networks it hears, and which channel would be quieter.

A topology plugin reports, per access point, its radios (`wifi.radios`) and the networks it hears (`wifi.neighbours`). Netlens keeps the latest state,
works out how crowded each radio's channel is, and says so when a clearly quieter channel exists.
"""
from __future__ import annotations

import sqlite3

from app.db import utcnow
from app.hierarchy import device_name
from app.plugins.enrich import device_lookup
from app.plugins.matching import norm_mac

FORGET_DAYS = 7                       # a neighbour not heard for this long is dropped
HEARD = -85                           # weaker than this is not counted as a neighbour that matters
CANDIDATES = {"2.4 GHz": (1, 6, 11), "5 GHz": (36, 40, 44, 48, 149, 153, 157, 161, 165), "6 GHz": (1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61)}


def centre_mhz(band: str | None, channel: int | None) -> int | None:
    if channel is None:
        return None
    if band == "2.4 GHz":
        return 2484 if channel == 14 else 2407 + 5 * channel
    if band == "6 GHz":
        return 5950 + 5 * channel
    return 5000 + 5 * channel


def band_of_channel(channel: int | None) -> str | None:
    if channel is None:
        return None
    return "2.4 GHz" if channel <= 14 else "5 GHz"


def _block_centre(band: str | None, channel: int, width: int) -> int:
    """The centre channel number of the block a wide channel sits in: 40, 80 and 160 MHz channels are blocks of 20 MHz channels that start at fixed places (36, 52, 100 ... on 5 GHz)."""
    n = width // 20
    if n <= 1:
        return channel
    base = 1 if band == "6 GHz" else 36 if channel <= 64 else 100 if channel <= 144 else 149
    start = base + ((channel - base) // (4 * n)) * 4 * n
    return start + 2 * (n - 1)


def _span(band: str | None, channel: int | None, width: int | None) -> tuple[float, float] | None:
    if channel is None:
        return None
    width = width or 20
    centre = centre_mhz(band, _block_centre(band, channel, width) if band in ("5 GHz", "6 GHz") else channel)
    half = width / 2
    return (centre - half, centre + half)


def _weight(signal: int | None) -> float:
    """How much a neighbour disturbs: 0.1 for a faint one, 1 for one that is right next to the access point."""
    if signal is None:
        return 0.5
    return max(0.0, min(1.0, (signal + 95) / 45))


def crowd(neighbours: list[dict], band: str | None, channel: int, width: int | None) -> tuple[float, int]:
    """(congestion, number of networks) of a channel: every neighbour whose frequencies overlap counts, a strong one more than a faint one."""
    mine = _span(band, channel, width)
    score, count = 0.0, 0
    for n in neighbours:
        if n.get("band") not in (None, band) or n.get("signal_dbm") is not None and n["signal_dbm"] < HEARD:
            continue
        theirs = _span(band, n.get("channel"), n.get("width_mhz"))
        if mine is None or theirs is None or theirs[1] <= mine[0] or theirs[0] >= mine[1]:
            continue
        score += _weight(n.get("signal_dbm"))
        count += 1
    return round(score, 2), count


def advise(radio: dict, neighbours: list[dict]) -> dict:
    """For one radio: how many networks share its channel and, when a clearly quieter channel exists, which one."""
    band, channel, width = radio.get("band"), radio.get("channel"), radio.get("width_mhz")
    here = [n for n in neighbours if n.get("band") in (None, band)]
    if channel is None or band is None:
        return {"networks": None, "congestion": None, "suggest": None}
    score, count = crowd(here, band, channel, width)
    best = None
    for c in CANDIDATES.get(band, ()):
        s, k = crowd(here, band, c, width)
        if best is None or (s, k) < (best[1], best[2]):
            best = (c, s, k)
    suggest = None
    if best and best[0] != channel and score >= 1.0 and best[1] <= score * 0.6 and score - best[1] >= 0.8:
        suggest = {"channel": best[0], "congestion": best[1], "networks": best[2]}
    return {"networks": count, "congestion": score, "suggest": suggest}


def record(conn: sqlite3.Connection, plugin_id: str, data: dict, now: str | None = None) -> dict:
    """Store the radios and neighbours that the nodes of a topology plugin report. A node that reports no neighbour list this time keeps what was stored."""
    from datetime import datetime, timedelta

    now = now or utcnow()
    by_mac, by_ip = device_lookup(conn)
    radios = neighbours = 0
    for node in data.get("nodes", []):
        wifi = node.get("wifi")
        device_id = next((by_mac[m] for m in node["macs"] if m in by_mac), None) or by_ip.get(node.get("ip") or "")
        if not wifi or device_id is None:
            continue
        conn.execute("DELETE FROM wifi_radios WHERE device_id = ? AND plugin_id = ?", (device_id, plugin_id))
        for r in wifi["radios"]:
            conn.execute("INSERT INTO wifi_radios (device_id, name, plugin_id, band, channel, width_mhz, clients, utilization_pct, noise_dbm, ssid, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                         (device_id, r["name"], plugin_id, r["band"], r["channel"], r["width_mhz"], r["clients"], r["utilization_pct"], r["noise_dbm"], r["ssid"], now))
            radios += 1
        if wifi["scanned"]:
            for n in wifi["neighbours"]:
                conn.execute(
                    "INSERT INTO wifi_neighbours (device_id, bssid, plugin_id, ssid, band, channel, signal_dbm, width_mhz, security, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(device_id, bssid) DO UPDATE SET ssid = excluded.ssid, band = excluded.band, channel = excluded.channel, signal_dbm = excluded.signal_dbm, "
                    "width_mhz = excluded.width_mhz, security = excluded.security, last_seen = excluded.last_seen, plugin_id = excluded.plugin_id",
                    (device_id, n["bssid"], plugin_id, n["ssid"], n["band"] or band_of_channel(n["channel"]), n["channel"], n["signal_dbm"], n["width_mhz"], n["security"], now, now))
                neighbours += 1
    old = (datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ") - timedelta(days=FORGET_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute("DELETE FROM wifi_neighbours WHERE last_seen < ?", (old,))
    conn.commit()
    return {"radios": radios, "neighbours": neighbours}


def scan_due(conn: sqlite3.Connection, plugin_id: str, minutes: int = 30, now: str | None = None) -> bool:
    """True when this plugin has not stored a neighbour list within `minutes` (an active scan briefly interrupts the radio, so it is not repeated at every sync)."""
    from datetime import datetime, timedelta

    now = now or utcnow()
    since = (datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ") - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return conn.execute("SELECT 1 FROM wifi_neighbours WHERE plugin_id = ? AND last_seen >= ? LIMIT 1", (plugin_id, since)).fetchone() is None


def _assemble(radios: list[dict], heard: list[dict], own: set[str]) -> dict:
    for n in heard:
        n["known"] = norm_mac(n["bssid"]) in own
    others = [n for n in heard if not n["known"]]
    for r in radios:
        r["advice"] = advise(r, others)
        r["neighbours"] = sum(1 for n in others if n["band"] == r["band"] and n["channel"] == r["channel"])
    return {"radios": radios, "neighbours": heard, "scanned": bool(heard)}


def _own_macs(conn: sqlite3.Connection) -> set[str]:
    return {norm_mac(r["mac"]) for r in conn.execute("SELECT mac FROM devices WHERE mac IS NOT NULL")}


def for_device(conn: sqlite3.Connection, device_id: int) -> dict:
    """The radios of one access point with their advice, and the networks it hears (strongest first)."""
    radios = [dict(r) for r in conn.execute("SELECT * FROM wifi_radios WHERE device_id = ? ORDER BY band, name", (device_id,))]
    heard = [dict(r) for r in conn.execute("SELECT bssid, ssid, band, channel, signal_dbm, width_mhz, security, last_seen FROM wifi_neighbours WHERE device_id = ? ORDER BY signal_dbm DESC", (device_id,))]
    return _assemble(radios, heard, _own_macs(conn))


def attention(conn: sqlite3.Connection) -> list[dict]:
    """Needs-attention lines: a radio on a crowded channel while a quieter one exists, or a channel that is busy on the air. Four queries, however many access points there are."""
    all_radios: dict[int, list[dict]] = {}
    for r in conn.execute("SELECT * FROM wifi_radios ORDER BY device_id, band, name"):
        all_radios.setdefault(r["device_id"], []).append(dict(r))
    if not all_radios:
        return []
    all_heard: dict[int, list[dict]] = {}
    for r in conn.execute("SELECT device_id, bssid, ssid, band, channel, signal_dbm, width_mhz, security, last_seen FROM wifi_neighbours ORDER BY signal_dbm DESC"):
        all_heard.setdefault(r["device_id"], []).append(dict(r))
    names = {r["id"]: device_name(dict(r)) for r in conn.execute("SELECT id, custom_name, hostname, primary_ip FROM devices")}
    own = _own_macs(conn)
    out = []
    for device_id, radios in all_radios.items():
        name = names.get(device_id, f"device {device_id}")
        for r in _assemble(radios, all_heard.get(device_id, []), own)["radios"]:
            where = f"{name} ({r['band'] or 'Wi-Fi'}, channel {r['channel']})"
            s = r["advice"]["suggest"]
            busy = r["utilization_pct"] is not None and r["utilization_pct"] >= 80
            href = f"#/device/{device_id}/network/wifichannels"
            if s:
                shared = r["advice"]["networks"]
                text = f"{where} shares its channel with {shared} other network{'s' if shared != 1 else ''}; channel {s['channel']} is much quieter"
                out.append({"level": "warn" if busy else "info", "text": text + (f" ({r['utilization_pct']:.0f}% of the airtime is in use)" if busy else ""), "href": href})
            elif busy:
                out.append({"level": "warn", "text": f"{where} is busy: {r['utilization_pct']:.0f}% of the airtime is in use", "href": href})
    return out
