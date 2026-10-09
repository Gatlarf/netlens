"""Why does a device keep going offline and online?

Two parts:

* `analyze()` reads the history Netlens already has (one check per scan): how often and how long the device is missed,
  whether the devices behind it stayed up meanwhile, whether the whole network missed the same scans, whether it is
  periodic, at what time of day it happens, and whether its answers were slow before a gap.
* `probe()` asks the device right now, several times, by ARP, ICMP and TCP, to see which kind of probe goes unanswered.

Both return plain data with a list of findings (level ok / info / warn) that the device page shows.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import sqlite3
import statistics
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from app import actions
from app.hierarchy import descendants, load_hierarchy
from app.scanner.nmap_parser import parse_nmap_xml

DAYS = (1, 3, 7, 14, 30)
MIN_OUTAGES = 3        # fewer than this is not "flapping"
RESPONSIVE = 0.8       # share of its outages during which the devices behind it were up


def _ts(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 90:
        return f"{seconds} s"
    if seconds < 5400:
        return f"{round(seconds / 60)} min"
    return f"{seconds / 3600:.1f} h"


def _finding(level: str, title: str, detail: str) -> dict[str, str]:
    return {"level": level, "title": title, "detail": detail}


def outages(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    """Runs of missed checks: start, end (when it was seen again; None while it still is down), number of checks."""
    found: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for r in rows:
        if not r["up"]:
            if current is None:
                current = {"start": r["ts"], "checks": 0, "end": None}
                found.append(current)
            current["checks"] += 1
        elif current is not None:
            current["end"] = r["ts"]
            current = None
    for o in found:
        end = _ts(o["end"]) if o["end"] else None
        o["seconds"] = (end - _ts(o["start"])).total_seconds() if end else None
    return found


def analyze(conn: sqlite3.Connection, device_id: int, days: int = 7, now: str | None = None, tz_minutes: int = 0) -> dict[str, Any]:
    device = conn.execute("SELECT id, primary_ip, device_type, type_override, vendor FROM devices WHERE id = ?", (device_id,)).fetchone()
    if device is None:
        raise KeyError(device_id)
    days = days if days in DAYS else 7
    current = _ts(now) if now else datetime.now(timezone.utc)
    since = (current - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = conn.execute("SELECT ts, up, rtt_ms FROM checks WHERE device_id = ? AND ts >= ? ORDER BY ts", (device_id, since)).fetchall()
    result: dict[str, Any] = {"device_id": device_id, "days": days, "checks": len(rows), "findings": []}
    findings = result["findings"]
    if len(rows) < 10:
        findings.append(_finding("info", "Not enough history yet", f"Only {len(rows)} scan result(s) in the last {days} day(s); a few more scans are needed."))
        return result

    down = [r for r in rows if not r["up"]]
    runs = outages(rows)
    result.update({
        "down_checks": len(down), "down_percent": round(100 * len(down) / len(rows), 1), "outages": len(runs),
        "currently_down": bool(rows and not rows[-1]["up"]),
    })
    timed = [o["seconds"] for o in runs if o["seconds"] is not None]
    result["median_outage_seconds"] = round(statistics.median(timed)) if timed else None
    result["longest_outage_seconds"] = round(max(timed)) if timed else None
    result["recent_outages"] = [{"start": o["start"], "end": o["end"], "checks": o["checks"], "seconds": o["seconds"]} for o in runs[-10:]][::-1]

    if not runs or len(runs) < MIN_OUTAGES and result["down_percent"] < 5:
        findings.append(_finding("ok", "Not flapping", f"Missed {len(runs)} time(s) in {days} day(s) ({result['down_percent']} % of the scans)."))
        return result

    # ---- the devices behind it, and everything else, at the moments it was missed
    down_ts = [r["ts"] for r in down]
    hierarchy = load_hierarchy(conn)[1]
    behind = sorted(descendants(hierarchy, device_id))
    result["devices_behind"] = len(behind)
    up_share_behind = None
    if behind:
        marks = ",".join("?" for _ in behind)
        counted = 0
        stayed_up = 0
        for ts in down_ts:
            total, up = conn.execute(f"SELECT COUNT(*), COALESCE(SUM(up), 0) FROM checks WHERE ts = ? AND device_id IN ({marks})", (ts, *behind)).fetchone()
            if total:
                counted += 1
                stayed_up += 1 if up / total >= 0.5 else 0
        if counted >= MIN_OUTAGES:
            up_share_behind = stayed_up / counted
            result["behind_stayed_up_percent"] = round(100 * up_share_behind)
    others_down = 0
    compared = 0
    for ts in down_ts:
        total, up = conn.execute("SELECT COUNT(*), COALESCE(SUM(up), 0) FROM checks WHERE ts = ? AND device_id != ?", (ts, device_id)).fetchone()
        if total >= 5:
            compared += 1
            others_down += 1 if (total - up) / total >= 0.5 else 0
    network_wide = others_down / compared if compared >= MIN_OUTAGES else None
    result["network_wide_percent"] = round(100 * network_wide) if network_wide is not None else None

    if up_share_behind is not None and up_share_behind >= RESPONSIVE:
        findings.append(_finding(
            "warn", "It is probably running; it just does not answer Netlens",
            f"In {round(100 * up_share_behind)} % of the scans that missed it, the {len(behind)} device(s) behind it were online, so traffic was passing through it. "
            "Most likely it answers Netlens' probes (ARP / ping) late or not at all when busy. Run the live test to see which probe fails."))
    elif up_share_behind is not None and up_share_behind <= 0.3:
        findings.append(_finding(
            "warn", "The devices behind it go down with it",
            f"Only {round(100 * up_share_behind)} % of the time its {len(behind)} downstream device(s) stayed online while it was missed, so these look like real outages "
            "(power, cable or port problems, restarts)."))
    elif not behind:
        findings.append(_finding(
            "info", "Netlens does not know what is behind it",
            "Choose it as the parent of the devices connected to it (their page, Edit → Network position). Then this check can tell a real outage from a device that merely stops answering."))
    if network_wide is not None and network_wide >= 0.6:
        findings.append(_finding(
            "warn", "Other devices were missed at the same moments",
            f"In {round(100 * network_wide)} % of its missed scans, at least half of all other devices were missed too. That points at the scan (Netlens' own network connection, a scan that "
            "timed out, a busy router) and not at this device."))
    elif network_wide is not None and network_wide <= 0.1:
        findings.append(_finding("info", "Only this device is affected", "Other devices were answering during its gaps, so the scans themselves are working."))

    # ---- how long are the gaps
    short = sum(1 for o in runs if o["checks"] == 1)
    result["single_check_outages"] = short
    if len(runs) >= MIN_OUTAGES and short / len(runs) >= 0.5:
        findings.append(_finding("info", "Most gaps last a single scan", f"{short} of {len(runs)} gaps are one missed scan: lost or ignored probes rather than real outages."))
    elif timed and statistics.median(timed) >= 1800:
        findings.append(_finding("info", "The gaps are long", f"Typical gap {_fmt_duration(statistics.median(timed))}; a device that is really switched off, asleep or unplugged behaves like this."))

    # ---- periodic?
    starts = [_ts(o["start"]) for o in runs]
    if len(starts) >= 5:
        intervals = [(b - a).total_seconds() for a, b in zip(starts, starts[1:])]
        middle = statistics.median(intervals)
        close = sum(1 for i in intervals if middle and abs(i - middle) <= 0.2 * middle)
        if middle >= 120 and close / len(intervals) >= 0.6:
            result["period_seconds"] = round(middle)
            findings.append(_finding(
                "info", f"It drops about every {_fmt_duration(middle)}",
                "A regular rhythm points at something scheduled: a DHCP lease or ARP cache that expires, a spanning-tree change, a timer on the device, a Wi-Fi / power-saving cycle."))

    # ---- time of day
    shift = timedelta(minutes=tz_minutes)
    hours = Counter(((_ts(r["ts"]) + shift).hour) for r in down)
    result["down_by_hour"] = [hours.get(h, 0) for h in range(24)]
    window = max(range(24), key=lambda h: sum(hours.get((h + k) % 24, 0) for k in range(4)))
    share = sum(hours.get((window + k) % 24, 0) for k in range(4)) / len(down)
    if len(down) >= 10 and share >= 0.6:
        findings.append(_finding("info", f"Mostly between {window:02d}:00 and {(window + 4) % 24:02d}:00", f"{round(100 * share)} % of the missed scans fall in this 4-hour window (your browser's time zone)."))

    # ---- slow before it drops?
    rtts = [r["rtt_ms"] for r in rows if r["up"] and r["rtt_ms"] is not None]
    before = []
    for i, r in enumerate(rows):
        if not r["up"] and i > 0 and rows[i - 1]["up"] and rows[i - 1]["rtt_ms"] is not None:
            before.append(rows[i - 1]["rtt_ms"])
    if len(rtts) >= 10 and len(before) >= MIN_OUTAGES:
        normal, last = statistics.median(rtts), statistics.median(before)
        result["rtt_normal_ms"], result["rtt_before_drop_ms"] = round(normal, 2), round(last, 2)
        if normal > 0 and last >= 3 * normal and last - normal > 5:
            findings.append(_finding("warn", "It slows down before it drops", f"Its answer takes {last:.0f} ms just before a gap, against {normal:.1f} ms normally: overload, a congested link or a failing port."))

    # ---- things that are typical for the kind of device
    kind = device["type_override"] or device["device_type"]
    if kind in ("switch", "ap") and up_share_behind is not None and up_share_behind >= RESPONSIVE:
        findings.append(_finding(
            "info", "Common with managed switches and access points",
            "Their management processor answers ARP and ping at low priority and drops them when it is busy, although traffic through them is fine. It does not affect the network."))
    return result


# ---- the live test ---------------------------------------------------------------------------

METHODS = (
    ("ARP", ["-sn", "-n", "-PR"]),
    ("ICMP ping", ["-sn", "-n", "-PE", "--disable-arp-ping"]),
    ("TCP 80/443/22", ["-sn", "-n", "-PS80,443,22", "--disable-arp-ping"]),
)


async def probe(ip: str | None, rounds: int = 8, pause: float = 1.0, runner=None) -> dict[str, Any]:
    """Ask the device `rounds` times by ARP, ICMP and TCP (in parallel) and report how many answers each got."""
    if not ip:
        raise actions.ActionError("this device has no IP address")
    try:
        if ipaddress.ip_address(ip).version != 4:
            raise ValueError
    except ValueError:
        raise actions.ActionError("this device has no usable IPv4 address")
    rounds = max(3, min(rounds, 15))

    async def one(args: list[str]) -> tuple[bool, float | None]:
        try:
            xml = await actions.nmap_output(args + ["-oX", "-", ip], 15, runner)
            hosts = parse_nmap_xml(xml)
        except (actions.ActionError, ValueError):
            return False, None
        return (True, hosts[0].rtt_ms) if hosts else (False, None)

    tally = {name: {"answered": 0, "rtts": []} for name, _ in METHODS}
    for i in range(rounds):
        outcomes = await asyncio.gather(*(one(args) for _, args in METHODS))
        for (name, _), (up, rtt) in zip(METHODS, outcomes):
            if up:
                tally[name]["answered"] += 1
                if rtt is not None:
                    tally[name]["rtts"].append(rtt)
        if i < rounds - 1:
            await asyncio.sleep(pause)
    methods = [{"method": name, "answered": t["answered"], "asked": rounds, "rtt_ms": round(statistics.median(t["rtts"]), 2) if t["rtts"] else None} for name, t in tally.items()]
    return {"ip": ip, "rounds": rounds, "methods": methods, "findings": probe_findings(methods)}


def probe_findings(methods: list[dict[str, Any]]) -> list[dict[str, str]]:
    by_name = {m["method"]: m for m in methods}
    arp, icmp, tcp = by_name["ARP"], by_name["ICMP ping"], by_name["TCP 80/443/22"]
    asked = arp["asked"]
    out: list[dict[str, str]] = []
    if all(m["answered"] == 0 for m in methods):
        return [_finding("warn", "It did not answer at all now", "It is off, unplugged, or on another network segment than Netlens. If it should be on, check its power and cable.")]
    if arp["answered"] == asked:
        out.append(_finding("ok", "ARP: always answered", f"All {asked} ARP requests were answered. On the local network this is what Netlens' scans depend on."))
    elif arp["answered"] >= asked * 0.5:
        out.append(_finding("warn", f"ARP: answered {arp['answered']} of {asked}", "The device does not always answer ARP requests. A scan that asks at a bad moment concludes it is offline. This is the usual cause of a device that flaps while everything behind it keeps working."))
    else:
        out.append(_finding("warn", f"ARP: answered only {arp['answered']} of {asked}", "It mostly ignores ARP requests. Netlens will keep thinking it is offline. A busy management processor or a rate limit on the device is likely."))
    if icmp["answered"] < asked and arp["answered"] > icmp["answered"]:
        out.append(_finding("info", f"Ping: answered {icmp['answered']} of {asked}", "It answers ARP better than ping; it gives ICMP a low priority, which is normal for switches."))
    if tcp["answered"] == 0 and arp["answered"] > 0:
        out.append(_finding("info", "No TCP answer on ports 80, 443 and 22", "It has no (reachable) web or SSH service on these ports, so TCP probes cannot be used as a backup."))
    return out
