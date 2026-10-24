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
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from app import actions
from app.hierarchy import descendants, load_hierarchy
from app.scanner.nmap_parser import parse_nmap_xml
from app.scanner.nmap_runner import build_args

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


def _is_beat(row) -> bool:
    try:
        return bool(row["beat"])
    except (IndexError, KeyError):
        return False


def outages(rows: list[sqlite3.Row], misses: int = 1) -> list[dict[str, Any]]:
    """Runs of missed checks: start, end (when it was seen again; None while it still is down), number of checks.

    A quick check between two scans (`beat`) is one ping: one lost answer is not an outage, so a run only counts once `misses` quick checks in a row
    were missed. A missed scan already had its second look before it was recorded, so it counts at once. Rows without a `beat` column (older data, tests)
    are scans, and with misses = 1 every missed check counts, as it always did."""
    found: list[dict[str, Any]] = []
    pending: list = []                   # down rows not yet enough to call an outage
    weight = 0
    current: dict[str, Any] | None = None
    for r in rows:
        if not r["up"]:
            if current is not None:
                current["checks"] += 1
                continue
            pending.append(r)
            weight += 1 if _is_beat(r) else misses
            if weight >= misses:
                current = {"start": pending[0]["ts"], "checks": len(pending), "end": None}
                found.append(current)
                pending, weight = [], 0
        else:
            if current is not None:
                current["end"] = r["ts"]
                current = None
            pending, weight = [], 0
    for o in found:
        end = _ts(o["end"]) if o["end"] else None
        o["seconds"] = (end - _ts(o["start"])).total_seconds() if end else None
    return found


MIN_ADDRESS_CHANGES = 3   # fewer address changes than this in the period is just a note
SEEN_TOGETHER = timedelta(hours=1)
# where to look for the virtual network card, per virtualisation product (the product names come from scanner.vendor.VIRTUAL_PREFIXES)
WHERE_TO_LOOK = {
    "Incus": "In TrueNAS that is the instance's network device under Instances.",
    "Proxmox": "In Proxmox that is the guest's Network Device (VM) or Network tab (container).",
    "VMware": "In VMware that is the virtual machine's network adapter settings.",
    "Microsoft Hyper-V": "In Hyper-V Manager that is the virtual machine's Network Adapter settings.",
    "QEMU/KVM": "With libvirt or virt-manager that is the guest's NIC in its hardware list.",
    "VirtualBox": "In VirtualBox that is the virtual machine's Network settings.",
    "Docker": "For Docker that is the container's network (a macvlan or bridge network).",
}
STANDALONE_CAUSES = (
    "The same causes exist on a physical device: a fixed address plus a lease from the router on one network card, extra addresses added to the same card, "
    "or a device that answers for others (a Wi-Fi extender or bridge, a VPN, or a router with proxy ARP shows other addresses with its own MAC)."
)


def _virtual_product(mac: str | None) -> str | None:
    """The virtualisation product behind a MAC prefix (VMware, Hyper-V, Proxmox, Incus ...), from the table the scanner already uses."""
    from app.scanner.vendor import VIRTUAL_PREFIXES

    value = (mac or "").lower()
    best = max((p for p in VIRTUAL_PREFIXES if value.startswith(p)), key=len, default=None)
    return VIRTUAL_PREFIXES[best].replace(" (virtual)", "") if best else None


def _guest_hint(conn: sqlite3.Connection, device_id: int, device) -> str:
    """What kind of thing it is and where its extra address probably comes from: a guest of a hypervisor or a physical device."""
    guest = conn.execute("SELECT kind, host_name, plugin_id FROM hypervisor_guests WHERE device_id = ? LIMIT 1", (device_id,)).fetchone()
    product = _virtual_product(device["mac"])
    effective = device["type_override"] or device["device_type"]
    if guest is None and product is None and effective not in ("vm", "container"):
        return STANDALONE_CAUSES
    parts = []
    if guest is not None:
        on = f" on {guest['host_name']}" if guest["host_name"] else ""
        parts.append(f"Netlens knows it as a {guest['kind']}{on} (from the {guest['plugin_id']} plugin).")
    elif product:
        parts.append(f"Its MAC address prefix belongs to {product} virtual machines or containers.")
    else:
        parts.append("It is registered as a virtual machine or container.")
    parts.append("So look at the network settings inside the guest (most likely it asks for an address by DHCP and also has a fixed one), and at its virtual network card on the host that runs it.")
    if product in WHERE_TO_LOOK:
        parts.append(WHERE_TO_LOOK[product])
    return " ".join(parts)


def address_findings(conn: sqlite3.Connection, device_id: int, since: str) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """Does the device keep changing its address, or answer on two addresses at once?

    Netlens keeps one entry per MAC address. A device with two addresses on one network card (a fixed one and a DHCP lease, a
    container that copies its host's MAC, ...) answers on both in every scan, so its entry's address "changes" back and forth
    and the history fills up with address changes. That is not an outage, but it explains odd uptime, names and DNS records.
    """
    device = conn.execute("SELECT mac, vendor, primary_ip, device_type, type_override FROM devices WHERE id = ?", (device_id,)).fetchone()
    changes = conn.execute("SELECT ts, detail FROM events WHERE device_id = ? AND kind = 'ip_changed' AND ts >= ? ORDER BY ts", (device_id, since)).fetchall()
    seen = conn.execute("SELECT ip, last_seen FROM device_ips WHERE device_id = ? AND last_seen >= ? ORDER BY last_seen DESC, ip", (device_id, since)).fetchall()
    info: dict[str, Any] = {"changes": len(changes), "addresses": [{"ip": r["ip"], "last_seen": r["last_seen"]} for r in seen], "at_once": False}
    if not changes:
        return [], info

    # one scan that reports "A -> B" and "B -> A" at the same moment saw both addresses answer
    directions: dict[str, set[str]] = {}
    for r in changes:
        directions.setdefault(r["ts"], set()).add(r["detail"] or "")
    swaps = 0
    for ts, details in directions.items():
        for d in details:
            a, _, b = d.partition(" -> ")
            if b and f"{b} -> {a}" in details:
                swaps += 1
                break
    newest = _ts(seen[0]["last_seen"]) if seen else None
    together = [r["ip"] for r in seen if newest and newest - _ts(r["last_seen"]) <= SEEN_TOGETHER]
    at_once = swaps >= 2 or len(together) >= 2 and len(changes) >= MIN_ADDRESS_CHANGES
    info.update({"at_once": at_once, "swapped_scans": swaps})

    addresses = [r["ip"] for r in seen] or [device["primary_ip"]]
    names = ", ".join(sorted(addresses))
    router_name = conn.execute("SELECT name FROM device_names WHERE device_id = ? AND source = 'router' ORDER BY last_seen DESC LIMIT 1", (device_id,)).fetchone()
    mac = device["mac"] or "?"
    if at_once and len(changes) >= MIN_ADDRESS_CHANGES:
        extra = [_guest_hint(conn, device_id, device)]
        if router_name:
            extra.append(f"The router knows it as \u201c{router_name['name']}\u201d, so one of the addresses is probably a DHCP lease from the router.")
        return [_finding(
            "warn", f"It answers on {len(together) if len(together) >= 2 else 2} addresses at the same time",
            f"{names} {'both' if len(addresses) == 2 else 'all'} answer with the same MAC address ({mac}), so this is one network card (or one virtual one) with more than one address. "
            f"Netlens keeps one entry per MAC, so in {swaps or 'many'} scans the entry's address \u201cchanged\u201d back and forth ({len(changes)} address changes in this period). "
            "It is not an outage, but it fills the history with changes and can confuse names and DNS records. "
            "To see its addresses, run `ip -4 addr` (Linux) or `ipconfig /all` (Windows) on the device, then remove the one you do not want: switch off DHCP on that interface, "
            "or delete its lease or reservation in the router. "
            + " ".join(extra))], info
    if len(changes) >= MIN_ADDRESS_CHANGES:
        return [_finding(
            "warn", "Its address keeps changing",
            f"Netlens saw the address of this device change {len(changes)} times in this period ({names}). A device with a fixed address does not do that: it usually gets its address from "
            "DHCP and the lease is handed out again. Give it a reservation in the router (or set a fixed address on the device) so that it keeps one.")], info
    return [_finding("info", "Its address changed", f"The address of this device changed {len(changes)} time(s) in this period ({names}).")], info


def analyze(conn: sqlite3.Connection, device_id: int, days: int = 7, now: str | None = None, tz_minutes: int = 0) -> dict[str, Any]:
    device = conn.execute("SELECT id, primary_ip, device_type, type_override, vendor FROM devices WHERE id = ?", (device_id,)).fetchone()
    if device is None:
        raise KeyError(device_id)
    days = days if days in DAYS else 7
    current = _ts(now) if now else datetime.now(timezone.utc)
    since = (current - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = conn.execute("SELECT ts, up, rtt_ms, beat FROM checks WHERE device_id = ? AND ts >= ? ORDER BY ts, id", (device_id, since)).fetchall()
    from app import beats

    misses = beats.settings(conn)[1]
    result: dict[str, Any] = {"device_id": device_id, "days": days, "checks": len(rows), "findings": []}
    findings = result["findings"]
    address, address_info = address_findings(conn, device_id, since)       # independent of the uptime history: checked first
    result["address"] = address_info
    findings.extend(address)
    if len(rows) < 10:
        findings.append(_finding("info", "Not enough history yet", f"Only {len(rows)} check(s) in the last {days} day(s); a few more are needed."))
        return result

    runs = outages(rows, misses)
    in_outage = {r["ts"] for r in rows if not r["up"] and any(o["start"] <= r["ts"] and (o["end"] is None or r["ts"] < o["end"]) for o in runs)}
    down = [r for r in rows if not r["up"] and r["ts"] in in_outage]           # a single lost quick check is not an outage
    result.update({
        "down_checks": len(down), "down_percent": round(100 * len(down) / len(rows), 1), "outages": len(runs),
        "currently_down": bool(rows and not rows[-1]["up"]),
    })
    timed = [o["seconds"] for o in runs if o["seconds"] is not None]
    result["median_outage_seconds"] = round(statistics.median(timed)) if timed else None
    result["longest_outage_seconds"] = round(max(timed)) if timed else None
    result["recent_outages"] = [{"start": o["start"], "end": o["end"], "checks": o["checks"], "seconds": o["seconds"]} for o in runs[-10:]][::-1]

    if not runs or len(runs) < MIN_OUTAGES and result["down_percent"] < 5:
        findings.append(_finding("ok", "Not flapping", f"Missed {len(runs)} time(s) in {days} day(s) ({result['down_percent']} % of the checks)."))
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
            f"In {round(100 * up_share_behind)} % of the checks that missed it, the {len(behind)} device(s) behind it were online, so traffic was passing through it. "
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
        findings.append(_finding("info", "Only this device is affected", "Other devices were answering during its gaps, so the checks themselves are working."))

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


async def probe(ip: str | None, rounds: int = 8, pause: float = 1.0, runner=None, options=None) -> dict[str, Any]:
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
    # ... and a real quick scan of just this device, the way Netlens scans: does it report the device as up?
    scan: dict[str, Any] = {"up": False, "seconds": None}
    started = time.monotonic()
    try:
        xml = await actions.nmap_output(build_args("quick", [ip], 3, options=options) + [], 150, runner)
        scan["up"] = bool(parse_nmap_xml(xml))
    except (actions.ActionError, ValueError):
        pass
    scan["seconds"] = round(time.monotonic() - started, 1)
    methods = [{"method": name, "answered": t["answered"], "asked": rounds, "rtt_ms": round(statistics.median(t["rtts"]), 2) if t["rtts"] else None} for name, t in tally.items()]
    return {"ip": ip, "rounds": rounds, "methods": methods, "scan": scan, "findings": probe_findings(methods, scan)}


def probe_findings(methods: list[dict[str, Any]], scan: dict[str, Any] | None = None) -> list[dict[str, str]]:
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
    if scan is not None and scan["up"] and (arp["answered"] or icmp["answered"]):
        out.append(_finding(
            "info", f"A scan aimed only at this device sees it ({scan['seconds']} s)",
            "So the device is reachable and Netlens can find it. If it is still missed in the regular scans, the big sweep gives up on it before its (late) answer arrives. "
            "Netlens now asks for a device the sweep missed once more on its own before marking it offline (Settings → Scan performance → Look again before marking a device offline)."))
    elif scan is not None and not scan["up"] and (arp["answered"] or icmp["answered"]):
        out.append(_finding("warn", "A scan aimed only at this device did NOT see it", "It answers the probes above, yet a Netlens quick scan of it reports nothing. Check the scan settings (Settings → Scan performance), for example a very short host time-out."))
    if tcp["answered"] == 0 and arp["answered"] > 0:
        out.append(_finding("info", "No TCP answer on ports 80, 443 and 22", "It has no (reachable) web or SSH service on these ports, so TCP probes cannot be used as a backup."))
    return out
