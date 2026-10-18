"""IPv6 health: is IPv6 on this network working as it should, in plain words.

Netlens looks at what this machine itself sees (its IPv6 addresses, the routes it learned from the router, the devices that announce
themselves as IPv6 routers), tries the internet over IPv6 (a TCP connection and a DNS lookup), and compares that with the IPv6
addresses found on the devices (Settings -> IPv6) and whether they answer an ICMPv6 echo. The result is a verdict, a list of findings that
each say what was seen and what it means, and the prefixes (the "subnets") in use.

Everything that reads the machine is split from the judging: `analyse` is a pure function of the collected facts, so it is tested with
fixtures. Only the networks this machine is directly connected to are visible (Docker host networking, like ARP).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import socket
import sqlite3
import time
from typing import Any

from app.db import get_setting, set_setting, utcnow
from app.scanner.ipv6 import SKIP_IFACES, scope_of
from app.scanner.netinfo import run_ip

log = logging.getLogger(__name__)
KEY = "ipv6.health"
INTERNET_TARGETS = (("2606:4700:4700::1111", 443), ("2001:4860:4860::8888", 443))       # Cloudflare and Google DNS over TCP
DNS_NAME = "ipv6.google.com"
MAX_PING = 80


# ----------------------------------------------------------------------------- parsing what the machine says
def parse_addresses(text: str) -> list[dict[str, Any]]:
    """`ip -6 -o addr show`: [{iface, addr, prefixlen, scope, temporary, deprecated, dadfailed, tentative}] without virtual interfaces."""
    out = []
    for line in text.splitlines():
        m = re.match(r"\d+:\s+(\S+)\s+inet6\s+([0-9a-fA-F:]+)/(\d+)\s+(.*)", line)
        if not m:
            continue
        iface, addr, plen, rest = m.group(1), m.group(2), int(m.group(3)), m.group(4)
        scope = scope_of(addr)
        if scope is None or iface.startswith(SKIP_IFACES):
            continue
        flags = set(rest.replace("\\", " ").split())
        out.append({"iface": iface, "addr": str(ipaddress.IPv6Address(addr)), "prefixlen": plen, "scope": scope, "temporary": "temporary" in flags,
                    "deprecated": "deprecated" in flags, "dadfailed": "dadfailed" in flags, "tentative": "tentative" in flags})
    return out


def parse_routes(text: str) -> dict[str, list[dict[str, Any]]]:
    """`ip -6 route show`: the default routes (the routers) and the prefixes that are on the link."""
    defaults, prefixes = [], []
    for line in text.splitlines():
        words = line.split()
        if not words:
            continue
        info = {words[i]: words[i + 1] for i in range(len(words) - 1) if words[i] in ("via", "dev", "proto", "metric", "expires")}
        if words[0] == "default" and "via" in info:
            defaults.append({"via": info["via"], "dev": info.get("dev", ""), "proto": info.get("proto", ""), "metric": info.get("metric", "")})
        elif "/" in words[0] and "via" not in info:
            try:
                net = ipaddress.IPv6Network(words[0], strict=False)
            except ValueError:
                continue
            if scope_of(str(net.network_address)) in ("global", "ula") and not info.get("dev", "").startswith(SKIP_IFACES):
                prefixes.append({"prefix": str(net), "dev": info.get("dev", ""), "proto": info.get("proto", ""), "expires": info.get("expires", "")})
    return {"defaults": defaults, "prefixes": prefixes}


def parse_routers(text: str) -> list[dict[str, str]]:
    """`ip -6 neigh show`: the neighbours that announced themselves as routers (the `router` flag): [{ip, mac, dev}]."""
    out = []
    for line in text.splitlines():
        words = line.split()
        if len(words) < 4 or "router" not in words or "lladdr" not in words:
            continue
        mac = words[words.index("lladdr") + 1].lower()
        dev = words[words.index("dev") + 1] if "dev" in words else ""
        if dev.startswith(SKIP_IFACES) or words[-1] in ("FAILED", "INCOMPLETE"):
            continue
        out.append({"ip": words[0].split("%")[0], "mac": mac, "dev": dev})
    return out


def prefix64(address: str) -> str:
    return str(ipaddress.IPv6Network((int(ipaddress.IPv6Address(address)) >> 64 << 64, 64)))


# ----------------------------------------------------------------------------- collecting
async def _tcp(host: str, port: int, timeout: float = 4.0) -> float | None:
    started = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    writer.close()
    return round((time.monotonic() - started) * 1000, 1)


async def _dns(name: str = DNS_NAME) -> dict[str, Any]:
    try:
        infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(name, 443, family=socket.AF_INET6, type=socket.SOCK_STREAM), timeout=5)
    except (OSError, asyncio.TimeoutError):
        return {"ok": False, "name": name}
    return {"ok": bool(infos), "name": name, "answer": infos[0][4][0] if infos else None}


async def ping_many(addresses: list[str], nmap_path: str = "nmap", timeout: float = 40.0) -> set[str] | None:
    """The addresses that answer an ICMPv6 echo (one nmap run), or None when it cannot be done."""
    addresses = [a for a in dict.fromkeys(addresses) if scope_of(a) in ("global", "ula")][:MAX_PING]
    if not addresses:
        return set()
    try:
        proc = await asyncio.create_subprocess_exec(nmap_path, "-6", "-sn", "-n", "-PE", "-oG", "-", *addresses, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (FileNotFoundError, asyncio.TimeoutError, OSError):
        return None
    up = set()
    for line in out.decode("utf-8", "replace").splitlines():
        m = re.match(r"Host:\s+(\S+)\s+\(.*\)\s+Status:\s+Up", line)
        if m:
            try:
                up.add(str(ipaddress.IPv6Address(m.group(1))))
            except ValueError:
                pass
    return up


async def collect(ip_path: str = "ip") -> dict[str, Any]:
    addr_text, route_text, neigh_text = await asyncio.gather(
        run_ip(["-6", "-o", "addr", "show"], ip_path), run_ip(["-6", "route", "show"], ip_path), run_ip(["-6", "neigh", "show"], ip_path))
    tcp = [(host, await _tcp(host, port)) for host, port in INTERNET_TARGETS]
    best = next(((h, ms) for h, ms in tcp if ms is not None), None)
    return {"addresses": parse_addresses(addr_text), "routes": parse_routes(route_text), "routers": parse_routers(neigh_text),
            "internet": {"ok": best is not None, "target": (best or tcp[0])[0], "ms": best[1] if best else None}, "dns": await _dns()}


def device_facts(conn: sqlite3.Connection) -> dict[str, Any]:
    """The devices as far as IPv6 is concerned: online ones, their IPv6 addresses, and their MAC addresses (to name the routers)."""
    devices = {r["id"]: {"id": r["id"], "name": r["name"], "mac": (r["mac"] or "").lower(), "online": bool(r["online"]), "addresses": []}
               for r in conn.execute("SELECT id, COALESCE(custom_name, hostname, primary_ip) AS name, mac, online FROM devices")}
    for r in conn.execute("SELECT device_id, ip, scope FROM device_ipv6"):
        if r["device_id"] in devices:
            devices[r["device_id"]]["addresses"].append({"ip": r["ip"], "scope": r["scope"]})
    return {"devices": list(devices.values()), "discovery": get_setting(conn, "ipv6.enabled") == "1"}


# ----------------------------------------------------------------------------- judging
def analyse(raw: dict[str, Any], facts: dict[str, Any], answered: set[str] | None = None) -> dict[str, Any]:
    """The verdict and the findings. `answered` = addresses that answered a ping (None: not tried)."""
    findings: list[dict[str, str]] = []

    def add(level: str, title: str, text: str) -> None:
        findings.append({"level": level, "title": title, "text": text})

    by_mac = {d["mac"]: d["name"] for d in facts["devices"] if d["mac"]}
    mine = [a for a in raw["addresses"] if a["scope"] in ("global", "ula") and not a["dadfailed"]]
    failed = [a for a in raw["addresses"] if a["dadfailed"]]
    global_addrs = [a for a in mine if a["scope"] == "global"]
    host_prefixes = sorted({prefix64(a["addr"]) for a in mine})
    routes = raw["routes"]

    # 1. does this network use IPv6 at all
    if not mine:
        add("info", "This network does not hand out IPv6 addresses",
            "This computer only has a link-local address (fe80::), which works on the local cable or Wi-Fi only. That is normal when your router has IPv6 switched off. "
            "If your provider offers IPv6, switch it on in the router (often called IPv6, DHCPv6-PD or 'native'): devices then get addresses that work on the internet.")
    else:
        if global_addrs:
            add("good", "Internet (global) addresses are handed out",
                "Prefix" + ("es" if len({prefix64(a['addr']) for a in global_addrs}) > 1 else "") + " " + ", ".join(sorted({prefix64(a["addr"]) + " on " + a["iface"] for a in global_addrs}))
                + ". Your router received this range from your provider and passes it on to the devices (router advertisement), so a device can build its own address from it.")
        else:
            add("info", "Only private (unique-local) addresses",
                "The addresses start with fd or fc: they work inside your network only, like 192.168.x.x. Your provider's IPv6 range is not (yet) handed out, so devices cannot use IPv6 on the internet.")
        # 2. the way out
        defaults = [r for r in routes["defaults"] if r["dev"] in {a["iface"] for a in mine}] or routes["defaults"]
        gateways = sorted({r["via"] for r in defaults})
        if not defaults:
            if global_addrs:
                add("bad", "There is an address but no way out", "This computer has a global IPv6 address but no default IPv6 route, so nothing leaves the local network over IPv6. "
                    "The router is not advertising itself as a default router (or the advertisement was blocked). Check the IPv6 settings of the router.")
            else:
                add("info", "No IPv6 default route", "There is no router to send IPv6 traffic to; only the local network is reachable over IPv6.")
        else:
            names = []
            for g in gateways:
                mac = next((r["mac"] for r in raw["routers"] if r["ip"] == g), None)
                names.append(f"{g} ({by_mac[mac]})" if mac and mac in by_mac else g)
            if len(gateways) == 1:
                add("good", "One router handles IPv6", f"Traffic leaves through {names[0]}.")
            else:
                add("warn", f"{len(gateways)} routers offer a way out over IPv6", ", ".join(names) + ". At home there is normally one. A second one is often a device that "
                    "was never meant to be a router (a mesh node, a VM host, a repeater) and can send some of your devices to the wrong place or a dead end.")
        # who announces itself as a router
        routers = {(r["ip"], r["mac"]) for r in raw["routers"]}
        if len(routers) > 1:
            names = [f"{ip} ({by_mac[mac]})" if mac in by_mac else ip for ip, mac in sorted(routers)]
            if len(gateways) <= 1:
                add("warn", f"{len(routers)} devices announce themselves as IPv6 routers", ", ".join(names) + ". Check that each of them is meant to be one.")
        # 3. the internet
        net = raw["internet"]
        if net["ok"]:
            add("good", "The internet works over IPv6", f"A connection to {net['target']} succeeded in {net['ms']:g} ms.")
        elif global_addrs and defaults:
            add("bad", "The internet cannot be reached over IPv6", "There is an address and a router, yet a connection to a well-known IPv6 server fails. Typical causes: the provider's IPv6 is down, "
                "the router's IPv6 firewall blocks outgoing traffic, or the router advertises a prefix it cannot route.")
        if net["ok"] or global_addrs:
            if raw["dns"]["ok"]:
                add("good", "Names resolve to IPv6 addresses", f"{raw['dns']['name']} resolves to {raw['dns'].get('answer')}.")
            else:
                add("warn", "Names do not resolve to IPv6 addresses", f"The lookup of {raw['dns']['name']} gave no IPv6 answer. Your DNS server may not pass on AAAA records.")
        # 4. problems with this computer's own addresses
        if failed:
            add("bad", "Another device uses the same IPv6 address", ", ".join(a["addr"] for a in failed) + ": duplicate address detection failed, so this address is not in use. Find the device with the same address.")
        if global_addrs and all(a["deprecated"] for a in global_addrs):
            add("warn", "The internet addresses are expiring", "Every global address is marked deprecated: the router stopped advertising the prefix (the provider changed it, or IPv6 was switched off there).")
        per_iface: dict[str, set[str]] = {}
        for a in global_addrs:
            if not a["deprecated"] and not a["temporary"]:
                per_iface.setdefault(a["iface"], set()).add(prefix64(a["addr"]))
        for iface, prefixes in per_iface.items():
            if len(prefixes) > 1:
                add("warn", f"More than one internet prefix on {iface}", ", ".join(sorted(prefixes)) + ". Normal for a short while after the provider changes the range; otherwise a second router is handing out its own range.")

    # 5. the devices
    online = [d for d in facts["devices"] if d["online"]]
    ranges: dict[str, dict[str, Any]] = {}
    other_prefix = []
    have = []
    for d in online:
        usable = [a for a in d["addresses"] if a["scope"] in ("global", "ula")]
        if usable:
            have.append(d)
        for a in usable:
            p = prefix64(a["ip"])
            ranges.setdefault(p, {"prefix": p, "scope": a["scope"], "devices": set()})["devices"].add(d["id"])
        if usable and host_prefixes and not any(prefix64(a["ip"]) in host_prefixes for a in usable):
            other_prefix.append(d)
    if facts["discovery"] and online:
        if mine and not have:
            add("warn", "No device shows an IPv6 address", "Discovery is on but found no device with a global or private IPv6 address. Run a scan, or check that devices are allowed to use IPv6.")
        elif mine:
            none = [d["name"] for d in online if d not in have]
            add("good" if not none else "info", f"{len(have)} of {len(online)} online devices have an IPv6 address",
                ("Without one: " + ", ".join(sorted(none)[:10]) + (" and more" if len(none) > 10 else "") + ". Many older devices, printers and smart plugs only speak IPv4; that is normal.") if none else "Every online device has one.")
        if other_prefix:
            n = len(other_prefix)
            add("warn", f"{n} device{'s' if n != 1 else ''} {'use' if n != 1 else 'uses'} a different prefix than this computer",
                ", ".join(sorted(d["name"] for d in other_prefix)[:10]) + ". They are in another IPv6 subnet (a guest network, a second router) or hold an old address from before the provider changed the range. "
                "They may not be able to talk to this computer over IPv6.")
    elif not facts["discovery"]:
        add("info", "Per-device results are off", "Switch on IPv6 discovery (Settings → IPv6) and Netlens also checks which devices have addresses, which subnet they are in and whether they answer.")

    # 6. do they answer
    unreachable: list[str] = []
    if answered is not None and have:
        for d in have:
            addrs = [a["ip"] for a in d["addresses"] if a["scope"] in ("global", "ula")]
            if not any(a in answered for a in addrs):
                unreachable.append(d["name"])
        if unreachable:
            add("info", f"{len(unreachable)} device{'s' if len(unreachable) != 1 else ''} did not answer a ping over IPv6", ", ".join(sorted(unreachable)[:10]) + (" and more" if len(unreachable) > 10 else "")
                + ". They are online over IPv4. Often a firewall: Windows blocks ping by default, and a device with a different prefix cannot be reached from here.")
        else:
            add("good", "Every device with an IPv6 address answers", f"{len(have)} device{'s' if len(have) != 1 else ''} replied to an ICMPv6 echo from this computer.")

    levels = {f["level"] for f in findings}
    if "bad" in levels:
        verdict, headline = "bad", "IPv6 has a problem"
    elif "warn" in levels:
        verdict, headline = "warn", "IPv6 works, with a few things to look at"
    elif "good" in levels:
        verdict, headline = "good", "IPv6 is working as it should"
    else:
        verdict, headline = "info", "IPv6 is not in use on this network"
    subnets = sorted(({"prefix": r["prefix"], "scope": r["scope"], "devices": len(r["devices"]), "this_computer": r["prefix"] in host_prefixes} for r in ranges.values()), key=lambda r: (-r["devices"], r["prefix"]))
    for p in host_prefixes:
        if not any(s["prefix"] == p for s in subnets):
            subnets.append({"prefix": p, "scope": "global" if any(a["scope"] == "global" and prefix64(a["addr"]) == p for a in mine) else "ula", "devices": 0, "this_computer": True})
    return {"verdict": verdict, "headline": headline, "findings": findings, "subnets": subnets,
            "routers": [{"ip": r["ip"], "name": by_mac.get(r["mac"])} for r in raw["routers"]],
            "devices": {"online": len(online), "with_ipv6": len(have), "pinged": answered is not None}}


async def run(conn: sqlite3.Connection, ip_path: str = "ip") -> dict[str, Any]:
    raw = await collect(ip_path)
    facts = device_facts(conn)
    targets = [a["ip"] for d in facts["devices"] if d["online"] for a in d["addresses"] if a["scope"] in ("global", "ula")]
    answered = await ping_many(targets) if targets else None
    result = analyse(raw, facts, answered)
    result["ts"] = utcnow()
    set_setting(conn, KEY, json.dumps(result))
    return result


def last(conn: sqlite3.Connection) -> dict[str, Any] | None:
    try:
        doc = json.loads(get_setting(conn, KEY) or "null")
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None
