"""IPv4 health: is the IPv4 side of this network in good order, in plain words.

It looks at what this machine sees (its addresses, the gateway and whether it answers, the DNS servers, the internet over IPv4 and a name
lookup) and at what Netlens already knows (the scanned ranges and how full they are, two devices with the same address, the DHCP servers that
answered and what they hand out, devices that gave themselves a 169.254 address). The judging is a pure function (`analyse`) of those facts,
like the IPv6 health, so it is tested with fixtures.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import socket
import sqlite3
from typing import Any

from app.db import set_setting, get_setting, utcnow
from app.ipv6health import _tcp, finding_key
from app.scanner.ipv6 import SKIP_IFACES
from app.scanner.netinfo import run_ip

log = logging.getLogger(__name__)
KEY = "ipv4.health"
INTERNET_TARGETS = (("1.1.1.1", 443), ("8.8.8.8", 443))
DNS_NAME = "example.com"


# ----------------------------------------------------------------------------- parsing
def parse_addresses(text: str) -> list[dict[str, Any]]:
    """`ip -4 -o addr show`: [{iface, addr, network, selfassigned}] without loopback and virtual interfaces."""
    out = []
    for line in text.splitlines():
        m = re.match(r"\d+:\s+(\S+)\s+inet\s+([0-9.]+)/(\d+)", line)
        if not m or m.group(1) == "lo" or m.group(1).split("@")[0].startswith(SKIP_IFACES):
            continue
        try:
            iface_ip = ipaddress.IPv4Interface(f"{m.group(2)}/{m.group(3)}")
        except ValueError:
            continue
        out.append({"iface": m.group(1).split("@")[0], "addr": str(iface_ip.ip), "network": str(iface_ip.network), "selfassigned": iface_ip.ip in ipaddress.IPv4Network("169.254.0.0/16")})
    return out


def parse_default_routes(text: str) -> list[dict[str, str]]:
    """`ip -4 route show default`: [{via, dev, metric}]."""
    out = []
    for line in text.splitlines():
        words = line.split()
        if not words or words[0] != "default":
            continue
        info = {words[i]: words[i + 1] for i in range(len(words) - 1) if words[i] in ("via", "dev", "metric")}
        if "via" in info:
            out.append({"via": info["via"], "dev": info.get("dev", ""), "metric": info.get("metric", "")})
    return out


def parse_resolv(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        words = line.split()
        if len(words) >= 2 and words[0] == "nameserver":
            try:
                out.append(str(ipaddress.ip_address(words[1].split("%")[0])))
            except ValueError:
                pass
    return out


# ----------------------------------------------------------------------------- collecting
async def _dns(name: str = DNS_NAME) -> dict[str, Any]:
    try:
        infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(name, 443, family=socket.AF_INET, type=socket.SOCK_STREAM), timeout=5)
    except (OSError, asyncio.TimeoutError):
        return {"ok": False, "name": name}
    return {"ok": bool(infos), "name": name, "answer": infos[0][4][0] if infos else None}


async def ping(address: str, nmap_path: str = "nmap", timeout: float = 15.0) -> bool | None:
    """Whether an address answers (nmap: ARP on the local network, an echo elsewhere), or None when that cannot be tried."""
    try:
        proc = await asyncio.create_subprocess_exec(nmap_path, "-sn", "-n", "-oG", "-", address, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (FileNotFoundError, asyncio.TimeoutError, OSError):
        return None
    return "Status: Up" in out.decode("utf-8", "replace")


def _read_resolv() -> str:
    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


async def collect(ip_path: str = "ip") -> dict[str, Any]:
    addr_text, route_text = await asyncio.gather(run_ip(["-4", "-o", "addr", "show"], ip_path), run_ip(["-4", "route", "show", "default"], ip_path))
    routes = parse_default_routes(route_text)
    tcp = [(host, await _tcp(host, port)) for host, port in INTERNET_TARGETS]
    best = next(((h, ms) for h, ms in tcp if ms is not None), None)
    gateway_up = await ping(routes[0]["via"]) if routes else None
    return {"addresses": parse_addresses(addr_text), "defaults": routes, "nameservers": parse_resolv(_read_resolv()),
            "internet": {"ok": best is not None, "target": (best or tcp[0])[0], "ms": best[1] if best else None}, "dns": await _dns(), "gateway_up": gateway_up}


def facts_from(conn: sqlite3.Connection, ranges: list[str]) -> dict[str, Any]:
    """What Netlens knows: devices, the scanned ranges, the DHCP servers, the gateway it remembers and the notable events of 30 days."""
    from app import netchecks

    devices = [{"id": r["id"], "name": r["name"], "ip": r["primary_ip"], "mac": (r["mac"] or "").lower(), "online": bool(r["online"])}
               for r in conn.execute("SELECT id, COALESCE(custom_name, hostname, primary_ip) AS name, primary_ip, mac, online FROM devices WHERE primary_ip IS NOT NULL")]
    events = {r["kind"]: r["n"] for r in conn.execute("SELECT kind, COUNT(*) AS n FROM events WHERE kind IN ('ip_reused', 'gateway_changed', 'dhcp_rogue') AND ts >= datetime('now', '-30 days') GROUP BY kind")}
    reused = conn.execute("SELECT COUNT(DISTINCT detail) FROM events WHERE kind = 'ip_reused' AND ts >= datetime('now', '-30 days')").fetchone()[0]
    return {"devices": devices, "ranges": ranges, "dhcp": netchecks.list_servers(conn), "dhcp_last": netchecks.get_last(conn), "gateway": netchecks.get_gateway(conn), "events": events, "reused_addresses": reused}


# ----------------------------------------------------------------------------- judging
def _in(ip: str, net: ipaddress.IPv4Network) -> bool:
    try:
        return ipaddress.IPv4Address(ip) in net
    except ValueError:
        return False


def analyse(raw: dict[str, Any], facts: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, str]] = []

    def add(level: str, title: str, text: str) -> None:
        findings.append({"level": level, "key": finding_key(title), "title": title, "text": text})

    devices = facts["devices"]
    by_ip = {d["ip"]: d["name"] for d in devices}
    mine = raw["addresses"]
    real = [a for a in mine if not a["selfassigned"]]

    # 1. this computer
    if not mine:
        add("bad", "This computer has no IPv4 address", "Netlens cannot see the network without one. If it runs in Docker, check that the container uses the host network.")
    elif not real:
        add("bad", "This computer gave itself a 169.254 address", "That means no DHCP server answered. The network is not handing out addresses, or this computer is not really connected.")
    # 2. the way out
    defaults = raw["defaults"]
    if real:
        if not defaults:
            add("bad", "There is no default gateway", "Without a gateway nothing leaves the local network. The router is missing from the settings, or DHCP did not hand out a gateway.")
        else:
            gw = defaults[0]["via"]
            label = f"{gw} ({by_ip[gw]})" if gw in by_ip else gw
            up = raw.get("gateway_up")
            if up is False:
                add("bad", "The gateway does not answer", f"{label} is the default gateway but does not reply. The router may be off or its address is not what devices use.")
            else:
                add("good", "The gateway answers" if up else "A gateway is set", f"{label} on {defaults[0]['dev']}.")
            if len({d["via"] for d in defaults}) > 1:
                add("info", "More than one default gateway", ", ".join(sorted({d["via"] for d in defaults})) + ". Fine with two internet connections, a mistake when there is only one router.")
            changed = facts["events"].get("gateway_changed", 0)
            if changed:
                add("warn", "The device behind the gateway address changed", f"{changed} time{'s' if changed != 1 else ''} in the last 30 days. A replaced router is harmless; otherwise it can be someone pretending to be the router (ARP spoofing).")
        # 3. the internet and names
        net = raw["internet"]
        if net["ok"]:
            add("good", "The internet works over IPv4", f"A connection to {net['target']} succeeded in {net['ms']:g} ms.")
        elif defaults:
            add("bad", "The internet cannot be reached over IPv4", "The gateway is set but a connection to a well-known server fails. Check the router's internet connection.")
        if raw["dns"]["ok"]:
            add("good", "Names resolve", f"{raw['dns']['name']} resolves to {raw['dns'].get('answer')}" + (f" (DNS server{'s' if len(raw['nameservers']) != 1 else ''}: {', '.join(raw['nameservers'])})." if raw["nameservers"] else "."))
        elif net["ok"]:
            add("bad", "Names do not resolve", "The internet works but a name lookup fails: the DNS server is down or unreachable" + (f" ({', '.join(raw['nameservers'])})." if raw["nameservers"] else "."))

    # 4. address ranges and how full they are
    subnets = []
    nets = []
    for r in facts["ranges"]:
        try:
            nets.append(ipaddress.IPv4Network(r, strict=False))
        except ValueError:
            continue
    attached = {a["network"] for a in mine}
    for net in nets:
        inside = [d for d in devices if _in(d["ip"], net)]
        hosts = max(net.num_addresses - 2, 1)
        usage = round(100 * len(inside) / hosts)
        subnets.append({"range": str(net), "online": sum(1 for d in inside if d["online"]), "known": len(inside), "size": hosts, "usage": usage, "attached": str(net) in attached})
        if str(net) not in attached and mine:
            add("info", f"{net} is not directly connected to this computer", "Devices there are found with pings only: their MAC addresses (and so vendors and renamed devices) are not visible. Put a Netlens on that network or let it report to this one as a remote site.")
        if hosts >= 100 and usage >= 95:
            add("bad", f"{net} is nearly full", f"{len(inside)} of {hosts} addresses are known. New devices may not get an address. Use a bigger range or remove old devices.")
        elif hosts >= 100 and usage >= 80:
            add("warn", f"{net} is filling up", f"{len(inside)} of {hosts} addresses are known ({usage}%). Plan a larger range before it runs out.")
    outside = [d for d in devices if d["online"] and nets and not any(_in(d["ip"], n) for n in nets)]
    if outside:
        add("info", f"{len(outside)} online device{'s' if len(outside) != 1 else ''} outside the scanned ranges", ", ".join(sorted(d["name"] for d in outside)[:10]) + ". They are known but not on a range Netlens scans, so they are only seen by other means.")
    if len(nets) > 1:
        add("info", f"{len(nets)} subnets are scanned", "Devices in different subnets reach each other through the router only. That is a way to separate guests, cameras or servers, and a common reason why something works from one device but not from another.")

    # 5. two devices with one address, addresses that keep moving, devices without an address
    seen: dict[str, list[dict]] = {}
    for d in devices:
        if d["online"]:
            seen.setdefault(d["ip"], []).append(d)
    clashes = {ip: ds for ip, ds in seen.items() if len({x["mac"] for x in ds}) > 1}
    if clashes:
        add("bad", "Two devices use the same IP address", "; ".join(f"{ip}: " + " and ".join(sorted(x["name"] for x in ds)) for ip, ds in sorted(clashes.items())[:5])
            + ". Both will have trouble. Give one of them a different address, or reserve addresses in the router.")
    if facts["reused_addresses"] >= 5:
        add("warn", "Addresses keep moving between devices", f"{facts['reused_addresses']} addresses were taken over by another device in the last 30 days. DHCP leases are probably short; reserve fixed addresses for servers, printers and cameras.")
    selfassigned = [d for d in devices if d["online"] and d["ip"].startswith("169.254.")]
    if selfassigned:
        add("warn", f"{len(selfassigned)} device{'s' if len(selfassigned) != 1 else ''} gave themselves a 169.254 address", ", ".join(sorted(d["name"] for d in selfassigned)[:10]) + ". They asked for an address and no DHCP server answered them.")

    # 6. DHCP
    dhcp = facts["dhcp"]
    untrusted = [s for s in dhcp if not s["trusted"]]
    if untrusted:
        add("bad", "A DHCP server you have not approved answers", ", ".join(s["ip"] + (f" ({s['name']})" if s.get("name") else "") for s in untrusted) + ". A second DHCP server (a router someone plugged in, a VM) hands out wrong gateways or addresses. Find it, or mark it as trusted on the Network checks settings.")
    elif len(dhcp) > 1:
        add("warn", f"{len(dhcp)} DHCP servers answer", ", ".join(s["ip"] for s in dhcp) + ". Two servers on one network need to be a planned pair; otherwise devices get random settings.")
    elif len(dhcp) == 1:
        s = dhcp[0]
        offers = []
        if s.get("router"):
            offers.append(f"gateway {s['router']}")
        if s.get("dns"):
            offers.append("DNS " + ", ".join(s["dns"]))
        add("good", "One DHCP server hands out addresses", f"{s['ip']}" + (f" ({s['name']})" if s.get("name") else "") + (", offering " + "; ".join(offers) if offers else "") + ".")
        if s.get("router") and defaults and s["router"] != defaults[0]["via"]:
            add("warn", "DHCP offers another gateway than this computer uses", f"DHCP says {s['router']}, this computer uses {defaults[0]['via']}. Devices may take different ways out.")
    elif not facts["dhcp_last"]:
        add("info", "No DHCP check yet", "Netlens looks for DHCP servers now and then (Settings → Network checks). Until it has, rogue servers are not noticed.")
    else:
        add("info", "No DHCP server answered", "Netlens asked and nothing answered. Normal when every device has a fixed address; otherwise the DHCP server may be down.")

    findings.sort(key=lambda f: ("bad", "warn", "info", "good").index(f["level"]))      # the problems first (the sort keeps the order within a level)
    levels = {f["level"] for f in findings}
    if "bad" in levels:
        verdict, headline = "bad", "IPv4 has a problem"
    elif "warn" in levels:
        verdict, headline = "warn", "IPv4 works, with a few things to look at"
    elif "good" in levels:
        verdict, headline = "good", "IPv4 is in good order"
    else:
        verdict, headline = "info", "Not enough to judge yet"
    return {"verdict": verdict, "headline": headline, "findings": findings, "subnets": subnets,
            "devices": {"online": sum(1 for d in devices if d["online"]), "known": len(devices)}}


async def run(conn: sqlite3.Connection, ranges: list[str], ip_path: str = "ip") -> dict[str, Any]:
    from app.scanner.netinfo import detect_ranges

    result = analyse(await collect(ip_path), facts_from(conn, ranges or await detect_ranges(ip_path)))
    result["ts"] = utcnow()
    set_setting(conn, KEY, json.dumps(result))
    return result


def last(conn: sqlite3.Connection) -> dict[str, Any] | None:
    try:
        doc = json.loads(get_setting(conn, KEY) or "null")
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None
