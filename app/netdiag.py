"""Why does a network not answer? One test of a scanned network: is there a route to it, does the gateway answer, and do the devices that used to live
there answer a few different kinds of probes?

A network that went quiet (app/networks.py) has one of a few causes that look the same from the outside (no host answers): a route is missing, the
gateway or the tunnel towards it is down, a firewall blocks the probes, or the hosts really are off. The test tells them apart as far as it can.
Everything here only asks (ping, TCP connection attempts, `ip route get`); nothing is changed.
"""

from __future__ import annotations

import ipaddress
import re
import sqlite3
from typing import Any

from app import actions
from app.scanner.netinfo import run_ip
from app.scanner.nmap_parser import parse_nmap_xml

MAX_PROBED = 6
PROBES = ["-sn", "-n", "-PE", "-PS22,80,443", "-PA80,443", "--max-retries", "1", "--host-timeout", "8s"]
GOOD_TYPES = ("router", "switch", "server", "nas", "ap")          # devices that are on all day and answer something


def _finding(level: str, title: str, text: str) -> dict[str, str]:
    return {"level": level, "title": title, "text": text}


def _pick(conn: sqlite3.Connection, net: ipaddress.IPv4Network) -> list[dict[str, Any]]:
    """The known devices of this network that are the best test subjects: always-on first, then routers, switches and servers, the most recently seen first."""
    rows = []
    for r in conn.execute("SELECT id, primary_ip, last_seen, online, always_on, COALESCE(type_override, device_type) AS t, COALESCE(custom_name, hostname, primary_ip) AS name FROM devices "
                          "WHERE primary_ip IS NOT NULL AND same_host_id IS NULL ORDER BY last_seen DESC"):
        try:
            if ipaddress.ip_address(r["primary_ip"]) in net:
                rows.append(dict(r))
        except ValueError:
            continue
    rows.sort(key=lambda r: (-int(r["always_on"] or 0), 0 if r["t"] in GOOD_TYPES else 1))
    return rows[:MAX_PROBED]


def parse_route(text: str) -> dict[str, Any]:
    """What `ip -4 route get <address>` says: the next hop and the interface, or that there is no route."""
    text = (text or "").strip()
    if not text:
        return {"found": False, "gateway": None, "dev": None}
    via, dev = re.search(r"\bvia (\S+)", text), re.search(r"\bdev (\S+)", text)
    return {"found": True, "gateway": via.group(1) if via else None, "dev": dev.group(1) if dev else None}


async def _answering(ips: list[str], runner) -> set[str]:
    if not ips:
        return set()
    try:
        xml = await actions.nmap_output(PROBES + ["-oX", "-", *ips], 40, runner)
        return {h.ip for h in parse_nmap_xml(xml)}
    except (actions.ActionError, ValueError):
        return set()


async def diagnose(conn: sqlite3.Connection, network_id: int, runner=None, ip_runner=None) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM networks WHERE id = ?", (network_id,)).fetchone()
    if row is None:
        raise KeyError(network_id)
    net = ipaddress.ip_network(row["cidr"])
    subjects = _pick(conn, net)
    asked = [s["primary_ip"] for s in subjects]
    # a fixed address of the network that always exists in the route table lookup: the first known device, else the first host of the range
    target = asked[0] if asked else str(next(net.hosts(), net.network_address))
    ip_runner = ip_runner or (lambda args: run_ip(args))
    route = parse_route(await ip_runner(["-4", "route", "get", target]))
    gateway_up = None
    if route["gateway"]:
        gateway_up = bool(await _answering([route["gateway"]], runner))
    up = await _answering(asked, runner)
    probes = [{"ip": s["primary_ip"], "name": s["name"], "type": s["t"], "answered": s["primary_ip"] in up} for s in subjects]
    found = []
    name = row["name"] or row["cidr"]
    on_link = route["found"] and not route["gateway"]
    if not route["found"]:
        found.append(_finding("bad", "There is no route to this network",
                              f"The host Netlens runs on has no route to {row['cidr']}. Add a route (a static route, or the VPN tunnel that leads there) on this host or its router; then the scan can reach it."))
    elif route["gateway"]:
        found.append(_finding("info", f"The way there goes through {route['gateway']}", f"Traffic to {row['cidr']} leaves through {route['dev'] or 'a network card'} towards {route['gateway']}."))
        if gateway_up is False:
            found.append(_finding("bad", f"The gateway {route['gateway']} does not answer",
                                  "That is the next hop towards this network. If it is a router or a VPN endpoint, it is down or blocks the probes: check it first, everything behind it follows."))
    elif on_link:
        found.append(_finding("info", "This network is directly connected", f"It is on the network card {route['dev'] or ''} of this host: devices are found with ARP and should answer at once."))
    if not asked:
        found.append(_finding("info", "No device of this network is known yet", "There is nothing to ask. After a scan found some, this test can try them."))
    elif up:
        found.append(_finding("ok", f"{len(up)} of {len(asked)} known devices answer now",
                              "The network is reachable. If the scan still finds fewer hosts than usual, those that are missing are probably switched off or ignore probes." if len(up) < len(asked)
                              else "The network is reachable and the devices answer."))
    else:
        if route["found"] and gateway_up is not False:
            if on_link:
                found.append(_finding("bad", "Nothing answers on a directly connected network",
                                      "The network is on a network card of this host, but no device answers ARP. The VLAN may not be carried to this host (a trunk or tagging problem on the switch port), the cable or the switch port may be down, or the devices are off."))
            else:
                found.append(_finding("bad", "A route exists, the gateway answers, but none of the known devices does",
                                      "The traffic probably does not get through: a firewall rule on the way (allow ping and TCP from the Netlens host towards this network), a tunnel that is up but not carrying this network, or the devices are off."))
    return {"network": {"id": row["id"], "cidr": row["cidr"], "label": name}, "route": {**route, "to": target, "gateway_answers": gateway_up}, "probes": probes, "findings": found}
