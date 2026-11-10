"""Router exposure check: what the default gateway answers to the network, seen from the Netlens host.

It is off until an admin switches it on, because it connects to a handful of ports on the router and asks it for its UPnP port mappings. It never logs in and never tries a
password. Everything is read-only, and every run is written to the audit log. Findings are kept (last result only) and a *new* risk or warning raises `gateway_exposure`.

What it can not know is said so: a port that answers on the LAN is not proof that it is reachable from the internet, and the admin password and WPS can not be seen from here.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import socket
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from app import safexml
from app.db import add_event, get_setting, set_setting, utcnow

log = logging.getLogger(__name__)

SETTINGS_KEY = "gateway.exposure.settings"
LAST_KEY = "gateway.exposure.last"
INTERVALS = (6, 12, 24, 72, 168)
DEFAULTS = {"enabled": False, "hours": 24}

PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP admin page", 443: "HTTPS admin page", 4567: "TR-069 (alternate)", 5000: "UPnP / web service",
         7547: "TR-069 / CWMP", 8080: "HTTP (alternate admin)", 8291: "MikroTik Winbox", 8443: "HTTPS (alternate admin)", 30005: "TR-069 (alternate)",
         49152: "UPnP control", 52869: "UPnP (Realtek SDK)"}
TR069 = (7547, 4567, 30005)
CONNECT_TIMEOUT = 0.9
UPNP_WAIT = 2.5
MAX_MAPPINGS = 30
MAX_BODY = 200_000
WEIGHTS = {"critical": 30, "high": 15, "medium": 8, "low": 3, "info": 0}


# ----------------------------------------------------------------------------- settings
def get_settings(conn) -> dict:
    try:
        raw = json.loads(get_setting(conn, SETTINGS_KEY) or "{}")
    except ValueError:
        raw = {}
    out = {**DEFAULTS, **{k: raw[k] for k in DEFAULTS if k in raw}}
    out["enabled"] = bool(out["enabled"])
    if out["hours"] not in INTERVALS:
        out["hours"] = DEFAULTS["hours"]
    return out


def set_settings(conn, enabled: bool | None = None, hours: int | None = None) -> dict:
    cur = get_settings(conn)
    if enabled is not None:
        cur["enabled"] = bool(enabled)
    if hours is not None:
        if hours not in INTERVALS:
            raise ValueError("choose one of the offered intervals")
        cur["hours"] = hours
    set_setting(conn, SETTINGS_KEY, json.dumps(cur))
    return cur


def get_last(conn) -> dict | None:
    try:
        value = json.loads(get_setting(conn, LAST_KEY) or "null")
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def due(conn, now: datetime | None = None) -> bool:
    cfg = get_settings(conn)
    if not cfg["enabled"]:
        return False
    last = get_last(conn)
    if not last or not last.get("at"):
        return True
    try:
        at = datetime.fromisoformat(last["at"].replace("Z", "+00:00"))
    except ValueError:
        return True
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    return (now or datetime.now(timezone.utc)) - at >= timedelta(hours=cfg["hours"])


# ----------------------------------------------------------------------------- probes
def _private_gateway(ip: str | None) -> str:
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        raise ValueError("the gateway address is not known yet (it is recorded after a scan)")
    if addr.version != 4 or not addr.is_private or addr.is_loopback or addr.is_link_local:
        raise ValueError("the gateway is not a private IPv4 address, so it is not probed")
    return str(addr)


async def probe_ports(ip: str, ports=tuple(PORTS), timeout: float = CONNECT_TIMEOUT) -> dict[int, str]:
    """TCP connect to each port: 'open' (answered), 'closed' (refused) or 'filtered' (no answer)."""
    sem = asyncio.Semaphore(8)

    async def one(port: int) -> tuple[int, str]:
        async with sem:
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
            except ConnectionRefusedError:
                return port, "closed"
            except (asyncio.TimeoutError, OSError):
                return port, "filtered"
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            return port, "open"

    return dict(await asyncio.gather(*(one(p) for p in ports)))


def _ssdp(ip: str) -> str | None:
    """Ask the router itself (unicast, no multicast) for its Internet Gateway Device description URL."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\n"
           "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n").encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(UPNP_WAIT)
    try:
        sock.sendto(msg, (ip, 1900))
        while True:
            data, addr = sock.recvfrom(4096)
            if addr[0] != ip:
                continue                                         # only the router's own answer counts
            m = re.search(rb"(?im)^location:\s*(\S+)", data)
            return m.group(1).decode("latin-1") if m else None
    except OSError:
        return None
    finally:
        sock.close()


def _get(url: str, data: bytes | None = None, headers: dict | None = None) -> bytes:
    req = urllib.request.Request(url, data=data, headers=headers or {})
    with urllib.request.urlopen(req, timeout=3) as res:           # noqa: S310 - the host was checked to be the gateway
        return res.read(MAX_BODY)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _upnp(ip: str) -> dict:
    """{found, manufacturer, model, mappings: [...], readable} for the router's UPnP service. Never raises."""
    out = {"found": False, "manufacturer": None, "model": None, "mappings": [], "readable": None, "problem": None}
    try:
        location = _ssdp(ip)
        if not location:
            return out
        parts = urllib.parse.urlsplit(location)
        if parts.scheme != "http" or parts.hostname != ip:        # a description that points elsewhere is not followed
            out["found"] = True
            out["problem"] = "the router answered with a description address on another host"
            return out
        out["found"] = True
        root = safexml.fromstring(_get(location))
        for el in root.iter():
            name = _local(el.tag)
            if name == "manufacturer" and not out["manufacturer"]:
                out["manufacturer"] = (el.text or "").strip()[:60] or None
            elif name == "modelName" and not out["model"]:
                out["model"] = (el.text or "").strip()[:60] or None
        control = service = None
        for svc in root.iter():
            if _local(svc.tag) != "service":
                continue
            fields = {_local(c.tag): (c.text or "").strip() for c in svc}
            if re.search(r"WAN(IP|PPP)Connection", fields.get("serviceType", "")):
                control, service = fields.get("controlURL"), fields["serviceType"]
                break
        if not control:
            out["readable"] = False
            out["problem"] = "no port-mapping service was described"
            return out
        url = urllib.parse.urljoin(location, control)
        if urllib.parse.urlsplit(url).hostname != ip:
            out["readable"] = False
            return out
        out["readable"] = True
        for i in range(MAX_MAPPINGS):
            body = (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
                    f'<s:Body><u:GetGenericPortMappingEntry xmlns:u="{service}"><NewPortMappingIndex>{i}</NewPortMappingIndex></u:GetGenericPortMappingEntry></s:Body></s:Envelope>').encode()
            try:
                reply = _get(url, body, {"Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{service}#GetGenericPortMappingEntry"'})
            except OSError:                                        # a SOAP fault (index out of range) ends the list; so does a refusal
                if i == 0:
                    out["readable"] = None
                break
            fields = {_local(e.tag): (e.text or "").strip() for e in safexml.fromstring(reply).iter()}
            if not fields.get("NewExternalPort"):
                break
            out["mappings"].append({"proto": fields.get("NewProtocol", "")[:5], "external": fields.get("NewExternalPort", "")[:6],
                                    "client": fields.get("NewInternalClient", "")[:45], "internal": fields.get("NewInternalPort", "")[:6],
                                    "description": fields.get("NewPortMappingDescription", "")[:60]})
    except (OSError, ValueError, safexml.UnsafeXml, KeyError) as exc:
        out["problem"] = str(exc)[:120]
    return out


async def probe_upnp(ip: str) -> dict:
    return await asyncio.to_thread(_upnp, ip)


# ----------------------------------------------------------------------------- findings
def _f(fid, title, status, severity, evidence, steps=None) -> dict:
    return {"id": fid, "title": title, "status": status, "severity": severity, "evidence": evidence, "steps": steps or []}


def _login(gw: str) -> str:
    return f"Open the router admin page (http://{gw}/) and sign in. The address and password are usually on a sticker on the router."


def evaluate(gw: str, ports: dict, upnp: dict) -> list[dict]:
    """Turn what the router answered into findings. Pure: no network."""
    states = {int(p): s for p, s in ports.items()}
    silent = bool(states) and all(s == "filtered" for s in states.values())
    quiet = f"The router ({gw}) answered none of the connection attempts, so it can not be told which ports are open. A firewall that drops everything, client isolation or a VPN looks the same."
    out: list[dict] = []

    def port_finding(fid, title, ok_title, severity, status, ports_, evidence, steps):
        if silent:
            out.append(_f(fid, title, "unknown", severity, quiet))
            return
        hit = [p for p in ports_ if states.get(p) == "open"]
        if hit:
            out.append(_f(fid, title, status, severity, evidence(hit), steps))
        else:
            out.append(_f(fid, ok_title, "ok", severity, "TCP " + ", ".join(str(p) for p in ports_) + f" on {gw} do not answer."))

    port_finding("tr069", "Provider remote management answers", "Provider remote management is closed", "critical", "risk", TR069,
                 lambda hit: f"TCP {gw}:{hit[0]} answers. This is the TR-069/CWMP port a provider uses to change router settings and firmware. It can not be told from here whether it is also reachable from the internet; providers normally keep it reachable for themselves.",
                 [_login(gw), "Look for TR-069, CWMP, Remote management or ACS (often under Advanced or Management) and turn it off, if the router allows it.",
                  "If the provider locks it, put your own router behind the provider box so the provider can only manage its own device.", "Run the check again."])
    port_finding("telnet", "Telnet answers on the router", "Telnet is closed", "high", "risk", (23,),
                 lambda hit: f"TCP {gw}:23 answers. Telnet sends the password unencrypted and is a favourite target of router botnets.",
                 [_login(gw), "Turn off Telnet (often under Administration or Services) and use SSH or the web page instead.", "Run the check again."])
    port_finding("ssh", "SSH answers on the router", "SSH is closed", "low", "warn", (22,),
                 lambda hit: f"TCP {gw}:22 answers. That is fine if you use it; otherwise it is one more way in.",
                 [_login(gw), "Turn off SSH if you do not use it, or limit it to your own devices."])
    port_finding("ftp", "FTP answers on the router", "FTP is closed", "medium", "warn", (21,),
                 lambda hit: f"TCP {gw}:21 answers. FTP sends passwords unencrypted.", [_login(gw), "Turn off the FTP server of the router, or the USB sharing that uses it."])
    port_finding("winbox", "MikroTik Winbox answers", "MikroTik Winbox is closed", "medium", "warn", (8291,),
                 lambda hit: f"TCP {gw}:8291 answers. Winbox has had serious flaws; limit it to a management address.", ["Restrict Winbox under IP > Services to your management addresses, or disable it."])

    if silent:
        out.append(_f("admin-http", "Router admin page encryption", "unknown", "medium", quiet))
    elif states.get(80) == "open" and states.get(443) != "open":
        out.append(_f("admin-http", "Router admin page is plain HTTP", "warn", "medium",
                      f"http://{gw}/ answers and there is no HTTPS on port 443, so the admin password travels unencrypted on your network.",
                      [_login(gw), "Turn on HTTPS for the admin page if the router has the option, or update its firmware."]))
    else:
        out.append(_f("admin-http", "Router admin page can use HTTPS", "ok", "medium", f"Port 80 is not the only admin page on {gw}."))

    if not upnp.get("found"):
        out.append(_f("upnp", "UPnP port opening is off", "ok", "medium", f"The router ({gw}) did not answer a UPnP discovery request within {UPNP_WAIT:g} seconds."))
    else:
        who = " ".join(x for x in (upnp.get("manufacturer"), upnp.get("model")) if x) or "The router"
        steps = [_login(gw), "Find UPnP (usually under Advanced or NAT forwarding) and turn it off. Games or apps that need open ports can get manual port forwarding instead."]
        maps = upnp.get("mappings") or []
        if maps:
            listing = "; ".join(f"{m['proto']} {m['external']} -> {m['client']}:{m['internal']}" + (f" ({m['description']})" if m["description"] else "") for m in maps[:8])
            out.append(_f("upnp", "Devices have opened ports to the internet", "warn", "high",
                          f"{who} has {len(maps)} UPnP port mapping{'s' if len(maps) != 1 else ''} open: {listing}{'; ...' if len(maps) > 8 else ''}.", steps))
        else:
            note = "No ports are open through it right now." if upnp.get("readable") else "The router would not list its port mappings, so it can not be told whether any are open."
            out.append(_f("upnp", "Any device can open ports on the router", "warn", "medium", f"{who} accepts UPnP requests. {note} Any app or infected device on the network can open a port to the internet without asking.", steps))

    out.append(_f("admin-password", "Router admin password", "unknown", "medium",
                  "Netlens never tries passwords on your router, so it can not tell whether the factory password is still set.", [_login(gw), "Set a long unique password under Administration or System."]))
    out.append(_f("wps", "WPS on the router", "unknown", "medium", "Whether WPS is on is only visible in the router settings.", [_login(gw), "Turn WPS off under the wireless settings."]))
    return out


def score(findings: list[dict]) -> int:
    total = 100.0
    for f in findings:
        w = WEIGHTS.get(f["severity"], 0)
        total -= w if f["status"] == "risk" else w / 2 if f["status"] == "warn" else 0
    return max(0, min(100, round(total)))


# ----------------------------------------------------------------------------- run
async def run(conn, gateway_ip: str | None, who: str = "system", now: str | None = None, ports_probe=probe_ports, upnp_probe=probe_upnp) -> dict:
    """Probe the gateway, store the findings and raise `gateway_exposure` for each risk or warning that was not there before."""
    from app import audit

    gw = _private_gateway(gateway_ip)
    now = now or utcnow()
    previous = get_last(conn)
    ports = await ports_probe(gw)
    upnp = await upnp_probe(gw)
    findings = evaluate(gw, ports, upnp)
    result = {"at": now, "gateway": gw, "score": score(findings), "findings": findings, "open_ports": sorted(p for p, s in ports.items() if s == "open")}
    before = {f["id"]: f["status"] for f in (previous or {}).get("findings", [])}
    for f in findings:
        if f["status"] not in ("risk", "warn") or before.get(f["id"]) in ("risk", "warn"):
            continue
        if previous is None and f["status"] != "risk":
            continue                                               # the first run is the baseline; only a real risk is announced right away
        add_event(conn, "gateway_exposure", f"{f['title']}: {f['evidence']}"[:400], now=now)
    set_setting(conn, LAST_KEY, json.dumps(result))
    audit.record_system(conn, f"Router exposure check on {gw} ({who}): {sum(f['status'] == 'risk' for f in findings)} risk, {sum(f['status'] == 'warn' for f in findings)} warning", "/gateway-exposure")
    return result
