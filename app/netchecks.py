"""Network checks: a second (rogue) DHCP server, and a changed gateway MAC address.

DHCP: Netlens broadcasts a DHCP discover (through nmap's `broadcast-dhcp-discover`) now and then and lists every server that
answers. The servers it sees the first time are taken as normal; a server that shows up later is reported as `dhcp_rogue`
until you mark it as trusted. Gateway: if the MAC address behind the default gateway's IP changes, `gateway_changed` is
reported (a classic sign of ARP spoofing, or just a replaced router).
"""

import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

from app.actions import ActionError, nmap_output
from app.db import add_event, get_setting, set_setting, utcnow

log = logging.getLogger(__name__)

SETTINGS_KEY = "netchecks.settings"
LAST_KEY = "netchecks.dhcp.last"
GATEWAY_KEY = "netchecks.gateway"
INTERVALS = (1, 6, 12, 24, 72)
DEFAULTS = {"dhcp_enabled": True, "dhcp_hours": 12}


# ----------------------------------------------------------------------------- settings
def get_settings(conn) -> dict:
    try:
        raw = json.loads(get_setting(conn, SETTINGS_KEY) or "{}")
    except ValueError:
        raw = {}
    out = {**DEFAULTS, **{k: raw[k] for k in DEFAULTS if k in raw}}
    if out["dhcp_hours"] not in INTERVALS:
        out["dhcp_hours"] = DEFAULTS["dhcp_hours"]
    out["dhcp_enabled"] = bool(out["dhcp_enabled"])
    return out


def set_settings(conn, enabled: bool | None = None, hours: int | None = None) -> dict:
    cur = get_settings(conn)
    if enabled is not None:
        cur["dhcp_enabled"] = bool(enabled)
    if hours is not None:
        if hours not in INTERVALS:
            raise ValueError("choose one of the offered intervals")
        cur["dhcp_hours"] = hours
    set_setting(conn, SETTINGS_KEY, json.dumps(cur))
    return cur


# ----------------------------------------------------------------------------- DHCP
def parse_dhcp_xml(xml_text: str) -> list[dict]:
    """The offers in nmap's XML: [{"server", "offered_ip", "router", "dns", "domain", "interface"}], one per answering server."""
    if "<!ENTITY" in xml_text:
        raise ValueError("invalid nmap xml")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError("invalid nmap xml") from exc
    offers: dict[str, dict] = {}
    for script in root.iter("script"):
        if script.get("id") != "broadcast-dhcp-discover":
            continue
        for table in script.findall("table"):
            fields = {e.get("key"): (e.text or "").strip() for e in table.findall("elem") if e.get("key")}
            dns = [(e.text or "").strip() for t in table.findall("table") if t.get("key") == "Domain Name Server" for e in t.findall("elem")]
            server = fields.get("Server Identifier")
            if server and server not in offers:
                offers[server] = {
                    "server": server, "offered_ip": fields.get("IP Offered") or None, "router": fields.get("Router") or None,
                    "dns": [d for d in dns if d], "domain": fields.get("Domain Name") or None, "interface": fields.get("Interface") or None,
                }
    return list(offers.values())


async def probe_dhcp(runner=None) -> list[dict]:
    """Ask the network who hands out addresses (takes about ten seconds)."""
    xml = await nmap_output(["--script", "broadcast-dhcp-discover", "-oX", "-"], 60, runner)
    return parse_dhcp_xml(xml)


def _device_for_ip(conn, ip: str):
    return conn.execute("SELECT id, mac, vendor, hostname, custom_name FROM devices WHERE primary_ip = ? ORDER BY last_seen DESC LIMIT 1", (ip,)).fetchone()


def _describe(conn, ip: str) -> str:
    dev = _device_for_ip(conn, ip)
    if not dev:
        return ip
    name = dev["custom_name"] or dev["hostname"]
    extra = ", ".join(x for x in (name, dev["mac"], dev["vendor"]) if x)
    return f"{ip} ({extra})" if extra else ip


def record_dhcp(conn, offers: list[dict], now: str | None = None) -> dict:
    """Store what answered. The first probe that finds servers trusts them; a new one later raises `dhcp_rogue`."""
    now = now or utcnow()
    first_time = conn.execute("SELECT COUNT(*) FROM dhcp_servers").fetchone()[0] == 0
    rogue = []
    for offer in offers:
        ip = offer["server"]
        row = conn.execute("SELECT trusted FROM dhcp_servers WHERE ip = ?", (ip,)).fetchone()
        dns = json.dumps(offer.get("dns") or [])
        if row is None:
            trusted = 1 if first_time else 0
            conn.execute(
                "INSERT INTO dhcp_servers (ip, trusted, first_seen, last_seen, router, dns, domain, offered_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (ip, trusted, now, now, offer.get("router"), dns, offer.get("domain"), offer.get("offered_ip")),
            )
            if not trusted:
                rogue.append(offer)
                dev = _device_for_ip(conn, ip)
                add_event(conn, "dhcp_rogue", f"A new DHCP server answered: {_describe(conn, ip)}; it offers router {offer.get('router') or '?'} and DNS {', '.join(offer.get('dns') or []) or '?'}", device_id=dev["id"] if dev else None, now=now)
        else:
            conn.execute(
                "UPDATE dhcp_servers SET last_seen = ?, router = ?, dns = ?, domain = ?, offered_ip = ? WHERE ip = ?",
                (now, offer.get("router"), dns, offer.get("domain"), offer.get("offered_ip"), ip),
            )
    conn.commit()
    return {"servers": [o["server"] for o in offers], "rogue": [o["server"] for o in rogue]}


def run_result(conn, ok: bool, now: str, servers=None, error: str | None = None) -> None:
    set_setting(conn, LAST_KEY, json.dumps({"at": now, "ok": ok, "servers": servers or [], "error": error}))


async def check_dhcp(conn, runner=None, now: str | None = None) -> dict:
    now = now or utcnow()
    try:
        offers = await probe_dhcp(runner)
    except (ActionError, ValueError) as exc:
        run_result(conn, False, now, error=str(exc)[:300])
        return {"ok": False, "error": str(exc)[:300], "servers": [], "rogue": []}
    result = record_dhcp(conn, offers, now)
    run_result(conn, True, now, servers=result["servers"])
    return {"ok": True, **result}


def get_last(conn) -> dict | None:
    try:
        value = json.loads(get_setting(conn, LAST_KEY) or "null")
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def dhcp_due(conn, now: str | None = None) -> bool:
    settings = get_settings(conn)
    if not settings["dhcp_enabled"]:
        return False
    last = get_last(conn)
    if not last:
        return True
    try:
        at = datetime.strptime(last["at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (KeyError, ValueError):
        return True
    current = datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) if now else datetime.now(timezone.utc)
    wait = timedelta(hours=settings["dhcp_hours"]) - timedelta(minutes=5) if last.get("ok") else timedelta(hours=1)
    return current - at >= wait


def list_servers(conn) -> list[dict]:
    out = []
    for r in conn.execute("SELECT * FROM dhcp_servers ORDER BY ip"):
        dev = _device_for_ip(conn, r["ip"])
        out.append({
            "ip": r["ip"], "trusted": bool(r["trusted"]), "first_seen": r["first_seen"], "last_seen": r["last_seen"],
            "router": r["router"], "dns": json.loads(r["dns"] or "[]"), "domain": r["domain"],
            "mac": dev["mac"] if dev else None, "vendor": dev["vendor"] if dev else None,
            "name": (dev["custom_name"] or dev["hostname"]) if dev else None, "device_id": dev["id"] if dev else None,
        })
    return out


def set_trusted(conn, ip: str, trusted: bool) -> None:
    if conn.execute("UPDATE dhcp_servers SET trusted = ? WHERE ip = ?", (1 if trusted else 0, ip)).rowcount == 0:
        raise KeyError(ip)
    conn.commit()


def forget_server(conn, ip: str) -> None:
    if conn.execute("DELETE FROM dhcp_servers WHERE ip = ?", (ip,)).rowcount == 0:
        raise KeyError(ip)
    conn.commit()


# ----------------------------------------------------------------------------- gateway
def check_gateway(conn, gateway_ip: str | None, now: str | None = None) -> dict | None:
    """Remember which MAC answers for the default gateway; raise `gateway_changed` when it changes."""
    if not gateway_ip:
        return None
    dev = conn.execute("SELECT id, mac FROM devices WHERE primary_ip = ? AND mac IS NOT NULL ORDER BY last_seen DESC LIMIT 1", (gateway_ip,)).fetchone()
    if not dev:
        return None
    now = now or utcnow()
    try:
        known = json.loads(get_setting(conn, GATEWAY_KEY) or "null")
    except ValueError:
        known = None
    if not isinstance(known, dict) or known.get("ip") != gateway_ip:
        state = {"ip": gateway_ip, "mac": dev["mac"], "since": now}  # first sight, or the gateway's address itself changed: a new baseline
        set_setting(conn, GATEWAY_KEY, json.dumps(state))
        return state
    if known.get("mac") != dev["mac"]:
        add_event(conn, "gateway_changed", f"The MAC address behind the gateway {gateway_ip} changed from {known.get('mac')} to {dev['mac']}. A replaced router, or someone pretending to be it (ARP spoofing).", device_id=dev["id"], now=now)
        state = {"ip": gateway_ip, "mac": dev["mac"], "since": now}
        set_setting(conn, GATEWAY_KEY, json.dumps(state))
        return state
    return known


def get_gateway(conn) -> dict | None:
    try:
        value = json.loads(get_setting(conn, GATEWAY_KEY) or "null")
    except ValueError:
        return None
    return value if isinstance(value, dict) else None
