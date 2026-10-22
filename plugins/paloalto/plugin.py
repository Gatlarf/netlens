"""Palo Alto Networks PAN-OS plugin (kind "topology"): the firewall as the gateway node, the devices behind it as clients, and its health.

Talks to the XML API (/api/?type=op&cmd=...) with the API key in the X-PAN-KEY header. Only operational "show" commands:

    show system info                    host name, model, serial number, software version, management MAC and address
    show interface all                  hardware interfaces: state, speed, duplex, MAC address
    show dhcp server lease              DHCP leases: address, MAC address, host name
    show arp all                        ARP table
    show high-availability state        mode, state of this unit and of the peer, whether the configuration is synchronised
    show vpn flow                       IPsec tunnels and their state
    request license info                licences with their end dates

PAN-OS has no device inventory with operating systems, so clients carry a name and an address only (Netlens identifies the rest itself).
Field names differ a little between PAN-OS versions: a reader accepts what it knows and leaves out what it cannot find. `diagnose` lists the
tags a firewall really answers with, so a tester can send them without addresses. Standard library only.
"""

import ipaddress
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime

MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
MAX_CLIENTS = 4000


class PanError(Exception):
    pass


class AuthRefused(PanError):
    auth_failed = True


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip().split("/")[0])
    except ValueError:
        return None
    return str(addr) if addr.version == 4 and not addr.is_unspecified else None


def _mac(value):
    value = str(value or "").strip().lower().replace("-", ":")
    return value if MAC.match(value) and value not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") else None


def _t(element, path):
    """The text of the first element at `path` below `element`, or ''."""
    found = element.find(path) if element is not None else None
    return (found.text or "").strip() if found is not None and found.text else ""


class Firewall:
    def __init__(self, url, key, role="", verify_tls=True, timeout=30):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "https://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise PanError(f"{url!r} is not an address like https://192.168.1.1")
        self.base, self.id, self.host, self.timeout = f"{parts.scheme}://{parts.netloc}/api/", parts.netloc, parts.hostname, float(timeout)
        self.key = key.strip()
        self.role = (role or "auto").strip().lower()
        if self.role not in ("auto", "gateway", "node"):
            raise PanError(f"{self.id}: the role must be auto, gateway or node")
        self.context = None
        if parts.scheme == "https" and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def op(self, cmd):
        """The <result> element of an operational command, or None when the command answers with an empty result."""
        request = urllib.request.Request(self.base + "?" + urllib.parse.urlencode({"type": "op", "cmd": cmd}), headers={"X-PAN-KEY": self.key}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise AuthRefused(f"{self.id} refused the API key (wrong, expired, or the administrator's role may not use the XML API)")
            raise PanError(f"{self.id} answered HTTP {exc.code}")
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, ssl.SSLCertVerificationError):
                raise PanError(f"{self.id}: the certificate is not trusted ({exc.reason.verify_message}); install your own certificate or untick Verify TLS certificate")
            raise PanError(f"cannot reach {self.id}: {exc.reason}")
        except OSError as exc:
            raise PanError(f"cannot reach {self.id}: {exc}")
        try:
            root = ET.fromstring(body)
        except ET.ParseError:
            raise PanError(f"{self.id} did not answer with XML (is this a Palo Alto firewall?)")
        if root.get("status") != "success":
            code, text = root.get("code") or "", _t(root, "msg") or _t(root, "result/msg") or " ".join(root.itertext()).strip()[:200]
            if code in ("403", "22") or "invalid credential" in text.lower() or "forbidden" in text.lower():
                raise AuthRefused(f"{self.id} refused the API key ({text or 'invalid credentials'})")
            raise PanError(f"{self.id} could not run the command ({text or 'error ' + code})")
        return root.find("result")


def optional(fw, cmd):
    """The result of a command that some PAN-OS versions or roles do not offer: None instead of an error (a refused key still stops everything)."""
    try:
        return fw.op(cmd)
    except AuthRefused:
        raise
    except PanError:
        return None


def parse_firewalls(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "api_key"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one firewall")
    out = []
    for i, r in enumerate(items, 1):
        url = str(r.get("host") or "").strip()
        if not url:
            raise ValueError(f"line {i}: enter the address")
        if not str(r.get("api_key") or "").strip():
            raise ValueError(f"{url}: enter the API key")
        out.append(Firewall(url, str(r["api_key"]), r.get("role"), config.get("verify_tls", True), config.get("timeout") or 30))
    return out


def _date(text):
    """'2027-01-31' from 'January 31, 2027' (or an ISO date); None for 'Never' and anything else."""
    text = (text or "").strip()
    for fmt in ("%B %d, %Y", "%b %d, %Y", "%Y-%m-%d", "%Y/%m/%d"):
        try:
            return datetime.strptime(text[:20] if fmt != "%Y-%m-%d" else text[:10], fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    return None


def ha_info(fw):
    result = optional(fw, "<show><high-availability><state/></high-availability></show>")
    if result is None or _t(result, "enabled").lower() not in ("yes", "true"):
        return None
    group = result.find("group") if result.find("group") is not None else result
    mode = _t(group, "mode") or _t(result, "mode")
    state = (_t(group, "local-info/state") or _t(group, "local-info/state-display")).lower()
    peer = (_t(group, "peer-info/state") or _t(group, "peer-info/state-display")).lower()
    sync = (_t(group, "running-sync") or _t(result, "running-sync")).lower()
    return {"mode": mode.lower() or None, "state": state or None, "peer_state": peer or None, "in_sync": None if not sync else sync == "synchronized"}


def read(fw):
    info = fw.op("<show><system><info/></system></show>")
    system = info.find("system") if info is not None else None
    if system is None:
        raise PanError(f"{fw.id} did not return its system information")
    mac = _mac(_t(system, "mac-address"))
    ip = _ipv4(fw.host) or _ipv4(_t(system, "ip-address"))
    node = {"ip": ip, "name": (_t(system, "hostname") or fw.id)[:100], "model": _t(system, "model")[:100] or None, "role": "gateway" if fw.role != "node" else "node"}
    if mac:
        node["mac"] = mac
    own = {mac} if mac else set()
    ports = []
    ifaces = optional(fw, "<show><interface>all</interface></show>")
    for i, e in enumerate(ifaces.findall("hw/entry") if ifaces is not None else [], 1):
        name = _t(e, "name")
        own.update(filter(None, [_mac(_t(e, "mac"))]))
        number = int(_t(e, "id")) if _t(e, "id").isdigit() and 0 < int(_t(e, "id")) <= 1024 else i
        speed = _t(e, "speed")
        ports.append({"port": number, "name": name[:40], "up": _t(e, "state").lower() == "up", "enabled": True,
                      "speed_mbps": float(speed) if re.match(r"^\d+(\.\d+)?$", speed) and float(speed) > 0 else None,
                      **({"duplex": _t(e, "duplex").lower()} if _t(e, "duplex").lower() in ("full", "half") else {})})
    node["ports"] = [p for i, p in enumerate(ports) if p["port"] not in {q["port"] for q in ports[:i]}][:128]

    clients = {}

    def entry(m, **fields):
        c = clients.setdefault(m, {"mac": m, "medium": "unknown"})
        for k, v in fields.items():
            if v not in (None, "") and c.get(k) is None:
                c[k] = v

    leases = optional(fw, "<show><dhcp><server><lease><interface>all</interface></lease></server></dhcp></show>")
    if leases is not None:
        for iface in leases.iter():
            for e in iface.findall("entry"):
                m = _mac(_t(e, "mac"))
                if m and _t(e, "ip"):
                    entry(m, ip=_ipv4(_t(e, "ip")), name=_t(e, "hostname")[:100] or None, port=(iface.get("name") or "")[:60] or None)
    arp = optional(fw, "<show><arp><entry name = 'all'/></arp></show>")
    for e in arp.findall("entries/entry") if arp is not None else []:
        m = _mac(_t(e, "mac"))
        if m and _t(e, "status").lower() not in ("i", "incomplete"):
            entry(m, ip=_ipv4(_t(e, "ip")), port=_t(e, "interface")[:60] or None)
    found = [{k: v for k, v in c.items() if v is not None} for m, c in clients.items() if m not in own and c.get("ip")]

    tunnels = []
    flow = optional(fw, "<show><vpn><flow/></vpn></show>")
    for e in flow.findall("IPSec/entry") if flow is not None else []:
        name = _t(e, "name")
        if name:
            tunnels.append({"name": name[:80], "remote": _t(e, "gw")[:80] or None, "up": _t(e, "state").lower() == "active"})
    licences = []
    lic = optional(fw, "<request><license><info/></license></request>")
    for e in lic.findall("licenses/entry") if lic is not None else []:
        date = _date(_t(e, "expires"))
        if date and _t(e, "feature"):
            licences.append({"name": _t(e, "feature")[:80], "expires": date})
    firewall = {"version": _t(system, "sw-version")[:60] or None, "serial": _t(system, "serial")[:60] or None, "model": node["model"], "ha": ha_info(fw),
                "tunnels": tunnels, "licences": sorted(licences, key=lambda x: x["expires"])[:50]}
    node["firewall"] = {k: v for k, v in firewall.items() if v}
    return node, found[:MAX_CLIENTS], {"version": firewall["version"] or "", "tunnels": len(tunnels)}


def connect(config):
    reads, problems = [], []
    for fw in parse_firewalls(config):
        try:
            reads.append((fw,) + read(fw))
        except AuthRefused:
            raise
        except PanError as exc:
            problems.append(str(exc))
    if not reads:
        raise PanError("; ".join(problems) or "no firewall answered")
    return reads, problems


def _key(node):
    return node.get("mac") or "02:00:" + ":".join(f"{int(p):02x}" for p in node["ip"].split("."))


def assemble(reads):
    nodes, clients, seen, gateway = [], [], set(), None
    for fw, node, found, _ in reads:
        entry = dict(node)
        if entry["role"] == "gateway" and gateway is not None:
            entry["role"] = "node"
        if entry["role"] == "gateway":
            gateway = _key(entry)
        elif gateway:
            entry["parent_mac"] = gateway
        nodes.append(entry)
    for (fw, node, found, _), entry in zip(reads, nodes):
        for c in found:
            if c["mac"] not in seen:
                seen.add(c["mac"])
                clients.append({**c, "node_mac": _key(entry)})
    return nodes, clients


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    reads, problems = connect(config)
    versions = sorted({r[3]["version"] for r in reads if r[3]["version"]})
    message = f"Connected to {len(reads)} firewall(s) (PAN-OS {', '.join(versions) or 'version unknown'}): {sum(len(r[2]) for r in reads)} device(s) behind it, {sum(r[3]['tunnels'] for r in reads)} VPN tunnel(s)"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    reads, _ = connect(config)
    nodes, clients = assemble(reads)
    return {"nodes": nodes, "clients": clients}


def _problem(exc):
    text = re.sub(r"https?://[^\s/]+", "<firewall>", str(exc))
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<firewall>", text)
    text = re.sub(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d{2,5})?\b", "<firewall>", text)
    return type(exc).__name__ + ": " + text[:300]


def _tags(result):
    """The tag names an answer contains (no values), so a report shows the shape without any address or name."""
    return sorted({el.tag for el in result.iter()} - {"result"})[:60] if result is not None else []


def diagnose(config):
    """What the firewalls answer, as counts and tag names (no addresses, names, serial numbers or keys)."""
    try:
        firewalls = parse_firewalls(config)
    except (ValueError, PanError) as exc:
        return {"error": str(exc)}
    report = {"firewalls": []}
    for fw in firewalls:
        entry = {"steps": {}}
        report["firewalls"].append(entry)
        for step, cmd in (("system", "<show><system><info/></system></show>"), ("interfaces", "<show><interface>all</interface></show>"),
                          ("dhcp", "<show><dhcp><server><lease><interface>all</interface></lease></server></dhcp></show>"), ("arp", "<show><arp><entry name = 'all'/></arp></show>"),
                          ("ha", "<show><high-availability><state/></high-availability></show>"), ("vpn", "<show><vpn><flow/></vpn></show>"), ("licences", "<request><license><info/></license></request>")):
            try:
                result = fw.op(cmd)
                entry["steps"][step] = {"ok": True, "entries": len(result.findall(".//entry")) if result is not None else 0, "tags": _tags(result)}
                if step == "system" and result is not None:
                    entry["steps"][step]["version"] = _t(result, "system/sw-version")
            except AuthRefused:
                raise
            except PanError as exc:
                entry["steps"][step] = {"ok": False, "error": _problem(exc)}
    return report
