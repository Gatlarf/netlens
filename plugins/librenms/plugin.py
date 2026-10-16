"""LibreNMS plugin (kind "topology"): the network LibreNMS discovered over SNMP, as nodes and clients.

Talks to the LibreNMS REST API (GET only, header `X-Auth-Token`):

    GET /api/v0/system                      version
    GET /api/v0/devices                     device_id, hostname, ip, sysName, type, os, hardware, disabled
    GET /api/v0/ports?columns=...           port_id, device_id, ifName, ifPhysAddress (12 hex digits, no separators)
    GET /api/v0/resources/links             LLDP / CDP links: local_device_id, local_port_id, remote_device_id, remote_port_id
    GET /api/v0/resources/fdb               forwarding tables: device_id, port_id, mac_address
    GET /api/v0/resources/ip/arp/all        mac_address, ipv4_address (gives the clients of the FDB an address)

A device whose type is in `network_types` is a *node*; every other device is a *client*. The links decide the tree (breadth first from the first
firewall, or the first node). The MAC addresses a switch learned on a port that is not an uplink become clients of that switch with the port name.
LibreNMS answers HTTP 404 with status "error" when a list is empty; that is read as an empty list. Standard library only.
"""

import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAX_ROWS = 100000
ROLES = {"firewall": "gateway", "wireless": "ap", "network": "switch"}


class LibreError(Exception):
    pass


class AuthRefused(LibreError):
    auth_failed = True


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


def _mac(value):
    """'bc2411db66a4' or 'bc:24:11:db:66:a4' -> 'bc:24:11:db:66:a4'; None for empty, all zero and group (multicast) addresses."""
    digits = re.sub(r"[^0-9a-fA-F]", "", str(value or ""))
    if len(digits) != 12 or int(digits, 16) == 0 or int(digits[:2], 16) & 1:
        return None
    digits = digits.lower()
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


class Server:
    def __init__(self, url, token, verify_tls=True, timeout=30):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "https://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise LibreError(f"{url!r} is not an address like https://librenms.example.com")
        self.url, self.timeout, self.id, self.token = f"{parts.scheme}://{parts.netloc}", float(timeout), parts.netloc, token.strip()
        self.context = None
        if parts.scheme == "https" and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def get(self, path, key=None, empty_ok=False):
        request = urllib.request.Request(f"{self.url}/api/v0/{path}", headers={"X-Auth-Token": self.token, "Accept": "application/json"}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                data = json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise AuthRefused(f"{self.id} refused the API token (wrong, expired, or the user may not read this)")
            if exc.code == 404 and empty_ok:
                return []
            raise LibreError(f"{self.id} answered HTTP {exc.code} for {path.split('?')[0]}")
        except urllib.error.URLError as exc:
            raise LibreError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise LibreError(f"{self.id} did not answer properly (is this LibreNMS?): {exc}")
        if not isinstance(data, dict):
            raise LibreError(f"{self.id} sent an unexpected answer for {path.split('?')[0]} (is this LibreNMS?)")
        if data.get("status") == "error":
            if empty_ok:
                return []
            raise LibreError(f"{self.id}: {str(data.get('message') or 'error')[:200]}")
        return data if key is None else (data.get(key) or [])[:MAX_ROWS]


def parse_servers(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "token"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one LibreNMS")
    out = []
    for i, r in enumerate(items, 1):
        host = str(r.get("host") or "").strip()
        if not host:
            raise ValueError(f"line {i}: enter the address")
        if not str(r.get("token") or "").strip():
            raise ValueError(f"{host}: enter the API token")
        out.append(Server(host, str(r["token"]), config.get("verify_tls", True), config.get("timeout") or 30))
    return out


def _types(config):
    text = config.get("network_types")
    text = "network, firewall, wireless" if text is None else text
    return {t.strip().lower() for t in re.split(r"[,;]+", str(text)) if t.strip()}


def read(server, config):
    version = str((server.get("system", "system") or [{}])[0].get("local_ver") or "")
    devices = {d["device_id"]: d for d in server.get("devices", "devices") if not d.get("disabled")}
    ports = server.get("ports?columns=port_id,device_id,ifName,ifPhysAddress", "ports")
    links = server.get("resources/links", "links", empty_ok=True)
    fdb = server.get("resources/fdb", "ports_fdb", empty_ok=True) if config.get("fdb_clients", True) else []
    arp = server.get("resources/ip/arp/all", "arp", empty_ok=True) if fdb else []
    return version, devices, ports, links, fdb, arp


def build(devices, ports, links, fdb, arp, network_types):
    """(nodes, clients, skipped) from one LibreNMS."""
    port_name = {p["port_id"]: str(p.get("ifName") or "") for p in ports}
    macs, taken = {}, set()                      # device id -> [mac, ...] (first device wins a MAC address that two devices report)
    for p in ports:
        mac = _mac(p.get("ifPhysAddress"))
        if mac and p.get("device_id") in devices and mac not in taken and (not macs.get(p["device_id"]) or mac not in macs[p["device_id"]]):
            macs.setdefault(p["device_id"], []).append(mac)
            taken.add(mac)
    skipped = [d for d in devices if not macs.get(d)]
    kinds = {d: ROLES.get(str(dev.get("type") or "").lower(), "node") for d, dev in devices.items() if str(dev.get("type") or "").lower() in network_types and macs.get(d)}
    uplink_ports = set()
    adj = {}
    for link in links:
        a, b = link.get("local_device_id"), link.get("remote_device_id")
        uplink_ports.update(x for x in (link.get("local_port_id"), link.get("remote_port_id")) if x)
        if a in devices and b in devices and a != b:
            adj.setdefault(a, {}).setdefault(b, (link.get("local_port_id"), link.get("remote_port_id"), link.get("remote_port")))
            adj.setdefault(b, {}).setdefault(a, (link.get("remote_port_id"), link.get("local_port_id"), None))
    root = next((d for d, k in kinds.items() if k == "gateway"), next(iter(kinds), None))
    parent, order = {}, [root] if root is not None else []
    for d in order:
        for other in sorted(adj.get(d, {})):
            if other in kinds and other != root and other not in parent:
                parent[other] = d
                order.append(other)
    nodes = []
    for d, kind in kinds.items():
        dev = devices[d]
        node = {"mac": macs[d][0], "macs": macs[d][1:16] or None, "ip": _ipv4(dev.get("ip") or dev.get("hostname")), "role": kind if d == root or kind != "gateway" else "node",
                "name": str(dev.get("sysName") or dev.get("display") or dev.get("hostname") or f"device {d}")[:100], "model": str(dev.get("hardware") or "")[:100] or None}
        if d in parent:
            node["parent_mac"] = macs[parent[d]][0]
        nodes.append({k: v for k, v in node.items() if v is not None})
    ip_of = {}
    for a in arp:
        mac, ip = _mac(a.get("mac_address")), _ipv4(a.get("ipv4_address"))
        if mac and ip:
            ip_of.setdefault(mac, ip)
    where = {}                                   # mac -> (node device id, port name) seen on a port that is not an uplink
    for entry in fdb:
        mac, dev, port = _mac(entry.get("mac_address")), entry.get("device_id"), entry.get("port_id")
        if mac and dev in kinds and port not in uplink_ports and mac not in where:
            where[mac] = (dev, port_name.get(port) or None)
    clients = []
    for d, dev in devices.items():
        if d in kinds or not macs.get(d):
            continue
        client = {"mac": macs[d][0], "ip": _ipv4(dev.get("ip") or dev.get("hostname")), "name": str(dev.get("sysName") or dev.get("display") or dev.get("hostname") or f"device {d}")[:100],
                  "medium": "wired", "model": str(dev.get("hardware") or "")[:100] or None, "os": str(dev.get("os") or "")[:100] or None}
        attach = next(((adj[d][o][1] and o, port_name.get(adj[d][o][1]) or adj[d][o][2]) for o in sorted(adj.get(d, {})) if o in kinds), None)
        if attach is None:
            attach = next(((where[m][0], where[m][1]) for m in macs[d] if m in where), None)
        if attach is not None and macs.get(attach[0]):
            client["node_mac"] = macs[attach[0]][0]
            client["port"] = (attach[1] or "")[:60] or None
        clients.append({k: v for k, v in client.items() if v is not None})
    known = taken
    for mac, (dev, port) in where.items():
        if mac not in known and macs.get(dev):
            client = {"mac": mac, "ip": ip_of.get(mac), "medium": "wired", "node_mac": macs[dev][0], "port": port}
            clients.append({k: v for k, v in client.items() if v is not None})
    return nodes, clients, len(skipped)


def connect(config):
    nodes, clients, versions, skipped, problems = [], [], [], 0, []
    types = _types(config)
    for server in parse_servers(config):
        try:
            version, devices, ports, links, fdb, arp = read(server, config)
            n, c, s = build(devices, ports, links, fdb, arp, types)
        except AuthRefused:
            raise
        except LibreError as exc:
            problems.append(str(exc))
            continue
        versions.append(version)
        seen = {x["mac"] for x in nodes} | {x["mac"] for x in clients}
        nodes.extend(x for x in n if x["mac"] not in seen)
        seen |= {x["mac"] for x in n}
        clients.extend(x for x in c if x["mac"] not in seen)
        skipped += s
    if not versions:
        raise LibreError("; ".join(problems) or "no LibreNMS answered")
    return versions, nodes, clients, skipped, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    versions, nodes, clients, skipped, problems = connect(config)
    message = f"Connected to LibreNMS {', '.join(sorted({v for v in versions if v})) or '(version unknown)'}: {len(nodes)} network device(s), {len(clients)} other device(s)"
    if skipped:
        message += f". {skipped} device(s) have no MAC address on any polled port and are skipped"
    if not nodes:
        message += ". No device has one of the network types (see 'Device types that are network equipment')"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    _, nodes, clients, _, _ = connect(config)
    return {"nodes": nodes, "clients": clients}


def _problem(exc, server=None):
    text = re.sub(r"https?://[^\s/]+", "<server>", str(exc))
    if server is not None:
        text = text.replace(server.id, "<server>")
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What LibreNMS answers, as counts and enumerations (no names, MAC or IP addresses)."""
    try:
        servers = parse_servers(config)
    except (ValueError, LibreError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for server in servers:
        entry = {"steps": {}}
        report["servers"].append(entry)
        try:
            entry["steps"]["system"] = {"ok": True, "version": str((server.get("system", "system") or [{}])[0].get("local_ver") or "")}
            devices = server.get("devices", "devices")
            entry["steps"]["devices"] = {"ok": True, "count": len(devices), "types": {t: sum(1 for d in devices if str(d.get("type")) == t) for t in sorted({str(d.get("type")) for d in devices})},
                                         "disabled": sum(1 for d in devices if d.get("disabled")), "fields": sorted(devices[0])[:80] if devices else []}
            ports = server.get("ports?columns=port_id,device_id,ifName,ifPhysAddress", "ports")
            entry["steps"]["ports"] = {"ok": True, "count": len(ports), "with_mac": sum(1 for p in ports if _mac(p.get("ifPhysAddress")))}
            links = server.get("resources/links", "links", empty_ok=True)
            entry["steps"]["links"] = {"ok": True, "count": len(links), "protocols": sorted({str(x.get("protocol")) for x in links}), "to_known_device": sum(1 for x in links if x.get("remote_device_id"))}
            fdb = server.get("resources/fdb", "ports_fdb", empty_ok=True)
            entry["steps"]["fdb"] = {"ok": True, "count": len(fdb), "devices": len({x.get("device_id") for x in fdb})}
            entry["steps"]["arp"] = {"ok": True, "count": len(server.get("resources/ip/arp/all", "arp", empty_ok=True))}
        except AuthRefused:
            raise
        except LibreError as exc:
            entry["steps"]["error"] = {"ok": False, "error": _problem(exc, server)}
    return report
