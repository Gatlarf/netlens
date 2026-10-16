"""NetBox plugin (kind "topology"): the documented network as nodes and clients.

Talks to the NetBox REST API (GET only), with a token (`Authorization: Bearer nbt_<key>.<token>` for NetBox 4.5+, `Token <40 characters>` before):

    GET /api/status/                     version
    GET /api/dcim/devices/               name, status, role (slug), site (slug), primary_ip4, tags  (paged: limit + next)
    GET /api/dcim/interfaces/            device, name, mac_address / primary_mac_address, link_peers (the other end of a cable)

A device whose role slug is in the setting `network_roles` is a *node*; every other device is a *client*. The cables decide the tree: starting at the
gateway (a router/firewall/gateway), every node is the child of the node that is closer to the gateway; a client hangs below the node it is cabled to,
and the interface name on that node becomes the client's `port`. A device without any MAC address cannot be matched by Netlens and is skipped.
NetBox says nothing about Wi-Fi, so clients are `wired`. Standard library only.
"""

import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

PAGE = 500
MAX_ROWS = 50000
MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
GATEWAY_ROLES = ("router", "firewall", "gateway")
SWITCH_ROLES = ("switch",)
AP_ROLES = ("access-point", "ap", "wireless-ap")


class NetboxError(Exception):
    pass


class AuthRefused(NetboxError):
    auth_failed = True


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip().split("/")[0])
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


def _mac(value):
    value = str(value or "").strip().lower().replace("-", ":")
    return value if MAC.match(value) else None


class Server:
    def __init__(self, url, token, sites="", verify_tls=True, timeout=30):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "https://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise NetboxError(f"{url!r} is not an address like https://netbox.example.com")
        self.url, self.timeout, self.id = f"{parts.scheme}://{parts.netloc}", float(timeout), parts.netloc
        token = token.strip()
        self.auth = f"Bearer {token}" if token.startswith("nbt_") else f"Token {token}"
        self.sites = [s for s in re.split(r"[,;\s]+", str(sites or "")) if s]
        for s in self.sites:
            if not re.fullmatch(r"[A-Za-z0-9_-]+", s):
                raise NetboxError(f"{s!r} is not a site slug")
        self.context = None
        if parts.scheme == "https" and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def get(self, path, query=None):
        url = path if path.startswith("http") else f"{self.url}{path}" + (f"?{query}" if query else "")
        if not url.startswith(self.url):
            raise NetboxError(f"{self.id} sent a next page on another server; ignored")
        request = urllib.request.Request(url, headers={"Authorization": self.auth, "Accept": "application/json"}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                return json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise AuthRefused(f"{self.id} refused the API token (wrong, expired, or it may not view this)")
            raise NetboxError(f"{self.id} answered HTTP {exc.code} for {path}")
        except urllib.error.URLError as exc:
            raise NetboxError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise NetboxError(f"{self.id} did not answer properly (is this NetBox?): {exc}")

    def results(self, path, **params):
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None}, doseq=True)
        rows, nxt = [], None
        data = self.get(path, f"limit={PAGE}" + (f"&{query}" if query else ""))
        while True:
            rows.extend(data.get("results") or [])
            nxt = data.get("next")
            if not nxt or len(rows) >= MAX_ROWS:
                return rows
            data = self.get(nxt)


def parse_servers(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "token"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one NetBox")
    out = []
    for i, r in enumerate(items, 1):
        host = str(r.get("host") or "").strip()
        if not host:
            raise ValueError(f"line {i}: enter the address")
        if not str(r.get("token") or "").strip():
            raise ValueError(f"{host}: enter the API token")
        out.append(Server(host, str(r["token"]), r.get("sites"), config.get("verify_tls", True), config.get("timeout") or 30))
    return out


def _roles(config):
    text = config.get("network_roles")
    text = "router, firewall, gateway, switch, access-point, ap, wireless-ap" if text is None else text
    return {r.strip().lower() for r in re.split(r"[,;]+", str(text)) if r.strip()}


def _role_of(slug):
    return "gateway" if slug in GATEWAY_ROLES else "switch" if slug in SWITCH_ROLES else "ap" if slug in AP_ROLES else "node"


def read(server, config):
    info = server.get("/api/status/")
    params = {"status": "active"} if config.get("only_active", True) else {}
    if server.sites:
        params["site"] = server.sites
    devices = {d["id"]: d for d in server.results("/api/dcim/devices/", **params)}
    interfaces = [i for i in server.results("/api/dcim/interfaces/", **({"site": server.sites} if server.sites else {})) if (i.get("device") or {}).get("id") in devices]
    return str(info.get("netbox-version") or ""), devices, interfaces


def build(server, devices, interfaces, network_roles):
    """(nodes, clients, skipped) from the devices and interfaces of one NetBox."""
    macs = {}                 # device id -> [mac, ...] in interface order
    ifaces = {}               # interface id -> (device id, name)
    for i in interfaces:
        did = (i.get("device") or {}).get("id")
        ifaces[i["id"]] = (did, i.get("name"))
        mac = _mac(i.get("mac_address") or (i.get("primary_mac_address") or {}).get("mac_address"))
        if mac and mac not in macs.setdefault(did, []):
            macs[did].append(mac)
    links = {}                # device id -> {other device id: (own interface name, other interface name)}
    for i in interfaces:
        did = (i.get("device") or {}).get("id")
        for peer in i.get("link_peers") or []:
            other = (peer.get("device") or {}).get("id")
            if other in devices and other != did:
                links.setdefault(did, {}).setdefault(other, (i.get("name"), peer.get("name")))
                links.setdefault(other, {}).setdefault(did, (peer.get("name"), i.get("name")))
    def slug(d):
        return str((d.get("role") or d.get("device_role") or {}).get("slug") or "").lower()
    node_ids = [d for d, dev in devices.items() if slug(dev) in network_roles and macs.get(d)]
    skipped = [d for d in devices if not macs.get(d)]
    kinds = {d: _role_of(slug(devices[d])) for d in node_ids}
    root = next((d for d in node_ids if kinds[d] == "gateway"), node_ids[0] if node_ids else None)
    parent, order = {}, [root] if root else []
    for d in order:                                             # breadth-first from the gateway over cables between nodes
        for other in sorted(links.get(d, {})):
            if other in kinds and other != root and other not in parent:
                parent[other] = d
                order.append(other)
    nodes = []
    for d in node_ids:
        dev = devices[d]
        kind = kinds[d] if d == root or kinds[d] != "gateway" else "node"          # only one gateway
        node = {"mac": macs[d][0], "macs": macs[d][1:] or None, "ip": _ipv4((dev.get("primary_ip4") or {}).get("address")), "name": str(dev.get("name") or f"device {d}")[:100],
                "model": str((dev.get("device_type") or {}).get("model") or "")[:100] or None, "role": kind}
        if d in parent and macs.get(parent[d]):
            node["parent_mac"] = macs[parent[d]][0]
        nodes.append({k: v for k, v in node.items() if v is not None})
    clients = []
    for d, dev in devices.items():
        if d in kinds or not macs.get(d):
            continue
        attach = next((o for o in sorted(links.get(d, {})) if o in kinds), None)
        client = {"mac": macs[d][0], "ip": _ipv4((dev.get("primary_ip4") or {}).get("address")), "name": str(dev.get("name") or f"device {d}")[:100], "medium": "wired",
                  "model": str((dev.get("device_type") or {}).get("model") or "")[:100] or None}
        if attach is not None:
            client["node_mac"] = macs[attach][0]
            client["port"] = str(links[d][attach][1] or "")[:60] or None
        clients.append({k: v for k, v in client.items() if v is not None})
    return nodes, clients, len(skipped)


def connect(config):
    nodes, clients, versions, skipped, problems = [], [], [], 0, []
    roles = _roles(config)
    for server in parse_servers(config):
        try:
            version, devices, interfaces = read(server, config)
            n, c, s = build(server, devices, interfaces, roles)
        except AuthRefused:
            raise
        except NetboxError as exc:
            problems.append(str(exc))
            continue
        versions.append(version)
        known = {x["mac"] for x in nodes}
        nodes.extend(x for x in n if x["mac"] not in known)
        seen = known | {x["mac"] for x in nodes} | {x["mac"] for x in clients}
        clients.extend(x for x in c if x["mac"] not in seen)
        skipped += s
    if not versions:
        raise NetboxError("; ".join(problems) or "no NetBox answered")
    return versions, nodes, clients, skipped, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    versions, nodes, clients, skipped, problems = connect(config)
    message = f"Connected to NetBox {', '.join(sorted({v for v in versions if v})) or '(version unknown)'}: {len(nodes)} network device(s), {len(clients)} other device(s)"
    if skipped:
        message += f". {skipped} device(s) have no MAC address on any interface and are skipped"
    if not any(n["role"] == "gateway" for n in nodes) and nodes:
        message += ". No device has a router/firewall/gateway role, so the first network device is the root"
    if not nodes:
        message += ". No device has one of the network roles (see 'Network roles')"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    _, nodes, clients, _, _ = connect(config)
    return {"nodes": nodes, "clients": clients}


def _problem(exc):
    """The error text for a diagnostic report, without any server address (URL, IP address, host:port or host name)."""
    text = re.sub(r"https?://[^\s/]+", "<server>", str(exc))
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<server>", text)
    text = re.sub(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*:\d{2,5}\b", "<server>", text)
    text = re.sub(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", "<server>", text)
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What NetBox answers, as counts and enumerations (no names, MAC or IP addresses, roles or sites)."""
    try:
        servers = parse_servers(config)
    except (ValueError, NetboxError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for server in servers:
        entry = {"steps": {}}
        report["servers"].append(entry)
        try:
            info = server.get("/api/status/")
            entry["steps"]["status"] = {"ok": True, "version": str(info.get("netbox-version") or "")}
            devices = server.results("/api/dcim/devices/")
            entry["steps"]["devices"] = {"ok": True, "count": len(devices), "statuses": {s: sum(1 for d in devices if (d.get("status") or {}).get("value") == s) for s in sorted({str((d.get("status") or {}).get("value")) for d in devices})},
                                         "with_primary_ip4": sum(1 for d in devices if d.get("primary_ip4")), "role_field": "role" if devices and "role" in devices[0] else "device_role" if devices else None}
            interfaces = server.results("/api/dcim/interfaces/")
            entry["steps"]["interfaces"] = {"ok": True, "count": len(interfaces), "with_mac": sum(1 for i in interfaces if i.get("mac_address") or i.get("primary_mac_address")),
                                            "cabled": sum(1 for i in interfaces if i.get("link_peers")), "fields": sorted(interfaces[0])[:60] if interfaces else []}
        except AuthRefused:
            raise
        except NetboxError as exc:
            entry["steps"]["error"] = {"ok": False, "error": _problem(exc)}
    return report
