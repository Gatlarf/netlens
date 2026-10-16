"""MikroTik RouterOS plugin (kind "topology"): the router or switch as a node, MikroTik neighbours as child nodes, the devices around it as clients.

Talks to the RouterOS 7.1+ REST API (/rest/...) with basic authentication. Only GET requests:

    /rest/system/identity, /rest/system/resource   name, model, version
    /rest/interface                                the device's own MAC addresses
    /rest/ip/address                               the management address
    /rest/ip/firewall/nat                          a srcnat masquerade rule marks the gateway
    /rest/ip/neighbor                              MNDP/LLDP neighbours (MikroTik ones become child nodes)
    /rest/interface/bridge/host                    the bridge host table: MAC -> port the device sits behind
    /rest/ip/dhcp-server/lease, /rest/ip/arp       addresses and names
    /rest/interface/wifi/registration-table        Wi-Fi stations (wifi package, RouterOS 7.13+)   } absent on devices
    /rest/interface/wireless/registration-table    Wi-Fi stations (wireless package)               } without Wi-Fi

RouterOS sends every value as a string. A device is `wifi` when it is in a registration table, `wired` otherwise; for a wired device the bridge port
is reported as `port`. The device's own MAC addresses are never reported as clients. Standard library only.
"""

import base64
import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
MAX_CLIENTS = 4000


class RouterosError(Exception):
    pass


class AuthRefused(RouterosError):
    auth_failed = True


class Missing(RouterosError):
    """The menu does not exist on this device (no Wi-Fi package, an older RouterOS ...)."""


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip().split("/")[0])
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


def _mac(value):
    value = str(value or "").strip().lower()
    return value if MAC.match(value) and value not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") else None


def _yes(value):
    return str(value).lower() in ("true", "yes")


def _number(value):
    m = re.search(r"-?\d+(\.\d+)?", str(value or ""))
    return float(m.group()) if m else None


class Router:
    def __init__(self, url, username, password, role="", uplink="", verify_tls=False, timeout=20):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "https://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise RouterosError(f"{url!r} is not an address like https://192.168.88.1")
        self.base, self.id, self.host, self.timeout = f"{parts.scheme}://{parts.netloc}/rest", parts.netloc, parts.hostname, float(timeout)
        self.auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        self.role = (role or "auto").strip().lower()
        if self.role not in ("auto", "gateway", "switch", "ap", "node"):
            raise RouterosError(f"{self.id}: the role must be auto, gateway, switch, ap or node")
        self.uplink = _ipv4(uplink) if uplink else None
        if uplink and not self.uplink:
            raise RouterosError(f"{self.id}: the uplink must be an IPv4 address")
        self.context = None
        if parts.scheme == "https" and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def get(self, path):
        request = urllib.request.Request(f"{self.base}/{path}", headers={"Authorization": self.auth, "Accept": "application/json"}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                return json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")[:300]
            if exc.code == 401:
                raise AuthRefused(f"{self.id} refused the login (wrong user name or password, or this user may not use the REST API)")
            if exc.code == 403:
                raise AuthRefused(f"{self.id} says this user may not read {path} (give the user's group the read and rest-api policies)")
            if exc.code in (400, 404) and "no such command" in body:
                raise Missing(f"{self.id} has no {path}")
            raise RouterosError(f"{self.id} answered HTTP {exc.code} for {path}")
        except urllib.error.URLError as exc:
            raise RouterosError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise RouterosError(f"{self.id} did not answer properly (is the REST API on, RouterOS 7.1+?): {exc}")

    def rows(self, path, optional=False):
        try:
            data = self.get(path)
        except Missing:
            if optional:
                return []
            raise
        return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []


def parse_routers(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "username", "password"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one MikroTik device")
    out = []
    for i, r in enumerate(items, 1):
        url = str(r.get("host") or "").strip()
        if not url:
            raise ValueError(f"line {i}: enter the address")
        if not str(r.get("username") or "").strip() or not str(r.get("password") or ""):
            raise ValueError(f"{url}: enter the user name and password")
        out.append(Router(url, str(r["username"]).strip(), str(r["password"]), r.get("role"), r.get("uplink"), config.get("verify_tls", False), config.get("timeout") or 20))
    return out


def band_of(row):
    text = " ".join(str(row.get(k) or "") for k in ("band", "signal-strength", "interface")).lower()
    if "6ghz" in text or "6 ghz" in text:
        return "6 GHz"
    if "5ghz" in text or "5 ghz" in text:
        return "5 GHz"
    if "2ghz" in text or "2.4ghz" in text or "2 ghz" in text:
        return "2.4 GHz"
    return None


def _rate(value):
    """Mbit/s from "130Mbps-20MHz/2S", "866.7Mbps", or a bare number of bit/s."""
    text = str(value or "")
    m = re.match(r"\s*([\d.]+)\s*(Gbps|Mbps|kbps|bps)?", text, re.I)
    if not m:
        return None
    number, unit = float(m.group(1)), (m.group(2) or "bps").lower()
    mbit = number * 1000 if unit == "gbps" else number if unit == "mbps" else number / 1000 if unit == "kbps" else number / 1e6
    return round(mbit, 1) if mbit > 0 else None


def read(router):
    identity = router.get("system/identity") or {}
    resource = router.get("system/resource") or {}
    interfaces = router.rows("interface")
    own = {m for m in (_mac(i.get("mac-address")) for i in interfaces) if m}
    bridges = [i for i in interfaces if i.get("type") == "bridge" and _mac(i.get("mac-address"))]
    mac = _mac((bridges[0] if bridges else next((i for i in interfaces if i.get("type") == "ether" and _mac(i.get("mac-address"))), {})).get("mac-address"))
    addresses = [a for a in router.rows("ip/address") if not _yes(a.get("disabled")) and not _yes(a.get("invalid"))]
    mine = next((a for a in addresses if _ipv4(a.get("address")) == _ipv4(router.host)), None) or (addresses[0] if addresses else None)
    ip = _ipv4(router.host) or _ipv4((mine or {}).get("address"))
    nat = [r for r in router.rows("ip/firewall/nat", optional=True) if r.get("chain") == "srcnat" and r.get("action") == "masquerade" and not _yes(r.get("disabled"))]
    role = router.role if router.role != "auto" else ("gateway" if nat else "switch")
    node = {"mac": mac, "ip": ip, "name": str(identity.get("name") or router.id)[:100], "model": str(resource.get("board-name") or "")[:100] or None, "role": role}
    if role != "gateway" and router.uplink:
        node["uplink_ip"] = router.uplink

    neighbors = []
    for n in router.rows("ip/neighbor", optional=True):
        m = _mac(n.get("mac-address"))
        if m and m not in own and "mikrotik" in str(n.get("platform") or "").lower():
            neighbors.append({"mac": m, "ip": _ipv4(n.get("address")), "name": str(n.get("identity") or "")[:100] or None, "model": str(n.get("board") or "")[:100] or None, "role": "node"})

    clients = {}

    def entry(m, **fields):
        c = clients.setdefault(m, {"mac": m, "medium": "wired"})
        for k, v in fields.items():
            if v is not None and c.get(k) is None:
                c[k] = v
        return c

    seen_online = set()
    for h in router.rows("interface/bridge/host"):
        m = _mac(h.get("mac-address"))
        if m and not _yes(h.get("local")) and not _yes(h.get("disabled")) and not _yes(h.get("invalid")):
            port = str(h.get("on-interface") or "")
            entry(m, port=port[:60] if port and not any(i.get("name") == port and i.get("type") == "bridge" for i in interfaces) else None)
            seen_online.add(m)
    for a in router.rows("ip/arp"):
        m = _mac(a.get("mac-address"))
        if m and _yes(a.get("complete")) and not _yes(a.get("invalid")) and not _yes(a.get("disabled")):
            entry(m, ip=_ipv4(a.get("address")))
            seen_online.add(m)
    for lease in router.rows("ip/dhcp-server/lease"):
        m = _mac(lease.get("mac-address") or lease.get("active-mac-address"))
        if not m or _yes(lease.get("disabled")):
            continue
        name = str(lease.get("host-name") or lease.get("comment") or "")[:100] or None
        if lease.get("status") == "bound":
            seen_online.add(m)
        if m in seen_online or lease.get("status") == "bound":
            entry(m, ip=_ipv4(lease.get("active-address") or lease.get("address")), name=name)
    wifi = []
    for path in ("interface/wifi/registration-table", "interface/wireless/registration-table"):
        wifi.extend(router.rows(path, optional=True))
    for w in wifi:
        m = _mac(w.get("mac-address"))
        if not m:
            continue
        c = entry(m)
        signal = _number(w.get("signal") if w.get("signal") is not None else w.get("signal-strength"))
        c.update(medium="wifi", band=band_of(w) or c.get("band"), rssi=int(signal) if signal is not None and -127 <= signal <= 0 else None,
                 tx_mbps=_rate(w.get("tx-rate")), rx_mbps=_rate(w.get("rx-rate")))
        c.pop("port", None)
        seen_online.add(m)
    out = [{k: v for k, v in c.items() if v is not None} for m, c in clients.items() if m not in own and m in seen_online and (c.get("ip") or c["medium"] == "wifi" or c.get("port"))]
    notes = {"nat": bool(nat), "version": str(resource.get("version") or ""), "stations": len(wifi)}
    return node, neighbors, out[:MAX_CLIENTS], notes


def connect(config):
    reads, problems = [], []
    for router in parse_routers(config):
        try:
            reads.append((router,) + read(router))
        except AuthRefused:
            raise
        except RouterosError as exc:
            problems.append(str(exc))
    if not reads:
        raise RouterosError("; ".join(problems) or "no MikroTik device answered")
    return reads, problems


def assemble(reads):
    """The topology output: nodes (listed devices first, then MikroTik neighbours that are not listed), parents by uplink or by neighbour, each client once."""
    listed = {node["mac"] for _, node, *_ in reads if node.get("mac")}
    by_ip = {node["ip"]: node["mac"] for _, node, *_ in reads if node.get("ip") and node.get("mac")}
    nodes, clients, seen = [], [], set()
    gateways = [node for _, node, *_ in reads if node["role"] == "gateway" and node.get("mac")]
    for router, node, neighbors, found, _ in reads:
        if not node.get("mac"):
            continue
        entry = {k: v for k, v in node.items() if k != "uplink_ip" and v is not None}
        if node["role"] == "gateway" and node is not gateways[0]:
            entry["role"] = "node"
        parent = by_ip.get(node.get("uplink_ip"))
        if parent and parent != entry["mac"]:
            entry["parent_mac"] = parent
        nodes.append(entry)
    listed_nodes = {n["mac"] for n in nodes}
    for router, node, neighbors, found, _ in reads:
        if not node.get("mac"):
            continue
        for n in neighbors:
            if n["mac"] not in listed_nodes and n["mac"] not in {x["mac"] for x in nodes}:
                nodes.append({**{k: v for k, v in n.items() if v is not None}, "parent_mac": node["mac"]})
    node_macs = {n["mac"] for n in nodes}
    for _, node, _, found, _ in sorted(reads, key=lambda r: 0 if any(c["medium"] == "wifi" for c in r[3]) else 1):
        if not node.get("mac"):
            continue
        for c in sorted(found, key=lambda x: 0 if x["medium"] == "wifi" else 1):
            if c["mac"] in seen or c["mac"] in node_macs:
                continue
            seen.add(c["mac"])
            clients.append({**c, "node_mac": node["mac"]})
    return nodes, clients


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    reads, problems = connect(config)
    total = sum(len(r[3]) for r in reads)
    wifi = sum(r[4]["stations"] for r in reads)
    versions = sorted({r[4]["version"] for r in reads if r[4]["version"]})
    message = f"Connected to {len(reads)} MikroTik device(s) ({', '.join(versions) or 'version unknown'}): {total} client(s), {wifi} on Wi-Fi, {sum(len(r[2]) for r in reads)} MikroTik neighbour(s)"
    if len([1 for r in reads if r[1]["role"] == "gateway"]) > 1:
        message += ". More than one device counts as gateway: the first is used, set the role of the others"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    reads, _ = connect(config)
    nodes, clients = assemble(reads)
    return {"nodes": nodes, "clients": clients}


def _problem(exc):
    return type(exc).__name__ + ": " + re.sub(r"https?://[^\s/]+", "<router>", str(exc))[:300]


def diagnose(config):
    """What the devices answer, as counts and field names (no MAC or IP addresses, names or passwords)."""
    try:
        routers = parse_routers(config)
    except (ValueError, RouterosError) as exc:
        return {"error": str(exc)}
    report = {"routers": []}
    for router in routers:
        entry = {"steps": {}}
        report["routers"].append(entry)
        for step, path in (("identity", "system/identity"), ("resource", "system/resource"), ("interfaces", "interface"), ("addresses", "ip/address"), ("nat", "ip/firewall/nat"),
                           ("neighbors", "ip/neighbor"), ("bridge_hosts", "interface/bridge/host"), ("dhcp_leases", "ip/dhcp-server/lease"), ("arp", "ip/arp"),
                           ("wifi_stations", "interface/wifi/registration-table"), ("wireless_stations", "interface/wireless/registration-table")):
            try:
                data = router.get(path)
                if isinstance(data, list):
                    info = {"ok": True, "count": len(data), "fields": sorted({k for r in data[:50] if isinstance(r, dict) for k in r})[:40]}
                    if step == "dhcp_leases":
                        info["statuses"] = {s: sum(1 for r in data if r.get("status") == s) for s in sorted({str(r.get("status")) for r in data})}
                    entry["steps"][step] = info
                else:
                    entry["steps"][step] = {"ok": True, "fields": sorted(data)[:40] if isinstance(data, dict) else type(data).__name__,
                                            **({"version": str(data.get("version") or "")} if step == "resource" and isinstance(data, dict) else {})}
            except Missing:
                entry["steps"][step] = {"ok": False, "error": "not on this device"}
            except AuthRefused:
                raise
            except RouterosError as exc:
                entry["steps"][step] = {"ok": False, "error": _problem(exc)}
        try:
            node, neighbors, found, note = read(router)
            entry["result"] = {"role": node["role"], "clients": len(found), "neighbors": len(neighbors), "wifi_stations": note["stations"], "nat": note["nat"]}
        except RouterosError as exc:
            entry["result"] = {"error": _problem(exc)}
    return report
