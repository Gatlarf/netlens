"""OPNsense plugin (kind "topology"): the firewall as the gateway node, the devices on its networks as clients.

Talks to the OPNsense API with an API key and secret (HTTP basic authentication), GET requests only:

    /api/diagnostics/system/system_information   host name and version
    /api/interfaces/overview/interfacesInfo      the interfaces: description, identifier (lan, wan, opt1), MAC address, IPv4 address
    /api/diagnostics/interface/search_arp         the ARP table: mac, ip, interface, expired, manufacturer, hostname (a search that returns all rows)
    /api/dnsmasq/leases/search                   DHCP leases (Dnsmasq), when it is the DHCP server   } the plugin tries both and
    /api/kea/leases4/search                      DHCP leases (Kea), when it is the DHCP server        } uses what answers

Every non-expired ARP entry on a non-WAN interface (or on the interfaces you list) is a client; a lease adds the host name when the ARP entry has none.
OPNsense knows nothing about how a device is connected, so `medium` stays unknown. The firewall's own MAC addresses are never clients.
Standard library only.
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


class OpnsenseError(Exception):
    pass


class AuthRefused(OpnsenseError):
    auth_failed = True


class Missing(OpnsenseError):
    pass


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip().split("/")[0])
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


def _mac(value):
    value = str(value or "").strip().lower().replace("-", ":")
    return value if MAC.match(value) and value not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") else None


class Firewall:
    def __init__(self, url, key, secret, verify_tls=False, timeout=20):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "https://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise OpnsenseError(f"{url!r} is not an address like https://192.168.1.1")
        self.base, self.id, self.host, self.timeout = f"{parts.scheme}://{parts.netloc}", parts.netloc, parts.hostname, float(timeout)
        self.auth = "Basic " + base64.b64encode(f"{key}:{secret}".encode()).decode()
        self.context = None
        if parts.scheme == "https" and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def get(self, path):
        request = urllib.request.Request(f"{self.base}/api/{path}", headers={"Authorization": self.auth, "Accept": "application/json"}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                return json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                raise AuthRefused(f"{self.id} refused the API key or secret")
            if exc.code == 403:
                raise AuthRefused(f"{self.id} says this API user may not read {path}: add the privilege listed in the box at the top of this page")
            if exc.code == 404:
                raise Missing(f"{self.id} has no {path}")
            raise OpnsenseError(f"{self.id} answered HTTP {exc.code} for {path}")
        except urllib.error.URLError as exc:
            raise OpnsenseError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise OpnsenseError(f"{self.id} did not answer properly (is this OPNsense?): {exc}")

    def search(self, path):
        """All rows of a search endpoint. A plain GET returns every row; should the answer say there are more (total > rows), ask again for all of them."""
        data = self.get(path)
        rows = _rows(data)
        if isinstance(data, dict) and isinstance(data.get("total"), int) and data["total"] > len(rows):
            request = urllib.request.Request(f"{self.base}/api/{path}", data=json.dumps({"current": 1, "rowCount": data["total"]}).encode(), method="POST",
                                             headers={"Authorization": self.auth, "Accept": "application/json", "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                    rows = _rows(json.loads(response.read().decode("utf-8", "replace")))
            except (OSError, ValueError):
                pass       # keep what the first answer had
        return rows


def parse_firewalls(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "api_key", "api_secret"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one OPNsense")
    out = []
    for i, r in enumerate(items, 1):
        url = str(r.get("host") or "").strip()
        if not url:
            raise ValueError(f"line {i}: enter the address")
        if not str(r.get("api_key") or "").strip() or not str(r.get("api_secret") or "").strip():
            raise ValueError(f"{url}: enter the API key and secret")
        out.append(Firewall(url, str(r["api_key"]).strip(), str(r["api_secret"]).strip(), config.get("verify_tls", False), config.get("timeout") or 20))
    return out


def _wanted(config):
    return [w.strip().lower() for w in re.split(r"[,;]+", str(config.get("interfaces") or "")) if w.strip()]


def _rows(data):
    if isinstance(data, dict):
        data = data.get("rows") if isinstance(data.get("rows"), list) else data.get("response", {}).get("rows") if isinstance(data.get("response"), dict) else []
    return [r for r in data or [] if isinstance(r, dict)]


def leases(fw):
    """{mac: {ip, hostname}} from the DHCP server that answers (Dnsmasq, then Kea, then the old ISC endpoint)."""
    found, sources = {}, []
    for path in ("dnsmasq/leases/search", "kea/leases4/search", "dhcpv4/leases/searchLease"):
        try:
            rows = fw.search(path)
        except Missing:
            continue
        sources.append((path.split("/")[0], len(rows)))
        for r in rows:
            m = _mac(r.get("hwaddr") or r.get("mac") or r.get("macaddr") or r.get("mac_address"))
            if m:
                found[m] = {"ip": _ipv4(r.get("address") or r.get("ip") or r.get("ipaddr") or r.get("ip_address")), "hostname": str(r.get("hostname") or r.get("host") or "").strip()[:100] or None}
    return found, sources


def read(fw, wanted):
    info = fw.get("diagnostics/system/system_information") or {}
    interfaces = [i for i in _rows(fw.get("interfaces/overview/interfacesInfo")) if isinstance(i, dict)]
    own = {m for i in interfaces for m in (_mac(i.get("macaddr")), _mac(i.get("macaddr_hw"))) if m}
    lans = [i for i in interfaces if i.get("addr4") and i.get("identifier") not in ("", "lo0") and i.get("device") != "lo0"]
    lan = next((i for i in lans if i.get("identifier") == "lan"), None) or next((i for i in lans if not str(i.get("identifier")).startswith("wan")), None) or (lans[0] if lans else None)
    mac = _mac((lan or {}).get("macaddr")) or next(iter(sorted(own)), None)
    node = {"mac": mac, "macs": sorted(own - {mac}) or None, "ip": _ipv4((lan or {}).get("addr4")) or _ipv4(fw.host), "name": str(info.get("name") or fw.id)[:100],
            "model": next((v for v in info.get("versions") or [] if str(v).startswith("OPNsense")), "")[:100] or None, "role": "gateway"}
    by_device = {i.get("device"): i for i in interfaces}
    dhcp, sources = leases(fw)
    clients = {}
    for row in fw.search("diagnostics/interface/search_arp"):
        if not isinstance(row, dict) or row.get("expired"):
            continue
        m, ip = _mac(row.get("mac")), _ipv4(row.get("ip"))
        if not m or not ip or m in own:
            continue
        iface = by_device.get(row.get("intf")) or {}
        description = str(row.get("intf_description") or iface.get("description") or "").strip()
        if wanted:
            if description.lower() not in wanted and str(iface.get("identifier") or "").lower() not in wanted:
                continue
        elif str(iface.get("identifier") or "").startswith("wan"):
            continue
        lease = dhcp.get(m, {})
        client = {"mac": m, "ip": ip, "medium": "unknown", "name": str(row.get("hostname") or "").strip()[:100] or lease.get("hostname"), "vendor": str(row.get("manufacturer") or "").strip()[:100] or None}
        clients[m] = {k: v for k, v in client.items() if v}
    out = list(clients.values())[:MAX_CLIENTS]
    return {k: v for k, v in node.items() if v is not None}, out, {"version": str(info.get("versions", [""])[0] if info.get("versions") else ""), "leases": sources, "arp": len(clients)}


def connect(config):
    reads, problems = [], []
    wanted = _wanted(config)
    for fw in parse_firewalls(config):
        try:
            reads.append(read(fw, wanted))
        except AuthRefused:
            raise
        except OpnsenseError as exc:
            problems.append(str(exc))
    if not reads:
        raise OpnsenseError("; ".join(problems) or "no OPNsense answered")
    return reads, problems


def assemble(reads):
    nodes, clients, seen = [], [], set()
    for index, (node, found, _) in enumerate(reads):
        if not node.get("mac") or any(node["mac"] == n["mac"] for n in nodes):       # the same firewall listed twice is one node
            continue
        entry = dict(node)
        if nodes:
            entry["role"] = "node"
        nodes.append(entry)
    gateway_mac = next((n["mac"] for n in nodes), None)
    node_macs = {m for n in nodes for m in [n["mac"], *n.get("macs", [])]}
    for index, (node, found, _) in enumerate(reads):
        if not node.get("mac"):
            continue
        for c in found:
            if c["mac"] in seen or c["mac"] in node_macs:
                continue
            seen.add(c["mac"])
            clients.append({**c, "node_mac": gateway_mac if index else node["mac"]})
    for n in nodes[1:]:      # further firewalls (an HA pair) hang below the first
        n["parent_mac"] = gateway_mac
    return nodes, clients


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    reads, problems = connect(config)
    versions = sorted({r[2]["version"] for r in reads if r[2]["version"]})
    message = f"Connected to {len(reads)} OPNsense ({', '.join(versions) or 'version unknown'}): {sum(len(r[1]) for r in reads)} client(s) in the ARP table"
    leases_seen = [f"{name} {n}" for r in reads for name, n in r[2]["leases"]]
    message += f", DHCP leases: {', '.join(leases_seen)}" if leases_seen else ", no DHCP lease list available (host names then come from ARP/DNS only)"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    reads, _ = connect(config)
    nodes, clients = assemble(reads)
    return {"nodes": nodes, "clients": clients}


def _problem(exc):
    return type(exc).__name__ + ": " + re.sub(r"https?://[^\s/]+", "<firewall>", str(exc))[:300]


def diagnose(config):
    """What the firewalls answer, as counts and field names (no MAC or IP addresses, host names, keys)."""
    try:
        firewalls = parse_firewalls(config)
    except (ValueError, OpnsenseError) as exc:
        return {"error": str(exc)}
    report = {"firewalls": []}
    for fw in firewalls:
        entry = {"steps": {}}
        report["firewalls"].append(entry)
        for step, path in (("system_information", "diagnostics/system/system_information"), ("interfaces", "interfaces/overview/interfacesInfo"), ("arp", "diagnostics/interface/search_arp"),
                           ("dnsmasq_leases", "dnsmasq/leases/search"), ("kea_leases", "kea/leases4/search"), ("isc_leases", "dhcpv4/leases/searchLease")):
            try:
                data = fw.get(path)
                rows = _rows(data) if not isinstance(data, list) else data
                if step == "system_information":
                    entry["steps"][step] = {"ok": True, "fields": sorted(data)[:20] if isinstance(data, dict) else type(data).__name__, "version": str((data.get("versions") or [""])[0])[:30]}
                else:
                    info = {"ok": True, "count": len(rows), "fields": sorted({k for r in rows[:50] if isinstance(r, dict) for k in r})[:40]}
                    if step == "interfaces":
                        info["identifiers"] = sorted({str(r.get("identifier")) for r in rows})[:20]
                    if step == "arp":
                        info["expired"] = sum(1 for r in rows if isinstance(r, dict) and r.get("expired"))
                        info["with_hostname"] = sum(1 for r in rows if isinstance(r, dict) and r.get("hostname"))
                        info["with_manufacturer"] = sum(1 for r in rows if isinstance(r, dict) and r.get("manufacturer"))
                    entry["steps"][step] = info
            except Missing:
                entry["steps"][step] = {"ok": False, "error": "not on this version"}
            except AuthRefused as exc:
                if step in ("system_information", "interfaces", "arp"):
                    raise
                entry["steps"][step] = {"ok": False, "error": "access denied for this API user"}
            except OpnsenseError as exc:
                entry["steps"][step] = {"ok": False, "error": _problem(exc)}
        try:
            node, found, note = read(fw, _wanted(config))
            entry["result"] = {"clients": len(found), "node_macs": 1 + len(node.get("macs", []))}
        except OpnsenseError as exc:
            entry["result"] = {"error": _problem(exc)}
    return report
