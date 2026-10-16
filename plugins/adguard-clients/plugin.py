"""AdGuard Home clients plugin (kind "topology"): DHCP leases and named clients as clients with a name, a type and an address.

Talks to the AdGuard Home HTTP API with HTTP basic authentication (GET only):

    GET /control/status         version
    GET /control/dhcp/status    leases and static_leases: mac, ip, hostname, expires   (empty when AdGuard Home does not run DHCP)
    GET /control/clients        clients: name, ids (MAC address, IP address or CIDR), tags (device_tv, os_android ...)

A client you named in AdGuard Home is reported when one of its `ids` is a MAC address; an IP address among its ids is its address (a lease with the
same MAC gives the address when there is none). Tags map to Netlens device types (device_tv -> tv ...) and operating systems (os_windows -> Windows).
The runtime clients AdGuard Home builds itself (`auto_clients`) have no MAC address and are not used. AdGuard Home does not know where a device is
connected, so clients have no `node_mac`. Standard library only.
"""

import base64
import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.request

MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
TYPES = {"device_audio": "speaker", "device_camera": "camera", "device_gameconsole": "console", "device_laptop": "pc", "device_nas": "nas", "device_pc": "pc",
         "device_phone": "phone", "device_printer": "printer", "device_securityalarm": "iot", "device_tablet": "tablet", "device_tv": "tv"}
SYSTEMS = {"os_android": "Android", "os_ios": "iOS", "os_linux": "Linux", "os_macos": "macOS", "os_windows": "Windows"}


class AdguardError(Exception):
    pass


class AuthRefused(AdguardError):
    auth_failed = True


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


def _mac(value):
    value = str(value or "").strip().lower().replace("-", ":")
    return value if MAC.match(value) and int(value[:2], 16) & 1 == 0 else None


class Server:
    def __init__(self, url, username, password, verify_tls=True, timeout=20):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "http://" + url
        if not re.match(r"^https?://[^/\s]+$", url):
            raise AdguardError(f"{url!r} is not an address like http://192.168.0.2:3000")
        self.url, self.timeout = url, float(timeout)
        self.id = url.split("://", 1)[1]
        self.auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        self.context = None
        if url.startswith("https://") and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def get(self, path):
        request = urllib.request.Request(f"{self.url}{path}", headers={"Authorization": self.auth, "Accept": "application/json"}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                return json.loads(response.read().decode("utf-8", "replace") or "{}")
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise AuthRefused(f"{self.id} refused the user name or password")
            raise AdguardError(f"{self.id} answered HTTP {exc.code} for {path}")
        except urllib.error.URLError as exc:
            raise AdguardError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise AdguardError(f"{self.id} did not answer properly (is this AdGuard Home?): {exc}")


def parse_servers(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "username", "password"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one AdGuard Home")
    out = []
    for i, r in enumerate(items, 1):
        host = str(r.get("host") or "").strip()
        if not host:
            raise ValueError(f"server {i}: enter its address")
        if not str(r.get("username") or "").strip():
            raise ValueError(f"{host}: enter the user name")
        out.append(Server(host, str(r["username"]).strip(), str(r.get("password") or ""), config.get("verify_tls", True), config.get("timeout") or 20))
    return out


def build(dhcp, clients):
    """Clients from /control/dhcp/status and /control/clients."""
    found = {}
    for lease in list(dhcp.get("static_leases") or []) + list(dhcp.get("leases") or []):
        mac = _mac(lease.get("mac"))
        if mac and mac not in found:
            found[mac] = {"mac": mac, "ip": _ipv4(lease.get("ip")), "name": str(lease.get("hostname") or "").strip()[:100] or None, "medium": "unknown"}
    for client in clients:
        ids = [str(i).strip() for i in client.get("ids") or []]
        macs = [m for m in (_mac(i) for i in ids) if m]
        ips = [a for a in (_ipv4(i) for i in ids) if a]
        tags = [str(t) for t in client.get("tags") or []]
        device_type = next((TYPES[t] for t in tags if t in TYPES), None)
        system = next((SYSTEMS[t] for t in tags if t in SYSTEMS), None)
        for mac in macs[:1]:
            entry = found.setdefault(mac, {"mac": mac, "medium": "unknown"})
            if client.get("name"):
                entry["name"] = str(client["name"]).strip()[:100]                      # the name you gave beats the host name of the lease
            if ips and not entry.get("ip"):
                entry["ip"] = ips[0]
            if device_type:
                entry["device_type"] = device_type
            if system:
                entry["os"] = system
    return [{k: v for k, v in e.items() if v is not None} for e in found.values()]


def read(server):
    version = str(server.get("/control/status").get("version") or "")
    try:
        dhcp = server.get("/control/dhcp/status")
    except AdguardError:
        dhcp = {}                                   # DHCP not available (older version, or not built in)
    clients = server.get("/control/clients").get("clients") or []
    return version, dhcp, clients


def connect(config):
    versions, clients, problems, seen = [], [], [], set()
    for server in parse_servers(config):
        try:
            version, dhcp, named = read(server)
        except AuthRefused:
            raise
        except AdguardError as exc:
            problems.append(str(exc))
            continue
        versions.append(version)
        for row in build(dhcp, named):
            if row["mac"] not in seen:
                seen.add(row["mac"])
                clients.append(row)
    if not versions:
        raise AdguardError("; ".join(problems) or "no AdGuard Home answered")
    return versions, clients, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    versions, clients, problems = connect(config)
    message = f"Connected to AdGuard Home {', '.join(sorted({v for v in versions if v})) or '(version unknown)'}: {len(clients)} device(s) with a MAC address"
    if not clients:
        message += ". Neither DHCP nor a named client with a MAC address gives any; add the MAC address to a client's identifiers (Settings > Client settings)"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    _, clients, _ = connect(config)
    return {"nodes": [], "clients": clients}


def _problem(exc, server=None):
    text = re.sub(r"https?://[^\s/]+", "<server>", str(exc))
    if server is not None:
        text = text.replace(server.id, "<server>")
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What AdGuard Home answers, as counts (no MAC or IP addresses, names or tags)."""
    try:
        servers = parse_servers(config)
    except (ValueError, AdguardError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for server in servers:
        entry = {"steps": {}}
        report["servers"].append(entry)
        try:
            version, dhcp, clients = read(server)
            entry["steps"]["status"] = {"ok": True, "version": version}
            entry["steps"]["dhcp"] = {"ok": True, "enabled": bool(dhcp.get("enabled")), "leases": len(dhcp.get("leases") or []), "static_leases": len(dhcp.get("static_leases") or []),
                                      "fields": sorted((dhcp.get("leases") or dhcp.get("static_leases") or [{}])[0])[:20]}
            entry["steps"]["clients"] = {"ok": True, "count": len(clients), "with_mac": sum(1 for c in clients if any(_mac(i) for i in c.get("ids") or [])),
                                         "with_device_tag": sum(1 for c in clients if any(t in TYPES for t in c.get("tags") or [])),
                                         "id_kinds": {"mac": sum(1 for c in clients for i in c.get("ids") or [] if _mac(i)), "ip": sum(1 for c in clients for i in c.get("ids") or [] if _ipv4(i)),
                                                      "other": sum(1 for c in clients for i in c.get("ids") or [] if not _mac(i) and not _ipv4(i))}}
        except AuthRefused:
            raise
        except AdguardError as exc:
            entry["steps"]["error"] = {"ok": False, "error": _problem(exc, server)}
    return report
