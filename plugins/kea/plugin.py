"""Kea DHCP plugin (kind "topology"): DHCP leases and reservations as clients.

Talks to the Kea Control Agent (HTTP POST of a JSON command, basic authentication) and sends only two commands:

    version-get                 service dhcp4   version
    lease4-get-all              service dhcp4   leases: ip-address, hw-address, hostname, cltt + valid-lft (expiry), state
    config-get                  service dhcp4   reservations: subnet4[].reservations and the global ones (hw-address, ip-address, hostname)

Needs the lease_cmds hook library on the DHCPv4 server. A lease that has expired or was declined is not reported. Kea does not know which switch or
access point a device sits on, so clients have no `node_mac`; Netlens uses them for the name and the address. Standard library only.
"""

import base64
import ipaddress
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
MAX_LEASES = 50000


class KeaError(Exception):
    pass


class AuthRefused(KeaError):
    auth_failed = True


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


def _mac(value):
    value = str(value or "").strip().lower().replace("-", ":")
    return value if MAC.match(value) else None


class Server:
    def __init__(self, url, user="", password="", verify_tls=True, timeout=30):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "http://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise KeaError(f"{url!r} is not an address like http://192.168.0.2:8000")
        self.url, self.timeout, self.id = f"{parts.scheme}://{parts.netloc}/", float(timeout), parts.netloc
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode() if user else None
        self.context = None
        if parts.scheme == "https" and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def command(self, name, service="dhcp4"):
        """Run one command; returns the `arguments` of the answer ({} when there are none)."""
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.auth:
            headers["Authorization"] = self.auth
        body = json.dumps({"command": name, "service": [service]}).encode()
        request = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                answer = json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise AuthRefused(f"{self.id} refused the user name or password")
            raise KeaError(f"{self.id} answered HTTP {exc.code}")
        except urllib.error.URLError as exc:
            raise KeaError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise KeaError(f"{self.id} did not answer properly (is this the Kea Control Agent?): {exc}")
        item = answer[0] if isinstance(answer, list) and answer else answer
        if not isinstance(item, dict):
            raise KeaError(f"{self.id} sent an unexpected answer to {name}")
        result = item.get("result")
        if result == 3:                      # no leases: not an error
            return {}
        if result != 0:
            text = str(item.get("text") or "")[:200]
            if "not supported" in text:
                raise KeaError(f"{self.id}: {name} is not supported; load the lease_cmds hook library in the DHCPv4 server")
            raise KeaError(f"{self.id}: {name} failed: {text}")
        return item.get("arguments") or {}


def parse_servers(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "user", "password"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one Kea Control Agent")
    out = []
    for i, r in enumerate(items, 1):
        host = str(r.get("host") or "").strip()
        if not host:
            raise ValueError(f"line {i}: enter the address")
        out.append(Server(host, str(r.get("user") or "").strip(), str(r.get("password") or ""), config.get("verify_tls", True), config.get("timeout") or 30))
    return out


def _name(hostname):
    return str(hostname or "").strip().rstrip(".")[:100]


def _reservations(config_get):
    """(mac, ip, hostname) of every reservation that has a hardware address, global and per subnet."""
    dhcp4 = config_get.get("Dhcp4") or {}
    hosts = list(dhcp4.get("reservations") or [])
    for subnet in dhcp4.get("subnet4") or []:
        hosts.extend(subnet.get("reservations") or [])
    for shared in dhcp4.get("shared-networks") or []:
        hosts.extend(shared.get("reservations") or [])
        for subnet in shared.get("subnet4") or []:
            hosts.extend(subnet.get("reservations") or [])
    out = []
    for h in hosts:
        mac = _mac(h.get("hw-address"))
        if mac:
            out.append((mac, _ipv4(h.get("ip-address")), _name(h.get("hostname"))))
    return out


def read(server, config, now=None):
    now = time.time() if now is None else now
    info = server.command("version-get")
    version = str(info.get("extended") or "").split("\n")[0].split()[0] if info.get("extended") else ""
    leases = (server.command("lease4-get-all").get("leases") or [])[:MAX_LEASES]
    clients = {}
    expired = 0
    for lease in leases:
        mac = _mac(lease.get("hw-address"))
        if not mac:
            continue
        if lease.get("state", 0) != 0 or float(lease.get("cltt") or 0) + float(lease.get("valid-lft") or 0) < now:
            expired += 1
            continue
        clients[mac] = {"mac": mac, "ip": _ipv4(lease.get("ip-address")), "name": _name(lease.get("hostname")) or None, "medium": "unknown"}
    reserved = 0
    if config.get("reservations", True):
        for mac, ip, name in _reservations(server.command("config-get")):
            entry = clients.get(mac)
            if entry is None:
                clients[mac] = {"mac": mac, "ip": ip, "name": name or None, "medium": "unknown"}
                reserved += 1
            elif not entry.get("name") and name:
                entry["name"] = name
    return version, [{k: v for k, v in c.items() if v is not None} for c in clients.values()], expired, reserved


def connect(config):
    versions, clients, expired, reserved, problems, seen = [], [], 0, 0, [], set()
    for server in parse_servers(config):
        try:
            version, rows, e, r = read(server, config)
        except AuthRefused:
            raise
        except KeaError as exc:
            problems.append(str(exc))
            continue
        versions.append(version)
        expired += e
        reserved += r
        for row in rows:
            if row["mac"] not in seen:
                seen.add(row["mac"])
                clients.append(row)
    if not versions:
        raise KeaError("; ".join(problems) or "no Kea answered")
    return versions, clients, expired, reserved, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    versions, clients, expired, reserved, problems = connect(config)
    message = f"Connected to Kea {', '.join(sorted({v for v in versions if v})) or '(version unknown)'}: {len(clients)} device(s) with a lease or reservation"
    if reserved:
        message += f" ({reserved} only reserved)"
    if expired:
        message += f"; {expired} expired lease(s) left out"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    _, clients, _, _, _ = connect(config)
    return {"nodes": [], "clients": clients}


def _problem(exc, server=None):
    text = re.sub(r"https?://[^\s/]+", "<server>", str(exc))
    if server is not None:
        text = text.replace(server.id, "<server>")
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What Kea answers, as counts only (no MAC or IP addresses, host names or subnets)."""
    try:
        servers = parse_servers(config)
    except (ValueError, KeaError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for server in servers:
        entry = {"steps": {}}
        report["servers"].append(entry)
        try:
            info = server.command("version-get")
            entry["steps"]["version"] = {"ok": True, "version": str(info.get("extended") or "").split("\n")[0][:40]}
            leases = (server.command("lease4-get-all").get("leases") or [])
            now = time.time()
            entry["steps"]["leases"] = {"ok": True, "count": len(leases), "with_hostname": sum(1 for x in leases if x.get("hostname")),
                                        "states": {str(s): sum(1 for x in leases if x.get("state", 0) == s) for s in sorted({x.get("state", 0) for x in leases})},
                                        "expired": sum(1 for x in leases if float(x.get("cltt") or 0) + float(x.get("valid-lft") or 0) < now),
                                        "fields": sorted(leases[0])[:30] if leases else []}
            cfg = server.command("config-get")
            entry["steps"]["reservations"] = {"ok": True, "count": len(_reservations(cfg)), "subnets": len((cfg.get("Dhcp4") or {}).get("subnet4") or [])}
        except AuthRefused:
            raise
        except KeaError as exc:
            entry["steps"]["error"] = {"ok": False, "error": _problem(exc, server)}
    return report
