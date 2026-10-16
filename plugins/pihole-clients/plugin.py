"""Pi-hole clients plugin (kind "topology"): the devices Pi-hole has seen, as clients with a name and a manufacturer.

Per server the plugin logs in once (POST /api/auth, the session id goes in the `sid` header), reads, and logs out again (Pi-hole v6 API):

    GET /api/info/version                          version
    GET /api/network/devices?max_devices=&max_addresses=
                                                   devices: hwaddr, interface, firstSeen, lastQuery, numQueries, macVendor, ips[{ip, name, lastSeen}]

A device whose `hwaddr` is not a MAC address (Pi-hole writes `ip-127.0.0.1` for what it only knows by address) is left out, as are devices
whose last query is older than the `days` setting. The IPv4 address that was seen last is the device's address; its name is the first name
Pi-hole resolved for one of its addresses. Pi-hole does not know where a device is connected, so clients have no `node_mac`. Standard library only.
"""

import http.client
import ipaddress
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
MAX_DEVICES = 5000


class PiholeError(Exception):
    pass


class AuthRefused(PiholeError):
    auth_failed = True


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 and not addr.is_loopback else None


def _mac(value):
    value = str(value or "").strip().lower().replace("-", ":")
    return value if MAC.match(value) and int(value[:2], 16) & 1 == 0 else None


class Server:
    def __init__(self, url, password, verify_tls=True, timeout=20):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "http://" + url
        if not re.match(r"^https?://[^/\s]+$", url):
            raise PiholeError(f"{url!r} is not an address like http://192.168.0.2")
        self.url, self.password, self.timeout = url, password, float(timeout)
        self.id = url.split("://", 1)[1]
        self.sid = None
        self.version = None
        self.context = None
        if url.startswith("https://") and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.sid:
            headers["sid"] = self.sid
        request = urllib.request.Request(f"{self.url}{path}", data=data, headers=headers, method=method)
        for attempt in (1, 2, 3):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                    raw, status = response.read().decode("utf-8", "replace"), response.status
                break
            except urllib.error.HTTPError as exc:
                raw, status = exc.read().decode("utf-8", "replace"), exc.code
                break
            except (http.client.RemoteDisconnected, ConnectionResetError, urllib.error.URLError) as exc:
                reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
                if attempt == 3:
                    raise PiholeError(f"cannot reach {self.id}: {reason}")
                time.sleep(1.5)
            except OSError as exc:
                raise PiholeError(f"{self.id} did not answer properly: {exc}")
        try:
            parsed = json.loads(raw) if raw.strip() else {}
        except ValueError:
            parsed = {}
        if 200 <= status < 300:
            return parsed
        if status == 401:
            raise AuthRefused(f"{self.id} refused the login; check the (app) password")
        if status == 429:
            raise PiholeError(f"{self.id} is rate limiting logins (HTTP 429); wait a minute and try again")
        raise PiholeError(f"{self.id} answered HTTP {status} for {path.split('?')[0]}")

    def login(self):
        if not self.password:
            raise AuthRefused(f"{self.id}: enter the password")
        session = self.call("POST", "/api/auth", {"password": self.password}).get("session") or {}
        if not session.get("valid") or not session.get("sid"):
            if session.get("totp"):
                raise AuthRefused(f"{self.id} has two-factor login on: create an app password and use that")
            raise AuthRefused(f"{self.id} refused the login (wrong password?)")
        self.sid = session["sid"]
        try:
            self.version = ((self.call("GET", "/api/info/version").get("version") or {}).get("core") or {}).get("local", {}).get("version")
        except PiholeError:
            self.version = None
        return self

    def logout(self):
        if self.sid:
            try:
                self.call("DELETE", "/api/auth")
            except PiholeError:
                pass
            self.sid = None

    def devices(self):
        return self.call("GET", f"/api/network/devices?max_devices={MAX_DEVICES}&max_addresses=10").get("devices") or []


def parse_servers(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and (str(r.get("host") or "").strip() or r.get("password"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one Pi-hole")
    out = []
    for i, r in enumerate(items, 1):
        host = str(r.get("host") or "").strip()
        if not host:
            raise ValueError(f"server {i}: enter its address")
        out.append(Server(host, str(r.get("password") or ""), config.get("verify_tls", True), config.get("timeout") or 20))
    return out


def build(devices, days=30, now=None):
    """Clients from the rows of /api/network/devices."""
    now = time.time() if now is None else now
    clients, seen = [], set()
    for d in sorted(devices, key=lambda x: -(x.get("lastQuery") or 0)):
        mac = _mac(d.get("hwaddr"))
        if not mac or mac in seen or now - float(d.get("lastQuery") or 0) > days * 86400:
            continue
        seen.add(mac)
        ips = sorted((i for i in d.get("ips") or [] if _ipv4(i.get("ip"))), key=lambda i: -(i.get("lastSeen") or 0))
        name = next((str(i["name"]).strip().rstrip(".") for i in ips + list(d.get("ips") or []) if i.get("name")), "")
        client = {"mac": mac, "ip": _ipv4(ips[0]["ip"]) if ips else None, "name": name[:100] or None, "medium": "unknown", "vendor": str(d.get("macVendor") or "")[:100] or None}
        clients.append({k: v for k, v in client.items() if v is not None})
    return clients


def connect(config):
    clients, versions, problems, seen = [], [], [], set()
    for server in parse_servers(config):
        try:
            server.login()
            try:
                rows = build(server.devices(), float(config.get("days") or 30))
            finally:
                server.logout()
        except AuthRefused:
            raise
        except PiholeError as exc:
            problems.append(str(exc))
            continue
        versions.append(server.version or "")
        for row in rows:
            if row["mac"] not in seen:
                seen.add(row["mac"])
                clients.append(row)
    if not versions:
        raise PiholeError("; ".join(problems) or "no Pi-hole answered")
    return versions, clients, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    versions, clients, problems = connect(config)
    named = sum(1 for c in clients if c.get("name"))
    message = f"Connected to Pi-hole {', '.join(sorted({v for v in versions if v})) or '(version unknown)'}: {len(clients)} device(s) with a MAC address, {named} with a name"
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
    """What Pi-hole answers, as counts (no MAC or IP addresses, names or vendors)."""
    try:
        servers = parse_servers(config)
    except (ValueError, PiholeError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for server in servers:
        entry = {"steps": {}}
        report["servers"].append(entry)
        try:
            server.login()
            try:
                rows = server.devices()
            finally:
                server.logout()
            entry["steps"]["version"] = {"ok": True, "version": server.version or ""}
            entry["steps"]["devices"] = {"ok": True, "count": len(rows), "with_mac": sum(1 for d in rows if _mac(d.get("hwaddr"))), "with_name": sum(1 for d in rows if any(i.get("name") for i in d.get("ips") or [])),
                                         "with_vendor": sum(1 for d in rows if d.get("macVendor")), "multi_address": sum(1 for d in rows if len(d.get("ips") or []) > 1),
                                         "fields": sorted({k for d in rows[:50] for k in d})[:30]}
        except AuthRefused:
            raise
        except PiholeError as exc:
            entry["steps"]["error"] = {"ok": False, "error": _problem(exc, server)}
    return report
