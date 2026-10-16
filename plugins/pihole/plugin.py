"""Pi-hole plugin (kind "dns"): register devices in Pi-hole's Local DNS records (Pi-hole v6 API).

Per server the plugin logs in once (POST /api/auth, the session id goes in the `sid` header), works, and logs out again:

    GET    /api/config/dns/hosts                       the Local DNS records, strings like "192.168.0.7 nas.home.lan"
    GET    /api/config/dns/cnameRecords                the CNAME records, strings like "files.home.lan,nas.home.lan"
    PUT    /api/config/dns/hosts/<ip name>             add a record (400 "Item already present" when it exists)
    DELETE /api/config/dns/hosts/<ip name>             remove it
    (the same two calls on /api/config/dns/cnameRecords/<name,target>)

Pi-hole has no zones and no record comments. The zones Netlens asks for (the `zones` setting) are reported as writable forward zones;
a record belongs to the zone its name ends in. Because there is no comment, no record is reported as `managed`: Netlens then relies on
the list of records it remembers writing, so a record you typed in Pi-hole yourself is never changed or removed. The reverse (PTR)
answer for a Local DNS record is made by Pi-hole itself, so no reverse zone is reported. Standard library only.
"""

import http.client
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

TYPES = ("A", "CNAME")


class PiholeError(Exception):
    pass


class AuthRefused(PiholeError):
    auth_failed = True


def _name(value):
    return str(value or "").strip().rstrip(".").lower()


class Server:
    def __init__(self, url, password, verify_tls=True, timeout=15):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "http://" + url
        if not re.match(r"^https?://[^/\s]+$", url):
            raise PiholeError(f"{url!r} is not an address like http://192.168.0.2")
        self.url, self.password, self.timeout = url, password, float(timeout)
        self.sid = None
        self.version = None
        self.context = None
        if url.startswith("https://") and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def call(self, method, path, body=None, ok=(200, 201, 204)):
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
                    raw = response.read().decode("utf-8", "replace")
                    status = response.status
                break
            except urllib.error.HTTPError as exc:
                raw, status = exc.read().decode("utf-8", "replace"), exc.code
                break
            except (http.client.RemoteDisconnected, ConnectionResetError, urllib.error.URLError) as exc:
                # Pi-hole restarts its web server for a moment after a settings change; reading is safe to repeat, a write is not
                reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
                if attempt == 3 or method not in ("GET", "POST"):
                    raise PiholeError(f"cannot reach {self.url}: {reason}")
                time.sleep(1.5)
            except OSError as exc:
                raise PiholeError(f"{self.url} did not answer properly: {exc}")
        try:
            parsed = json.loads(raw) if raw.strip() else {}
        except ValueError:
            parsed = {}
        if status in ok:
            return parsed
        if status == 401:
            message = ((parsed.get("session") or {}).get("message") if isinstance(parsed, dict) else None) or "unauthorized"
            raise AuthRefused(f"{self.url} refused the login ({message}); check the (app) password")
        if status == 429:
            raise PiholeError(f"{self.url} is rate limiting logins (HTTP 429); wait a minute and try again")
        error = (parsed.get("error") or {}) if isinstance(parsed, dict) else {}
        detail = error.get("message") or f"HTTP {status}"
        err = PiholeError(f"{self.url} answered {detail}" + (f" ({error['hint']})" if error.get("hint") else ""))
        err.status = status
        raise err

    def login(self):
        if not self.password:
            raise AuthRefused(f"{self.url}: enter the password")
        answer = self.call("POST", "/api/auth", {"password": self.password})
        session = answer.get("session") or {}
        if not session.get("valid") or not session.get("sid"):
            if session.get("totp"):
                raise AuthRefused(f"{self.url} has two-factor login on: create an app password and use that")
            raise AuthRefused(f"{self.url} refused the login (wrong password?)")
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

    def hosts(self):
        return ((self.call("GET", "/api/config/dns/hosts").get("config") or {}).get("dns") or {}).get("hosts") or []

    def cnames(self):
        return ((self.call("GET", "/api/config/dns/cnameRecords").get("config") or {}).get("dns") or {}).get("cnameRecords") or []


def parse_servers(config):
    rows = config.get("servers")
    pairs = []
    if isinstance(rows, list):
        pairs = [(str(r.get("host") or "").strip(), str(r.get("password") or "")) for r in rows if isinstance(r, dict)]
        pairs = [p for p in pairs if p[0] or p[1]]
    if not pairs:
        raise ValueError("enter the address of at least one Pi-hole")
    for i, (url, password) in enumerate(pairs, 1):
        if not url:
            raise ValueError(f"server {i}: enter its address")
        if not password:
            raise ValueError(f"{url}: enter the (app) password")
    return [Server(url, password, config.get("verify_tls", True), config.get("timeout") or 15) for url, password in pairs]


def _zone_of(name, zones):
    """The longest configured zone the name ends in (or equals)."""
    best = None
    for zone in zones:
        if (name == zone or name.endswith("." + zone)) and (best is None or len(zone) > len(best)):
            best = zone
    return best


def records_of(server, zones):
    """Local DNS entries as Netlens records. One "ip name1 name2" line is several records."""
    out = []
    for line in server.hosts():
        parts = str(line).split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        for host in parts[1:]:
            host = _name(host)
            zone = _zone_of(host, zones)
            if zone:
                out.append({"zone": zone, "name": host, "type": "A", "value": ip, "ttl": None, "managed": False, "comment": ""})
    for line in server.cnames():
        parts = str(line).split(",")
        if len(parts) < 2:
            continue
        host, target = _name(parts[0]), _name(parts[1])
        zone = _zone_of(host, zones)
        if zone:
            out.append({"zone": zone, "name": host, "type": "CNAME", "value": target, "ttl": None, "managed": False, "comment": ""})
    return out


def connect(config):
    """Log in to every server; returns the ones that work (the caller must log out) and the problems."""
    servers, problems = [], []
    for server in parse_servers(config):
        try:
            servers.append(server.login())
        except AuthRefused:
            for s in servers:
                s.logout()
            raise
        except PiholeError as exc:
            problems.append(str(exc))
    if not servers:
        raise PiholeError("; ".join(problems) or "no Pi-hole answered")
    return servers, problems


def _zones(config):
    return [z for z in dict.fromkeys(_name(z) for z in config.get("zones", [])) if z]


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    servers, problems = connect(config)
    try:
        zones = _zones(config)
        parts = [f"Connected to {len(servers)} Pi-hole(s)"]
        versions = sorted({s.version for s in servers if s.version})
        if versions:
            parts.append("version " + ", ".join(versions))
        total = sum(len(records_of(s, zones)) for s in servers) if zones else sum(len(s.hosts()) for s in servers)
        parts.append(f"{total} Local DNS record(s)" + (" in your zone(s)" if zones else ""))
        if problems:
            parts.append("not reachable: " + "; ".join(problems))
        return {"message": ", ".join(parts)}
    finally:
        for s in servers:
            s.logout()


def fetch(config):
    servers, _ = connect(config)
    try:
        zones = _zones(config)
        records, seen = [], set()
        for server in servers:       # servers kept in sync show the same records; list each once
            for r in records_of(server, zones):
                key = (r["name"], r["type"], r["value"])
                if key not in seen:
                    seen.add(key)
                    records.append(r)
        return {"zones": [{"name": z, "kind": "forward", "writable": True} for z in zones], "records": records,
                "server": ", ".join(s.url.split("//", 1)[-1] for s in servers)[:100] or None}
    finally:
        for s in servers:
            s.logout()


def _entry(change):
    if change["type"] == "CNAME":
        return "cnameRecords", f"{change['name']},{change['value']}"
    return "hosts", f"{change['value']} {change['name']}"


def _put(server, change, value):
    section, entry = _entry({**change, "value": value})
    server.call("PUT", f"/api/config/dns/{section}/{urllib.parse.quote(entry, safe=',')}")


def _delete(server, change, value):
    section, entry = _entry({**change, "value": value})
    server.call("DELETE", f"/api/config/dns/{section}/{urllib.parse.quote(entry, safe=',')}")


def _names_with_a(server, name):
    return [str(line).split()[0] for line in server.hosts() if name in [_name(p) for p in str(line).split()[1:]]]


def _apply_one(server, change):
    action, rtype, name = change["action"], change["type"], change["name"]
    if rtype not in TYPES:
        raise PiholeError(f"{rtype} records are not kept in Pi-hole's Local DNS (the reverse record is made by Pi-hole itself)")
    if action == "add":
        if rtype == "A" and _names_with_a(server, name):
            raise PiholeError(f"{name} got a record in the meantime; nothing was written")
        if rtype == "CNAME" and any(_name(str(l).split(",")[0]) == name for l in server.cnames()):
            raise PiholeError(f"{name} got a CNAME in the meantime; nothing was written")
        _put(server, change, change["value"])
    elif action == "update":
        old = change.get("old_value")
        # names are unique per address line: replace exactly the entry that still has the old value, else refuse
        if rtype == "A":
            if old not in _names_with_a(server, name):
                raise PiholeError(f"{name} no longer points to {old}; nothing was changed")
        elif not any(_name(str(l).split(",")[0]) == name and _name(str(l).split(",")[1]) == _name(old) for l in server.cnames() if "," in str(l)):
            raise PiholeError(f"{name} no longer points to {old}; nothing was changed")
        _put(server, change, change["value"])
        try:
            _delete(server, change, old)
        except PiholeError:
            _delete(server, change, change["value"])    # undo, so there is never a half change
            raise
    elif action == "delete":
        try:
            _delete(server, change, change["value"])
        except PiholeError as exc:
            if getattr(exc, "status", None) != 404:
                raise
    else:
        raise PiholeError(f"unknown action {action!r}")


def apply(config, changes):
    servers, _ = connect(config)
    results = []
    try:
        for change in changes:
            errors = []
            for server in servers:
                try:
                    _apply_one(server, change)
                except AuthRefused:
                    raise
                except PiholeError as exc:
                    errors.append(f"{server.url.split('//', 1)[-1]}: {exc}" if len(servers) > 1 else str(exc))
            results.append({"id": change["id"], "ok": not errors, "error": "; ".join(errors)[:300] or None})
    finally:
        for s in servers:
            s.logout()
    return results


# ----------------------------------------------------------------------------- diagnostic (for the plugin's author)
def _problem(exc):
    """The error text for a diagnostic report, without any server address (URL, IP address, host:port or host name)."""
    text = re.sub(r"https?://[^\s/]+", "<server>", str(exc))
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<server>", text)
    text = re.sub(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*:\d{2,5}\b", "<server>", text)
    text = re.sub(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", "<server>", text)
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What the servers answer, as counts and yes/no (no names, addresses or passwords)."""
    try:
        servers = parse_servers(config)
    except ValueError as exc:
        return {"error": str(exc)}
    zones = _zones(config)
    report = {"servers": []}
    for server in servers:
        entry = {"steps": {}}
        report["servers"].append(entry)
        try:
            server.login()
        except AuthRefused:
            raise
        except PiholeError as exc:
            entry["error"] = _problem(exc)
            continue
        try:
            entry["version"] = server.version
            for step, call in (("hosts", server.hosts), ("cname_records", server.cnames)):
                try:
                    rows = call()
                    entry["steps"][step] = {"ok": True, "count": len(rows)}
                except PiholeError as exc:
                    entry["steps"][step] = {"ok": False, "error": _problem(exc)}
            entry["records_in_your_zones"] = len(records_of(server, zones))
        finally:
            server.logout()
    return report
