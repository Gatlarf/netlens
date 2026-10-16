"""AdGuard Home plugin (kind "dns"): register devices as DNS rewrites (Filters -> DNS rewrites).

Talks to the AdGuard Home HTTP API with HTTP basic authentication:

    GET  /control/status            version
    GET  /control/rewrite/list      [{"domain": ..., "answer": ..., "enabled": true}]
    POST /control/rewrite/add       {"domain", "answer"}   (also 200 when the rewrite exists already)
    POST /control/rewrite/delete    {"domain", "answer"}   (also 200 when it does not exist)

An answer that is an IPv4 address makes an A rewrite, an IPv6 address an AAAA, and a name a CNAME. AdGuard Home has no zones, no record
comments and makes no reverse (PTR) answers for rewrites, so: the zones Netlens asks for (the `zones` setting) are reported as writable
forward zones, no record is `managed` (Netlens relies on the list of records it remembers writing, so a rewrite you typed in yourself is
never changed or removed) and no reverse zone is reported. Because AdGuard Home answers 200 to everything, the plugin checks the list
before and after each write. A change is made with delete + add (the update call of v0.107.79 keeps the old rewrite). Standard library only.
"""

import base64
import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.request


class AdguardError(Exception):
    pass


class AuthRefused(AdguardError):
    auth_failed = True


def _name(value):
    return str(value or "").strip().rstrip(".").lower()


def _kind(answer):
    """(record type, value) for a rewrite answer, or None for the special answers ("A", "AAAA") and anything else."""
    answer = str(answer or "").strip()
    try:
        return ("A" if ipaddress.ip_address(answer).version == 4 else "AAAA"), answer
    except ValueError:
        pass
    if answer.upper() in ("A", "AAAA") or not re.fullmatch(r"[A-Za-z0-9_.-]+", answer):
        return None
    return "CNAME", _name(answer)


class Server:
    def __init__(self, url, username, password, verify_tls=True, timeout=15):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "http://" + url
        if not re.match(r"^https?://[^/\s]+$", url):
            raise AdguardError(f"{url!r} is not an address like http://192.168.0.2:3000")
        self.url, self.timeout = url, float(timeout)
        self.auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        self.version = None
        self.context = None
        if url.startswith("https://") and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Accept": "application/json", "Authorization": self.auth}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(f"{self.url}{path}", data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                raw = response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise AuthRefused(f"{self.url} refused the login (wrong user name or password)")
            detail = exc.read().decode("utf-8", "replace").strip()[:200]
            raise AdguardError(f"{self.url} answered HTTP {exc.code}" + (f": {detail}" if detail else ""))
        except urllib.error.URLError as exc:
            raise AdguardError(f"cannot reach {self.url}: {exc.reason}")
        except OSError as exc:
            raise AdguardError(f"{self.url} did not answer properly: {exc}")
        try:
            return json.loads(raw) if raw.strip() else {}
        except ValueError:
            raise AdguardError(f"{self.url} did not answer properly (not JSON; is this AdGuard Home?)")

    def load(self):
        status = self.call("GET", "/control/status")
        self.version = status.get("version") if isinstance(status, dict) else None
        return self

    def rewrites(self):
        rows = self.call("GET", "/control/rewrite/list")
        if not isinstance(rows, list):
            raise AdguardError(f"{self.url} did not return a list of rewrites")
        return rows


def parse_servers(config):
    rows = config.get("servers")
    pairs = []
    if isinstance(rows, list):
        pairs = [(str(r.get("host") or "").strip(), str(r.get("username") or "").strip(), str(r.get("password") or "")) for r in rows if isinstance(r, dict)]
        pairs = [p for p in pairs if any(p)]
    if not pairs:
        raise ValueError("enter the address of at least one AdGuard Home")
    for i, (url, user, password) in enumerate(pairs, 1):
        if not url:
            raise ValueError(f"server {i}: enter its address")
        if not user or not password:
            raise ValueError(f"{url}: enter the user name and password")
    return [Server(url, user, password, config.get("verify_tls", True), config.get("timeout") or 15) for url, user, password in pairs]


def _zones(config):
    return [z for z in dict.fromkeys(_name(z) for z in config.get("zones", [])) if z]


def _zone_of(name, zones):
    best = None
    for zone in zones:
        if (name == zone or name.endswith("." + zone)) and (best is None or len(zone) > len(best)):
            best = zone
    return best


def records_of(server, zones):
    out = []
    for row in server.rewrites():
        if not isinstance(row, dict) or row.get("enabled") is False:
            continue
        name = _name(row.get("domain"))
        kind = _kind(row.get("answer"))
        zone = _zone_of(name, zones)
        if kind and zone and "*" not in name:
            out.append({"zone": zone, "name": name, "type": kind[0], "value": kind[1], "ttl": None, "managed": False, "comment": ""})
    return out


def connect(config):
    servers, problems = [], []
    for server in parse_servers(config):
        try:
            servers.append(server.load())
        except AuthRefused:
            raise
        except AdguardError as exc:
            problems.append(str(exc))
    if not servers:
        raise AdguardError("; ".join(problems) or "no AdGuard Home answered")
    return servers, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    servers, problems = connect(config)
    zones = _zones(config)
    parts = [f"Connected to {len(servers)} AdGuard Home server(s)"]
    versions = sorted({s.version for s in servers if s.version})
    if versions:
        parts.append("version " + ", ".join(versions))
    parts.append(f"{sum(len(s.rewrites()) for s in servers) if not zones else sum(len(records_of(s, zones)) for s in servers)} DNS rewrite(s)" + (" in your zone(s)" if zones else ""))
    if problems:
        parts.append("not reachable: " + "; ".join(problems))
    return {"message": ", ".join(parts)}


def fetch(config):
    servers, _ = connect(config)
    zones = _zones(config)
    records, seen = [], set()
    for server in servers:
        for r in records_of(server, zones):
            key = (r["name"], r["type"], r["value"])
            if key not in seen:
                seen.add(key)
                records.append(r)
    return {"zones": [{"name": z, "kind": "forward", "writable": True} for z in zones], "records": records,
            "server": ", ".join(s.url.split("//", 1)[-1] for s in servers)[:100] or None}


def _has(server, name, answer=None, types=("A", "AAAA", "CNAME")):
    """The rewrites at `name` (of these kinds), optionally only the one with this answer."""
    found = []
    for row in server.rewrites():
        kind = _kind(row.get("answer")) if isinstance(row, dict) else None
        if kind and kind[0] in types and _name(row.get("domain")) == name and (answer is None or kind[1] == _name(answer) or kind[1] == answer):
            found.append(row)
    return found


def _add(server, name, value):
    server.call("POST", "/control/rewrite/add", {"domain": name, "answer": value})
    if not _has(server, name, value):
        raise AdguardError(f"AdGuard Home accepted the rewrite for {name} but it is not in the list")


def _remove(server, name, value):
    for row in _has(server, name, value):                 # delete with the answer exactly as stored
        server.call("POST", "/control/rewrite/delete", {"domain": row["domain"], "answer": row["answer"]})


def _apply_one(server, change):
    action, rtype, name = change["action"], change["type"], change["name"]
    if rtype not in ("A", "AAAA", "CNAME"):
        raise AdguardError(f"{rtype} records are not available in AdGuard Home rewrites")
    if action == "add":
        if _has(server, name):
            raise AdguardError(f"{name} got a rewrite in the meantime; nothing was written")
        _add(server, name, change["value"])
    elif action == "update":
        old = change.get("old_value")
        if not _has(server, name, old):
            raise AdguardError(f"{name} no longer points to {old}; nothing was changed")
        _add(server, name, change["value"])
        _remove(server, name, old)
    elif action == "delete":
        _remove(server, name, change["value"])
    else:
        raise AdguardError(f"unknown action {action!r}")


def apply(config, changes):
    servers, _ = connect(config)
    results = []
    for change in changes:
        errors = []
        for server in servers:
            try:
                _apply_one(server, change)
            except AuthRefused:
                raise
            except AdguardError as exc:
                errors.append(f"{server.url.split('//', 1)[-1]}: {exc}" if len(servers) > 1 else str(exc))
        results.append({"id": change["id"], "ok": not errors, "error": "; ".join(errors)[:300] or None})
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
            server.load()
            entry["version"] = server.version
        except AuthRefused:
            raise
        except AdguardError as exc:
            entry["error"] = _problem(exc)
            continue
        try:
            rows = server.rewrites()
            kinds = {}
            for row in rows:
                k = _kind(row.get("answer"))
                kinds[k[0] if k else "other"] = kinds.get(k[0] if k else "other", 0) + 1
            entry["steps"]["rewrites"] = {"ok": True, "count": len(rows), "kinds": kinds, "disabled": sum(1 for r in rows if r.get("enabled") is False),
                                          "fields": sorted({key for r in rows for key in r}), "in_your_zones": len(records_of(server, zones))}
        except AdguardError as exc:
            entry["steps"]["rewrites"] = {"ok": False, "error": _problem(exc)}
    return report
