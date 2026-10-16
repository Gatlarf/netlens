"""HAProxy plugin (kind "proxy"): the backends of an HAProxy as sites.

Reads HAProxy's statistics page as CSV (`<stats uri>;csv`, optionally with basic authentication), GET only. The columns used are pxname, svname,
status and addr (the server's address and port; HAProxy only lists it with `stats show-legends`). Rows with svname FRONTEND/BACKEND are the
proxies themselves; every other row is a server of the proxy named in pxname.

A backend with at least one server is a site. Its upstream is its first server that is UP (else the first one). HAProxy knows nothing about host names at this level, so
the names come from the `domains` setting ("backend=host name" pairs); without them a site has no domain. A backend whose status is MAINT is
reported as disabled. Frontends are not sites. Standard library only.
"""

import base64
import csv
import io
import ipaddress
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAX_BACKENDS = 1000


class HaproxyError(Exception):
    pass


class AuthRefused(HaproxyError):
    auth_failed = True


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


class Stats:
    def __init__(self, url, username="", password="", lan="", verify_tls=True, timeout=15):
        url = url.strip()
        if "://" not in url:
            url = "http://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise HaproxyError(f"{url!r} is not an address like http://192.168.0.4:8404/stats")
        path = parts.path or "/"
        self.csv_url = f"{parts.scheme}://{parts.netloc}{path}" + ("" if path.endswith(";csv") else ";csv")
        self.id, self.timeout = parts.netloc, float(timeout)
        self.auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode() if username else None
        self.lan_ip = _ipv4(lan) if lan else None
        if lan and not self.lan_ip:
            raise HaproxyError(f"{lan!r} is not an IPv4 address")
        self.ip = self.lan_ip or _ipv4(parts.hostname)
        self.context = None
        if parts.scheme == "https" and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def rows(self):
        headers = {"Accept": "text/csv"}
        if self.auth:
            headers["Authorization"] = self.auth
        request = urllib.request.Request(self.csv_url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                text = response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise AuthRefused(f"{self.id} refused the login for the statistics page (wrong user name or password)")
            raise HaproxyError(f"{self.id} answered HTTP {exc.code} (is the address the 'stats uri' of HAProxy?)")
        except urllib.error.URLError as exc:
            raise HaproxyError(f"cannot reach {self.id}: {exc.reason}")
        except OSError as exc:
            raise HaproxyError(f"{self.id} did not answer properly: {exc}")
        if not text.lstrip().startswith("# pxname"):
            raise HaproxyError(f"{self.id} did not return HAProxy statistics as CSV (is the address the 'stats uri'?)")
        reader = csv.DictReader(io.StringIO(text.lstrip()[2:]))
        return [r for r in reader if r.get("pxname")]


def parse_stats(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and str(r.get("host") or "").strip()] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one HAProxy statistics page")
    return [Stats(str(r["host"]), str(r.get("username") or "").strip(), str(r.get("password") or ""), str(r.get("lan") or "").strip(),
                  config.get("verify_tls", True), config.get("timeout") or 15) for r in items]


def parse_domains(text):
    out = {}
    for pair in re.split(r"[,;\n]+", str(text or "")):
        if "=" in pair:
            backend, _, name = pair.partition("=")
            name = name.strip().lower()
            if backend.strip() and name:
                out.setdefault(backend.strip(), []).append(name)
    return out


def sites_of(stats, rows, domains):
    backends = {}
    for r in rows:
        if r.get("svname") == "BACKEND":
            backends[r["pxname"]] = {"status": r.get("status") or "", "servers": []}
    for r in rows:
        if r.get("svname") not in ("FRONTEND", "BACKEND") and r["pxname"] in backends:
            backends[r["pxname"]]["servers"].append(r)
    proxy = {"id": stats.id, "name": stats.id, "ip": stats.ip, "warnings": []}
    sites = []
    for name, b in list(backends.items())[:MAX_BACKENDS]:
        if not b["servers"]:
            continue            # a listener without servers (the statistics page itself) or an empty backend: nothing to tie to a device
        servers = [s for s in b["servers"] if s.get("addr")]
        chosen = next((s for s in servers if str(s.get("status")).startswith("UP")), None) or (servers[0] if servers else None)
        site = {"id": f"{stats.id}/{name}", "proxy_id": stats.id, "type": "proxy" if chosen else "dead", "domains": domains.get(name, []), "enabled": b["status"] != "MAINT",
                "name": name[:100], "ssl": False, "ssl_forced": False, "websockets": True}
        if chosen:
            host, _, port = chosen["addr"].rpartition(":")
            if host.startswith("[") or host.count(":") > 1:
                host = host.strip("[]")
            site.update(forward_host=host or None, forward_port=int(port) if port.isdigit() else None, scheme="http")
        sites.append({k: v for k, v in site.items() if v not in (None, "")} | {"enabled": site["enabled"], "ssl": False})
    return proxy, sites


def connect(config):
    proxies, sites, problems = [], [], []
    domains = parse_domains(config.get("domains"))
    for stats in parse_stats(config):
        try:
            proxy, found = sites_of(stats, stats.rows(), domains)
        except AuthRefused:
            raise
        except HaproxyError as exc:
            problems.append(str(exc))
            continue
        proxies.append(proxy)
        sites.extend(found)
    if not proxies:
        raise HaproxyError("; ".join(problems) or "no HAProxy answered")
    return proxies, sites, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    proxies, sites, problems = connect(config)
    message = f"Connected to {len(proxies)} HAProxy: {len(sites)} backend(s)"
    named = sum(1 for s in sites if s.get("domains"))
    message += f", {named} with host names" if named else ", none with a host name (see 'Host names per backend')"
    no_addr = sum(1 for s in sites if s["type"] == "dead")
    if no_addr:
        message += f". {no_addr} backend(s) show no server address: add 'stats show-legends' to the statistics listener"
    if any(p["ip"] is None for p in proxies):
        message += ". Fill in the HAProxy host's own address so Netlens can find its device"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    proxies, sites, _ = connect(config)
    return {"proxies": proxies, "sites": sites, "certificates": []}


def _problem(exc):
    return type(exc).__name__ + ": " + re.sub(r"https?://[^\s/]+", "<server>", str(exc))[:300]


def diagnose(config):
    """What HAProxy answers, as counts and enumerations (no names or addresses)."""
    try:
        stats_list = parse_stats(config)
    except (ValueError, HaproxyError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for stats in stats_list:
        entry = {"steps": {}}
        report["servers"].append(entry)
        try:
            rows = stats.rows()
        except AuthRefused:
            raise
        except HaproxyError as exc:
            entry["steps"]["csv"] = {"ok": False, "error": _problem(exc)}
            continue
        servers = [r for r in rows if r.get("svname") not in ("FRONTEND", "BACKEND")]
        entry["steps"]["csv"] = {"ok": True, "rows": len(rows), "frontends": sum(1 for r in rows if r.get("svname") == "FRONTEND"), "backends": sum(1 for r in rows if r.get("svname") == "BACKEND"),
                                 "servers": len(servers), "servers_with_addr": sum(1 for r in servers if r.get("addr")), "server_statuses": {s: sum(1 for r in servers if r.get("status") == s) for s in sorted({str(r.get("status")) for r in servers})},
                                 "has_addr_column": "addr" in (rows[0] if rows else {})}
    return report
