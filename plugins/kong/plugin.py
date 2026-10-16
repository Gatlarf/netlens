"""Kong Gateway plugin (kind "proxy"): the routes a Kong publishes.

Talks to Kong's Admin API, read-only (GET only), with an RBAC token when Kong Enterprise uses one (header Kong-Admin-Token):

    GET /                 version, database mode
    GET /services         the upstreams: protocol, host, port, path, enabled
    GET /routes           the routes: hosts, paths, protocols, service, and (tcp/tls routes) destinations and snis

Both lists are paged (`offset`); the plugin follows the pages. A route is a site: its domains are the route's `hosts` (and `snis`), its
upstream the service it points to. Routes of the `grpc`/`grpcs` protocols are skipped. Kong keeps its certificates as PEM text that the
Admin API does not parse, so no certificate expiry is reported. Standard library only.
"""

import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAX_ROUTES = 3000


class KongError(Exception):
    pass


class AuthRefused(KongError):
    auth_failed = True


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


class Admin:
    def __init__(self, url, token="", lan="", verify_tls=True, timeout=15):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "http://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise KongError(f"{url!r} is not an address like http://192.168.0.4:8001")
        self.url, self.token, self.timeout, self.id = f"{parts.scheme}://{parts.netloc}", token, float(timeout), parts.netloc
        self.lan_ip = _ipv4(lan) if lan else None
        if lan and not self.lan_ip:
            raise KongError(f"{lan!r} is not an IPv4 address")
        self.ip = self.lan_ip or _ipv4(parts.hostname)
        self.context = None
        if parts.scheme == "https" and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def get(self, path, **params):
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Kong-Admin-Token"] = self.token
        request = urllib.request.Request(f"{self.url}{path}" + (f"?{query}" if query else ""), headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                return json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise AuthRefused(f"{self.id} refused the admin token for {path}")
            raise KongError(f"{self.id} answered HTTP {exc.code} for {path}")
        except urllib.error.URLError as exc:
            raise KongError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise KongError(f"{self.id} did not answer properly (is this Kong's Admin API?): {exc}")

    def paged(self, path):
        rows, offset = [], None
        while len(rows) < MAX_ROUTES:
            page = self.get(path, size=200, offset=offset)
            rows.extend(page.get("data") or [])
            offset = page.get("offset")
            if not offset:
                break
        return rows


def parse_admins(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and str(r.get("host") or "").strip()] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one Kong Admin API")
    return [Admin(str(r["host"]), str(r.get("token") or "").strip(), str(r.get("lan") or "").strip(), config.get("verify_tls", True), config.get("timeout") or 15) for r in items]


def read(admin):
    info = admin.get("/")
    services = {s.get("id"): s for s in admin.paged("/services")}
    routes = admin.paged("/routes")
    proxy = {"id": admin.id, "name": str(info.get("hostname") or admin.id)[:100], "ip": admin.ip, "version": str(info.get("version") or "") or None, "warnings": []}
    if admin.url.startswith("http://") and not admin.ip:
        proxy["warnings"].append("the Admin API is reached over plain http")
    sites = []
    for route in routes:
        protocols = [str(p).lower() for p in route.get("protocols") or ["http", "https"]]
        if protocols and all(p in ("grpc", "grpcs") for p in protocols):
            continue
        service = services.get((route.get("service") or {}).get("id")) or {}
        stream = all(p in ("tcp", "tls", "udp", "tls_passthrough") for p in protocols)
        domains = [str(h).lower() for h in (route.get("hosts") or []) + (route.get("snis") or [])]
        site = {"id": str(route.get("id")), "proxy_id": admin.id, "type": "stream" if stream else "proxy", "domains": list(dict.fromkeys(domains)),
                "enabled": service.get("enabled", True) is not False, "name": str(route.get("name") or (domains[0] if domains else route.get("id")))[:100],
                "ssl": any(p in ("https", "tls", "tls_passthrough") for p in protocols), "ssl_forced": False, "websockets": True}
        if service.get("host"):
            scheme = str(service.get("protocol") or "http").lower()
            site.update(scheme="https" if scheme in ("https", "tls") else "http", forward_host=service["host"], forward_port=service.get("port") or (443 if scheme == "https" else 80))
        else:
            site["type"] = "dead" if not stream else site["type"]
        if stream:
            site["protocols"] = ["udp" if "udp" in protocols else "tcp"]
            dest = (route.get("destinations") or [{}])[0]
            if dest.get("port"):
                site["incoming_port"] = dest["port"]
        sites.append({k: v for k, v in site.items() if v not in (None, "")} | {"enabled": site["enabled"], "ssl": site["ssl"]})
    return proxy, sites


def connect(config):
    proxies, sites, problems = [], [], []
    for admin in parse_admins(config):
        try:
            proxy, found = read(admin)
        except AuthRefused:
            raise
        except KongError as exc:
            problems.append(str(exc))
            continue
        proxies.append(proxy)
        sites.extend(found)
    if not proxies:
        raise KongError("; ".join(problems) or "no Kong answered")
    return proxies, sites, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    proxies, sites, problems = connect(config)
    kinds = {}
    for s in sites:
        kinds[s["type"]] = kinds.get(s["type"], 0) + 1
    message = f"Connected to {len(proxies)} Kong ({', '.join(sorted({p['version'] for p in proxies if p.get('version')})) or 'version unknown'}): {len(sites)} route(s)"
    if kinds:
        message += " (" + ", ".join(f"{n} {k}" for k, n in sorted(kinds.items())) + ")"
    if any(p["ip"] is None for p in proxies):
        message += ". Fill in the Kong host's own address so Netlens can find its device"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    proxies, sites, _ = connect(config)
    return {"proxies": proxies, "sites": sites, "certificates": []}


def _problem(exc):
    return type(exc).__name__ + ": " + re.sub(r"https?://[^\s/]+", "<server>", str(exc))[:300]


def diagnose(config):
    """What Kong answers, as counts and enumerations (no names, hosts, paths or addresses)."""
    try:
        admins = parse_admins(config)
    except (ValueError, KongError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for admin in admins:
        entry = {"steps": {}}
        report["servers"].append(entry)
        try:
            info = admin.get("/")
            entry["steps"]["root"] = {"ok": True, "version": str(info.get("version") or ""), "database": str((info.get("configuration") or {}).get("database") or "")}
        except AuthRefused:
            raise
        except KongError as exc:
            entry["steps"]["root"] = {"ok": False, "error": _problem(exc)}
            continue
        for step, path in (("services", "/services"), ("routes", "/routes")):
            try:
                rows = admin.paged(path)
                info = {"ok": True, "count": len(rows), "fields": sorted({k for r in rows[:50] for k in r})[:40]}
                if step == "services":
                    info["protocols"] = {p: sum(1 for r in rows if r.get("protocol") == p) for p in sorted({str(r.get("protocol")) for r in rows})}
                else:
                    info["with_hosts"] = sum(1 for r in rows if r.get("hosts"))
                    info["protocols"] = {p: sum(1 for r in rows if p in (r.get("protocols") or [])) for p in sorted({str(p) for r in rows for p in r.get("protocols") or []})}
                entry["steps"][step] = info
            except KongError as exc:
                entry["steps"][step] = {"ok": False, "error": _problem(exc)}
    return report
