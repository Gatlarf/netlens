"""Traefik plugin (kind "proxy"): the sites a Traefik v2/v3 publishes.

Talks to Traefik's API, read-only (GET), optionally with basic authentication:

    GET /api/version                  version
    GET /api/entrypoints              entry points and their ports
    GET /api/http/routers             rule (Host(`a.example.com`)), service, entry points, tls, middlewares, status
    GET /api/http/services            load balancer servers (the upstream url)
    GET /api/http/middlewares         redirect middlewares (to tell a redirect from a site)
    GET /api/tcp/routers, /api/tcp/services   TCP routers become `stream` sites

A router is a site. Its domains come from the Host() / HostSNI() terms of the rule; its upstream is the first server of its service's
load balancer (a Docker provider gives the container's address on its Docker network, which Netlens cannot match to a device; a file
provider usually gives a real address or name). Traefik's own routers (provider `internal`) are skipped. Traefik does not list the
certificates it holds, so no certificate information is reported. Standard library only.
"""

import base64
import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAX_SITES = 2000
HOST_TERM = re.compile(r"Host(?:SNI)?\(([^)]*)\)")
BACKTICKED = re.compile(r"`([^`]+)`")


class TraefikError(Exception):
    pass


class AuthRefused(TraefikError):
    auth_failed = True


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


class Server:
    def __init__(self, url, username="", password="", lan="", verify_tls=True, timeout=15):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "http://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise TraefikError(f"{url!r} is not an address like http://192.168.0.4:8080")
        self.url, self.timeout, self.id = f"{parts.scheme}://{parts.netloc}", float(timeout), parts.netloc
        self.auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode() if username else None
        self.lan_ip = _ipv4(lan) if lan else None
        if lan and not self.lan_ip:
            raise TraefikError(f"{lan!r} is not an IPv4 address")
        self.ip = self.lan_ip or _ipv4(parts.hostname)
        self.context = None
        if parts.scheme == "https" and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def get(self, path):
        headers = {"Accept": "application/json"}
        if self.auth:
            headers["Authorization"] = self.auth
        request = urllib.request.Request(f"{self.url}{path}", headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                return json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise AuthRefused(f"{self.id} refused the login (wrong user name or password)")
            err = TraefikError(f"{self.id} answered HTTP {exc.code} for {path}")
            err.status = exc.code
            raise err
        except urllib.error.URLError as exc:
            raise TraefikError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise TraefikError(f"{self.id} did not answer properly (is this Traefik's API?): {exc}")


def parse_servers(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and str(r.get("host") or "").strip()] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one Traefik API")
    return [Server(str(r["host"]), str(r.get("username") or "").strip(), str(r.get("password") or ""), str(r.get("lan") or "").strip(),
                   config.get("verify_tls", True), config.get("timeout") or 15) for r in items]


def domains_of(rule):
    """The names in Host(`a`, `b`) and HostSNI(`a`) terms of a rule (HostRegexp and wildcards-by-regex are not names)."""
    out = []
    for term in HOST_TERM.findall(str(rule or "")):
        out.extend(n.lower() for n in BACKTICKED.findall(term) if n != "*")
    return list(dict.fromkeys(out))


def _split_hostport(address):
    address = str(address or "")
    url = urllib.parse.urlsplit(address if "://" in address else "tcp://" + address)
    try:
        return url.scheme if "://" in address else "", url.hostname or "", url.port
    except ValueError:
        return "", url.hostname or "", None


def _entry_port(entrypoints, names):
    for n in names or []:
        port = str(entrypoints.get(n) or "").rsplit(":", 1)[-1]
        if port.isdigit():
            return int(port)
    return None


def read(server):
    """Everything the plugin needs from one Traefik, as lists keyed by Traefik's names."""
    version = (server.get("/api/version") or {}).get("Version")
    entrypoints = {e.get("name"): e.get("address") for e in server.get("/api/entrypoints") or []}
    routers = server.get("/api/http/routers") or []
    services = {s.get("name"): s for s in server.get("/api/http/services") or []}
    middlewares = {}
    try:
        middlewares = {m.get("name"): m for m in server.get("/api/http/middlewares") or []}
    except TraefikError:
        pass
    tcp_routers, tcp_services = [], {}
    try:
        tcp_routers = server.get("/api/tcp/routers") or []
        tcp_services = {s.get("name"): s for s in server.get("/api/tcp/services") or []}
    except TraefikError:
        pass
    return version, entrypoints, routers, services, middlewares, tcp_routers, tcp_services


def _qualified(name, provider):
    return name if "@" in str(name or "") else f"{name}@{provider}"


def sites_of(server, data):
    version, entrypoints, routers, services, middlewares, tcp_routers, tcp_services = data
    proxy = {"id": server.id, "name": server.id, "ip": server.ip, "version": version, "warnings": []}
    sites = []
    for router in routers:
        provider = router.get("provider")
        if provider == "internal" or not router.get("name"):
            continue
        service = services.get(_qualified(router.get("service"), provider)) or {}
        domains = domains_of(router.get("rule"))
        redirect = next((middlewares[m] for m in router.get("middlewares") or [] if m in middlewares and str(middlewares[m].get("type", "")).startswith("redirect")), None)
        site = {"id": f"http:{router['name']}", "proxy_id": server.id, "type": "proxy", "domains": domains, "enabled": router.get("status") == "enabled",
                "name": router["name"].split("@")[0][:100], "ssl": bool(router.get("tls")), "ssl_forced": False, "websockets": True}
        if router.get("tls") and (router["tls"].get("certResolver") or router["tls"].get("domains")):
            site["cert_provider"] = str(router["tls"].get("certResolver") or "")[:60] or None
        if redirect is not None:
            site["type"] = "redirect"
            target = ((redirect.get("redirectScheme") or {}).get("scheme") or "") + (" (permanent)" if (redirect.get("redirectScheme") or {}).get("permanent") else "") if redirect.get("redirectScheme") else str((redirect.get("redirectRegex") or {}).get("replacement") or "")
            site["redirect_to"] = target[:200] or None
        else:
            servers = ((service.get("loadBalancer") or {}).get("servers")) or []
            if servers and servers[0].get("url"):
                scheme, host, port = _split_hostport(servers[0]["url"])
                site.update(scheme=scheme if scheme in ("http", "https") else "http", forward_host=host or None,
                            forward_port=port or (443 if scheme == "https" else 80 if host else None))
            else:
                site["type"] = "dead"
        sites.append({k: v for k, v in site.items() if v not in (None, "")} | {"enabled": site["enabled"], "ssl": site["ssl"]})
    for router in tcp_routers:
        if router.get("provider") == "internal" or not router.get("name"):
            continue
        service = tcp_services.get(_qualified(router.get("service"), router.get("provider"))) or {}
        servers = ((service.get("loadBalancer") or {}).get("servers")) or []
        site = {"id": f"tcp:{router['name']}", "proxy_id": server.id, "type": "stream", "domains": domains_of(router.get("rule")), "enabled": router.get("status") == "enabled",
                "name": router["name"].split("@")[0][:100], "protocols": ["tcp"], "incoming_port": _entry_port(entrypoints, router.get("entryPoints")), "ssl": bool(router.get("tls"))}
        if servers and servers[0].get("address"):
            _, host, port = _split_hostport(servers[0]["address"])
            site.update(forward_host=host or None, forward_port=port)
        sites.append({k: v for k, v in site.items() if v not in (None, "")} | {"enabled": site["enabled"], "ssl": site["ssl"]})
    return proxy, sites[:MAX_SITES]


def connect(config):
    proxies, sites, problems = [], [], []
    for server in parse_servers(config):
        try:
            proxy, found = sites_of(server, read(server))
        except AuthRefused:
            raise
        except TraefikError as exc:
            problems.append(str(exc))
            continue
        proxies.append(proxy)
        sites.extend(found)
    if not proxies:
        raise TraefikError("; ".join(problems) or "no Traefik answered")
    return proxies, sites, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    proxies, sites, problems = connect(config)
    kinds = {}
    for s in sites:
        kinds[s["type"]] = kinds.get(s["type"], 0) + 1
    message = f"Connected to {len(proxies)} Traefik ({', '.join(sorted({p['version'] for p in proxies if p.get('version')})) or 'version unknown'}): {len(sites)} site(s)"
    if kinds:
        message += " (" + ", ".join(f"{n} {k}" for k, n in sorted(kinds.items())) + ")"
    no_domain = sum(1 for s in sites if s["type"] in ("proxy", "redirect") and not s.get("domains"))
    if no_domain:
        message += f". {no_domain} router(s) have no Host() name in their rule"
    if any(p["ip"] is None for p in proxies):
        message += ". Fill in the Traefik host's own address so Netlens can find its device"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    proxies, sites, _ = connect(config)
    return {"proxies": proxies, "sites": sites, "certificates": []}


def _problem(exc):
    """The error text for a diagnostic report, without any server address (URL, IP address, host:port or host name)."""
    text = re.sub(r"https?://[^\s/]+", "<server>", str(exc))
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<server>", text)
    text = re.sub(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*:\d{2,5}\b", "<server>", text)
    text = re.sub(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", "<server>", text)
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What Traefik answers, as counts and enumerations (no names, rules, addresses or passwords)."""
    try:
        servers = parse_servers(config)
    except (ValueError, TraefikError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for server in servers:
        entry = {"steps": {}}
        report["servers"].append(entry)
        for step, path in (("version", "/api/version"), ("entrypoints", "/api/entrypoints"), ("http_routers", "/api/http/routers"), ("http_services", "/api/http/services"),
                           ("http_middlewares", "/api/http/middlewares"), ("tcp_routers", "/api/tcp/routers"), ("tcp_services", "/api/tcp/services")):
            try:
                data = server.get(path)
                if isinstance(data, list):
                    info = {"ok": True, "count": len(data), "providers": {p: sum(1 for r in data if r.get("provider") == p) for p in sorted({str(r.get("provider")) for r in data})}}
                    if step == "http_routers":
                        info["with_tls"] = sum(1 for r in data if r.get("tls"))
                        info["with_host_rule"] = sum(1 for r in data if domains_of(r.get("rule")))
                        info["statuses"] = {s: sum(1 for r in data if r.get("status") == s) for s in sorted({str(r.get("status")) for r in data})}
                    if step == "http_services":
                        info["with_servers"] = sum(1 for s in data if (s.get("loadBalancer") or {}).get("servers"))
                    if step == "http_middlewares":
                        info["types"] = {t: sum(1 for m in data if m.get("type") == t) for t in sorted({str(m.get("type")) for m in data})}
                    entry["steps"][step] = info
                else:
                    entry["steps"][step] = {"ok": True, "keys": sorted(data)[:10] if isinstance(data, dict) else type(data).__name__}
            except AuthRefused:
                raise
            except TraefikError as exc:
                entry["steps"][step] = {"ok": False, "error": _problem(exc)}
    return report
