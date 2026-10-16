"""Caddy plugin (kind "proxy"): the sites a Caddy 2 serves as a reverse proxy.

Talks to Caddy's admin API, read-only:

    GET /config/apps/http/servers      every HTTP server: listen addresses and routes
    GET /config/apps/tls               (optional) whether certificates are managed by Caddy

A *route* is a site when it matches host names (match -> host) and its handlers, however deeply nested in `subroute` handlers, contain a
`reverse_proxy` (the first upstream becomes the site's upstream; `transport.tls` means https), or a `static_response` that sends a
`Location` header with a 3xx status (a redirect). Routes that serve files or have no host match are not sites. A site has TLS when its
server listens on :443 and automatic HTTPS is not disabled. Caddy does not tell the certificate's expiry through the API, so no
certificate information is reported. Standard library only.
"""

import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request

MAX_SITES = 2000


class CaddyError(Exception):
    pass


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


class Server:
    def __init__(self, url, lan="", timeout=15):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "http://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise CaddyError(f"{url!r} is not an address like http://192.168.0.4:2019")
        self.url, self.timeout, self.id = f"{parts.scheme}://{parts.netloc}", float(timeout), parts.netloc
        self.lan_ip = _ipv4(lan) if lan else None
        if lan and not self.lan_ip:
            raise CaddyError(f"{lan!r} is not an IPv4 address")
        self.ip = self.lan_ip or _ipv4(parts.hostname)

    def get(self, path):
        request = urllib.request.Request(f"{self.url}{path}", headers={"Accept": "application/json"}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            raise CaddyError(f"{self.id} answered HTTP {exc.code} for {path}")
        except urllib.error.URLError as exc:
            raise CaddyError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise CaddyError(f"{self.id} did not answer properly (is this Caddy's admin API?): {exc}")


def parse_servers(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and str(r.get("host") or "").strip()] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one Caddy admin API")
    return [Server(str(r["host"]), str(r.get("lan") or "").strip(), config.get("timeout") or 15) for r in items]


def _handlers(handles):
    """Every handler in a list, descending into subroute handlers."""
    for h in handles or []:
        if not isinstance(h, dict):
            continue
        if h.get("handler") == "subroute":
            for route in h.get("routes") or []:
                yield from _handlers(route.get("handle"))
        else:
            yield h


def _hosts(route):
    hosts = []
    for match in route.get("match") or []:
        hosts.extend(str(h).lower() for h in match.get("host") or [])
    return list(dict.fromkeys(hosts))


def _dial(upstream):
    """(host, port) of an upstream's dial address ("whoami:80", "10.0.0.5:8080", "unix//run/x.sock" has none)."""
    dial = str((upstream or {}).get("dial") or "")
    if not dial or dial.startswith("unix/"):
        return None, None
    url = urllib.parse.urlsplit("//" + dial.split("/")[0])
    try:
        return url.hostname, url.port
    except ValueError:
        return url.hostname, None


def site_of(proxy_id, key, route, https_server):
    hosts = _hosts(route)
    if not hosts:
        return None
    proxy = redirect = None
    for handler in _handlers(route.get("handle")):
        if handler.get("handler") == "reverse_proxy" and proxy is None:
            proxy = handler
        elif handler.get("handler") == "static_response" and str(handler.get("status_code", "")).startswith("3") and (handler.get("headers") or {}).get("Location"):
            redirect = handler
    site = {"id": key, "proxy_id": proxy_id, "domains": hosts, "enabled": True, "ssl": https_server, "ssl_forced": False, "websockets": True, "name": hosts[0][:100]}
    if proxy is not None:
        host, port = _dial((proxy.get("upstreams") or [{}])[0])
        https = bool(((proxy.get("transport") or {}).get("tls")) is not None and "tls" in (proxy.get("transport") or {}))
        site.update(type="proxy", scheme="https" if https else "http", forward_host=host, forward_port=port or (443 if https else 80 if host else None))
    elif redirect is not None:
        site.update(type="redirect", redirect_to=str(redirect["headers"]["Location"][0])[:200])
    else:
        return None
    return {k: v for k, v in site.items() if v not in (None, "")} | {"enabled": True, "ssl": https_server}


def sites_of(server, servers_config, tls_config=None):
    proxy = {"id": server.id, "name": server.id, "ip": server.ip, "warnings": [] if not server.url.startswith("http://") else []}
    sites = []
    for name, srv in (servers_config or {}).items():
        listen = [str(a) for a in srv.get("listen") or []]
        auto = srv.get("automatic_https") or {}
        https_server = any(a.rsplit(":", 1)[-1] == "443" for a in listen) and not auto.get("disable")
        for i, route in enumerate(srv.get("routes") or []):
            site = site_of(server.id, f"{name}/{i}", route, https_server)
            if site:
                site["incoming_port"] = int(listen[0].rsplit(":", 1)[-1]) if listen and listen[0].rsplit(":", 1)[-1].isdigit() else None
                if site["incoming_port"] is None:
                    del site["incoming_port"]
                if https_server and tls_config is not None:
                    site["cert_provider"] = "caddy (automatic)"
                sites.append(site)
    return proxy, sites[:MAX_SITES]


def read(server):
    http = server.get("/config/apps/http/servers")
    try:
        tls = server.get("/config/apps/tls")
    except CaddyError:
        tls = None
    return http if isinstance(http, dict) else {}, tls


def connect(config):
    proxies, sites, problems = [], [], []
    for server in parse_servers(config):
        try:
            http, tls = read(server)
            proxy, found = sites_of(server, http, tls)
        except CaddyError as exc:
            problems.append(str(exc))
            continue
        proxies.append(proxy)
        sites.extend(found)
    if not proxies:
        raise CaddyError("; ".join(problems) or "no Caddy answered")
    return proxies, sites, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    proxies, sites, problems = connect(config)
    kinds = {}
    for s in sites:
        kinds[s["type"]] = kinds.get(s["type"], 0) + 1
    message = f"Connected to {len(proxies)} Caddy: {len(sites)} site(s)"
    if kinds:
        message += " (" + ", ".join(f"{n} {k}" for k, n in sorted(kinds.items())) + ")"
    if any(p["ip"] is None for p in proxies):
        message += ". Fill in the Caddy host's own address so Netlens can find its device"
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
    """What Caddy answers, as counts (no names, addresses or paths)."""
    try:
        servers = parse_servers(config)
    except (ValueError, CaddyError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for server in servers:
        entry = {"steps": {}}
        report["servers"].append(entry)
        try:
            http, tls = read(server)
            routes = [r for srv in http.values() for r in srv.get("routes") or []]
            handlers = {}
            for r in routes:
                for h in _handlers(r.get("handle")):
                    handlers[str(h.get("handler"))] = handlers.get(str(h.get("handler")), 0) + 1
            entry["steps"]["http"] = {"ok": True, "servers": len(http), "routes": len(routes), "routes_with_host": sum(1 for r in routes if _hosts(r)), "handlers": handlers,
                                      "listen_ports": sorted({a.rsplit(":", 1)[-1] for srv in http.values() for a in srv.get("listen") or []}),
                                      "automatic_https_disabled": sum(1 for srv in http.values() if (srv.get("automatic_https") or {}).get("disable"))}
            entry["steps"]["tls"] = {"ok": tls is not None}
            entry["result"] = {"sites": len(sites_of(server, http, tls)[1])}
        except CaddyError as exc:
            entry["steps"]["http"] = {"ok": False, "error": _problem(exc)}
    return report
