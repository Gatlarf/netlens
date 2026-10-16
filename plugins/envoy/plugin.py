"""Envoy plugin (kind "proxy"): the sites an Envoy publishes.

Talks to Envoy's admin interface, read-only (GET only):

    GET /server_info                       version, state
    GET /config_dump?include_eds           running configuration: listeners, route configurations, clusters (+ their endpoints)
    GET /clusters                          text: `cluster::ip:port::health_flags::healthy` per endpoint

Static configuration (`static_*`) and xDS configuration (`dynamic_*`) are read the same way. A *virtual host* of a route configuration is a site: its
domains, and the upstream of the first route that has a cluster (the cluster's first endpoint); a virtual host that only redirects is a `redirect`
site. A listener with a `tcp_proxy` filter is a `stream` site on the listener's port. The route configuration is attached to the HTTP listeners
that name it; one that is not referenced by any listener is still reported. Envoy knows no certificate expiry. Standard library only.
"""

import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAX_SITES = 3000


class EnvoyError(Exception):
    pass


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


class Admin:
    def __init__(self, url, lan="", verify_tls=True, timeout=20):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "http://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise EnvoyError(f"{url!r} is not an address like http://192.168.0.4:9901")
        self.url, self.timeout, self.id = f"{parts.scheme}://{parts.netloc}", float(timeout), parts.netloc
        self.lan_ip = _ipv4(lan) if lan else None
        if lan and not self.lan_ip:
            raise EnvoyError(f"{lan!r} is not an IPv4 address")
        self.ip = self.lan_ip or _ipv4(parts.hostname)
        self.context = None
        if parts.scheme == "https" and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def get(self, path, as_json=True):
        request = urllib.request.Request(f"{self.url}{path}", headers={"Accept": "application/json"}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                text = response.read().decode("utf-8", "replace")
            return json.loads(text) if as_json else text
        except urllib.error.HTTPError as exc:
            raise EnvoyError(f"{self.id} answered HTTP {exc.code} for {path.split('?')[0]}")
        except urllib.error.URLError as exc:
            raise EnvoyError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise EnvoyError(f"{self.id} did not answer properly (is this Envoy's admin interface?): {exc}")


def parse_admins(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and str(r.get("host") or "").strip()] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one Envoy admin interface")
    return [Admin(str(r["host"]), str(r.get("lan") or "").strip(), config.get("verify_tls", True), config.get("timeout") or 20) for r in items]


def _by_type(dump):
    out = {}
    for item in dump.get("configs") or []:
        out[str(item.get("@type") or "").rsplit(".", 1)[-1]] = item
    return out


def _listeners(section):
    rows = [x.get("listener") for x in section.get("static_listeners") or []]
    rows += [(x.get("active_state") or {}).get("listener") for x in section.get("dynamic_listeners") or []]
    return [r for r in rows if r]


def _route_configs(section):
    rows = [x.get("route_config") for x in section.get("static_route_configs") or []]
    rows += [x.get("route_config") for x in section.get("dynamic_route_configs") or []]
    return [r for r in rows if r]


def _clusters(section):
    rows = [x.get("cluster") for x in section.get("static_clusters") or []]
    rows += [x.get("cluster") for x in section.get("dynamic_active_clusters") or []]
    return {c["name"]: c for c in rows if c and c.get("name")}


def _endpoints(cluster, eds):
    """[(host, port)] of a cluster: its inline load assignment, or the endpoints xDS sent for it."""
    assignment = cluster.get("load_assignment") or eds.get(cluster.get("name")) or eds.get(cluster.get("eds_cluster_config", {}).get("service_name") or "") or {}
    out = []
    for group in assignment.get("endpoints") or []:
        for lb in group.get("lb_endpoints") or []:
            address = ((lb.get("endpoint") or {}).get("address") or {}).get("socket_address") or {}
            if address.get("address"):
                out.append((str(address["address"]), address.get("port_value")))
    return out


def _eds(section):
    rows = [x.get("endpoint_config") for x in section.get("dynamic_endpoint_configs") or []]
    rows += [x.get("endpoint_config") for x in section.get("static_endpoint_configs") or []]
    return {r.get("cluster_name"): r for r in rows if r and r.get("cluster_name")}


def _hcm(chain):
    for f in chain.get("filters") or []:
        cfg = f.get("typed_config") or {}
        if str(f.get("name") or "").endswith("http_connection_manager") or "HttpConnectionManager" in str(cfg.get("@type")):
            return cfg
    return None


def _tcp(chain):
    for f in chain.get("filters") or []:
        cfg = f.get("typed_config") or {}
        if str(f.get("name") or "").endswith("tcp_proxy") or str(cfg.get("@type") or "").endswith(".TcpProxy"):
            return cfg
    return None


def _upstream(site, cluster, clusters, eds):
    cl = clusters.get(cluster)
    if not cl:
        return
    ends = _endpoints(cl, eds)
    if ends:
        host, port = ends[0]
        site["forward_host"] = host
        if port:
            site["forward_port"] = port
        ips = [a for a in (_ipv4(h) for h, _ in ends) if a]
        if ips:
            site["forward_ips"] = list(dict.fromkeys(ips))[:10]
        if (cl.get("transport_socket") or {}).get("name", "").endswith("tls") or cl.get("transport_socket_matches"):
            site["scheme"] = "https"


def _health(text):
    """Number of endpoints Envoy marks as not healthy, from the /clusters text."""
    bad = 0
    for line in text.splitlines():
        parts = line.split("::")
        if len(parts) == 4 and parts[2] == "health_flags" and parts[3].strip() != "healthy":
            bad += 1
    return bad


def read(admin):
    info = admin.get("/server_info")
    dump = _by_type(admin.get("/config_dump?include_eds"))
    listeners = _listeners(dump.get("ListenersConfigDump") or {})
    route_configs = _route_configs(dump.get("RoutesConfigDump") or {})
    clusters = _clusters(dump.get("ClustersConfigDump") or {})
    eds = _eds(dump.get("EndpointsConfigDump") or {})
    proxy = {"id": admin.id, "name": admin.id, "ip": admin.ip, "version": str(info.get("version") or "").split("/")[1] if "/" in str(info.get("version") or "") else str(info.get("version") or "") or None,
             "online": str(info.get("state") or "LIVE") == "LIVE", "warnings": []}
    try:
        bad = _health(admin.get("/clusters", as_json=False))
        if bad:
            proxy["warnings"].append(f"{bad} upstream endpoint(s) are not healthy")
    except EnvoyError:
        pass
    configs = {c.get("name"): c for c in route_configs}
    referenced, sites = set(), []
    for listener in listeners:
        port = ((listener.get("address") or {}).get("socket_address") or {}).get("port_value")
        for chain in listener.get("filter_chains") or []:
            tls = bool(chain.get("transport_socket")) or bool((chain.get("filter_chain_match") or {}).get("server_names"))
            hcm = _hcm(chain)
            if hcm:
                rc = hcm.get("route_config") or configs.get(((hcm.get("rds") or {}).get("route_config_name")))
                if rc:
                    referenced.add(rc.get("name"))
                    sites.extend(_http_sites(admin, rc, clusters, eds, tls, port, listener.get("name")))
                continue
            tcp = _tcp(chain)
            if tcp and tcp.get("cluster"):
                site = {"id": f"{listener.get('name')}:{port}", "proxy_id": admin.id, "type": "stream", "name": str(listener.get("name") or f"port {port}")[:100], "domains": [],
                        "enabled": True, "ssl": tls, "protocols": ["tcp"], "websockets": False}
                if port:
                    site["incoming_port"] = port
                _upstream(site, tcp["cluster"], clusters, eds)
                sites.append(site)
    for rc in route_configs:
        if rc.get("name") not in referenced:
            sites.extend(_http_sites(admin, rc, clusters, eds, False, None, None))
    return proxy, sites[:MAX_SITES]


def _http_sites(admin, rc, clusters, eds, tls, port, listener):
    out = []
    for vh in rc.get("virtual_hosts") or []:
        domains = [d.lower() for d in vh.get("domains") or [] if d and d != "*"]
        name = str(vh.get("name") or (domains[0] if domains else "virtual host"))[:100]
        site = {"id": f"{rc.get('name') or 'routes'}/{vh.get('name') or len(out)}", "proxy_id": admin.id, "type": "proxy", "name": name, "domains": domains, "enabled": True,
                "ssl": tls, "websockets": True}
        if port:
            site["incoming_port"] = port
        routes = vh.get("routes") or []
        target = next((r for r in routes if (r.get("route") or {}).get("cluster")), None) or next((r for r in routes if (r.get("route") or {}).get("weighted_clusters")), None)
        if target and (target["route"].get("cluster") or target["route"].get("weighted_clusters")):
            cluster = target["route"].get("cluster") or ((target["route"]["weighted_clusters"].get("clusters") or [{}])[0].get("name"))
            _upstream(site, cluster, clusters, eds)
        else:
            redirect = next((r.get("redirect") for r in routes if r.get("redirect")), None)
            if redirect:
                site["type"] = "redirect"
                host = redirect.get("host_redirect") or ""
                site["redirect_to"] = (("https://" if redirect.get("https_redirect") or redirect.get("scheme_redirect") == "https" else "http://") + host)[:300] if host else ""
            else:
                site["type"] = "dead"
        if tls:
            site["ssl_forced"] = False
        out.append({k: v for k, v in site.items() if v not in (None, "")} | {"domains": domains, "enabled": True, "ssl": tls})
    return out


def connect(config):
    proxies, sites, problems = [], [], []
    for admin in parse_admins(config):
        try:
            proxy, found = read(admin)
        except EnvoyError as exc:
            problems.append(str(exc))
            continue
        proxies.append(proxy)
        sites.extend(found)
    if not proxies:
        raise EnvoyError("; ".join(problems) or "no Envoy answered")
    return proxies, sites, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    proxies, sites, problems = connect(config)
    kinds = {}
    for s in sites:
        kinds[s["type"]] = kinds.get(s["type"], 0) + 1
    message = f"Connected to {len(proxies)} Envoy ({', '.join(sorted({p['version'] for p in proxies if p.get('version')})) or 'version unknown'}): {len(sites)} site(s)"
    if kinds:
        message += " (" + ", ".join(f"{n} {k}" for k, n in sorted(kinds.items())) + ")"
    if any(p["ip"] is None for p in proxies):
        message += ". Fill in the Envoy host's own address so Netlens can find its device"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    proxies, sites, _ = connect(config)
    return {"proxies": proxies, "sites": sites, "certificates": []}


def _problem(exc, server=None):
    text = re.sub(r"https?://[^\s/]+", "<server>", str(exc))
    if server is not None:
        text = text.replace(server.id, "<server>")
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What Envoy answers, as counts and enumerations (no names, domains, clusters or addresses)."""
    try:
        admins = parse_admins(config)
    except (ValueError, EnvoyError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for admin in admins:
        entry = {"steps": {}}
        report["servers"].append(entry)
        try:
            info = admin.get("/server_info")
            entry["steps"]["server_info"] = {"ok": True, "version": str(info.get("version") or "").split("/")[1] if "/" in str(info.get("version") or "") else "", "state": str(info.get("state") or "")}
            dump = _by_type(admin.get("/config_dump?include_eds"))
            listeners = _listeners(dump.get("ListenersConfigDump") or {})
            kinds = {}
            for l in listeners:
                for chain in l.get("filter_chains") or []:
                    k = "http" if _hcm(chain) else "tcp_proxy" if _tcp(chain) else "other"
                    kinds[k] = kinds.get(k, 0) + 1
            entry["steps"]["config_dump"] = {"ok": True, "sections": sorted(dump), "listeners": len(listeners), "filter_chains": kinds,
                                             "route_configs": len(_route_configs(dump.get("RoutesConfigDump") or {})),
                                             "virtual_hosts": sum(len(r.get("virtual_hosts") or []) for r in _route_configs(dump.get("RoutesConfigDump") or {})),
                                             "clusters": len(_clusters(dump.get("ClustersConfigDump") or {})), "dynamic": any(k.startswith("dynamic") for sec in dump.values() for k in sec)}
            entry["steps"]["clusters"] = {"ok": True, "unhealthy_endpoints": _health(admin.get("/clusters", as_json=False))}
        except EnvoyError as exc:
            entry["steps"]["error"] = {"ok": False, "error": _problem(exc, admin)}
    return report
