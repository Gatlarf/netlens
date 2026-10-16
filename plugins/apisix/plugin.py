"""Apache APISIX plugin (kind "proxy"): the routes an APISIX publishes.

Talks to APISIX's Admin API (GET only, header `X-API-KEY`, the key of the read-only `viewer` role is enough):

    GET /apisix/admin/routes          hosts / host, uris, upstream or upstream_id or service_id, plugins (redirect), status (0 = off)
    GET /apisix/admin/upstreams       nodes ({"ip:port": weight} or [{"host", "port"}]), scheme
    GET /apisix/admin/services        upstream / upstream_id, plugins
    GET /apisix/admin/ssls            snis, cert (PEM; its notAfter gives the expiry), status
    GET /apisix/admin/stream_routes   server_port, upstream  (only when APISIX runs the stream proxy)

A route is a site: its domains are `hosts` (or `host`); the upstream is the route's own, else the shared upstream it names, else its service's. A route
with the `redirect` plugin is a `redirect` site, one without any upstream a `dead` site. The version comes from the `Server: APISIX/x.y.z` header.
A certificate is attached to a site when one of its SNIs (wildcards allowed) matches a domain of the route. Standard library only.
"""

import base64
import fnmatch
import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

MAX_ROWS = 5000


class ApisixError(Exception):
    pass


class AuthRefused(ApisixError):
    auth_failed = True


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


def _tlv(data, pos):
    """(tag, start of content, end of content) of the DER element at pos."""
    tag, length = data[pos], data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    return tag, pos, pos + length


def _validity(pem):
    match = re.search(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", str(pem or ""), re.S)
    if not match:
        return None
    try:
        der = base64.b64decode(re.sub(r"\s+", "", match.group(1)))
        _, pos, _ = _tlv(der, 0)                        # Certificate -> tbsCertificate
        _, pos, _ = _tlv(der, pos)
        tag, _, end = _tlv(der, pos)
        if tag == 0xA0:                                 # optional [0] version
            pos = end
        for _ in range(3):                              # serialNumber, signature, issuer
            _, _, pos = _tlv(der, pos)
        _, pos, _ = _tlv(der, pos)                      # validity SEQUENCE -> notBefore
        _, _, pos = _tlv(der, pos)
        tag, s, e = _tlv(der, pos)                      # notAfter
        text = der[s:e].decode("ascii")
        if tag == 0x17:                                 # UTCTime YYMMDDHHMMSSZ
            year = int(text[:2])
            text = ("20" if year < 50 else "19") + text
        return datetime.strptime(text[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, IndexError, UnicodeDecodeError):
        return None


class Admin:
    def __init__(self, url, key, lan="", verify_tls=True, timeout=20):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "http://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ApisixError(f"{url!r} is not an address like http://192.168.0.4:9180")
        self.url, self.key, self.timeout, self.id = f"{parts.scheme}://{parts.netloc}", key.strip(), float(timeout), parts.netloc
        self.version = None
        self.lan_ip = _ipv4(lan) if lan else None
        if lan and not self.lan_ip:
            raise ApisixError(f"{lan!r} is not an IPv4 address")
        self.ip = self.lan_ip or _ipv4(parts.hostname)
        self.context = None
        if parts.scheme == "https" and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def get(self, name, optional=False):
        """The `value` of every item of /apisix/admin/<name>, each with its `id`."""
        request = urllib.request.Request(f"{self.url}/apisix/admin/{name}", headers={"X-API-KEY": self.key, "Accept": "application/json"}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                self.version = self.version or (re.search(r"APISIX/([0-9][0-9.]*)", response.headers.get("Server", "")) or [None, None])[1]
                data = json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise AuthRefused(f"{self.id} refused the key (wrong, or the role may not read {name})")
            if optional:
                return []
            raise ApisixError(f"{self.id} answered HTTP {exc.code} for {name}")
        except urllib.error.URLError as exc:
            raise ApisixError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise ApisixError(f"{self.id} did not answer properly (is this APISIX's Admin API?): {exc}")
        items = data.get("list") if isinstance(data, dict) else None
        if items is None:
            items = (data.get("node") or {}).get("nodes") if isinstance(data, dict) else None      # APISIX 2.x
        if not isinstance(items, list):
            raise ApisixError(f"{self.id} sent an unexpected answer for {name} (is this APISIX's Admin API?)")
        out = []
        for item in items[:MAX_ROWS]:
            value = dict(item.get("value") or {})
            value.setdefault("id", str(item.get("key") or "").rsplit("/", 1)[-1])
            out.append(value)
        return out


def parse_admins(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "key"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one APISIX Admin API")
    out = []
    for i, r in enumerate(items, 1):
        host = str(r.get("host") or "").strip()
        if not host:
            raise ValueError(f"line {i}: enter the address")
        if not str(r.get("key") or "").strip():
            raise ValueError(f"{host}: enter the viewer key")
        out.append(Admin(host, str(r["key"]), str(r.get("lan") or "").strip(), config.get("verify_tls", True), config.get("timeout") or 20))
    return out


def _nodes(upstream):
    """[(host, port)] of an upstream's nodes."""
    nodes = (upstream or {}).get("nodes")
    out = []
    if isinstance(nodes, dict):
        for key in nodes:
            host, _, port = str(key).rpartition(":")
            out.append((host or str(key), int(port) if port.isdigit() else None))
    elif isinstance(nodes, list):
        for n in nodes:
            if isinstance(n, dict) and n.get("host"):
                out.append((str(n["host"]), n.get("port")))
    return out


def _apply_upstream(site, upstream):
    nodes = _nodes(upstream)
    if not nodes:
        return False
    host, port = nodes[0]
    scheme = str(upstream.get("scheme") or "http").lower()
    site["scheme"] = "https" if scheme in ("https", "grpcs") else "http"
    site["forward_host"] = host.strip("[]")
    site["forward_port"] = port or (443 if site["scheme"] == "https" else 80)
    ips = [a for a in (_ipv4(h) for h, _ in nodes) if a]
    if ips:
        site["forward_ips"] = list(dict.fromkeys(ips))[:10]
    return True


def _sni_match(snis, domain):
    return any(fnmatch.fnmatchcase(domain, s.lower()) for s in snis)


def read(admin):
    routes = admin.get("routes")
    upstreams = {str(u["id"]): u for u in admin.get("upstreams")}
    services = {str(s["id"]): s for s in admin.get("services")}
    ssls = [s for s in admin.get("ssls") if s.get("status", 1) != 0]
    streams = admin.get("stream_routes", optional=True)
    certificates = []
    for s in ssls:
        snis = [str(x).lower() for x in (s.get("snis") or ([s["sni"]] if s.get("sni") else []))]
        certificates.append({"id": f"ssl-{s['id']}", "proxy_id": admin.id, "name": (snis[0] if snis else f"certificate {s['id']}")[:100], "domains": snis[:100], "expires": _validity(s.get("cert")), "in_use": False,
                             "_snis": snis})
    sites = []
    for route in routes:
        service = services.get(str(route.get("service_id") or "")) or {}
        domains = [str(d).lower() for d in (route.get("hosts") or ([route["host"]] if route.get("host") else []))]
        site = {"id": f"route-{route['id']}", "proxy_id": admin.id, "type": "proxy", "name": str(route.get("name") or (domains[0] if domains else f"route {route['id']}"))[:100], "domains": domains[:100],
                "enabled": route.get("status", 1) != 0, "websockets": bool(route.get("enable_websocket"))}
        upstream = route.get("upstream") or upstreams.get(str(route.get("upstream_id") or "")) or service.get("upstream") or upstreams.get(str(service.get("upstream_id") or ""))
        plugins = {**(service.get("plugins") or {}), **(route.get("plugins") or {})}
        redirect = plugins.get("redirect") or {}
        if redirect and not _nodes(upstream):
            site["type"] = "redirect"
            site["redirect_to"] = str(redirect.get("uri") or ("https://$host$request_uri" if redirect.get("http_to_https") else ""))[:300]
        elif not _apply_upstream(site, upstream):
            site["type"] = "dead"
        for cert in certificates:
            if any(_sni_match(cert["_snis"], d) for d in domains):
                site.update(ssl=True, certificate_id=cert["id"], cert_name=cert["name"], cert_expires=cert["expires"])
                cert["in_use"] = True
                break
        sites.append({k: v for k, v in site.items() if v not in (None, "")} | {"domains": site["domains"], "enabled": site["enabled"]})
    for route in streams:
        port = route.get("server_port") or (route.get("match") or {}).get("server_port")
        site = {"id": f"stream-{route['id']}", "proxy_id": admin.id, "type": "stream", "name": str(route.get("name") or f"stream {port or route['id']}")[:100], "domains": [], "enabled": route.get("status", 1) != 0, "protocols": ["tcp"]}
        if port:
            site["incoming_port"] = port
        upstream = route.get("upstream") or upstreams.get(str(route.get("upstream_id") or "")) or {}
        _apply_upstream(site, upstream)
        site.pop("scheme", None)
        sites.append(site)
    for cert in certificates:
        cert.pop("_snis")
    proxy = {"id": admin.id, "name": admin.id, "ip": admin.ip, "version": admin.version, "warnings": []}
    return proxy, [{k: v for k, v in c.items() if v is not None} for c in certificates], sites


def connect(config):
    proxies, certificates, sites, problems = [], [], [], []
    for admin in parse_admins(config):
        try:
            proxy, certs, found = read(admin)
        except AuthRefused:
            raise
        except ApisixError as exc:
            problems.append(str(exc))
            continue
        proxies.append(proxy)
        certificates.extend(certs)
        sites.extend(found)
    if not proxies:
        raise ApisixError("; ".join(problems) or "no APISIX answered")
    return proxies, certificates, sites, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    proxies, certificates, sites, problems = connect(config)
    kinds = {}
    for s in sites:
        kinds[s["type"]] = kinds.get(s["type"], 0) + 1
    message = f"Connected to {len(proxies)} APISIX ({', '.join(sorted({p['version'] for p in proxies if p.get('version')})) or 'version unknown'}): {len(sites)} route(s)"
    if kinds:
        message += " (" + ", ".join(f"{n} {k}" for k, n in sorted(kinds.items())) + ")"
    message += f", {len(certificates)} certificate(s)"
    if any(p["ip"] is None for p in proxies):
        message += ". Fill in the APISIX host's own address so Netlens can find its device"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    proxies, certificates, sites, _ = connect(config)
    return {"proxies": proxies, "sites": sites, "certificates": certificates}


def _problem(exc, server=None):
    text = re.sub(r"https?://[^\s/]+", "<server>", str(exc))
    if server is not None:
        text = text.replace(server.id, "<server>")
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What APISIX answers, as counts and enumerations (no names, hosts, keys or addresses)."""
    try:
        admins = parse_admins(config)
    except (ValueError, ApisixError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for admin in admins:
        entry = {"steps": {}}
        report["servers"].append(entry)
        for name in ("routes", "upstreams", "services", "ssls", "stream_routes"):
            try:
                rows = admin.get(name, optional=(name == "stream_routes"))
                info = {"ok": True, "count": len(rows), "fields": sorted({k for r in rows[:50] for k in r})[:40]}
                if name == "routes":
                    info.update(with_hosts=sum(1 for r in rows if r.get("hosts") or r.get("host")), with_upstream_id=sum(1 for r in rows if r.get("upstream_id")), with_service=sum(1 for r in rows if r.get("service_id")),
                                disabled=sum(1 for r in rows if r.get("status") == 0), redirects=sum(1 for r in rows if "redirect" in (r.get("plugins") or {})))
                if name == "ssls":
                    info.update(readable_expiry=sum(1 for r in rows if _validity(r.get("cert"))))
                entry["steps"][name] = info
            except AuthRefused:
                raise
            except ApisixError as exc:
                entry["steps"][name] = {"ok": False, "error": _problem(exc, admin)}
        entry["steps"]["version"] = admin.version or ""
    return report
