"""Netlens plugin for Nginx Proxy Manager (kind "proxy").

Reads, with the Nginx Proxy Manager API (version 2.x), every proxy host, redirection host, stream and 404 host with the
certificates they use. Nothing is ever changed: the plugin logs in (POST /api/tokens) and then only does GET requests.

    POST /api/tokens                   e-mail address and password -> a token for 24 hours
    GET  /api/                         the version
    GET  /api/users/me?expand=permissions   what this user may see (Item Visibility) and do
    GET  /api/nginx/proxy-hosts        domains, where they forward to, certificate, on/off
    GET  /api/nginx/redirection-hosts  GET /api/nginx/streams  GET /api/nginx/dead-hosts
    GET  /api/nginx/certificates       name, provider, expiry
    GET  /api/nginx/access-lists       names of the access lists

Only the Python standard library is used.
"""

import ipaddress
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait

LOCAL_NAMES = ("localhost", "host.docker.internal", "gateway.docker.internal")
MAX_NAMES = 200


class NpmError(Exception):
    pass


class AuthRefused(NpmError):
    auth_failed = True      # the login was refused: Netlens stops asking until the settings are saved again


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


def _clean_url(text):
    url = str(text or "").strip().rstrip("/")
    if "://" not in url:
        url = "http://" + url
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise NpmError(f"{text!r} is not an address like http://192.168.0.2:81")
    return f"{parts.scheme}://{parts.netloc}"


class Server:
    def __init__(self, url, email, password, lan="", verify_tls=True, timeout=15):
        self.url = _clean_url(url)
        self.email, self.password = str(email or "").strip(), str(password or "")
        self.timeout = float(timeout or 15)
        self.lan_ip = _ipv4(lan) if str(lan or "").strip() else None
        if str(lan or "").strip() and not self.lan_ip:
            raise NpmError(f"{lan!r} (the proxy's own address) is not an IPv4 address")
        self.context = None
        if self.url.startswith("https://") and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE
        self.id = urllib.parse.urlsplit(self.url).netloc
        self.address = urllib.parse.urlsplit(self.url).hostname
        self.token = None

    def _request(self, path, body=None, auth=True):
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if auth and self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request(self.url + path, data=data, headers=headers, method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                return json.loads(response.read().decode("utf-8", "replace") or "null")
        except urllib.error.HTTPError as exc:
            message = ""
            try:
                message = (json.loads(exc.read().decode("utf-8", "replace")).get("error") or {}).get("message") or ""
            except (ValueError, AttributeError):
                pass
            if path == "/api/tokens" and (exc.code == 401 or exc.code == 400 and "invalid" in message.lower()):     # 2.15 answers a wrong password with 400
                raise AuthRefused(f"{self.id} refused the login ({message or 'wrong e-mail address or password'})")
            if exc.code in (401, 403):
                raise AuthRefused(f"{self.id} refused {path} ({message or 'HTTP %d' % exc.code}): check what this user may see")
            raise NpmError(f"{self.id} answered HTTP {exc.code} for {path}" + (f": {message}" if message else ""))
        except urllib.error.URLError as exc:
            raise NpmError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise NpmError(f"{self.id} did not answer properly: {exc}")

    def login(self):
        if not self.email or not self.password:
            raise AuthRefused(f"{self.id}: enter the e-mail address and the password of the Netlens user")
        answer = self._request("/api/tokens", {"identity": self.email, "secret": self.password}, auth=False)
        if isinstance(answer, dict) and answer.get("requires_2fa"):
            raise AuthRefused(f"{self.id}: this user has two-factor authentication on, which the API login cannot answer. Use a separate user without it")
        if not isinstance(answer, dict) or not answer.get("token"):
            raise NpmError(f"{self.id} did not return a login token")
        self.token = answer["token"]

    def get(self, path):
        if self.token is None:
            self.login()
        return self._request(path)


def parse_servers(config):
    rows = config.get("servers")
    out = []
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, dict) and str(row.get("host") or "").strip():
            out.append(Server(row["host"], row.get("email"), row.get("password"), row.get("lan"), config.get("verify_tls", True), config.get("timeout") or 15))
    if not out:
        raise ValueError("enter the address, e-mail address and password of your Nginx Proxy Manager")
    return out


# ----------------------------------------------------------------------------- reading
def _list(server, path):
    data = server.get(path)
    return data if isinstance(data, list) else []


def _stamp(value):
    """'2026-12-31 23:59:59' / '2026-12-31T23:59:59.000Z' -> '2026-12-31T23:59:59Z' (NPM keeps UTC)."""
    m = re.match(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})", str(value or ""))
    return f"{m.group(1)}T{m.group(2)}Z" if m else None


def _id(value):
    return str(value) if value not in (None, "", 0, "0") else None


def proxy_ip(server):
    if server.lan_ip:
        return server.lan_ip
    ip = _ipv4(server.address)
    if ip and ip.startswith("127."):
        return None
    if ip:
        return ip
    try:
        return _ipv4(socket.gethostbyname(server.address))
    except OSError:
        return None


def permission_warnings(me):
    """What is wrong with the account, so the user can fix it in NPM (only a hint: the plugin works either way)."""
    warnings = []
    if not isinstance(me, dict):
        return warnings
    perms = me.get("permissions") if isinstance(me.get("permissions"), dict) else {}
    roles = me.get("roles") if isinstance(me.get("roles"), list) else []
    if "admin" in roles:
        warnings.append("This user is an administrator, which can change everything. Create a user with View Only permissions for Netlens.")
    elif perms.get("visibility") == "user":
        warnings.append("This user only sees the items it created itself, so most sites are missing. In Nginx Proxy Manager open Users, the user's Permissions, and set Item Visibility to All Items.")
    if "admin" not in roles and any(v == "manage" for k, v in perms.items() if k != "visibility"):
        warnings.append("This user is allowed to change things. In its Permissions set every item to View Only: Netlens only reads.")
    return warnings


def read_server(server, resolve=True):
    """(proxy entry, sites, certificates) of one Nginx Proxy Manager."""
    version = ""
    try:
        v = (server.get("/api/") or {}).get("version") or {}
        version = ".".join(str(v[k]) for k in ("major", "minor", "revision") if k in v)
    except NpmError:
        pass
    try:
        me = server.get("/api/users/me?expand=permissions")
    except NpmError:
        me = None
    warnings = permission_warnings(me)
    certs_raw, lists_raw = [], []
    try:
        certs_raw = _list(server, "/api/nginx/certificates")
    except NpmError as exc:
        warnings.append(f"The certificates could not be read ({exc}); expiry dates are missing.")
    try:
        lists_raw = _list(server, "/api/nginx/access-lists")
    except NpmError:
        pass
    access = {_id(a.get("id")): str(a.get("name") or "") for a in lists_raw if isinstance(a, dict)}
    certs = {}
    for c in certs_raw:
        if isinstance(c, dict) and _id(c.get("id")):
            certs[_id(c["id"])] = {"id": _id(c["id"]), "proxy_id": server.id, "name": str(c.get("nice_name") or "")[:200], "provider": str(c.get("provider") or "")[:40],
                                   "domains": [str(d) for d in (c.get("domain_names") or [])][:100], "expires": _stamp(c.get("expires_on")), "in_use": False}
    sites = []

    def common(kind, item, prefix):
        cert = certs.get(_id(item.get("certificate_id")))
        if cert:
            cert["in_use"] = True
        return {
            "id": f"{prefix}-{item.get('id')}", "proxy_id": server.id, "type": kind, "enabled": bool(item.get("enabled", True)),
            "domains": [str(d) for d in (item.get("domain_names") or [])][:100],
            "ssl": cert is not None, "ssl_forced": bool(item.get("ssl_forced")), "certificate_id": _id(item.get("certificate_id")),
            "cert_name": cert["name"] if cert else "", "cert_provider": cert["provider"] if cert else "", "cert_expires": cert["expires"] if cert else None,
        }

    for kind, path, prefix in (("proxy", "/api/nginx/proxy-hosts", "proxy"), ("redirect", "/api/nginx/redirection-hosts", "redirect"),
                               ("stream", "/api/nginx/streams", "stream"), ("dead", "/api/nginx/dead-hosts", "dead")):
        try:
            items = _list(server, path)
        except NpmError as exc:
            if kind == "proxy":
                raise
            warnings.append(f"{path.rsplit('/', 1)[1]} could not be read ({exc}).")
            continue
        for item in items:
            if not isinstance(item, dict) or item.get("id") is None:
                continue
            site = common(kind, item, prefix)
            if kind == "proxy":
                site.update({"scheme": str(item.get("forward_scheme") or "http"), "forward_host": str(item.get("forward_host") or ""), "forward_port": item.get("forward_port"),
                             "websockets": bool(item.get("allow_websocket_upgrade")), "access_list": access.get(_id(item.get("access_list_id")), "")})
            elif kind == "redirect":
                target = str(item.get("forward_domain_name") or "")
                site.update({"scheme": str(item.get("forward_scheme") or "http") if str(item.get("forward_scheme")) in ("http", "https") else "http", "forward_host": target,
                             "redirect_to": f"{item.get('forward_scheme') or ''}://{target}".lstrip(":/") + f" ({item.get('forward_http_code') or 301})"})
            elif kind == "stream":
                protocols = [p for p, on in (("tcp", item.get("tcp_forwarding")), ("udp", item.get("udp_forwarding"))) if on]
                site.update({"forward_host": str(item.get("forwarding_host") or ""), "forward_port": item.get("forwarding_port"), "incoming_port": item.get("incoming_port"), "protocols": protocols})
            sites.append(site)
    if resolve:
        _resolve_names(sites)
    entry = {"id": server.id, "name": server.address, "ip": proxy_ip(server), "version": version, "online": True, "warnings": warnings}
    return entry, sites, list(certs.values())


def _resolve_names(sites):
    """The IPv4 addresses of the host names sites forward to (so a site can be tied to the device that has that address)."""
    wanted = sorted({s["forward_host"].lower() for s in sites if s["type"] in ("proxy", "stream") and s.get("forward_host")
                     if not _ipv4(s["forward_host"]) and s["forward_host"].lower() not in LOCAL_NAMES})[:MAX_NAMES]
    if not wanted:
        return
    found = {}

    def look(name):
        try:
            found[name] = sorted({a[4][0] for a in socket.getaddrinfo(name, None, socket.AF_INET)})[:5]
        except OSError:
            found[name] = []

    pool = ThreadPoolExecutor(max_workers=8)
    wait([pool.submit(look, n) for n in wanted], timeout=8)
    pool.shutdown(wait=False, cancel_futures=True)
    for s in sites:
        if (s.get("forward_host") or "").lower() in found:
            s["forward_ips"] = found[s["forward_host"].lower()]


def connect(config):
    proxies, sites, certificates, problems = [], [], [], []
    for server in parse_servers(config):
        try:
            entry, found, certs = read_server(server, config.get("resolve_names", True))
        except AuthRefused:
            raise
        except NpmError as exc:
            problems.append(str(exc))
            continue
        proxies.append(entry)
        sites.extend(found)
        certificates.extend(certs)
    if not proxies:
        raise NpmError("; ".join(problems) or "no Nginx Proxy Manager answered")
    return proxies, sites, certificates, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    proxies, sites, certificates, problems = connect(config)
    counts = {}
    for s in sites:
        counts[s["type"]] = counts.get(s["type"], 0) + 1
    names = {"proxy": "proxy host", "redirect": "redirection", "stream": "stream", "dead": "404 host"}
    text = ", ".join(f"{n} {names[k]}{'s' if n != 1 else ''}" for k, n in counts.items()) or "no sites"
    message = f"Connected to {len(proxies)} Nginx Proxy Manager ({', '.join(p['version'] for p in proxies if p['version']) or 'version unknown'}): {text}, {len(certificates)} certificate(s)"
    if any(p["ip"] is None for p in proxies):
        message += ". Fill in 'Proxy\'s own address' so Netlens can find the device it runs on"
    warnings = [w for p in proxies for w in p["warnings"]]
    if warnings:
        message += ". Note: " + " ".join(warnings)
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    proxies, sites, certificates, _ = connect(config)
    return {"proxies": proxies, "sites": sites, "certificates": certificates}


def _problem(exc):
    return type(exc).__name__ + ": " + re.sub(r"https?://[^\s/]+", "<host>", str(exc))[:300]


def diagnose(config):
    """What the proxy answers, as counts and yes/no (no domains, names or addresses)."""
    try:
        servers = parse_servers(config)
    except (ValueError, NpmError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for server in servers:
        entry = {"steps": {}}
        report["servers"].append(entry)
        try:
            server.login()
            entry["steps"]["login"] = {"ok": True}
        except NpmError as exc:
            entry["steps"]["login"] = {"ok": False, "error": _problem(exc)}
            continue
        try:
            me = server.get("/api/users/me?expand=permissions")
            perms = me.get("permissions") if isinstance(me.get("permissions"), dict) else {}
            entry["steps"]["user"] = {"ok": True, "roles": [str(r) for r in me.get("roles") or []], "visibility": perms.get("visibility"),
                                      "permissions": sorted({str(v) for k, v in perms.items() if k != "visibility"})}
        except NpmError as exc:
            entry["steps"]["user"] = {"ok": False, "error": _problem(exc)}
        for step, path in (("proxy_hosts", "/api/nginx/proxy-hosts"), ("redirection_hosts", "/api/nginx/redirection-hosts"), ("streams", "/api/nginx/streams"),
                           ("dead_hosts", "/api/nginx/dead-hosts"), ("certificates", "/api/nginx/certificates"), ("access_lists", "/api/nginx/access-lists")):
            try:
                data = _list(server, path)
                info = {"ok": True, "count": len(data)}
                if step == "proxy_hosts":
                    info["enabled"] = sum(1 for d in data if isinstance(d, dict) and d.get("enabled"))
                    info["forward_to_ip"] = sum(1 for d in data if isinstance(d, dict) and _ipv4(d.get("forward_host")))
                    info["with_certificate"] = sum(1 for d in data if isinstance(d, dict) and _id(d.get("certificate_id")))
                entry["steps"][step] = info
            except NpmError as exc:
                entry["steps"][step] = {"ok": False, "error": _problem(exc)}
    return report
