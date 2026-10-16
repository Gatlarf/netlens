"""Incus / LXD plugin (kind "hypervisor"): the servers of an Incus (or LXD) installation as hosts, its containers and virtual machines as guests.

Talks to the REST API over HTTPS with a client certificate, read-only (GET only):

    GET /1.0                                          server name, version, addresses, whether it is clustered, and whether this certificate is trusted
    GET /1.0/cluster/members?recursion=1              the members of a cluster (null on a single server)
    GET /1.0/instances?recursion=2&all-projects=true  every instance with config, devices and live state (network addresses, MAC addresses)
    GET /1.0/networks?recursion=1                     which managed networks do NAT (their addresses are internal)

The client certificate and key are pasted into the plugin's settings as PEM text; for the TLS library they are written to a private temporary
file for a moment and removed again. An instance that sits behind a NAT network keeps its internal addresses to itself (they are of no use on
your LAN); one on a bridge, macvlan or physical NIC reports its LAN addresses. Standard library only.
"""

import ipaddress
import json
import os
import re
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request

MAX_INSTANCES = 3000
PEM = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.S)


class IncusError(Exception):
    pass


class AuthRefused(IncusError):
    auth_failed = True


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


def normalize_pem(text, what):
    """PEM text re-wrapped to 64 columns. A settings field may have turned the line breaks into spaces; the base64 body is what matters."""
    m = PEM.search(str(text or ""))
    if not m:
        raise IncusError(f"the {what} must be the full PEM text, from -----BEGIN ... to -----END ...-----")
    body = re.sub(r"\s+", "", m.group(2))
    if not body or not re.fullmatch(r"[A-Za-z0-9+/=]+", body):
        raise IncusError(f"the {what} is not valid PEM text")
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return f"-----BEGIN {m.group(1)}-----\n" + "\n".join(lines) + f"\n-----END {m.group(1)}-----\n"


def make_context(cert, key, verify_tls):
    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    paths = []
    try:
        for text in (cert, key):
            handle, path = tempfile.mkstemp(prefix="netlens-incus-")
            paths.append(path)
            with os.fdopen(handle, "w") as f:
                f.write(text)
        try:
            context.load_cert_chain(paths[0], paths[1])
        except (ssl.SSLError, OSError) as exc:
            raise IncusError(f"the client certificate and key do not fit together or are not valid ({exc.__class__.__name__})")
    finally:
        for path in paths:
            try:
                os.unlink(path)
            except OSError:
                pass
    return context


class Server:
    def __init__(self, url, cert, key, verify_tls=False, timeout=20):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "https://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            raise IncusError(f"{url!r} is not an address like https://192.168.0.20:8443 (Incus needs https)")
        self.url, self.timeout, self.id = f"https://{parts.netloc}", float(timeout), parts.netloc
        self.address = _ipv4(parts.hostname)
        self.context = make_context(normalize_pem(cert, "client certificate"), normalize_pem(key, "client key"), verify_tls)

    def get(self, path, **params):
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        request = urllib.request.Request(f"{self.url}{path}" + (f"?{query}" if query else ""), headers={"Accept": "application/json"}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                data = json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise AuthRefused(f"{self.id} refused the client certificate for {path} (is it in the trust store, and not restricted away from this project?)")
            raise IncusError(f"{self.id} answered HTTP {exc.code} for {path}")
        except urllib.error.URLError as exc:
            raise IncusError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise IncusError(f"{self.id} did not answer properly (is this Incus on an https port?): {exc}")
        if isinstance(data, dict) and data.get("type") == "error":
            raise IncusError(f"{self.id} reported an error for {path}: {str(data.get('error'))[:200]}")
        return data.get("metadata") if isinstance(data, dict) else None


def parse_servers(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "cert", "key"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one Incus server")
    out = []
    for i, r in enumerate(items, 1):
        host = str(r.get("host") or "").strip()
        if not host:
            raise ValueError(f"line {i}: enter the address")
        if not str(r.get("cert") or "").strip() or not str(r.get("key") or "").strip():
            raise ValueError(f"{host}: enter the client certificate and key")
        out.append((host, r["cert"], r["key"]))
    return [Server(h, c, k, config.get("verify_tls", False), config.get("timeout") or 20) for h, c, k in out]


def _memory_mb(text):
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([KMGT]i?B?|B)?\s*", str(text or ""), re.I)
    if not m:
        return None
    unit = (m.group(2) or "B").upper().rstrip("B").rstrip("I") or "B"
    factor = {"B": 1, "K": 1 / 1024, "M": 1, "G": 1024, "T": 1024 * 1024}.get(unit)
    value = float(m.group(1)) * factor / (1 if unit != "B" else 1024 * 1024)
    return int(value) if value >= 1 else None


def _guest(server, host_ids, nat_networks, inst):
    cfg, dev = inst.get("config") or {}, inst.get("expanded_devices") or {}
    state = inst.get("state") or {}
    status = str(inst.get("status") or "unknown").lower()
    macs, ips = [], []
    behind_nat = {name for name, d in dev.items() if d.get("type") == "nic" and (d.get("network") in nat_networks)}
    for name, net in (state.get("network") or {}).items():
        if name == "lo" or net.get("type") == "loopback":
            continue
        if net.get("hwaddr"):
            macs.append(net["hwaddr"])
        if name not in behind_nat:
            ips.extend(a["address"] for a in net.get("addresses") or [] if a.get("family") == "inet" and a.get("scope") == "global" and _ipv4(a.get("address")))
    if not macs:           # a stopped instance has no state; its generated MAC addresses are kept in the config
        macs = [v for k, v in cfg.items() if k.startswith("volatile.") and k.endswith(".hwaddr") and v]
    details = {
        "image": cfg.get("image.description") or "",
        "os": " ".join(x for x in (cfg.get("image.os"), cfg.get("image.release")) if x)[:60],
        "project": inst.get("project") or "",
        "cpus": int(cfg["limits.cpu"]) if str(cfg.get("limits.cpu") or "").isdigit() else None,
        "memory_mb": _memory_mb(cfg.get("limits.memory")),
        "autostart": str(cfg.get("boot.autostart", "")).lower() == "true" or None,
        "network": ", ".join(sorted(n for n, d in dev.items() if d.get("type") == "nic"))[:100],
    }
    guest = {"id": f"{server.id}/{inst.get('project') or 'default'}/{inst.get('name')}", "name": str(inst.get("name"))[:100], "kind": "vm" if inst.get("type") == "virtual-machine" else "container",
             "status": status[:30], "macs": list(dict.fromkeys(macs)), "ips": list(dict.fromkeys(ips)), "details": {k: v for k, v in details.items() if v not in ("", None)}}
    location = inst.get("location")
    if location in host_ids:
        guest["host_id"] = host_ids[location]
    elif len(host_ids) == 1:
        guest["host_id"] = next(iter(host_ids.values()))
    return guest


def read(server):
    info = server.get("/1.0") or {}
    if info.get("auth") != "trusted":
        raise AuthRefused(f"{server.id} does not trust this client certificate yet (auth: {info.get('auth')}): add it with 'incus config trust add-certificate'")
    env = info.get("environment") or {}
    members = server.get("/1.0/cluster/members", recursion=1) if env.get("server_clustered") else None
    hosts, host_ids = [], {}
    if members:
        for m in members:
            ip = _ipv4(urllib.parse.urlsplit(m.get("url") or "").hostname)
            hid = f"{server.id}/{m.get('server_name')}"
            host_ids[m.get("server_name")] = hid
            hosts.append({"id": hid, "name": str(m.get("server_name"))[:100], "ip": ip, "online": str(m.get("status")).lower() == "online"})
    else:
        name = env.get("server_name") or server.id
        ip = server.address
        if ip is None or ip.startswith("127."):
            ip = next((a for a in (_ipv4(x.rsplit(":", 1)[0]) for x in env.get("addresses") or []) if a and not a.startswith(("127.", "172.", "10.", "169.254."))), None)
        hid = f"{server.id}/{name}"
        host_ids[name] = hid
        hosts.append({"id": hid, "name": str(name)[:100], "ip": ip, "online": True})
    nat = set()
    try:
        nat = {n.get("name") for n in server.get("/1.0/networks", recursion=1) or [] if n.get("managed") and str((n.get("config") or {}).get("ipv4.nat", "")).lower() == "true"}
    except IncusError:
        pass
    try:
        instances = server.get("/1.0/instances", recursion=2, **{"all-projects": "true"}) or []
    except AuthRefused:
        raise
    except IncusError:
        instances = server.get("/1.0/instances", recursion=2) or []
    guests = [_guest(server, host_ids, nat, i) for i in instances[:MAX_INSTANCES]]
    return str(env.get("server_version") or ""), hosts, guests


def connect(config):
    versions, hosts, guests, problems = [], [], [], []
    for server in parse_servers(config):
        try:
            version, found_hosts, found = read(server)
        except AuthRefused:
            raise
        except IncusError as exc:
            problems.append(str(exc))
            continue
        versions.append(version)
        hosts.extend(found_hosts)
        guests.extend(found)
    if not versions:
        raise IncusError("; ".join(problems) or "no Incus server answered")
    return versions, hosts, guests, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    versions, hosts, guests, problems = connect(config)
    running = sum(1 for g in guests if g["status"] == "running")
    vms = sum(1 for g in guests if g["kind"] == "vm")
    message = f"Connected to {len(hosts)} server(s) (version {', '.join(sorted({v for v in versions if v})) or 'unknown'}): {len(guests)} instance(s) ({vms} virtual machine(s)), {running} running"
    own = sum(1 for g in guests if g["ips"])
    message += f", {own} with a LAN address" if own else ""
    if any(h["ip"] is None for h in hosts):
        message += ". Some servers have no known address"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    _, hosts, guests, _ = connect(config)
    return {"hosts": hosts, "guests": guests}


def _problem(exc):
    return type(exc).__name__ + ": " + re.sub(r"https?://[^\s/]+", "<server>", str(exc))[:300]


def diagnose(config):
    """What the servers answer, as counts and enumerations (no names, images, addresses or certificates)."""
    try:
        servers = parse_servers(config)
    except (ValueError, IncusError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for server in servers:
        entry = {"steps": {}}
        report["servers"].append(entry)
        try:
            info = server.get("/1.0") or {}
            env = info.get("environment") or {}
            entry["steps"]["server"] = {"ok": True, "auth": info.get("auth"), "version": env.get("server_version"), "clustered": env.get("server_clustered"), "driver": str(env.get("driver"))[:60]}
            data = server.get("/1.0/instances", recursion=2, **{"all-projects": "true"}) or []
            entry["steps"]["instances"] = {"ok": True, "count": len(data), "types": {t: sum(1 for i in data if i.get("type") == t) for t in sorted({str(i.get("type")) for i in data})},
                                           "statuses": {s: sum(1 for i in data if i.get("status") == s) for s in sorted({str(i.get("status")) for i in data})},
                                           "with_network_state": sum(1 for i in data if (i.get("state") or {}).get("network")), "projects": len({i.get("project") for i in data})}
            nets = server.get("/1.0/networks", recursion=1) or []
            entry["steps"]["networks"] = {"ok": True, "count": len(nets), "managed": sum(1 for n in nets if n.get("managed")), "nat": sum(1 for n in nets if str((n.get("config") or {}).get("ipv4.nat", "")).lower() == "true")}
        except AuthRefused:
            raise
        except IncusError as exc:
            entry["steps"]["error"] = {"ok": False, "error": _problem(exc)}
    return report
