"""Portainer plugin (kind "hypervisor"): the Docker environments a Portainer manages as hosts, their containers as guests.

Talks to the Portainer API with an access token (header X-API-Key), read-only (GET only):

    GET /api/endpoints                              the environments: Id, Name, Type, URL, Status
    GET /api/endpoints/<id>/docker/info             host name and version      } Portainer forwards these
    GET /api/endpoints/<id>/docker/networks         bridge / macvlan / ...     } to the environment's
    GET /api/endpoints/<id>/docker/containers/json  the containers             } Docker Engine API
    GET /api/endpoints/<id>/docker/containers/<c>/json   health, restarts, start time

Environment types: 1 Docker (local socket or tcp), 2 Docker through a Portainer agent, 4 Docker through an Edge agent. Types 3 (Azure) and
5, 6, 7 (Kubernetes) are skipped. A stopped environment (Status 2) is reported as an offline host. The mapping of a container to a guest is
the same as in the Docker plugin. Standard library only.
"""

import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAX_CONTAINERS = 1000
DOCKER_TYPES = (1, 2, 4)
LAN_DRIVERS = ("macvlan", "ipvlan")
ALL_INTERFACES = ("", "0.0.0.0", "::", "[::]")


class PortainerError(Exception):
    pass


class AuthRefused(PortainerError):
    auth_failed = True


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


class Server:
    def __init__(self, url, api_key, lan="", verify_tls=False, timeout=20):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "https://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise PortainerError(f"{url!r} is not an address like https://192.168.0.5:9443")
        self.url, self.api_key, self.timeout = f"{parts.scheme}://{parts.netloc}", api_key, float(timeout)
        self.id = parts.netloc
        self.lan_ip = _ipv4(lan) if lan else None
        if lan and not self.lan_ip:
            raise PortainerError(f"{lan!r} is not an IPv4 address")
        self.address = _ipv4(parts.hostname)
        self.context = None
        if parts.scheme == "https" and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def get(self, path, **params):
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        request = urllib.request.Request(f"{self.url}{path}" + (f"?{query}" if query else ""), headers={"X-API-Key": self.api_key, "Accept": "application/json"}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                return json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403) and path == "/api/endpoints":
                raise AuthRefused(f"{self.id} refused the access token (wrong, revoked, or the user may not list environments)")
            raise PortainerError(f"{self.id} answered HTTP {exc.code} for {path}")
        except urllib.error.URLError as exc:
            raise PortainerError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise PortainerError(f"{self.id} did not answer properly: {exc}")

    def environments(self):
        rows = self.get("/api/endpoints")
        if not isinstance(rows, list):
            raise PortainerError(f"{self.id} did not return a list of environments (is this Portainer?)")
        return rows


def parse_servers(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "api_key"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one Portainer")
    out = []
    for i, r in enumerate(items, 1):
        url, key = str(r.get("host") or "").strip(), str(r.get("api_key") or "").strip()
        if not url:
            raise ValueError(f"server {i}: enter its address")
        if not key:
            raise ValueError(f"{url}: enter an access token")
        out.append(Server(url, key, str(r.get("lan") or "").strip(), config.get("verify_tls", False), config.get("timeout") or 20))
    return out


# ----------------------------------------------------------------------------- containers (same mapping as the Docker plugin)
def _name(container):
    names = container.get("Names") or []
    return (names[0] if names else container.get("Id", "")[:12]).lstrip("/")


def _ports(container):
    out, exposed = [], False
    for p in container.get("Ports") or []:
        ip = str(p.get("IP") or "")
        out.append({"container_port": p.get("PrivatePort"), "host_port": p.get("PublicPort"), "proto": p.get("Type") or "tcp", "bind": ip})
        if p.get("PublicPort") and ip in ALL_INTERFACES:
            exposed = True
    seen, unique = set(), []
    for e in out:     # Docker lists a published port once for IPv4 and once for IPv6
        key = (e["container_port"], e["host_port"], e["proto"], e["bind"] if e["bind"] not in ("0.0.0.0", "::") else "all")
        if key not in seen:
            seen.add(key)
            unique.append(e)
    return unique, exposed


def to_guest(host_id, container, inspect, drivers):
    state = str(container.get("State") or "unknown").lower()
    networks = (container.get("NetworkSettings") or {}).get("Networks") or {}
    mode = (container.get("HostConfig") or {}).get("NetworkMode") or ""
    ips, macs, names, driver = [], [], [], ""
    for net_name, net in networks.items():
        names.append(net_name)
        kind = drivers.get(net.get("NetworkID")) or drivers.get(net_name) or ""
        driver = driver or kind
        if kind in LAN_DRIVERS:
            ip = _ipv4(net.get("IPAddress"))
            if ip:
                ips.append(ip)
            if kind == "macvlan" and net.get("MacAddress"):
                macs.append(net["MacAddress"])
    if mode == "host":
        driver, names = "host", ["host"]
    labels = container.get("Labels") or {}
    ports, exposed = _ports(container)
    inspected = (inspect or {}).get("State") or {}
    details = {
        "image": container.get("Image") or "",
        "project": labels.get("com.docker.compose.project") or "",
        "service": labels.get("com.docker.compose.service") or "",
        "network": ", ".join(names),
        "network_driver": driver,
        "health": (inspected.get("Health") or {}).get("Status") or "",
        "restarts": (inspect or {}).get("RestartCount"),
        "restarting": bool(inspected.get("Restarting")),
        "started": inspected.get("StartedAt") if state == "running" else "",
        "exposed": exposed,
    }
    if state == "exited" and inspected.get("ExitCode") is not None:
        details["exit_code"] = inspected["ExitCode"]
    if ports:
        details["ports"] = ports
    status = "restarting" if details["restarting"] else state
    return {"id": f"{host_id}/{_name(container)}", "name": _name(container), "kind": "container", "host_id": host_id, "status": status[:30],
            "macs": macs, "ips": ips, "details": {k: v for k, v in details.items() if v not in ("", None)}}


# ----------------------------------------------------------------------------- environments
def _host_ip(server, env):
    """The network address of the machine behind an environment, when it is known."""
    url = str(env.get("URL") or "")
    if url.startswith(("unix://", "npipe://")) or not url:
        if env.get("Type") == 4:
            return None                      # an Edge agent calls home; Portainer does not know where it is
        return server.lan_ip or server.address
    parts = urllib.parse.urlsplit(url if "://" in url else "tcp://" + url)
    ip = _ipv4(parts.hostname)
    if ip and ip.startswith("127."):
        return server.lan_ip or server.address
    return ip


def read_environment(server, env):
    base = f"/api/endpoints/{env['Id']}/docker"
    host_id = f"{server.id}/{env['Id']}"
    entry = {"id": host_id, "name": str(env.get("Name") or host_id)[:100], "ip": _host_ip(server, env), "online": env.get("Status") == 1}
    if not entry["online"]:
        return entry, []
    info = server.get(f"{base}/info")
    entry["name"] = str(info.get("Name") or entry["name"])[:100]
    drivers = {}
    for net in server.get(f"{base}/networks") or []:
        drivers[net.get("Id")] = net.get("Driver") or ""
        drivers[net.get("Name")] = net.get("Driver") or ""
    guests = []
    for c in (server.get(f"{base}/containers/json", all="1") or [])[:MAX_CONTAINERS]:
        try:
            inspect = server.get(f"{base}/containers/{c['Id']}/json")
        except PortainerError:
            inspect = None
        guests.append(to_guest(host_id, c, inspect, drivers))
    return entry, guests


def connect(config):
    hosts, guests, problems, skipped = [], [], [], 0
    for server in parse_servers(config):
        try:
            envs = server.environments()
        except AuthRefused:
            raise
        except PortainerError as exc:
            problems.append(str(exc))
            continue
        for env in envs:
            if env.get("Type") not in DOCKER_TYPES:
                skipped += 1
                continue
            try:
                entry, found = read_environment(server, env)
            except PortainerError as exc:
                problems.append(f"{env.get('Name')}: {exc}")
                hosts.append({"id": f"{server.id}/{env['Id']}", "name": str(env.get("Name") or env["Id"])[:100], "ip": _host_ip(server, env), "online": False})
                continue
            hosts.append(entry)
            guests.extend(found)
    if not hosts:
        raise PortainerError("; ".join(problems) or "Portainer manages no Docker environment")
    return hosts, guests, problems, skipped


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    hosts, guests, problems, skipped = connect(config)
    running = sum(1 for g in guests if g["status"] == "running")
    message = f"Connected: {len(hosts)} Docker environment(s), {len(guests)} container(s), {running} running"
    if skipped:
        message += f". {skipped} Kubernetes or Azure environment(s) skipped"
    offline = sum(1 for h in hosts if not h["online"])
    if offline:
        message += f". {offline} environment(s) are down in Portainer"
    if any(h["ip"] is None and h["online"] for h in hosts):
        message += ". Some environments have no known network address, so Netlens cannot place them on its map"
    if problems:
        message += ". Problems: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    hosts, guests, _, _ = connect(config)
    return {"hosts": hosts, "guests": guests}


def _problem(exc):
    return type(exc).__name__ + ": " + re.sub(r"https?://[^\s/]+", "<server>", str(exc))[:300]


def diagnose(config):
    """What Portainer answers, as counts and yes/no (no names, addresses, labels or tokens)."""
    try:
        servers = parse_servers(config)
    except (ValueError, PortainerError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for server in servers:
        entry = {"environments": [], "steps": {}}
        report["servers"].append(entry)
        try:
            envs = server.environments()
        except AuthRefused:
            raise
        except PortainerError as exc:
            entry["error"] = _problem(exc)
            continue
        entry["steps"]["environments"] = {"ok": True, "count": len(envs), "types": {str(t): sum(1 for e in envs if e.get("Type") == t) for t in sorted({e.get("Type") for e in envs}, key=str)},
                                          "fields": sorted({k for e in envs for k in e})[:40]}
        for env in envs[:20]:
            item = {"type": env.get("Type"), "status": env.get("Status"), "url_scheme": str(env.get("URL") or "").split("://")[0] if "://" in str(env.get("URL") or "") else "none", "steps": {}}
            entry["environments"].append(item)
            if env.get("Type") not in DOCKER_TYPES or env.get("Status") != 1:
                continue
            base = f"/api/endpoints/{env['Id']}/docker"
            for step, path, params in (("info", "/info", {}), ("networks", "/networks", {}), ("containers", "/containers/json", {"all": "1"})):
                try:
                    data = server.get(base + path, **params)
                    if step == "info":
                        item["steps"][step] = {"ok": True, "server_version": str(data.get("ServerVersion") or ""), "containers": data.get("Containers"), "running": data.get("ContainersRunning")}
                    elif step == "networks":
                        item["steps"][step] = {"ok": True, "count": len(data), "drivers": {d: sum(1 for n in data if (n.get("Driver") or "?") == d) for d in sorted({n.get("Driver") or "?" for n in data})}}
                    else:
                        item["steps"][step] = {"ok": True, "count": len(data), "states": {s: sum(1 for c in data if (c.get("State") or "?") == s) for s in sorted({c.get("State") or "?" for c in data})},
                                               "with_ports": sum(1 for c in data if c.get("Ports"))}
                except PortainerError as exc:
                    item["steps"][step] = {"ok": False, "error": _problem(exc)}
    return report
