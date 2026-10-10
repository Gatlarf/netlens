"""Docker plugin (kind "hypervisor"): Docker hosts as hosts and their containers as guests.

Talks to the Docker Engine API, read-only (it only sends GET requests):

    GET /info                  host name and version
    GET /networks              which network is a bridge, macvlan, ipvlan ...
    GET /containers/json?all=1 every container with its published ports and addresses
    GET /containers/<id>/json  health, restart count, start time

Docker's API controls the whole host, so it should be reached through a read-only socket proxy
(tecnativa/docker-socket-proxy with CONTAINERS=1, NETWORKS=1, INFO=1 and POST=0), see the README.

A container on a bridge network only has an address inside the host, so it is shown as a guest of its host (with the
ports it publishes). A container on a macvlan or ipvlan network has its own address on the LAN: the plugin reports that
address (and the MAC of a macvlan), so Netlens matches the container to the device its scans found. Standard library only.
"""

import ipaddress
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAX_CONTAINERS = 1000
LAN_DRIVERS = ("macvlan", "ipvlan")
ALL_INTERFACES = ("", "0.0.0.0", "::", "[::]")


class DockerError(Exception):
    pass


def _clean_url(text):
    url = text.strip().rstrip("/")
    if "://" not in url:
        url = "http://" + url
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise DockerError(f"{text!r} is not an address like http://192.168.0.2:2375")
    return f"{parts.scheme}://{parts.netloc}"


class Host:
    def __init__(self, url, verify_tls=True, timeout=15):
        self.url = _clean_url(url)
        self.timeout = float(timeout)
        self.context = None
        if self.url.startswith("https://") and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE
        self.id = urllib.parse.urlsplit(self.url).netloc
        self.address = urllib.parse.urlsplit(self.url).hostname

    def get(self, path, **params):
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        request = urllib.request.Request(f"{self.url}{path}" + (f"?{query}" if query else ""), headers={"Accept": "application/json"}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                return json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                raise DockerError(f"{self.id} refused {path}: the socket proxy does not allow it (set CONTAINERS=1, NETWORKS=1 and INFO=1 on the proxy)")
            raise DockerError(f"{self.id} answered HTTP {exc.code} for {path}")
        except urllib.error.URLError as exc:
            raise DockerError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise DockerError(f"{self.id} did not answer properly: {exc}")


def parse_hosts(config):
    urls = [u for u in re.split(r"[,;\s]+", str(config.get("hosts") or "").strip()) if u]
    if not urls:
        raise ValueError("enter the address of at least one Docker host (its socket proxy)")
    return [Host(u, config.get("verify_tls", True), config.get("timeout") or 15) for u in urls]


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


def _host_ip(host):
    ip = _ipv4(host.address)
    if ip:
        return ip
    try:
        return _ipv4(socket.gethostbyname(host.address))
    except OSError:
        return None


def _name(container):
    names = container.get("Names") or []
    return (names[0] if names else container.get("Id", "")[:12]).lstrip("/")


def _ports(container):
    out, exposed = [], False
    for p in container.get("Ports") or []:
        ip = str(p.get("IP") or "")
        entry = {"container_port": p.get("PrivatePort"), "host_port": p.get("PublicPort"), "proto": p.get("Type") or "tcp", "bind": ip}
        out.append(entry)
        if p.get("PublicPort") and ip in ALL_INTERFACES:
            exposed = True
    seen, unique = set(), []
    for e in out:     # Docker lists a published port once for IPv4 and once for IPv6
        key = (e["container_port"], e["host_port"], e["proto"], e["bind"] if e["bind"] not in ("0.0.0.0", "::") else "all")
        if key not in seen:
            seen.add(key)
            unique.append(e)
    return unique, exposed


def to_guest(host, container, inspect, drivers):
    """One container as a Netlens guest (see the hypervisor contract)."""
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
    inspected_state = (inspect or {}).get("State") or {}
    details = {
        "image": container.get("Image") or "",
        "project": labels.get("com.docker.compose.project") or "",
        "service": labels.get("com.docker.compose.service") or "",
        "network": ", ".join(names),
        "network_driver": driver,
        "health": (inspected_state.get("Health") or {}).get("Status") or "",
        "restarts": (inspect or {}).get("RestartCount"),
        "restarting": bool(inspected_state.get("Restarting")),
        "started": inspected_state.get("StartedAt") if state == "running" else "",
        "exposed": exposed,
    }
    if state == "exited" and inspected_state.get("ExitCode") is not None:
        details["exit_code"] = inspected_state["ExitCode"]
    if ports:
        details["ports"] = ports
    status = "restarting" if details["restarting"] else state
    return {
        "id": f"{host.id}/{_name(container)}",
        "name": _name(container),
        "kind": "container",
        "host_id": host.id,
        "status": status[:30],
        "macs": macs,
        "ips": ips,
        "details": {k: v for k, v in details.items() if v not in ("", None)},
    }


def read_host(host):
    info = host.get("/info")
    drivers = {}
    for net in host.get("/networks") or []:
        drivers[net.get("Id")] = net.get("Driver") or ""
        drivers[net.get("Name")] = net.get("Driver") or ""
    containers = host.get("/containers/json", all="1") or []
    guests = []
    for c in containers[:MAX_CONTAINERS]:
        try:
            inspect = host.get(f"/containers/{c['Id']}/json")
        except DockerError:
            inspect = None      # the list is still useful without health and restart count
        guests.append(to_guest(host, c, inspect, drivers))
    entry = {"id": host.id, "name": str(info.get("Name") or host.id)[:100], "ip": _host_ip(host), "online": True}
    return entry, guests, info


def connect(config):
    hosts, guests, problems = [], [], []
    for host in parse_hosts(config):
        try:
            entry, found, _ = read_host(host)
        except DockerError as exc:
            problems.append(str(exc))
            continue
        hosts.append(entry)
        guests.extend(found)
    if not hosts:
        raise DockerError("; ".join(problems) or "no Docker host answered")
    return hosts, guests, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    hosts, guests, problems = connect(config)
    running = sum(1 for g in guests if g["status"] == "running")
    message = f"Connected to {len(hosts)} Docker host(s): {len(guests)} container(s), {running} running"
    own = sum(1 for g in guests if g["ips"])
    if own:
        message += f", {own} with their own network address"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    hosts, guests, _ = connect(config)
    return {"hosts": hosts, "guests": guests}


def _problem(exc):
    return type(exc).__name__ + ": " + re.sub(r"https?://[^\s/]+", "<host>", str(exc))[:300]


def diagnose(config):
    """What the hosts answer, as counts and yes/no (no names, addresses or labels)."""
    try:
        hosts = parse_hosts(config)
    except (ValueError, DockerError) as exc:
        return {"error": str(exc)}
    report = {"hosts": []}
    for host in hosts:
        entry = {"steps": {}}
        report["hosts"].append(entry)
        for step, path, params in (("info", "/info", {}), ("networks", "/networks", {}), ("containers", "/containers/json", {"all": "1"})):
            try:
                data = host.get(path, **params)
                if step == "info":
                    entry["steps"][step] = {"ok": True, "server_version": str(data.get("ServerVersion") or ""), "containers": data.get("Containers"), "running": data.get("ContainersRunning")}
                elif step == "networks":
                    drivers = {}
                    for n in data:
                        drivers[n.get("Driver") or "?"] = drivers.get(n.get("Driver") or "?", 0) + 1
                    entry["steps"][step] = {"ok": True, "count": len(data), "drivers": drivers}
                else:
                    states = {}
                    for c in data:
                        states[c.get("State") or "?"] = states.get(c.get("State") or "?", 0) + 1
                    entry["steps"][step] = {"ok": True, "count": len(data), "states": states, "with_ports": sum(1 for c in data if c.get("Ports"))}
            except DockerError as exc:
                entry["steps"][step] = {"ok": False, "error": _problem(exc)}
    return report
