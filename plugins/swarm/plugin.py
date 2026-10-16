"""Docker Swarm plugin (kind "hypervisor"): the nodes of a swarm as hosts, its tasks as guests.

Talks to the Docker Engine API of one manager node, read-only (GET only), normally through tecnativa/docker-socket-proxy:

    GET /info        cluster id and whether this node is a manager (not /swarm: that answer contains the join tokens)
    GET /nodes       every node: hostname, role, availability, state (ready/down), address, engine version
    GET /services    name, image, stack label, published ports
    GET /tasks       every copy of every service: service, node, slot, desired and current state

A task is a guest of its node. Tasks that were shut down and replaced (desired state shutdown) are left out. A service port published
through the routing mesh (`ingress`) is reachable on every node, so it is reported on each task. Overlay addresses are inside the
cluster and are not reported. Standard library only.
"""

import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAX_TASKS = 3000
LIVE = ("new", "pending", "assigned", "accepted", "ready", "preparing", "starting", "running", "failed", "rejected", "orphaned")


class SwarmError(Exception):
    pass


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


class Manager:
    def __init__(self, url, verify_tls=True, timeout=15):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "http://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise SwarmError(f"{url!r} is not an address like http://192.168.0.189:2375")
        self.url, self.timeout, self.id = f"{parts.scheme}://{parts.netloc}", float(timeout), parts.netloc
        self.context = None
        if parts.scheme == "https" and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def get(self, path):
        request = urllib.request.Request(f"{self.url}{path}", headers={"Accept": "application/json"}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                return json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                raise SwarmError(f"{self.id} refused {path}: the socket proxy does not allow it (set INFO=1, NODES=1, SERVICES=1 and TASKS=1 on the proxy)")
            if exc.code == 503:
                raise SwarmError(f"{self.id} is not a swarm manager (HTTP 503): point the plugin at a manager node")
            raise SwarmError(f"{self.id} answered HTTP {exc.code} for {path}")
        except urllib.error.URLError as exc:
            raise SwarmError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise SwarmError(f"{self.id} did not answer properly: {exc}")


def parse_managers(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and str(r.get("host") or "").strip()] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one swarm manager (its socket proxy)")
    return [Manager(str(r["host"]), config.get("verify_tls", True), config.get("timeout") or 15) for r in items]


def _plain_image(ref):
    return str(ref or "").split("@")[0]


def read(manager):
    swarm = manager.get("/info").get("Swarm") or {}
    if not swarm.get("ControlAvailable"):
        raise SwarmError(f"{manager.id} is not a swarm manager: point the plugin at a manager node")
    cluster = str((swarm.get("Cluster") or {}).get("ID") or manager.id)[:12]
    nodes_raw = manager.get("/nodes")
    services = {s.get("ID"): s for s in manager.get("/services")}
    tasks = manager.get("/tasks")
    hosts, host_of = [], {}
    for n in nodes_raw:
        hid = f"{cluster}/{n.get('ID')}"
        host_of[n.get("ID")] = hid
        status = n.get("Status") or {}
        online = status.get("State") == "ready" and (n.get("Spec") or {}).get("Availability") != "drain"
        hosts.append({"id": hid, "name": str((n.get("Description") or {}).get("Hostname") or n.get("ID"))[:100], "ip": _ipv4(status.get("Addr")), "online": online})
    guests = []
    for t in tasks[:MAX_TASKS]:
        state = str((t.get("Status") or {}).get("State") or "unknown").lower()
        if t.get("DesiredState") != "running" and state not in ("running", "starting", "preparing"):
            continue            # an old copy that was replaced
        svc = services.get(t.get("ServiceID")) or {}
        spec = svc.get("Spec") or {}
        labels = spec.get("Labels") or {}
        name = spec.get("Name") or str(t.get("ServiceID"))[:12]
        slot = t.get("Slot")
        ports = []
        for p in (svc.get("Endpoint") or {}).get("Ports") or []:
            if p.get("PublishedPort"):
                ports.append({"container_port": p.get("TargetPort"), "host_port": p["PublishedPort"], "proto": p.get("Protocol") or "tcp", "bind": ""})
        details = {
            "image": _plain_image(((spec.get("TaskTemplate") or {}).get("ContainerSpec") or {}).get("Image")),
            "project": labels.get("com.docker.stack.namespace") or "",
            "service": name,
            "network_driver": "overlay",
            "health": "healthy" if state == "running" else "unhealthy" if state in ("failed", "rejected") else "",
            "started": (t.get("Status") or {}).get("Timestamp") if state == "running" else "",
            "exposed": bool(ports),
        }
        if ports:
            details["ports"] = ports
        guest = {"id": f"{cluster}/{t.get('ID')}", "name": (f"{name}.{slot}" if slot else f"{name}.{str(t.get('NodeID'))[:6]}")[:100], "kind": "task", "status": state[:30],
                 "macs": [], "ips": [], "details": {k: v for k, v in details.items() if v not in ("", None)}}
        if t.get("NodeID") in host_of:
            guest["host_id"] = host_of[t["NodeID"]]
        guests.append(guest)
    return cluster, hosts, guests


def connect(config):
    clusters, hosts, guests, problems = [], [], [], []
    for manager in parse_managers(config):
        try:
            cluster, found_hosts, found = read(manager)
        except SwarmError as exc:
            problems.append(str(exc))
            continue
        if cluster in clusters:
            continue            # two managers of the same swarm
        clusters.append(cluster)
        hosts.extend(found_hosts)
        guests.extend(found)
    if not clusters:
        raise SwarmError("; ".join(problems) or "no swarm manager answered")
    return clusters, hosts, guests, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    clusters, hosts, guests, problems = connect(config)
    running = sum(1 for g in guests if g["status"] == "running")
    message = f"Connected to {len(clusters)} swarm(s): {len(hosts)} node(s), {len(guests)} task(s), {running} running"
    down = sum(1 for h in hosts if not h["online"])
    if down:
        message += f". {down} node(s) are down or drained"
    if problems:
        message += ". Problems: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    _, hosts, guests, _ = connect(config)
    return {"hosts": hosts, "guests": guests}


def _problem(exc):
    """The error text for a diagnostic report, without any server address (URL, IP address, host:port or host name)."""
    text = re.sub(r"https?://[^\s/]+", "<manager>", str(exc))
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<manager>", text)
    text = re.sub(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*:\d{2,5}\b", "<manager>", text)
    text = re.sub(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", "<manager>", text)
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What the manager answers, as counts and enumerations (no names, images or addresses)."""
    try:
        managers = parse_managers(config)
    except (ValueError, SwarmError) as exc:
        return {"error": str(exc)}
    report = {"managers": []}
    for manager in managers:
        entry = {"steps": {}}
        report["managers"].append(entry)
        for step, path in (("info", "/info"), ("nodes", "/nodes"), ("services", "/services"), ("tasks", "/tasks")):
            try:
                data = manager.get(path)
                if step == "info":
                    swarm = data.get("Swarm") or {}
                    entry["steps"][step] = {"ok": True, "state": swarm.get("LocalNodeState"), "manager": bool(swarm.get("ControlAvailable")), "managers": swarm.get("Managers"), "nodes": swarm.get("Nodes")}
                elif step == "nodes":
                    entry["steps"][step] = {"ok": True, "count": len(data), "roles": {r: sum(1 for n in data if (n.get("Spec") or {}).get("Role") == r) for r in ("manager", "worker")},
                                            "states": {s: sum(1 for n in data if (n.get("Status") or {}).get("State") == s) for s in sorted({str((n.get("Status") or {}).get("State")) for n in data})}}
                elif step == "services":
                    entry["steps"][step] = {"ok": True, "count": len(data), "with_ports": sum(1 for s in data if (s.get("Endpoint") or {}).get("Ports")), "with_stack_label": sum(1 for s in data if (s.get("Spec") or {}).get("Labels", {}).get("com.docker.stack.namespace"))}
                else:
                    entry["steps"][step] = {"ok": True, "count": len(data), "states": {s: sum(1 for t in data if (t.get("Status") or {}).get("State") == s) for s in sorted({str((t.get("Status") or {}).get("State")) for t in data})},
                                            "desired": {s: sum(1 for t in data if t.get("DesiredState") == s) for s in sorted({str(t.get("DesiredState")) for t in data})}}
            except SwarmError as exc:
                entry["steps"][step] = {"ok": False, "error": _problem(exc)}
    return report
