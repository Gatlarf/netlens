"""HashiCorp Nomad plugin (kind "hypervisor"): the client nodes as hosts, the allocations as guests.

Talks to the Nomad HTTP API (/v1), read-only (GET), with an ACL token when the cluster uses ACLs (header X-Nomad-Token):

    GET /v1/agent/self                          version (needs agent:read; the node list's Version is used when it is refused)
    GET /v1/nodes                               the client nodes: ID, Name, Address, Status, SchedulingEligibility, Drain
    GET /v1/allocations?namespace=*             every allocation: job, task group, node, client status, task states
    GET /v1/allocation/<id>                     for the running ones: published ports and the first task's image

An allocation is a guest of its node. Finished allocations (client status complete) and ones Nomad has already replaced are left out. The
node's `Address` is its network address. Allocations that publish ports (network blocks) share the node's address, so the ports are
reported on the guest ("Open ports" of the host names it) rather than as an address of its own. Standard library only.
"""

import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAX_ALLOCS = 1500
MAX_DETAILS = 300
SHOWN = ("running", "pending", "failed", "lost", "unknown")


class NomadError(Exception):
    pass


class AuthRefused(NomadError):
    auth_failed = True


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


class Cluster:
    def __init__(self, url, token="", verify_tls=True, timeout=20):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "http://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise NomadError(f"{url!r} is not an address like http://192.168.0.10:4646")
        self.url, self.token, self.timeout, self.id = f"{parts.scheme}://{parts.netloc}", token, float(timeout), parts.netloc
        self.context = None
        if parts.scheme == "https" and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def get(self, path, **params):
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        headers = {"Accept": "application/json"}
        if self.token:
            headers["X-Nomad-Token"] = self.token
        request = urllib.request.Request(f"{self.url}/v1/{path}" + (f"?{query}" if query else ""), headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                return json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                raise AuthRefused(f"{self.id} refused the token for {path} (missing or not allowed: see the box at the top of this page)")
            err = NomadError(f"{self.id} answered HTTP {exc.code} for {path}")
            err.status = exc.code
            raise err
        except urllib.error.URLError as exc:
            raise NomadError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise NomadError(f"{self.id} did not answer properly (is this Nomad?): {exc}")


def parse_clusters(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and str(r.get("host") or "").strip()] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one Nomad cluster")
    return [Cluster(str(r["host"]), str(r.get("token") or "").strip(), config.get("verify_tls", True), config.get("timeout") or 20) for r in items]


def node_entry(cluster, node):
    address = str(node.get("Address") or "")
    return {"id": f"{cluster.id}/{node.get('ID')}", "name": str(node.get("Name") or node.get("ID") or "node")[:100], "ip": _ipv4(address),
            "online": node.get("Status") == "ready"}


def alloc_guest(cluster, stub, detail, host_id):
    tasks = stub.get("TaskStates") or {}
    status = str(stub.get("ClientStatus") or "unknown").lower()
    ports = []
    shared = ((detail or {}).get("AllocatedResources") or {}).get("Shared") or {}
    for p in shared.get("Ports") or []:
        if p.get("Value"):
            ports.append({"container_port": p.get("To") or p.get("Value"), "host_port": p["Value"], "proto": "tcp", "bind": p.get("HostIP") or ""})
    image = ""
    for group in (((detail or {}).get("Job") or {}).get("TaskGroups") or []):
        if group.get("Name") == stub.get("TaskGroup"):
            for task in group.get("Tasks") or []:
                image = image or str((task.get("Config") or {}).get("image") or "")
    started = [t.get("StartedAt") for t in tasks.values() if t.get("StartedAt") and not str(t["StartedAt"]).startswith("0001")]
    details = {
        "image": image,
        "project": stub.get("Namespace") or "",
        "service": stub.get("JobID") or "",
        "restarts": sum(int(t.get("Restarts") or 0) for t in tasks.values()) if tasks else None,
        "restarting": status == "running" and any(t.get("State") == "pending" for t in tasks.values()),
        "health": ("unhealthy" if any(t.get("Failed") for t in tasks.values()) else "healthy") if status == "running" and tasks else "",
        "started": min(started) if started and status == "running" else "",
        "exposed": bool(ports),
    }
    if ports:
        details["ports"] = ports
    guest = {"id": f"{cluster.id}/{stub.get('ID')}", "name": str(stub.get("Name") or stub.get("ID"))[:100], "kind": "alloc", "status": status[:30], "macs": [], "ips": [],
             "details": {k: v for k, v in details.items() if v not in ("", None)}}
    if host_id:
        guest["host_id"] = host_id
    return guest


def read(cluster):
    version = None
    try:
        version = ((cluster.get("agent/self").get("config") or {}).get("Version") or {}).get("Version")
    except AuthRefused:
        pass
    nodes_raw = cluster.get("nodes")
    if not isinstance(nodes_raw, list):
        raise NomadError(f"{cluster.id} did not return a list of nodes")
    version = version or next((n.get("Version") for n in nodes_raw if n.get("Version")), None)
    nodes = [node_entry(cluster, n) for n in nodes_raw]
    host_of = {n.get("ID"): f"{cluster.id}/{n.get('ID')}" for n in nodes_raw}
    try:
        stubs = cluster.get("allocations", namespace="*", task_states="true")
    except NomadError as exc:
        if getattr(exc, "status", None) not in (400, 404):
            raise
        stubs = cluster.get("allocations")          # a Nomad without the wildcard namespace: the default namespace only
    guests, details_left = [], MAX_DETAILS
    for stub in stubs[:MAX_ALLOCS]:
        if str(stub.get("ClientStatus")).lower() not in SHOWN or (stub.get("DesiredStatus") == "stop" and stub.get("ClientStatus") != "running"):
            continue
        detail = None
        if stub.get("ClientStatus") == "running" and details_left > 0:
            details_left -= 1
            try:
                detail = cluster.get(f"allocation/{stub['ID']}")
            except NomadError:
                detail = None
        guests.append(alloc_guest(cluster, stub, detail, host_of.get(stub.get("NodeID"))))
    return version, nodes, guests


def connect(config):
    versions, hosts, guests, problems = [], [], [], []
    for cluster in parse_clusters(config):
        try:
            version, nodes, found = read(cluster)
        except AuthRefused:
            raise
        except NomadError as exc:
            problems.append(str(exc))
            continue
        versions.append(version)
        hosts.extend(nodes)
        guests.extend(found)
    if not versions:
        raise NomadError("; ".join(problems) or "no Nomad cluster answered")
    return versions, hosts, guests, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    versions, hosts, guests, problems = connect(config)
    running = sum(1 for g in guests if g["status"] == "running")
    message = f"Connected to {len(versions)} Nomad cluster(s) ({', '.join(sorted({v for v in versions if v})) or 'version unknown'}): {len(hosts)} node(s), {len(guests)} allocation(s), {running} running"
    down = sum(1 for h in hosts if not h["online"])
    if down:
        message += f". {down} node(s) are not ready"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    _, hosts, guests, _ = connect(config)
    return {"hosts": hosts, "guests": guests}


def _problem(exc):
    return type(exc).__name__ + ": " + re.sub(r"https?://[^\s/]+", "<server>", str(exc))[:300]


def diagnose(config):
    """What the cluster answers, as counts and enumerations (no names, jobs, images or addresses)."""
    try:
        clusters = parse_clusters(config)
    except (ValueError, NomadError) as exc:
        return {"error": str(exc)}
    report = {"clusters": []}
    for cluster in clusters:
        entry = {"steps": {}}
        report["clusters"].append(entry)
        for step, path, params in (("agent_self", "agent/self", {}), ("nodes", "nodes", {}), ("allocations", "allocations", {"namespace": "*", "task_states": "true"})):
            try:
                data = cluster.get(path, **params)
                if step == "agent_self":
                    entry["steps"][step] = {"ok": True, "version": str(((data.get("config") or {}).get("Version") or {}).get("Version") or "")}
                elif step == "nodes":
                    entry["steps"][step] = {"ok": True, "count": len(data), "statuses": {s: sum(1 for n in data if n.get("Status") == s) for s in sorted({str(n.get("Status")) for n in data})},
                                            "fields": sorted({k for n in data for k in n})[:30]}
                else:
                    entry["steps"][step] = {"ok": True, "count": len(data), "client_statuses": {s: sum(1 for a in data if a.get("ClientStatus") == s) for s in sorted({str(a.get("ClientStatus")) for a in data})},
                                            "fields": sorted({k for a in data[:50] for k in a})[:40], "namespaces": len({a.get("Namespace") for a in data})}
            except AuthRefused:
                entry["steps"][step] = {"ok": False, "error": "access denied for this token"}
            except NomadError as exc:
                entry["steps"][step] = {"ok": False, "error": _problem(exc)}
    return report
