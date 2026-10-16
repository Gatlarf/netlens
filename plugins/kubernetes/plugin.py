"""Kubernetes plugin (kind "hypervisor"): the nodes of a cluster as hosts, its pods as guests.

Talks to the Kubernetes API with a service account token (Authorization: Bearer), read-only (GET only):

    GET /version              cluster version
    GET /api/v1/nodes         the nodes: InternalIP, Ready condition, kubelet version, capacity
    GET /api/v1/pods          every pod (paged with limit/continue), or /api/v1/namespaces/<ns>/pods for the namespaces you list

A pod is a guest of the node it runs on. Its `project` is the namespace and its `service` the workload that owns it (the Deployment,
StatefulSet, DaemonSet, Job ... found from the owner reference; a ReplicaSet's name loses its hash). Pods that finished (phase
Succeeded) are skipped. Pod addresses lie inside the cluster network, so they are only reported when the setting asks for it (and
never for pods on the host network, whose address is the node's). Standard library only.
"""

import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

PAGE = 500
MAX_PODS = 3000


class KubernetesError(Exception):
    pass


class AuthRefused(KubernetesError):
    auth_failed = True


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


class Cluster:
    def __init__(self, url, token, namespaces="", verify_tls=False, timeout=20):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "https://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise KubernetesError(f"{url!r} is not an address like https://192.168.0.10:6443")
        self.url, self.token, self.timeout, self.id = f"{parts.scheme}://{parts.netloc}", token, float(timeout), parts.netloc
        self.namespaces = [n for n in re.split(r"[,;\s]+", str(namespaces or "")) if n]
        for n in self.namespaces:
            if not re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", n):
                raise KubernetesError(f"{n!r} is not a namespace name")
        self.context = None
        if parts.scheme == "https" and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def get(self, path, **params):
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v})
        request = urllib.request.Request(f"{self.url}{path}" + (f"?{query}" if query else ""), headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                return json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                raise AuthRefused(f"{self.id} refused the token (wrong, expired or revoked)")
            if exc.code == 403:
                raise AuthRefused(f"{self.id} says the token may not read {path}: give the service account the rights from the box at the top of this page")
            raise KubernetesError(f"{self.id} answered HTTP {exc.code} for {path}")
        except urllib.error.URLError as exc:
            raise KubernetesError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise KubernetesError(f"{self.id} did not answer properly (is this the Kubernetes API?): {exc}")

    def items(self, path):
        out, token = [], None
        while len(out) < MAX_PODS:
            page = self.get(path, limit=PAGE, **{"continue": token})
            out.extend(page.get("items") or [])
            token = (page.get("metadata") or {}).get("continue")
            if not token:
                break
        return out

    def pods(self):
        if not self.namespaces:
            return self.items("/api/v1/pods")
        return [p for ns in self.namespaces for p in self.items(f"/api/v1/namespaces/{ns}/pods")]


def parse_clusters(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and any(str(r.get(k) or "").strip() for k in ("host", "token"))] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one cluster")
    out = []
    for i, r in enumerate(items, 1):
        url, token = str(r.get("host") or "").strip(), str(r.get("token") or "").strip()
        if not url:
            raise ValueError(f"cluster {i}: enter the API server address")
        if not token:
            raise ValueError(f"{url}: enter a token")
        out.append(Cluster(url, token, r.get("namespaces"), config.get("verify_tls", False), config.get("timeout") or 20))
    return out


def _workload(pod):
    owner = next(iter((pod.get("metadata") or {}).get("ownerReferences") or []), None)
    if not owner:
        return ""
    name = str(owner.get("name") or "")
    if owner.get("kind") == "ReplicaSet":
        name = re.sub(r"-[a-z0-9]{6,10}$", "", name)      # web-5d6b5c7df9 -> web (the Deployment)
    return name


def node_entry(cluster, node):
    addresses = {a.get("type"): a.get("address") for a in (node.get("status") or {}).get("addresses") or []}
    ready = next((c.get("status") for c in (node.get("status") or {}).get("conditions") or [] if c.get("type") == "Ready"), "Unknown")
    name = (node.get("metadata") or {}).get("name") or addresses.get("Hostname") or "node"
    return {"id": f"{cluster.id}/{name}", "name": name[:100], "ip": _ipv4(addresses.get("InternalIP")) or _ipv4(addresses.get("ExternalIP")), "online": ready == "True"}


def pod_guest(cluster, pod, node_ids, pod_ips):
    meta, spec, status = pod.get("metadata") or {}, pod.get("spec") or {}, pod.get("status") or {}
    name, namespace = meta.get("name") or "pod", meta.get("namespace") or ""
    phase = str(status.get("phase") or "Unknown")
    containers = status.get("containerStatuses") or []
    waiting = next((((c.get("state") or {}).get("waiting") or {}).get("reason") for c in containers if (c.get("state") or {}).get("waiting")), None)
    state = phase.lower()
    if waiting in ("CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError"):
        state = waiting.lower()
    ports = []
    for c in spec.get("containers") or []:
        for p in c.get("ports") or []:
            if p.get("hostPort"):
                ports.append({"container_port": p.get("containerPort"), "host_port": p["hostPort"], "proto": str(p.get("protocol") or "TCP").lower(), "bind": p.get("hostIP") or "0.0.0.0"})
    ready = bool(containers) and all(c.get("ready") for c in containers)
    details = {
        "image": ((spec.get("containers") or [{}])[0].get("image") or ""),
        "project": namespace,
        "service": _workload(pod),
        "network": "host network" if spec.get("hostNetwork") else "pod network",
        "network_driver": "host" if spec.get("hostNetwork") else "",
        "health": ("healthy" if ready else "unhealthy") if phase == "Running" and containers else "",
        "restarts": sum(int(c.get("restartCount") or 0) for c in containers) if containers else None,
        "started": status.get("startTime") if phase == "Running" else "",
        "exposed": bool(ports),
    }
    if ports:
        details["ports"] = ports
    ips = [] if spec.get("hostNetwork") or not pod_ips else [ip for ip in (_ipv4(p.get("ip")) for p in status.get("podIPs") or [{"ip": status.get("podIP")}]) if ip]
    node = spec.get("nodeName")
    guest = {"id": f"{cluster.id}/{namespace}/{name}", "name": name[:100], "kind": "pod", "status": state[:30], "macs": [], "ips": ips,
             "details": {k: v for k, v in details.items() if v not in ("", None)}}
    if node in node_ids:
        guest["host_id"] = node_ids[node]
    return guest


def read(cluster, pod_ips):
    version = (cluster.get("/version") or {}).get("gitVersion")
    nodes = [node_entry(cluster, n) for n in cluster.items("/api/v1/nodes")]
    by_name = {n["name"]: n["id"] for n in nodes}
    guests = [pod_guest(cluster, p, by_name, pod_ips) for p in cluster.pods() if (p.get("status") or {}).get("phase") != "Succeeded"]
    return version, nodes, guests


def connect(config):
    versions, hosts, guests, problems = [], [], [], []
    for cluster in parse_clusters(config):
        try:
            version, nodes, found = read(cluster, bool(config.get("pod_ips")))
        except AuthRefused:
            raise
        except KubernetesError as exc:
            problems.append(str(exc))
            continue
        versions.append(version)
        hosts.extend(nodes)
        guests.extend(found)
    if not versions:
        raise KubernetesError("; ".join(problems) or "no cluster answered")
    return versions, hosts, guests, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    versions, hosts, guests, problems = connect(config)
    running = sum(1 for g in guests if g["status"] == "running")
    down = sum(1 for h in hosts if not h["online"])
    message = f"Connected to {len(versions)} cluster(s) ({', '.join(sorted({v for v in versions if v})) or 'version unknown'}): {len(hosts)} node(s), {len(guests)} pod(s), {running} running"
    if down:
        message += f". {down} node(s) are not Ready"
    if any(h["ip"] is None for h in hosts):
        message += ". Some nodes have no InternalIP"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    _, hosts, guests, _ = connect(config)
    return {"hosts": hosts, "guests": guests[:MAX_PODS]}


def _problem(exc):
    """The error text for a diagnostic report, without any server address (URL, IP address, host:port or host name)."""
    text = re.sub(r"https?://[^\s/]+", "<server>", str(exc))
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<server>", text)
    text = re.sub(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*:\d{2,5}\b", "<server>", text)
    text = re.sub(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", "<server>", text)
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What the cluster answers, as counts and enumerations (no names, namespaces, images or addresses)."""
    try:
        clusters = parse_clusters(config)
    except (ValueError, KubernetesError) as exc:
        return {"error": str(exc)}
    report = {"clusters": []}
    for cluster in clusters:
        entry = {"steps": {}}
        report["clusters"].append(entry)
        try:
            entry["steps"]["version"] = {"ok": True, "version": str((cluster.get("/version") or {}).get("gitVersion") or "")}
        except AuthRefused:
            raise
        except KubernetesError as exc:
            entry["steps"]["version"] = {"ok": False, "error": _problem(exc)}
            continue
        try:
            nodes = cluster.items("/api/v1/nodes")
            entry["steps"]["nodes"] = {"ok": True, "count": len(nodes), "with_internal_ip": sum(1 for n in nodes if any(a.get("type") == "InternalIP" for a in (n.get("status") or {}).get("addresses") or [])),
                                       "ready": sum(1 for n in nodes if any(c.get("type") == "Ready" and c.get("status") == "True" for c in (n.get("status") or {}).get("conditions") or []))}
        except AuthRefused as exc:
            entry["steps"]["nodes"] = {"ok": False, "error": _problem(exc)}
        except KubernetesError as exc:
            entry["steps"]["nodes"] = {"ok": False, "error": _problem(exc)}
        try:
            pods = cluster.pods()
            phases, owners = {}, {}
            for p in pods:
                phase = str((p.get("status") or {}).get("phase"))
                phases[phase] = phases.get(phase, 0) + 1
                kind = str(next(iter((p.get("metadata") or {}).get("ownerReferences") or []), {}).get("kind") or "none")
                owners[kind] = owners.get(kind, 0) + 1
            entry["steps"]["pods"] = {"ok": True, "count": len(pods), "phases": phases, "owners": owners, "host_network": sum(1 for p in pods if (p.get("spec") or {}).get("hostNetwork")),
                                      "with_host_ports": sum(1 for p in pods if any(c.get("ports") and any(x.get("hostPort") for x in c["ports"]) for c in (p.get("spec") or {}).get("containers") or []))}
        except AuthRefused as exc:
            entry["steps"]["pods"] = {"ok": False, "error": _problem(exc)}
        except KubernetesError as exc:
            entry["steps"]["pods"] = {"ok": False, "error": _problem(exc)}
    return report
