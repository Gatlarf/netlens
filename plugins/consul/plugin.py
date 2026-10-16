"""HashiCorp Consul plugin (kind "hypervisor"): the catalog's nodes as hosts, the registered service instances as guests.

Talks to the Consul HTTP API (/v1), read-only (GET), with an ACL token when ACLs are on (header X-Consul-Token):

    GET /v1/agent/self           version (needs agent:read; skipped when refused)
    GET /v1/catalog/nodes        Node, Address, Datacenter, Meta
    GET /v1/catalog/services     service names
    GET /v1/catalog/service/<n>  every instance: Node, ServiceID, ServiceAddress, ServicePort, ServiceTags
    GET /v1/health/state/any     every check: Node, CheckID, Status, ServiceID  (the health of services, and `serfHealth` of nodes)

A service instance is a guest of its node (kind "service"). Its status is `running` when all its checks pass, otherwise `warning` or `critical`
(the worst check wins); a service without checks is `running`. A node is online when its `serfHealth` check passes (nodes registered through the
catalog API have none and count as online). The guest's address is the service address, else the node's. Loopback addresses are not reported.
Standard library only.
"""

import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAX_GUESTS = 3000
ORDER = {"passing": 0, "warning": 1, "critical": 2}
STATUS = {"passing": "running", "warning": "warning", "critical": "critical"}


class ConsulError(Exception):
    pass


class AuthRefused(ConsulError):
    auth_failed = True


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    if addr.version != 4 or addr.is_loopback or addr.is_unspecified:
        return None
    return str(addr)


class Cluster:
    def __init__(self, url, token="", verify_tls=True, timeout=20):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "http://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ConsulError(f"{url!r} is not an address like http://192.168.0.4:8500")
        self.url, self.token, self.timeout, self.id = f"{parts.scheme}://{parts.netloc}", token, float(timeout), parts.netloc
        self.context = None
        if parts.scheme == "https" and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def get(self, path):
        headers = {"Accept": "application/json"}
        if self.token:
            headers["X-Consul-Token"] = self.token
        request = urllib.request.Request(f"{self.url}/v1/{path}", headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                return json.loads(response.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                err = AuthRefused(f"{self.id} refused the token for {path} (missing or not allowed: see the box at the top of this page)")
                err.status = 403
                raise err
            err = ConsulError(f"{self.id} answered HTTP {exc.code} for {path}")
            err.status = exc.code
            raise err
        except urllib.error.URLError as exc:
            raise ConsulError(f"cannot reach {self.id}: {exc.reason}")
        except (OSError, ValueError) as exc:
            raise ConsulError(f"{self.id} did not answer properly (is this Consul?): {exc}")


def parse_clusters(config):
    rows = config.get("servers")
    items = [r for r in rows if isinstance(r, dict) and str(r.get("host") or "").strip()] if isinstance(rows, list) else []
    if not items:
        raise ValueError("enter the address of at least one Consul agent")
    return [Cluster(str(r["host"]), str(r.get("token") or "").strip(), config.get("verify_tls", True), config.get("timeout") or 20) for r in items]


def read(cluster, config):
    try:
        version = str(((cluster.get("agent/self") or {}).get("Config") or {}).get("Version") or "")
    except AuthRefused:
        version = ""
    nodes = cluster.get("catalog/nodes") or []
    names = sorted(cluster.get("catalog/services") or {})
    checks = cluster.get("health/state/any") or []
    instances = []
    for name in names:
        if name == "consul" and config.get("hide_consul", True):
            continue
        instances.extend(cluster.get(f"catalog/service/{urllib.parse.quote(name, safe='')}") or [])
    return version, nodes, instances, checks


def build(cluster, nodes, instances, checks):
    serf = {c.get("Node"): c.get("Status") for c in checks if c.get("CheckID") == "serfHealth"}
    worst = {}
    for c in checks:
        if c.get("ServiceID") and c.get("Status") in ORDER:
            key = (c.get("Node"), c.get("ServiceID"))
            if ORDER[c["Status"]] >= ORDER.get(worst.get(key), -1):
                worst[key] = c["Status"]
    host_ids = {}
    hosts = []
    for n in nodes:
        name = str(n.get("Node") or "")
        if not name or name in host_ids:
            continue
        host_ids[name] = name[:100]
        hosts.append({"id": name[:100], "name": name[:100], "ip": _ipv4(n.get("Address")), "online": serf.get(name, "passing") == "passing"})
    node_ip = {n.get("Node"): _ipv4(n.get("Address")) for n in nodes}
    guests, seen = [], set()
    for inst in instances[:MAX_GUESTS]:
        node = inst.get("Node")
        if node not in host_ids:
            continue
        gid = f"{node}/{inst.get('ServiceID')}"[:100]
        if gid in seen:
            continue
        seen.add(gid)
        health = worst.get((node, inst.get("ServiceID")), "passing")
        address = _ipv4(inst.get("ServiceAddress")) or node_ip.get(node)
        details = {"health": health, "service": str(inst.get("ServiceName") or "")[:100], "tags": ", ".join(str(t) for t in inst.get("ServiceTags") or [])[:200]}
        if inst.get("ServicePort"):
            details["ports"] = [{"container_port": inst["ServicePort"], "host_port": inst["ServicePort"], "proto": "tcp", "bind": address or ""}]
        guest = {"id": gid, "name": str(inst.get("ServiceName") or inst.get("ServiceID"))[:100], "kind": "service", "host_id": host_ids[node], "status": STATUS.get(health, "unknown"),
                 "ips": [address] if address else [], "macs": [], "details": {k: v for k, v in details.items() if v not in ("", None)}}
        guests.append(guest)
    return hosts, guests


def connect(config):
    hosts, guests, versions, problems = [], [], [], []
    for cluster in parse_clusters(config):
        try:
            version, nodes, instances, checks = read(cluster, config)
            h, g = build(cluster, nodes, instances, checks)
        except AuthRefused:
            raise
        except ConsulError as exc:
            problems.append(str(exc))
            continue
        versions.append(version)
        known = {x["id"] for x in hosts}
        suffix = "" if not known & {x["id"] for x in h} else f"@{cluster.id}"
        if suffix:                                           # two datacenters with the same node name: keep both
            for x in h:
                x["id"] += suffix
            for x in g:
                x["id"] += suffix
                x["host_id"] += suffix
        hosts.extend(h)
        guests.extend(g)
    if not versions:
        raise ConsulError("; ".join(problems) or "no Consul answered")
    return versions, hosts, guests, problems


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    versions, hosts, guests, problems = connect(config)
    bad = sum(1 for g in guests if g["status"] != "running")
    message = f"Connected to Consul {', '.join(sorted({v for v in versions if v})) or '(version unknown)'}: {len(hosts)} node(s), {len(guests)} service instance(s)"
    if bad:
        message += f", {bad} not passing"
    if problems:
        message += ". Not reachable: " + "; ".join(problems)
    return {"message": message}


def fetch(config):
    _, hosts, guests, _ = connect(config)
    return {"hosts": hosts, "guests": guests}


def _problem(exc, server=None):
    text = re.sub(r"https?://[^\s/]+", "<server>", str(exc))
    if server is not None:
        text = text.replace(server.id, "<server>")
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What Consul answers, as counts and enumerations (no node or service names, tags or addresses)."""
    try:
        clusters = parse_clusters(config)
    except (ValueError, ConsulError) as exc:
        return {"error": str(exc)}
    report = {"servers": []}
    for cluster in clusters:
        entry = {"steps": {}}
        report["servers"].append(entry)
        try:
            try:
                entry["steps"]["agent_self"] = {"ok": True, "version": str(((cluster.get("agent/self") or {}).get("Config") or {}).get("Version") or "")}
            except AuthRefused:
                entry["steps"]["agent_self"] = {"ok": False, "error": "refused (no agent:read)"}
            nodes = cluster.get("catalog/nodes") or []
            entry["steps"]["nodes"] = {"ok": True, "count": len(nodes), "with_loopback_address": sum(1 for n in nodes if not _ipv4(n.get("Address"))), "fields": sorted({k for n in nodes[:50] for k in n})[:30]}
            services = cluster.get("catalog/services") or {}
            entry["steps"]["services"] = {"ok": True, "count": len(services)}
            checks = cluster.get("health/state/any") or []
            entry["steps"]["checks"] = {"ok": True, "count": len(checks), "statuses": {s: sum(1 for c in checks if c.get("Status") == s) for s in sorted({str(c.get("Status")) for c in checks})},
                                        "service_checks": sum(1 for c in checks if c.get("ServiceID"))}
        except AuthRefused:
            raise
        except ConsulError as exc:
            entry["steps"]["error"] = {"ok": False, "error": _problem(exc, cluster)}
    return report
