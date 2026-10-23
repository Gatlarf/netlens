"""NetApp ONTAP plugin (kind "storage"): an ONTAP cluster (AFF, FAS, ASA, ONTAP Select, Cloud Volumes ONTAP) with its nodes, aggregates, volumes,
LUNs, disks, the NFS clients that use the volumes and the open health events.

Talks to the ONTAP REST API (ONTAP 9.8 or newer; the client list needs 9.8, everything else 9.6), read-only, with HTTP Basic authentication:

    GET /api/cluster                              name, version, management address
    GET /api/cluster/nodes                        nodes: state, model, serial, management address, failed fans and power supplies
    GET /api/network/ethernet/ports               the MAC address of each node's management port
    GET /api/storage/aggregates                   aggregates: state and space
    GET /api/storage/volumes                      volumes: SVM, state, space, junction path
    GET /api/storage/luns                         LUNs
    GET /api/storage/disks                        disks: state, container (aggregate, spare, broken)
    GET /api/protocols/nfs/connected-clients      the hosts that have a volume mounted over NFS
    GET /api/support/ems/events                   emergency, alert and error events of the last day

Standard library only. A refused login is reported with `auth_failed`. Everything but the cluster and the nodes is optional.
"""

import base64
import ipaddress
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

MAX_BODY = 16 * 1024 * 1024
PAGE = 1000
MAX_RECORDS = 5000
RANK = {"unknown": 0, "ok": 1, "warning": 2, "critical": 3}


class OntapError(Exception):
    pass


class ConnectError(OntapError):
    """The cluster could not be reached (not a login problem)."""


class LoginRefused(OntapError):
    auth_failed = True


def normalize(url):
    text = str(url or "").strip()
    if not text:
        raise ValueError("enter the address of the cluster management interface (for example https://192.168.0.80)")
    if "://" not in text:
        text = "https://" + text
    parts = urllib.parse.urlsplit(text)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ValueError("the address must start with https:// and name the cluster")
    host = parts.hostname
    shown = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{shown}" + (f":{parts.port}" if parts.port else ""), host


class Ontap:
    def __init__(self, config):
        self.base, self.host = normalize(config.get("url") or config.get("host"))
        self.id = urllib.parse.urlsplit(self.base).netloc
        self.user, self.password = str(config.get("username") or ""), str(config.get("password") or "")
        if not self.user or not self.password:
            raise ValueError("enter the user name and the password")
        self.timeout = int(config.get("timeout") or 30)
        context = ssl.create_default_context()
        if not config.get("verify_tls"):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        self.auth = "Basic " + base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        self.notes = []

    def get(self, path, **query):
        url = self.base + path + ("?" + urllib.parse.urlencode(query, safe=",.") if query else "")
        request = urllib.request.Request(url, headers={"Authorization": self.auth, "Accept": "application/json"})
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                code, raw = response.status, response.read(MAX_BODY)
        except urllib.error.HTTPError as exc:
            code, raw = exc.code, exc.read(MAX_BODY)
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as exc:
            raise ConnectError(f"cannot reach the cluster at {self.host}: {getattr(exc, 'reason', exc)}") from None
        if code in (401, 403):
            raise LoginRefused(f"login refused (HTTP {code}): check the user name and password, and that the user has the readonly role for the http application")
        try:
            data = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            raise ConnectError(f"this does not look like an ONTAP cluster (HTTP {code}, the answer is not JSON)") from None
        if code >= 400:
            error = (data.get("error") or {}) if isinstance(data, dict) else {}
            raise OntapError(f"{path}: {str(error.get('message') or 'HTTP ' + str(code))[:200]}")
        if not isinstance(data, dict):
            raise ConnectError("this does not look like an ONTAP cluster (unexpected answer)")
        return data

    def records(self, path, fields, **query):
        """All records of a collection (follows _links.next)."""
        out, page = [], self.get(path, fields=fields, max_records=PAGE, **query)
        while True:
            out += [r for r in page.get("records") or [] if isinstance(r, dict)]
            nxt = (((page.get("_links") or {}).get("next") or {}).get("href"))
            if not nxt or len(out) >= MAX_RECORDS or not str(nxt).startswith("/api/"):
                return out[:MAX_RECORDS]
            page = self.get(nxt)

    def optional(self, label, path, fields, **query):
        try:
            return self.records(path, fields, **query)
        except LoginRefused:
            raise
        except OntapError as exc:
            self.notes.append(f"{label}: {exc}")
        return []

    def snapshot(self):
        cluster = self.get("/api/cluster", fields="name,uuid,version,management_interfaces")
        nodes = self.records("/api/cluster/nodes", "name,uuid,model,serial_number,version,state,management_interfaces,controller")
        return {
            "cluster": cluster, "nodes": nodes,
            "ports": self.optional("network ports", "/api/network/ethernet/ports", "name,mac_address,node.name,type,state"),
            "aggregates": self.optional("aggregates", "/api/storage/aggregates", "name,uuid,state,node.name,space.block_storage,block_storage.primary.raid_type"),
            "volumes": self.optional("volumes", "/api/storage/volumes", "name,uuid,svm.name,state,type,style,space,nas.path,aggregates"),
            "luns": self.optional("LUNs", "/api/storage/luns", "name,uuid,svm.name,status.state,space,location"),
            "disks": self.optional("disks", "/api/storage/disks", "name,uuid,state,model,bay,shelf,usable_size,container_type,node.name"),
            "clients": self.optional("NFS clients", "/api/protocols/nfs/connected-clients", "client_ip,svm.name,volume.name"),
            "events": self.optional("health events", "/api/support/ems/events", "message.name,message.severity,time,log_message", **{"message.severity": "emergency|alert|error", "order_by": "time desc"}),
            "notes": self.notes,
        }


# ----------------------------------------------------------------------------- mapping to the storage contract
def _ip(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 and not addr.is_unspecified and not addr.is_loopback else None


def _mac(value):
    text = str(value or "").strip().lower().replace("-", ":")
    return text if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", text) and text != "00:00:00:00:00:00" else None


def _int(value):
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0 else None


def _text(value, limit=100):
    return str(value or "").strip()[:limit]


def _get(d, *keys):
    for k in keys:
        d = d.get(k) if isinstance(d, dict) else None
    return d


def worst(*levels):
    return max(levels, key=lambda x: RANK.get(x, 0)) if levels else "unknown"


def _stamp(value):
    try:
        when = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_storage(snapshot, connect_host=""):
    cluster = snapshot["cluster"]
    cid = _text(cluster.get("uuid") or cluster.get("name") or "cluster")
    version = _text(_get(cluster, "version", "full"), 60)
    mgmt = _ip(connect_host) or next((_ip(_get(i, "ip", "address")) for i in cluster.get("management_interfaces") or [] if _ip(_get(i, "ip", "address"))), None)
    mac_of_node = {}
    for port in snapshot["ports"]:
        node, mac = _get(port, "node", "name"), _mac(port.get("mac_address"))
        if node and mac and (node not in mac_of_node or str(port.get("name")) == "e0M"):
            mac_of_node[node] = mac
    controllers, alerts, level = [], [], "ok"
    for node in snapshot["nodes"]:
        name = _text(node.get("name") or node.get("uuid"))
        state = str(node.get("state") or "").lower()
        ctrl = node.get("controller") if isinstance(node.get("controller"), dict) else {}
        health = "critical" if state not in ("up", "") else "ok"
        problems = []
        if _int(_get(ctrl, "failed_fan", "count")):
            problems.append(f"{_get(ctrl, 'failed_fan', 'count')} failed fan(s)")
        if _int(_get(ctrl, "failed_power_supply", "count")):
            problems.append(f"{_get(ctrl, 'failed_power_supply', 'count')} failed power supply(s)")
        if ctrl.get("over_temperature") and str(ctrl.get("over_temperature")).lower() not in ("normal", "ok"):
            problems.append(f"temperature {ctrl.get('over_temperature')}")
        if state not in ("up", ""):
            problems.append(f"node is {state}")
        if problems and health == "ok":
            health = "warning"
        for p in problems:
            alerts.append({"id": f"node/{name}/{p}", "system_id": cid, "severity": "critical" if state not in ("up", "") else "warning", "text": f"Node {name}: {p}"})
        level = worst(level, health)
        node_ip = next((_ip(_get(i, "ip", "address")) for i in node.get("management_interfaces") or [] if _ip(_get(i, "ip", "address"))), None)
        controllers.append({"id": f"node/{_text(node.get('uuid') or name)}", "system_id": cid, "name": name, "ip": node_ip, "mac": mac_of_node.get(name), "online": state in ("up", ""), "health": health})
    first = snapshot["nodes"][0] if snapshot["nodes"] else {}
    pools = []
    for agg in snapshot["aggregates"]:
        space = _get(agg, "space", "block_storage") or {}
        state = str(agg.get("state") or "").lower()
        health = "ok" if state == "online" else "warning" if state in ("restricted", "creating", "relocating", "unknown", "") else "critical"
        pools.append({"id": _text(agg.get("uuid") or agg.get("name")), "system_id": cid, "name": _text(agg.get("name")), "total": _int(space.get("size")), "used": _int(space.get("used")),
                      "avail": _int(space.get("available")), "health": health, "raid": _text(_get(agg, "block_storage", "primary", "raid_type"), 60)})
        if health != "ok":
            alerts.append({"id": f"aggr/{agg.get('uuid') or agg.get('name')}", "system_id": cid, "severity": health, "text": f"Aggregate {_text(agg.get('name'))} is {state or 'in an unknown state'}"})
        level = worst(level, health)
    pool_ids = {_text(a.get("name")): _text(a.get("uuid") or a.get("name")) for a in snapshot["aggregates"]}
    clients = {}
    for c in snapshot["clients"]:
        ip, key = _ip(c.get("client_ip")), (_get(c, "svm", "name"), _get(c, "volume", "name"))
        if ip and key[1]:
            clients.setdefault(key, []).append(ip)
    volumes = []
    for vol in snapshot["volumes"]:
        name, svm = _text(vol.get("name"), 200), _get(vol, "svm", "name") or ""
        if str(vol.get("type") or "").lower() == "dp" or name == "vol0" or name.endswith("_root"):
            continue
        state = str(vol.get("state") or "").lower()
        aggs = [a.get("name") for a in vol.get("aggregates") or [] if isinstance(a, dict)]
        space = vol.get("space") if isinstance(vol.get("space"), dict) else {}
        volumes.append({"id": f"vol/{_text(vol.get('uuid') or name)}", "system_id": cid, "pool_id": pool_ids.get(aggs[0]) if len(aggs) == 1 else None, "name": f"{svm}:{name}" if svm else name,
                        "kind": "volume", "protocol": "nas" if _get(vol, "nas", "path") else "", "size": _int(space.get("size")), "used": _int(space.get("used")),
                        "health": "ok" if state in ("online", "") else "warning", "clients": clients.get((svm, vol.get("name")), [])})
    for lun in snapshot["luns"]:
        space = lun.get("space") if isinstance(lun.get("space"), dict) else {}
        state = str(_get(lun, "status", "state") or "").lower()
        volumes.append({"id": f"lun/{_text(lun.get('uuid') or lun.get('name'))}", "system_id": cid, "pool_id": None, "name": _text(lun.get("name"), 200), "kind": "lun", "protocol": "iscsi/fc",
                        "size": _int(space.get("size")), "used": _int(space.get("used")), "health": "ok" if state in ("online", "") else "warning", "clients": []})
    disks = []
    for d in snapshot["disks"]:
        state, container = str(d.get("state") or "").lower(), str(d.get("container_type") or "").lower()
        mapped = "failed" if state in ("broken", "failed") or container == "broken" else "degraded" if state in ("unfail", "offline", "removed") else "spare" if container == "spare" else "ok" if state in ("present", "") else "unknown"
        disks.append({"id": _text(d.get("uuid") or d.get("name")), "system_id": cid, "name": _text(d.get("name")), "slot": _text(f"{_get(d, 'shelf', 'uid')}.{d.get('bay')}" if _get(d, "shelf", "uid") is not None and d.get("bay") is not None else d.get("bay"), 40),
                      "model": _text(d.get("model")), "size": _int(d.get("usable_size")), "state": mapped})
        if mapped == "failed":
            alerts.append({"id": f"disk/{d.get('uuid') or d.get('name')}", "system_id": cid, "severity": "critical", "text": f"Disk {_text(d.get('name'))}: failed"})
            level = worst(level, "warning")
    cutoff = datetime.now(timezone.utc) - timedelta(days=1)
    for ev in snapshot["events"][:50]:
        at = _stamp(ev.get("time"))
        if at and datetime.strptime(at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) < cutoff:
            continue
        sev = str(_get(ev, "message", "severity") or "").lower()
        alerts.append({"id": f"ems/{_get(ev, 'message', 'name')}/{ev.get('time')}", "system_id": cid, "severity": "critical" if sev in ("emergency", "alert") else "warning",
                       "text": _text(ev.get("log_message") or _get(ev, "message", "name"), 300), "at": at})
    system = {"id": cid, "name": _text(cluster.get("name") or cid), "ip": mgmt, "vendor": "NetApp", "model": _text(first.get("model")), "version": version, "serial": _text(first.get("serial_number"), 60),
              "online": True, "health": level, "warnings": list(snapshot["notes"])[:5]}
    return {"systems": [system], "controllers": controllers, "pools": pools, "volumes": volumes, "disks": disks, "alerts": alerts[:200]}


# ----------------------------------------------------------------------------- settings and entry points
def _servers(config):
    rows = config.get("servers")
    if not isinstance(rows, list):
        return [config]
    out = [{"url": r.get("host"), "username": r.get("username"), "password": r.get("password"), "verify_tls": config.get("verify_tls"), "timeout": config.get("timeout")}
           for r in rows if isinstance(r, dict) and (r.get("host") or r.get("username"))]
    if not out:
        raise ValueError("enter the address, user name and password of at least one cluster")
    return out


def _each(config, work):
    servers = _servers(config)
    results = []
    for one in servers:
        try:
            results.append(work(one))
        except Exception as exc:  # noqa: BLE001 - the type stays (a refused login must stay recognisable)
            label = urllib.parse.urlsplit(str(one.get("url") or "")).netloc or str(one.get("url") or "") if len(servers) > 1 else ""
            if label and exc.args:
                exc.args = (f"{label}: {exc.args[0]}",) + tuple(exc.args[1:])
            raise
    return results


def _fetch_one(one):
    client = Ontap(one)
    snapshot = client.snapshot()
    return to_storage(snapshot, client.host), snapshot


def test(config):
    def one(row):
        out, snapshot = _fetch_one(row)
        s = out["systems"][0]
        message = (f"Connected to cluster {s['name']} (ONTAP {s['version'] or '?'}): {len(out['controllers'])} node(s), {len(out['pools'])} aggregate(s), "
                   f"{len(out['volumes'])} volume(s)/LUN(s), {len(out['disks'])} disk(s), health {s['health']}")
        if snapshot["notes"]:
            message += ". Not available: " + "; ".join(snapshot["notes"][:5])
        return message
    messages = _each(config, one)
    return {"message": messages[0] if len(messages) == 1 else f"{len(messages)} clusters answered. " + " | ".join(messages)}


def fetch(config):
    merged = {"systems": [], "controllers": [], "pools": [], "volumes": [], "disks": [], "alerts": []}
    for n, (out, _) in enumerate(_each(config, _fetch_one)):
        prefix = f"{n}-" if n else ""
        for key in merged:
            for item in out[key]:
                item = dict(item, id=prefix + item["id"])
                if key != "systems":
                    item["system_id"] = prefix + item["system_id"]
                    if item.get("pool_id"):
                        item["pool_id"] = prefix + item["pool_id"]
                merged[key].append(item)
    return merged


# ----------------------------------------------------------------------------- diagnostic (for the plugin's author)
KEEP_WORDS = {"state", "type", "style", "container_type", "raid_type", "severity", "status"}


def describe(value, key=""):
    """The shape of a value: types and sizes, never the content (except a few harmless enumerations)."""
    if isinstance(value, dict):
        return {k: describe(v, k) for k, v in value.items() if k != "_links"}
    if isinstance(value, list):
        return [describe(v, key) for v in value[:2]] + ([f"... {len(value)} items"] if len(value) > 2 else [])
    if isinstance(value, bool) or value is None:
        return value
    if key in KEEP_WORDS and isinstance(value, str) and len(value) < 30:
        return value
    if isinstance(value, (int, float)):
        return f"<number {'negative' if value < 0 else 'positive' if value > 0 else 'zero'}, {len(str(abs(value)))} digits>"
    if isinstance(value, str):
        if re.fullmatch(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", value):
            return "<mac>"
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value):
            return "<ipv4>"
        return f"<text {len(value)} chars>"
    return f"<{type(value).__name__}>"


def _problem(exc, server=None):
    """The error text for a diagnostic report, without any server address (URL, IP address, host:port or host name)."""
    text = str(exc)
    if server is not None:
        for secret in (getattr(server, "id", ""), getattr(server, "base", ""), getattr(server, "host", "")):
            if secret:
                text = text.replace(secret, "<url>")
    text = re.sub(r"https?://\S+", "<url>", text)
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<url>", text)
    text = re.sub(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*:\d{2,5}\b", "<url>", text)
    text = re.sub(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", "<url>", text)
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What this cluster answers, described by field names and types, and what the plugin made of it (no names, serials, MACs or IPs)."""
    client = Ontap(_servers(config)[0])
    report = {"steps": {}}
    for name, path, fields in (("cluster", "/api/cluster", "name,uuid,version,management_interfaces"), ("nodes", "/api/cluster/nodes", "name,uuid,model,serial_number,version,state,management_interfaces,controller"),
                               ("aggregates", "/api/storage/aggregates", "name,uuid,state,node.name,space.block_storage,block_storage.primary.raid_type"),
                               ("volumes", "/api/storage/volumes", "name,uuid,svm.name,state,type,style,space,nas.path,aggregates"),
                               ("disks", "/api/storage/disks", "name,uuid,state,model,bay,shelf,usable_size,container_type,node.name"),
                               ("nfs_clients", "/api/protocols/nfs/connected-clients", "client_ip,svm.name,volume.name"),
                               ("events", "/api/support/ems/events", "message.name,message.severity,time,log_message")):
        try:
            data = client.get(path, fields=fields, max_records=2)
            report["steps"][name] = {"ok": True, "shape": describe(data)}
        except LoginRefused:
            raise
        except Exception as exc:  # noqa: BLE001 - the point is to record what failed
            report["steps"][name] = {"ok": False, "error": _problem(exc, client)}
    try:
        client.notes = []
        snapshot = client.snapshot()
        out = to_storage(snapshot, client.host)
        report["result"] = {"nodes": len(out["controllers"]), "nodes_with_mac": sum(1 for c in out["controllers"] if c["mac"]), "nodes_with_ip": sum(1 for c in out["controllers"] if c["ip"]),
                            "aggregates": len(out["pools"]), "volumes": len(out["volumes"]), "volumes_with_clients": sum(1 for v in out["volumes"] if v["clients"]),
                            "disks": len(out["disks"]), "alerts": len(out["alerts"]), "health": out["systems"][0]["health"], "not_available": [_problem(RuntimeError(n), client) for n in snapshot["notes"]]}
    except Exception as exc:  # noqa: BLE001
        report["error"] = _problem(exc, client)
    return report
