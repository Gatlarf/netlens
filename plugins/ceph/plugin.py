"""Ceph plugin (kind "storage"): a Ceph cluster (cephadm, Rook, Proxmox VE Ceph, MicroCeph with the dashboard) with its hosts, pools, OSDs, CephFS file
systems, RBD images and health checks.

Talks to the Ceph Manager's dashboard REST API, read-only (a user with the read-only role):

    POST /api/auth                         user name and password -> a token (sent as Bearer afterwards); POST /api/auth/logout at the end
    GET  /api/health/minimal               health status and checks, capacity, monitors, hosts, pools
    GET  /api/monitor                      cluster id and monitor addresses
    GET  /api/summary                      Ceph version
    GET  /api/host                         hosts: name, address, status
    GET  /api/osd                          OSDs: state (up/in), size, host, device class
    GET  /api/pool?stats=true              pools: replicas or erasure coding, bytes used and available
    GET  /api/cephfs, /api/cephfs/<id>/clients    file systems and the addresses of the hosts that mounted them
    GET  /api/block/image  (API version 2.0)      RBD images

Standard library only. A refused login is reported with `auth_failed`. Everything but the health report is optional.
"""

import ipaddress
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAX_BODY = 16 * 1024 * 1024
MAX_ITEMS = 2000
RANK = {"unknown": 0, "ok": 1, "warning": 2, "critical": 3}
STATUS = {"HEALTH_OK": "ok", "HEALTH_WARN": "warning", "HEALTH_ERR": "critical"}


class CephError(Exception):
    pass


class ConnectError(CephError):
    """The manager could not be reached (not a login problem)."""


class LoginRefused(CephError):
    auth_failed = True


def normalize(url):
    text = str(url or "").strip()
    if not text:
        raise ValueError("enter the address of the Ceph dashboard (for example https://192.168.0.90:8443)")
    if "://" not in text:
        text = "https://" + text
    parts = urllib.parse.urlsplit(text)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ValueError("the address must start with https:// and name the dashboard")
    host = parts.hostname
    shown = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{shown}" + (f":{parts.port}" if parts.port else ""), host


class Ceph:
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
        self.token = None
        self.notes = []

    def call(self, path, body=None, version="1.0"):
        headers = {"Accept": f"application/vnd.ceph.api.v{version}+json", "Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method="POST" if body is not None else "GET")
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                code, raw = response.status, response.read(MAX_BODY)
        except urllib.error.HTTPError as exc:
            code, raw = exc.code, exc.read(MAX_BODY)
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as exc:
            raise ConnectError(f"cannot reach the Ceph dashboard at {self.host}: {getattr(exc, 'reason', exc)}") from None
        try:
            answer = json.loads(raw.decode("utf-8", "replace") or "null")
        except ValueError:
            raise ConnectError(f"this does not look like the Ceph dashboard (HTTP {code}, the answer is not JSON)") from None
        if code in (401, 403) or (isinstance(answer, dict) and answer.get("code") == "invalid_credentials"):
            raise LoginRefused("login refused: check the user name and password (the user needs the read-only role)")
        if code >= 400:
            detail = str((answer or {}).get("detail") or f"HTTP {code}")[:200] if isinstance(answer, dict) else f"HTTP {code}"
            raise CephError(f"{path}: {detail}")
        return answer

    def open(self):
        answer = self.call("/api/auth", {"username": self.user, "password": self.password})
        token = answer.get("token") if isinstance(answer, dict) else None
        if not token:
            raise LoginRefused("login refused: " + str((answer or {}).get("detail") or "no token returned") if isinstance(answer, dict) else "login refused")
        self.token = token

    def close(self):
        if self.token:
            try:
                self.call("/api/auth/logout", {})
            except CephError:
                pass
        self.token = None

    def optional(self, label, path, version="1.0"):
        try:
            return self.call(path, version=version)
        except LoginRefused:
            raise
        except CephError as exc:
            self.notes.append(f"{label}: {exc}")
        return None

    def snapshot(self):
        health = self.call("/api/health/minimal")
        if not isinstance(health, dict) or "health" not in health:
            raise CephError("this does not look like the Ceph dashboard (no health report)")
        summary = self.optional("version", "/api/summary") or {}
        monitor = self.optional("monitors", "/api/monitor")
        hosts = self.optional("hosts", "/api/host")
        osds = self.optional("OSDs", "/api/osd")
        pools = self.optional("pools", "/api/pool?stats=true")
        filesystems = self.optional("CephFS", "/api/cephfs")
        clients = {}
        for fs in (filesystems if isinstance(filesystems, list) else [])[:16]:
            fid = fs.get("id")
            if isinstance(fid, int):
                found = self.optional("CephFS clients", f"/api/cephfs/{fid}/clients")
                clients[fid] = (found or {}).get("data") if isinstance(found, dict) else []
        images = self.optional("RBD images", "/api/block/image", version="2.0")
        return {"health": health, "monitor": monitor if isinstance(monitor, dict) else {}, "summary": summary if isinstance(summary, dict) else {}, "hosts": hosts if isinstance(hosts, list) else [], "osds": osds if isinstance(osds, list) else [],
                "pools": pools if isinstance(pools, list) else [], "filesystems": filesystems if isinstance(filesystems, list) else [], "clients": clients,
                "images": images if isinstance(images, list) else [], "notes": self.notes}


# ----------------------------------------------------------------------------- mapping to the storage contract
def _ip(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 and not addr.is_unspecified and not addr.is_loopback else None


def _int(value):
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0 else None


def _text(value, limit=100):
    return str(value or "").strip()[:limit]


def _latest(stat):
    return _int(stat.get("latest")) if isinstance(stat, dict) else _int(stat)


def worst(*levels):
    return max(levels, key=lambda x: RANK.get(x, 0)) if levels else "unknown"


def to_storage(snapshot, connect_host=""):
    health = snapshot["health"]
    status = STATUS.get(str(_get(health, "health", "status") or ""), "unknown")
    monmap = _get(snapshot["monitor"], "mon_status", "monmap") or {}
    fsid = _text(monmap.get("fsid") or _get(health, "mon_status", "monmap", "fsid") or "ceph", 60)
    version = _text(snapshot["summary"].get("version"), 60)
    version = re.sub(r"^ceph version\s+", "", version)
    version = re.sub(r"\s*\(.*$", "", version)
    hosts = snapshot["hosts"]
    ip = _ip(connect_host) or next((_ip(h.get("addr")) for h in hosts if _ip(h.get("addr"))), None)
    alerts = []
    for chk in _get(health, "health", "checks") or []:
        if not isinstance(chk, dict) or chk.get("muted"):
            continue
        sev = "critical" if chk.get("severity") == "HEALTH_ERR" else "warning"
        alerts.append({"id": f"check/{chk.get('type')}", "system_id": fsid, "severity": sev, "text": _text(_get(chk, "summary", "message") or chk.get("type"), 300)})
    controllers = []
    for h in hosts:
        state = str(h.get("status") or "").lower()
        controllers.append({"id": f"host/{_text(h.get('hostname'))}", "system_id": fsid, "name": _text(h.get("hostname")), "ip": _ip(h.get("addr")), "mac": None,
                            "online": state not in ("offline",), "health": "warning" if state in ("maintenance", "offline") else "ok"})
    seen_ips = {c["ip"] for c in controllers if c["ip"]}
    for mon in monmap.get("mons") or []:
        mip = _ip(str(mon.get("addr") or "").split("/")[0].rsplit(":", 1)[0])
        if mip and mip not in seen_ips:
            seen_ips.add(mip)
            controllers.append({"id": f"mon/{_text(mon.get('name'))}", "system_id": fsid, "name": f"mon.{_text(mon.get('name'))}", "ip": mip, "mac": None, "online": True, "health": "ok"})
    disks = []
    for o in snapshot["osds"]:
        up, inn = bool(o.get("up")), bool(o.get("in"))
        state = "ok" if up and inn else "degraded" if up else "failed" if inn else "degraded"
        host = _get(o, "host", "name") or ""
        disks.append({"id": f"osd.{o.get('osd', o.get('id'))}", "system_id": fsid, "name": f"osd.{o.get('osd', o.get('id'))}", "slot": _text(host, 40), "model": _text(o.get("device_class") or _get(o, "tree", "device_class"), 100),
                      "size": _int(_get(o, "osd_stats", "statfs", "total")), "state": state})
        if state != "ok":
            alerts.append({"id": f"osd/{o.get('osd')}", "system_id": fsid, "severity": "critical" if state == "failed" else "warning", "text": f"osd.{o.get('osd')} is {'down' if not up else 'out'}"})
    stats = _get(health, "df", "stats") or {}
    pools = []
    if _int(stats.get("total_bytes")):
        pools.append({"id": "raw", "system_id": fsid, "name": "All disks (raw)", "total": _int(stats.get("total_bytes")), "used": _int(stats.get("total_used_raw_bytes")),
                      "avail": _int(stats.get("total_avail_bytes")), "health": "ok", "raid": ""})
    pool_by_name = {}
    for p in snapshot["pools"]:
        st = p.get("stats") or {}
        used, avail = _latest(st.get("bytes_used")), _latest(st.get("max_avail"))
        total = used + avail if used is not None and avail is not None else None
        pid = f"pool/{p.get('pool')}"
        pool_by_name[p.get("pool_name")] = pid
        raid = f"replica {p.get('size')}" if p.get("type") == "replicated" else f"erasure {_text(p.get('erasure_code_profile'), 30)}".strip()
        pools.append({"id": pid, "system_id": fsid, "name": _text(p.get("pool_name")), "total": total, "used": used, "avail": avail, "health": "ok", "raid": _text(raid, 60)})
    volumes = []
    for fs in snapshot["filesystems"]:
        md = fs.get("mdsmap") or {}
        fid = fs.get("id")
        ips = []
        for c in snapshot["clients"].get(fid) or []:
            if _get(c, "auth_name", "type_str") not in (None, "client"):
                continue
            ip = _ip(str(_get(c, "entity", "addr", "addr") or "").rsplit(":", 1)[0])
            if ip and ip not in ips:
                ips.append(ip)
        active = any(str(i.get("state", "")).startswith("up:active") for i in (md.get("info") or {}).values() if isinstance(i, dict))
        volumes.append({"id": f"cephfs/{fid}", "system_id": fsid, "pool_id": None, "name": _text(md.get("fs_name") or f"cephfs {fid}", 200), "kind": "filesystem", "protocol": "cephfs",
                        "size": None, "used": None, "health": "ok" if active else "warning", "clients": ips})
        if not active:
            alerts.append({"id": f"cephfs/{fid}", "system_id": fsid, "severity": "warning", "text": f"CephFS {_text(md.get('fs_name'))} has no active metadata server"})
    for group in snapshot["images"]:
        for img in (group.get("value") if isinstance(group, dict) else None) or []:
            volumes.append({"id": f"rbd/{img.get('unique_id') or img.get('pool_name', '') + '/' + img.get('name', '')}", "system_id": fsid, "pool_id": pool_by_name.get(img.get("pool_name")),
                            "name": _text(f"{img.get('pool_name')}/{img.get('name')}", 200), "kind": "volume", "protocol": "rbd", "size": _int(img.get("size")), "used": _int(img.get("total_disk_usage")),
                            "health": "ok", "clients": []})
    system = {"id": fsid, "name": f"Ceph {fsid[:8]}", "ip": ip, "vendor": "Ceph", "model": "Ceph cluster", "version": version, "serial": "", "online": True, "health": status, "warnings": list(snapshot["notes"])[:5]}
    return {"systems": [system], "controllers": controllers, "pools": pools, "volumes": volumes[:MAX_ITEMS], "disks": disks, "alerts": alerts[:200]}


def _get(d, *keys):
    for k in keys:
        d = d.get(k) if isinstance(d, dict) else None
    return d


# ----------------------------------------------------------------------------- settings and entry points
def _servers(config):
    rows = config.get("servers")
    if not isinstance(rows, list):
        return [config]
    out = [{"url": r.get("host"), "username": r.get("username"), "password": r.get("password"), "verify_tls": config.get("verify_tls"), "timeout": config.get("timeout")}
           for r in rows if isinstance(r, dict) and (r.get("host") or r.get("username"))]
    if not out:
        raise ValueError("enter the address, user name and password of at least one Ceph dashboard")
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
    client = Ceph(one)
    client.open()
    try:
        snapshot = client.snapshot()
    finally:
        client.close()
    return to_storage(snapshot, client.host), snapshot


def test(config):
    def one(row):
        out, snapshot = _fetch_one(row)
        s = out["systems"][0]
        osds = out["disks"]
        message = (f"Connected to {s['name']} (Ceph {s['version'] or '?'}): health {s['health']}, {len(out['controllers'])} host(s), {sum(1 for d in osds if d['state'] == 'ok')}/{len(osds)} OSDs up and in, "
                   f"{len([p for p in out['pools'] if p['id'] != 'raw'])} pool(s), {len(out['volumes'])} file system(s)/image(s)")
        if snapshot["notes"]:
            message += ". Not available: " + "; ".join(snapshot["notes"][:5])
        return message
    messages = _each(config, one)
    return {"message": messages[0] if len(messages) == 1 else f"{len(messages)} clusters answered. " + " | ".join(messages)}


def fetch(config):
    merged = {"systems": [], "controllers": [], "pools": [], "volumes": [], "disks": [], "alerts": []}
    taken = set()
    for out, _ in _each(config, _fetch_one):
        sid = out["systems"][0]["id"]
        prefix = f"{len(taken)}-" if sid in taken else ""
        taken.add(sid)
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
KEEP_WORDS = {"status", "state", "severity", "type", "type_str", "device_class", "operational_status", "mirror_mode"}


def describe(value, key=""):
    """The shape of a value: types and sizes, never the content (except a few harmless enumerations)."""
    if isinstance(value, dict):
        return {k: describe(v, k) for k, v in list(value.items())[:60]}
    if isinstance(value, list):
        return [describe(v, key) for v in value[:2]] + ([f"... {len(value)} items"] if len(value) > 2 else [])
    if isinstance(value, bool) or value is None:
        return value
    if key in KEEP_WORDS and isinstance(value, str) and len(value) < 30:
        return value
    if isinstance(value, (int, float)):
        return f"<number {'negative' if value < 0 else 'positive' if value > 0 else 'zero'}, {len(str(abs(int(value))))} digits>"
    if isinstance(value, str):
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}(:\d+(/\d+)?)?", value):
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
    """What this cluster answers, described by field names and types, and what the plugin made of it (no names, addresses or ids)."""
    client = Ceph(_servers(config)[0])
    client.open()
    report = {"steps": {}}
    try:
        for name, path, version in (("health", "/api/health/minimal", "1.0"), ("monitor", "/api/monitor", "1.0"), ("summary", "/api/summary", "1.0"), ("hosts", "/api/host", "1.0"), ("osds", "/api/osd", "1.0"),
                                    ("pools", "/api/pool?stats=true", "1.0"), ("cephfs", "/api/cephfs", "1.0"), ("rbd", "/api/block/image", "2.0")):
            try:
                data = client.call(path, version=version)
                if name == "monitor" and isinstance(data, dict):
                    data = {"mon_status": {"monmap": {k: v for k, v in (_get(data, "mon_status", "monmap") or {}).items() if k in ("fsid", "epoch", "mons")}}}
                if name == "health" and isinstance(data, dict):
                    data = {k: data.get(k) for k in ("health", "df", "osd_map", "pg_info")}
                if name in ("osds", "cephfs") and isinstance(data, list):
                    data = [{k: v for k, v in item.items() if k not in ("tree", "stats_history", "mdsmap", "osd_stats")} for item in data[:1]]
                report["steps"][name] = {"ok": True, "shape": describe(data)}
            except LoginRefused:
                raise
            except Exception as exc:  # noqa: BLE001 - the point is to record what failed
                report["steps"][name] = {"ok": False, "error": _problem(exc, client)}
        try:
            client.notes = []
            snapshot = client.snapshot()
            out = to_storage(snapshot, client.host)
            report["result"] = {"health": out["systems"][0]["health"], "hosts": len(out["controllers"]), "hosts_with_ip": sum(1 for c in out["controllers"] if c["ip"]), "osds": len(out["disks"]),
                                "pools": len(out["pools"]), "volumes": len(out["volumes"]), "volumes_with_clients": sum(1 for v in out["volumes"] if v["clients"]), "alerts": len(out["alerts"]),
                                "not_available": [_problem(RuntimeError(n), client) for n in snapshot["notes"]]}
        except Exception as exc:  # noqa: BLE001
            report["error"] = _problem(exc, client)
    finally:
        client.close()
    return report
