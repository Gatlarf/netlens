"""Rockstor plugin (kind "hypervisor"): a Rockstor NAS as a host, with the Docker containers of its installed Rock-ons as guests.

Talks to Rockstor's REST API over HTTPS, read-only (HTTP Basic authentication, which every Rockstor API view accepts):

    GET /api/appliances            the name and address of the NAS
    GET /api/network/devices       its network cards (with MAC addresses)
    GET /api/network/connections   the addresses of those cards
    GET /api/rockons               Rock-ons: name, version, state (installed, ...) and status (started, stopped, ...)
    GET /api/rockons/docker/containers/<id>   the Docker containers of one Rock-on
    GET /api/rockons/ports/<id>               the ports it publishes
    GET /api/pools, /api/disks, /api/shares   Btrfs pools with their health, disks and shares (the Storage page)

Standard library only. A refused login is reported with `auth_failed` so Netlens stops retrying until the user acts.
"""

import base64
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAX_BODY = 8 * 1024 * 1024
PAGE = 1000
MAX_ROCKONS = 120
STATUS = {"started": "running", "stopped": "stopped", "pending_start": "starting", "pending_stop": "stopping", "start_failed": "failed", "stop_failed": "failed"}


class RockstorError(Exception):
    pass


class ConnectError(RockstorError):
    """The NAS could not be reached (not a login problem)."""


class LoginRefused(RockstorError):
    auth_failed = True


def normalize(url):
    text = str(url or "").strip()
    if not text:
        raise ValueError("enter the address of the Rockstor NAS (for example https://192.168.0.30)")
    if "://" not in text:
        text = "https://" + text
    parts = urllib.parse.urlsplit(text)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ValueError("the address must start with https:// (or http://) and name the NAS")
    host = parts.hostname
    shown = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{shown}" + (f":{parts.port}" if parts.port else ""), host


class Rockstor:
    def __init__(self, config):
        self.base, self.host = normalize(config.get("url") or config.get("host"))
        self.id = urllib.parse.urlsplit(self.base).netloc
        user, password = str(config.get("username") or ""), str(config.get("password") or "")
        if not user or not password:
            raise ValueError("enter the user name and the password")
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self.verify = bool(config.get("verify_tls"))
        self.timeout = int(config.get("timeout") or 30)
        context = ssl.create_default_context()
        if not self.verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))

    def get(self, path, paged=True):
        url = self.base + path + (("&" if "?" in path else "?") + f"page_size={PAGE}" if paged else "")
        request = urllib.request.Request(url, headers={"Authorization": self.auth, "Accept": "application/json"})
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(MAX_BODY)
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise LoginRefused("login refused: check the user name and password (the user needs to exist in Rockstor; an administrator account is the safe choice)") from None
            raise ConnectError(f"the NAS answered with HTTP {exc.code} for {path.split('?')[0]} (is this a Rockstor NAS?)") from None
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as exc:
            raise ConnectError(f"cannot reach the Rockstor NAS at {self.host}: {getattr(exc, 'reason', exc)}") from None
        try:
            data = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            raise ConnectError("this does not look like Rockstor (the answer is not JSON)") from None
        return data

    def listing(self, path):
        data = self.get(path)
        if isinstance(data, dict) and isinstance(data.get("results"), list):
            data = data["results"]
        return [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []

    def optional(self, notes, label, path):
        try:
            return self.listing(path)
        except LoginRefused:
            raise
        except RockstorError as exc:
            notes.append(f"{label}: {exc}")
            return []

    def snapshot(self):
        notes = []
        appliances = self.listing("/api/appliances")                  # also proves the login works and that this is Rockstor
        devices = self.optional(notes, "network cards", "/api/network/devices")
        connections = self.optional(notes, "network addresses", "/api/network/connections")
        rockons = self.optional(notes, "Rock-ons", "/api/rockons")
        storage = {"pools": self.optional(notes, "pools", "/api/pools"), "disks": self.optional(notes, "disks", "/api/disks"), "shares": self.optional(notes, "shares", "/api/shares")}
        containers, ports, failed = {}, {}, 0
        for rockon in [r for r in rockons if str(r.get("state") or "") == "installed"][:MAX_ROCKONS]:
            rid = rockon.get("id")
            if not isinstance(rid, int) or failed >= 3:
                continue
            try:
                containers[rid] = self.listing(f"/api/rockons/docker/containers/{rid}")
                ports[rid] = self.listing(f"/api/rockons/ports/{rid}")
            except LoginRefused:
                raise
            except RockstorError as exc:
                failed += 1
                if failed == 1:
                    notes.append(f"Rock-on details: {exc}")
        return {"appliances": appliances, "devices": devices, "connections": connections, "rockons": rockons, "containers": containers, "ports": ports, "storage": storage, "notes": notes}


# ----------------------------------------------------------------------------- turning Rockstor's answers into Netlens' format
def _mac(value):
    text = str(value or "").strip().lower().replace("-", ":")
    return text if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", text) and text != "00:00:00:00:00:00" else None


def _ipv4(value):
    m = re.match(r"\s*(\d{1,3}(?:\.\d{1,3}){3})", str(value or ""))
    return m.group(1) if m else None


def _int(value):
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0 else None


def _clean(details):
    return {k: v for k, v in details.items() if v not in (None, "", [])}


def _host(snapshot, connect_host):
    me = next((a for a in snapshot["appliances"] if a.get("current_appliance")), snapshot["appliances"][0] if snapshot["appliances"] else {})
    name = str(me.get("hostname") or "").strip()
    addresses = {}                                              # connection id -> its IPv4 addresses
    for c in snapshot["connections"]:
        ips = [_ipv4(x) for x in str(c.get("ipv4_addresses") or "").split(",")]
        addresses[c.get("id")] = [x for x in ips if x]
    ip = connect_host if _ipv4(connect_host) and not connect_host.startswith("127.") else _ipv4(me.get("ip"))
    host = {"id": (name or connect_host).lower(), "name": name or connect_host, "online": True}
    mac = None
    for d in snapshot["devices"]:
        if _mac(d.get("mac")) and ip and ip in addresses.get(d.get("connection"), []):
            mac = _mac(d["mac"])
            break
    if ip:
        host["ip"] = ip
    if mac:
        host["mac"] = mac
    return host


def to_hypervisor(snapshot, connect_host=""):
    host = _host(snapshot, connect_host)
    guests, by_id = [], {r.get("id"): r for r in snapshot["rockons"]}
    for rid, items in snapshot["containers"].items():
        rockon = by_id.get(rid, {})
        status = STATUS.get(str(rockon.get("status") or "").lower(), str(rockon.get("status") or "unknown").lower())
        by_container = {}
        for p in snapshot["ports"].get(rid, []):
            by_container.setdefault(p.get("container"), []).append(p)
        for c in items:
            name = str(c.get("name") or "").strip()
            if not name:
                continue
            ports = [{"container_port": _int(p.get("containerp")), "host_port": _int(p.get("hostp")), "proto": str(p.get("protocol") or "tcp").lower(), "bind": ""}
                     for p in by_container.get(c.get("id"), []) if _int(p.get("hostp")) and p.get("publish", True)]
            details = {"project": str(rockon.get("name") or "")[:80], "version": str(rockon.get("version") or "")[:60], "ports": ports[:100]}
            details["exposed"] = True if ports else None
            guests.append({"id": f"container:{name}", "name": name, "kind": "container", "host_id": host["id"], "status": status,
                           "macs": [], "ips": [], "details": _clean(details)})
    seen, unique = set(), []
    for g in guests:
        if g["id"] not in seen:
            seen.add(g["id"])
            unique.append(g)
    return {"hosts": [host], "guests": unique}


# ----------------------------------------------------------------------------- storage (pools, disks, shares)
RANK = {"unknown": 0, "ok": 1, "warning": 2, "critical": 3}


def _kb(value):
    """Rockstor sizes are in KiB."""
    try:
        number = int(float(str(value))) * 1024
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def to_storage(snapshot, connect_host=""):
    """The storage part of the output: Btrfs pools, their disks and the shares (the Storage page)."""
    host = _host(snapshot, connect_host)
    sid = host["id"]
    data = snapshot.get("storage") or {}
    pools, disks, volumes, alerts, level = [], [], [], [], "ok"
    for pool in data.get("pools") or []:
        name = str(pool.get("name") or "")
        if not name:
            continue
        problems = []
        if pool.get("is_mounted") is False:
            problems.append("not mounted")
        if pool.get("has_missing_dev") or (_kb(pool.get("dev_missing_count")) or 0):
            problems.append("a disk is missing")
        if pool.get("redundancy_exceeded"):
            problems.append("more disks failed than the RAID level survives")
        health = "critical" if problems else "warning" if pool.get("dev_stats_ok") is False else "ok"
        if health == "warning":
            problems.append("disk errors were counted")
        total = _kb(pool.get("size"))
        free = _kb(pool.get("free"))
        pools.append({"id": f"pool:{pool.get('uuid') or name}", "system_id": sid, "name": name[:100], "total": total, "used": total - free if total is not None and free is not None else None,
                      "avail": free, "health": health, "raid": str(pool.get("data_raid") or pool.get("raid") or "")[:60]})
        for text in problems:
            alerts.append({"id": f"pool:{name}:{text}", "system_id": sid, "severity": "critical" if health == "critical" else "warning", "text": f"Pool {name}: {text}"})
        level = max(level, health, key=lambda x: RANK[x])
    for disk in data.get("disks") or []:
        name = str(disk.get("name") or "")
        if not name:
            continue
        state = "failed" if disk.get("offline") else "ok"
        disks.append({"id": f"disk:{disk.get('serial') or name}", "system_id": sid, "name": name[:100], "slot": str(disk.get("pool_name") or "")[:40], "model": str(disk.get("model") or disk.get("vendor") or "")[:100],
                      "size": _kb(disk.get("size")), "state": state})
        if state == "failed":
            alerts.append({"id": f"disk:{disk.get('serial') or name}", "system_id": sid, "severity": "critical", "text": f"Disk {name} is offline"})
            level = "critical"
    pool_ids = {p["name"]: p["id"] for p in pools}
    for share in data.get("shares") or []:
        name = str(share.get("name") or "")
        if not name:
            continue
        pool_name = (share.get("pool") or {}).get("name") if isinstance(share.get("pool"), dict) else share.get("pool_name")
        exports = share.get("nfs_exports") or []
        volumes.append({"id": f"share:{share.get('id', name)}", "system_id": sid, "pool_id": pool_ids.get(pool_name), "name": name[:200], "kind": "share", "protocol": "nfs" if exports else "",
                        "size": _kb(share.get("size")), "used": _kb(share.get("r_usage")), "health": "ok" if share.get("is_mounted") is not False else "warning", "clients": []})
    system = {"id": sid, "name": host["name"], "ip": host.get("ip"), "vendor": "Rockstor", "model": "", "version": "", "serial": "", "online": True, "health": level if pools or disks else "unknown", "warnings": []}
    controllers = [{"id": f"{sid}:host", "system_id": sid, "name": host["name"], "ip": host.get("ip"), "mac": host.get("mac"), "online": True, "health": "unknown"}] if host.get("ip") or host.get("mac") else []
    return {"systems": [system], "controllers": controllers, "pools": pools, "volumes": volumes, "disks": disks, "alerts": alerts[:200]}


# ----------------------------------------------------------------------------- settings and entry points
def _servers(config):
    rows = config.get("servers")
    if not isinstance(rows, list):
        return [config]
    out = [{"url": r.get("host"), "username": r.get("username"), "password": r.get("password"), "verify_tls": config.get("verify_tls"), "timeout": config.get("timeout")}
           for r in rows if isinstance(r, dict) and (r.get("host") or r.get("username"))]
    if not out:
        raise ValueError("enter the address, user name and password of at least one Rockstor NAS")
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
    client = Rockstor(one)
    snapshot = client.snapshot()
    out = to_hypervisor(snapshot, client.host)
    storage = to_storage(snapshot, client.host)
    if storage["pools"] or storage["disks"]:
        out["storage"] = storage
    return out, snapshot


def test(config):
    def one(row):
        out, snapshot = _fetch_one(row)
        installed = sum(1 for r in snapshot["rockons"] if r.get("state") == "installed")
        message = f"Connected to {out['hosts'][0]['name']}: {installed} installed Rock-on(s), {len(out['guests'])} container(s)"
        if snapshot["notes"]:
            message += ". Not available: " + "; ".join(snapshot["notes"])
        return message
    messages = _each(config, one)
    return {"message": messages[0] if len(messages) == 1 else f"{len(messages)} Rockstor NAS systems answered. " + " | ".join(messages)}


def fetch(config):
    results = [r[0] for r in _each(config, _fetch_one)]
    if len(results) == 1:
        return results[0]
    hosts, guests, taken = [], [], set()
    storage = {k: [] for k in ("systems", "controllers", "pools", "volumes", "disks", "alerts")}
    for out in results:
        for key in storage:
            storage[key] += (out.get("storage") or {}).get(key, [])
        hosts += out["hosts"]
        for g in out["guests"]:
            if g["id"] in taken:
                g = {**g, "id": f"{g['host_id']}/{g['id']}"}
            taken.add(g["id"])
            guests.append(g)
    out = {"hosts": hosts, "guests": guests}
    if storage["systems"]:
        out["storage"] = storage
    return out


# ----------------------------------------------------------------------------- diagnostic (for the plugin's author)
KEEP_WORDS = {"state", "status", "protocol", "publish", "current_appliance", "dtype", "ctype", "ipv4_method", "raid", "data_raid", "metadata_raid", "is_mounted", "offline", "has_missing_dev", "dev_stats_ok", "redundancy_exceeded"}


def describe(value, key=""):
    """The shape of a value: types and sizes, never the content (except a few harmless enumerations)."""
    if isinstance(value, dict):
        return {k: describe(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [describe(v, key) for v in value[:2]] + ([f"... {len(value)} items"] if len(value) > 2 else [])
    if isinstance(value, bool) or value is None:
        return value
    if key in KEEP_WORDS and isinstance(value, str) and len(value) < 24:
        return value
    if isinstance(value, (int, float)):
        return f"<number {'negative' if value < 0 else 'positive' if value > 0 else 'zero'}, {len(str(abs(value)))} digits>"
    if isinstance(value, str):
        if re.fullmatch(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", value):
            return "<mac>"
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}(/\d+)?", value):
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
    """What this Rockstor answers, described by field names and types, and what the plugin made of it (no names, MACs or IPs)."""
    client = Rockstor(_servers(config)[0])
    report = {"steps": {}}
    first_rockon = None
    for name, path in (("appliances", "/api/appliances"), ("network_devices", "/api/network/devices"), ("network_connections", "/api/network/connections"), ("rockons", "/api/rockons"),
                       ("pools", "/api/pools"), ("disks", "/api/disks"), ("shares", "/api/shares")):
        try:
            data = client.get(path)
            report["steps"][name] = {"ok": True, "shape": describe(data)}
            if name == "rockons":
                rows = data.get("results") if isinstance(data, dict) else data
                first_rockon = next((r.get("id") for r in rows or [] if isinstance(r, dict) and r.get("state") == "installed"), None)
        except Exception as exc:  # noqa: BLE001 - the point is to record what failed
            report["steps"][name] = {"ok": False, "error": _problem(exc, client)}
            if isinstance(exc, LoginRefused):
                raise
    if first_rockon is not None:
        for name, path in (("rockon_containers", f"/api/rockons/docker/containers/{first_rockon}"), ("rockon_ports", f"/api/rockons/ports/{first_rockon}")):
            try:
                report["steps"][name] = {"ok": True, "shape": describe(client.get(path))}
            except Exception as exc:  # noqa: BLE001
                report["steps"][name] = {"ok": False, "error": _problem(exc, client)}
    try:
        snapshot = client.snapshot()
        out = to_hypervisor(snapshot, client.host)
        report["result"] = {"host_has_ip": "ip" in out["hosts"][0], "host_has_mac": "mac" in out["hosts"][0], "guests": len(out["guests"]),
                            "rockons": len(snapshot["rockons"]), "not_available": [_problem(RuntimeError(n), client) for n in snapshot["notes"]]}
        st = to_storage(snapshot, client.host)
        report["result"]["storage"] = {"pools": len(st["pools"]), "disks": len(st["disks"]), "shares": len(st["volumes"]), "alerts": len(st["alerts"]), "health": st["systems"][0]["health"]}
    except Exception as exc:  # noqa: BLE001
        report["error"] = _problem(exc, client)
    return report
