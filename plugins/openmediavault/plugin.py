"""OpenMediaVault plugin (kind "hypervisor"): an OpenMediaVault NAS as a host, with its Docker containers (the openmediavault-compose
plugin) and its virtual machines (the openmediavault-kvm plugin) as guests.

Talks to OpenMediaVault's JSON-RPC interface, read-only. OMV 6, 7 and 8 use the same calls:

    POST /rpc.php   {"service": "Session", "method": "login", "params": {"username", "password"}}   a session cookie
    System.getInformation          host name, OMV version, kernel, uptime
    Network.enumerateDevices       network cards with address and MAC
    Compose.getContainerList       Docker containers (plugin openmediavault-compose, also with Podman)
    Kvm.getVmList / Kvm.enumerateVmNic   virtual machines and their MAC addresses (plugin openmediavault-kvm)
    FileSystemMgmt.getList, DiskMgmt.enumerateDevices, Smart.getList, Smb.getShareList, Nfs.getShareList   file systems, disks with their S.M.A.R.T.
                          status and the shares (the Storage page)
    Session.logout

Standard library only. A refused login is reported with `auth_failed` so Netlens stops retrying until the user acts. The two
plugin parts are optional: a NAS without them reports no containers or machines, with a note.
"""

import http.cookiejar
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAX_BODY = 16 * 1024 * 1024
MAX_VM_NICS = 60
LIST = {"start": 0, "limit": None}
STATES = {"running": "running", "exited": "stopped", "created": "stopped", "paused": "paused", "restarting": "restarting", "dead": "failed", "removing": "stopped",
          "shut off": "stopped", "shutoff": "stopped", "idle": "running", "in shutdown": "stopping", "crashed": "crashed", "pmsuspended": "paused"}
ETHERNET = {"ethernet", "bond", "bridge", "wifi", "vlan"}


class OmvError(Exception):
    pass


class ConnectError(OmvError):
    """The NAS could not be reached (not a login problem)."""


class LoginRefused(OmvError):
    auth_failed = True


class ServiceMissing(OmvError):
    """This OpenMediaVault does not have the RPC service (the plugin is not installed)."""


def normalize(url):
    text = str(url or "").strip()
    if not text:
        raise ValueError("enter the address of the OpenMediaVault (for example http://192.168.0.60 or https://nas.lan)")
    if "://" not in text:
        text = "http://" + text
    parts = urllib.parse.urlsplit(text)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ValueError("the address must start with http:// or https:// and name the NAS")
    host = parts.hostname
    shown = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{shown}" + (f":{parts.port}" if parts.port else ""), host


class Omv:
    def __init__(self, config):
        self.base, self.host = normalize(config.get("url") or config.get("host"))
        self.id = urllib.parse.urlsplit(self.base).netloc
        self.user, self.password = str(config.get("username") or ""), str(config.get("password") or "")
        if not self.user or not self.password:
            raise ValueError("enter the user name and the password")
        self.verify = bool(config.get("verify_tls"))
        self.timeout = int(config.get("timeout") or 30)
        context = ssl.create_default_context()
        if not self.verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor(self.jar))
        self.session = None

    def _rpc(self, service, method, params=None):
        body = json.dumps({"service": service, "method": method, "params": params, "options": None}).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.session:
            headers["X-OPENMEDIAVAULT-SESSIONID"] = self.session
        request = urllib.request.Request(self.base + "/rpc.php", data=body, headers=headers)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                code, raw = response.status, response.read(MAX_BODY)
        except urllib.error.HTTPError as exc:
            code, raw = exc.code, exc.read(MAX_BODY)
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as exc:
            raise ConnectError(f"cannot reach the OpenMediaVault at {self.host}: {getattr(exc, 'reason', exc)}") from None
        try:
            answer = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            raise ConnectError(f"this does not look like OpenMediaVault (HTTP {code}, the answer is not JSON)") from None
        if not isinstance(answer, dict) or ("response" not in answer and "error" not in answer):
            raise ConnectError("this does not look like OpenMediaVault (unexpected answer)")
        error = answer.get("error")
        if error:
            message = str((error or {}).get("message") or f"HTTP {code}")[:200]
            if "not found" in message and "RPC service" in message:
                raise ServiceMissing(message)
            if code == 401 or "not authenticated" in message.lower():
                raise LoginRefused("the session was refused: " + message)
            raise OmvError(f"{service}.{method}: {message}")
        return answer.get("response")

    def open(self):
        try:
            answer = self._rpc("Session", "login", {"username": self.user, "password": self.password})
        except OmvError as exc:
            if isinstance(exc, (ConnectError, LoginRefused)):
                raise
            raise LoginRefused("login refused: " + str(exc).split(": ", 1)[-1]) from None
        if not isinstance(answer, dict) or not (answer.get("authenticated") is True or answer.get("status") == "authenticated"):
            status = str((answer or {}).get("status") or "") if isinstance(answer, dict) else ""
            raise LoginRefused("login refused" + (f" ({status})" if status else "") + ": check the user name and password (the user needs the web interface administrator role, and no 2-step verification)")
        self.session = str(answer.get("sessionid") or "") or None

    def close(self):
        if self.session is not None or len(self.jar):
            try:
                self._rpc("Session", "logout")
            except OmvError:
                pass
        self.session = None

    def optional(self, notes, label, service, method, params=None):
        """Data from a part that may be missing (a plugin that is not installed) or may fail (Docker stopped): None, with a note."""
        try:
            return self._rpc(service, method, params)
        except ServiceMissing:
            notes.append(f"{label}: not installed on this OpenMediaVault")
        except LoginRefused:
            raise
        except OmvError as exc:
            notes.append(f"{label}: {exc}")
        return None

    def snapshot(self):
        notes = []
        info = self._rpc("System", "getInformation")
        if not isinstance(info, dict):
            raise OmvError("unexpected answer from System.getInformation")
        devices = self.optional(notes, "network cards", "Network", "enumerateDevices")
        containers = self.optional(notes, "Docker containers (openmediavault-compose)", "Compose", "getContainerList", LIST)
        machines = self.optional(notes, "virtual machines (openmediavault-kvm)", "Kvm", "getVmList", LIST)
        rows = _rows(machines)
        nics = {}
        for vm in rows[:MAX_VM_NICS]:
            name = str(vm.get("vmname") or "")
            if not name:
                continue
            try:
                nics[(name, str(vm.get("virttype") or "vm"))] = self._rpc("Kvm", "enumerateVmNic", {"vmname": name, "virttype": str(vm.get("virttype") or "vm")})
            except LoginRefused:
                raise
            except OmvError:
                pass
        storage = {
            "filesystems": _rows(self.optional(notes, "file systems", "FileSystemMgmt", "getList", LIST)),
            "disks": _list(self.optional(notes, "disks", "DiskMgmt", "enumerateDevices")),
            "smart": _rows(self.optional(notes, "S.M.A.R.T. status", "Smart", "getList", LIST)),
            "smb": _rows(self.optional(notes, "SMB shares", "Smb", "getShareList", LIST)),
            "nfs": _rows(self.optional(notes, "NFS shares", "Nfs", "getShareList", LIST)),
        }
        return {"info": info, "devices": devices if isinstance(devices, list) else [], "containers": _rows(containers), "machines": rows, "nics": nics, "storage": storage, "notes": notes}


def _rows(data):
    """OMV's lists come as {"total": n, "data": [...]}."""
    items = data.get("data") if isinstance(data, dict) else data
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


def _list(data):
    return [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []


# ----------------------------------------------------------------------------- turning OMV's answers into Netlens' format
def _mac(value):
    text = str(value or "").strip().lower().replace("-", ":")
    return text if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", text) and text != "00:00:00:00:00:00" else None


def _ipv4(value):
    text = str(value or "").strip()
    return text if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", text) else None


def _int(value):
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0 else None


def _clean(details):
    return {k: v for k, v in details.items() if v not in (None, "", [])}


def _host(snapshot, connect_host):
    info = snapshot["info"]
    name = str(info.get("hostname") or "").strip()
    host = {"id": (name or connect_host).lower(), "name": name or connect_host, "online": True}
    cards = [d for d in snapshot["devices"] if isinstance(d, dict) and _mac(d.get("ether")) and _ipv4(d.get("address"))]
    ip = connect_host if _ipv4(connect_host) and not connect_host.startswith("127.") else None
    chosen = next((d for d in cards if ip and d["address"] == ip), None)
    if chosen is None and not ip:
        chosen = next((d for d in cards if str(d.get("type") or "") in ETHERNET), cards[0] if cards else None)
        ip = chosen["address"] if chosen else None
    if ip:
        host["ip"] = ip
    if chosen:
        host["mac"] = _mac(chosen.get("ether"))
    return host


PORT = re.compile(r"(?:(?P<ip>[0-9.]*|\[[0-9a-fA-F:]*\])?:)?(?P<host>\d+)(?:-\d+)?->(?P<cont>\d+)(?:-\d+)?/(?P<proto>tcp|udp)")


def _ports(text):
    """'<a href=...>0.0.0.0:8080->80/tcp</a><br/>:8080->80/tcp<br/>443/tcp' -> published ports (the IPv6 twin and unpublished ones are dropped)."""
    out, seen = [], set()
    for part in re.split(r"<br\s*/?>|,", str(text or "")):
        plain = re.sub(r"<[^>]+>", "", part).strip()
        m = PORT.search(plain)
        if not m:
            continue
        key = (int(m.group("host")), m.group("proto"))
        if key in seen:
            continue
        seen.add(key)
        bind = (m.group("ip") or "").strip("[]")
        out.append({"container_port": int(m.group("cont")), "host_port": int(m.group("host")), "proto": m.group("proto"), "bind": bind})
    return out[:100]


def to_hypervisor(snapshot, connect_host=""):
    host = _host(snapshot, connect_host)
    guests = []
    for item in snapshot["containers"]:
        name = str(item.get("name") or "").lstrip("/").strip()
        if not name:
            continue
        state = STATES.get(str(item.get("state") or "").lower(), str(item.get("state") or "unknown").lower()[:30])
        text = str(item.get("status") or "")
        health = "healthy" if "(healthy)" in text else "unhealthy" if "(unhealthy)" in text else "starting" if "(health: starting)" in text else ""
        ports = _ports(item.get("ports"))
        details = {"image": str(item.get("image") or "")[:200], "health": health, "ports": ports, "network": str(item.get("network") or "").split(",")[0][:40]}
        details["exposed"] = any(p["bind"] in ("0.0.0.0", "::", "") for p in ports) if ports else None
        guests.append({"id": f"container:{name}", "name": name, "kind": "container", "host_id": host["id"], "status": state, "macs": [], "ips": [], "details": _clean(details)})
    for vm in snapshot["machines"]:
        name = str(vm.get("vmname") or "").strip()
        if not name:
            continue
        kind = "lxc" if str(vm.get("virttype") or "") == "lxc" else "qemu"
        macs = [m for m in (_mac(n.get("mac")) for n in snapshot["nics"].get((name, str(vm.get("virttype") or "vm"))) or [] if isinstance(n, dict)) if m]
        memory = _int(vm.get("mem"))
        details = {"cpus": _int(vm.get("cpu")), "memory_mb": memory // (1024 * 1024) if memory else None, "autostart": vm["autostart"] if isinstance(vm.get("autostart"), bool) else None}
        guests.append({"id": f"{'lxc' if kind == 'lxc' else 'vm'}:{name}", "name": name, "kind": kind, "host_id": host["id"],
                       "status": STATES.get(str(vm.get("state") or "").lower(), str(vm.get("state") or "unknown").lower()[:30]), "macs": macs, "ips": [], "details": _clean(details)})
    seen, unique = set(), []
    for g in guests:
        if g["id"] not in seen:
            seen.add(g["id"])
            unique.append(g)
    return {"hosts": [host], "guests": unique}


# ----------------------------------------------------------------------------- storage (file systems, disks, shares)
RANK = {"unknown": 0, "ok": 1, "warning": 2, "critical": 3}


def _num(value):
    """OMV gives sizes as numbers or as text."""
    try:
        number = int(float(str(value)))
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _smart_state(text):
    status = str(text or "").upper()
    if status in ("", "GOOD", "OK"):
        return "ok"
    return "failed" if status in ("BAD", "BAD_STATUS", "FAILED") else "degraded"


def to_storage(snapshot, connect_host=""):
    """The storage part of the output: file systems (as pools), disks with their S.M.A.R.T. status and the shares (the Storage page)."""
    host = _host(snapshot, connect_host)
    sid = host["id"]
    data = snapshot.get("storage") or {}
    pools, disks, volumes, alerts, level = [], [], [], [], "ok"
    for fs in data.get("filesystems") or []:
        device = str(fs.get("devicefile") or fs.get("uuid") or "")
        if not device:
            continue
        status = fs.get("status")
        health = "critical" if status == 3 else "warning" if fs.get("mounted") is False else "ok"
        name = str(fs.get("label") or device)
        pools.append({"id": f"fs:{fs.get('uuid') or device}", "system_id": sid, "name": name[:100], "total": _num(fs.get("size")), "used": _num(fs.get("used")), "avail": _num(fs.get("available")),
                      "health": health, "raid": str(fs.get("type") or "")[:60]})
        if health != "ok":
            alerts.append({"id": f"fs:{fs.get('uuid') or device}", "system_id": sid, "severity": health, "text": f"File system {name} is {'missing' if status == 3 else 'not mounted'}"})
        level = max(level, health, key=lambda x: RANK[x])
    smart = {str(x.get("devicefile")): x for x in data.get("smart") or []}
    seen = set()
    for d in list(data.get("disks") or []) + list(data.get("smart") or []):
        device = str(d.get("devicefile") or "")
        if not device or device in seen:
            continue
        seen.add(device)
        info = smart.get(device, {})
        state = _smart_state(info.get("overallstatus"))
        disks.append({"id": f"disk:{device}", "system_id": sid, "name": device[:100], "slot": "", "model": str(d.get("model") or info.get("model") or "")[:100],
                      "size": _num(d.get("size") or info.get("size")), "state": state})
        if state != "ok":
            alerts.append({"id": f"disk:{device}:{state}", "system_id": sid, "severity": "critical" if state == "failed" else "warning", "text": f"Disk {device}: S.M.A.R.T. status {info.get('overallstatus')}"})
            level = max(level, "critical" if state == "failed" else "warning", key=lambda x: RANK[x])
    for kind, rows, label in (("smb", data.get("smb"), "name"), ("nfs", data.get("nfs"), "client")):
        for share in rows or []:
            name = str(share.get("name") or share.get(label) or share.get("mntentref") or "")
            if name:
                volumes.append({"id": f"{kind}:{share.get('uuid') or name}", "system_id": sid, "pool_id": None, "name": name[:200], "kind": "share", "protocol": kind, "size": None, "used": None, "health": "ok", "clients": []})
    system = {"id": sid, "name": host["name"], "ip": host.get("ip"), "vendor": "OpenMediaVault", "model": "", "version": str(snapshot["info"].get("version") or "")[:60], "serial": "",
              "online": True, "health": level if pools or disks else "unknown", "warnings": []}
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
        raise ValueError("enter the address, user name and password of at least one OpenMediaVault")
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
    client = Omv(one)
    client.open()
    try:
        snapshot = client.snapshot()
    finally:
        client.close()
    out = to_hypervisor(snapshot, client.host)
    storage = to_storage(snapshot, client.host)
    if storage["pools"] or storage["disks"]:
        out["storage"] = storage
    return out, snapshot


def test(config):
    def one(row):
        out, snapshot = _fetch_one(row)
        kinds = [g["kind"] for g in out["guests"]]
        version = str(snapshot["info"].get("version") or "").strip()
        message = (f"Connected to {out['hosts'][0]['name']} (OpenMediaVault{' ' + version if version else ''}): "
                   f"{kinds.count('container')} container(s), {kinds.count('qemu') + kinds.count('lxc')} virtual machine(s)")
        if snapshot["notes"]:
            message += ". Not available: " + "; ".join(snapshot["notes"])
        return message
    messages = _each(config, one)
    return {"message": messages[0] if len(messages) == 1 else f"{len(messages)} OpenMediaVault systems answered. " + " | ".join(messages)}


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
KEEP_WORDS = {"state", "type", "virttype", "link", "status_code", "authenticated", "status", "overallstatus", "mounted"}


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
    """What this OpenMediaVault answers, described by field names and types, and what the plugin made of it (no names, MACs or IPs)."""
    client = Omv(_servers(config)[0])
    client.open()                          # a refused login is reported as such (and stops automatic syncing), like test()
    report = {"steps": {}}
    try:
        for name, service, method, params in (("system", "System", "getInformation", None), ("network", "Network", "enumerateDevices", None),
                                              ("containers", "Compose", "getContainerList", LIST), ("virtual_machines", "Kvm", "getVmList", LIST),
                                              ("file_systems", "FileSystemMgmt", "getList", LIST), ("disks", "DiskMgmt", "enumerateDevices", None), ("smart", "Smart", "getList", LIST),
                                              ("smb_shares", "Smb", "getShareList", LIST), ("nfs_shares", "Nfs", "getShareList", LIST)):
            try:
                report["steps"][name] = {"ok": True, "shape": describe(client._rpc(service, method, params))}
            except Exception as exc:  # noqa: BLE001 - the point is to record what failed
                report["steps"][name] = {"ok": False, "error": _problem(exc, client)}
        try:
            snapshot = client.snapshot()
            out = to_hypervisor(snapshot, client.host)
            report["result"] = {"host_has_ip": "ip" in out["hosts"][0], "host_has_mac": "mac" in out["hosts"][0], "guests": len(out["guests"]),
                                "by_kind": {k: sum(1 for g in out["guests"] if g["kind"] == k) for k in ("container", "qemu", "lxc")},
                                "guests_with_ports": sum(1 for g in out["guests"] if g["details"].get("ports")), "guests_with_mac": sum(1 for g in out["guests"] if g["macs"]),
                                "not_available": [_problem(RuntimeError(n), client) for n in snapshot["notes"]]}
            st = to_storage(snapshot, client.host)
            report["result"]["storage"] = {"file_systems": len(st["pools"]), "disks": len(st["disks"]), "shares": len(st["volumes"]), "alerts": len(st["alerts"]), "health": st["systems"][0]["health"]}
        except Exception as exc:  # noqa: BLE001
            report["error"] = _problem(exc, client)
    finally:
        client.close()
    return report
