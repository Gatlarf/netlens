"""TrueNAS plugin (kind "hypervisor"): the TrueNAS box as a host, with its containers, virtual machines and apps as guests.

Talks to the TrueNAS middleware over its JSON-RPC 2.0 WebSocket API (`wss://<host>/api/current`, TrueNAS 25.04 and newer),
read-only:

    auth.login_with_api_key   one login with the API key
    system.info               host name and version
    interface.query           the interface that holds the address of the box (its IP and MAC)
    virt.instance.query       containers and VMs of the Instances / Containers feature
    vm.query                  classic virtual machines (with their network cards' MAC addresses)
    app.query                 the apps
    pool.query                pools: health, size and free space, and the disks of each pool
    boot.get_state            the boot pool (the disks the operating system lives on)
    disk.query                disk sizes and models
    alert.list                the open alerts
    sharing.nfs.query / sharing.smb.query   the shares
    iscsi.extent.query / iscsi.target.query / iscsi.targetextent.query / iscsi.global.sessions   iSCSI LUNs, their targets and the hosts logged in
    pool.dataset.query        zvol sizes (the size of an iSCSI LUN on a zvol)

Standard library only (a small WebSocket client is included). The key is only sent over TLS: TrueNAS revokes an API key that
is used over an unencrypted connection. A refused login is reported with `auth_failed`, so Netlens stops retrying until the user
acts (this protects the account from being locked).
"""

import base64
import hashlib
import json
import os
import re
import socket
import ssl
import struct
import time
import urllib.parse

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_MESSAGE = 32 * 1024 * 1024
USE_TLS = True  # only the tests switch this off


class TruenasError(Exception):
    pass


class ConnectError(TruenasError):
    """TrueNAS could not be reached (not a login problem)."""


class LoginRefused(TruenasError):
    auth_failed = True


class MethodMissing(TruenasError):
    pass


# ----------------------------------------------------------------------------- a small WebSocket client (RFC 6455)
class WebSocket:
    def __init__(self, host, port, path="/api/current", tls=True, verify=False, timeout=20):
        try:
            raw = socket.create_connection((host, port), timeout=timeout)
            if tls:
                context = ssl.create_default_context()
                if not verify:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                raw = context.wrap_socket(raw, server_hostname=host)
        except (OSError, ssl.SSLError) as exc:
            raise ConnectError(f"cannot reach TrueNAS at {host}:{port}: {exc}") from None
        self.sock = raw
        self.buf = b""
        key = base64.b64encode(os.urandom(16)).decode()
        request = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        try:
            raw.sendall(request.encode())
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = raw.recv(4096)
                if not chunk:
                    raise ConnectError("TrueNAS closed the connection during the handshake")
                head += chunk
                if len(head) > 65536:
                    raise ConnectError("unexpected answer from TrueNAS")
        except OSError as exc:
            raise ConnectError(f"cannot reach TrueNAS: {exc}") from None
        header, _, self.buf = head.partition(b"\r\n\r\n")
        lines = header.decode("latin-1").split("\r\n")
        if " 101 " not in lines[0]:
            raise ConnectError(f"TrueNAS refused the WebSocket connection ({lines[0].strip()}); is this the TrueNAS address, and is it 25.04 or newer?")
        accept = next((l.split(":", 1)[1].strip() for l in lines[1:] if l.lower().startswith("sec-websocket-accept:")), "")
        if accept != base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode():
            raise ConnectError("the server did not complete the WebSocket handshake correctly")

    def _read(self, n):
        while len(self.buf) < n:
            try:
                chunk = self.sock.recv(65536)
            except (OSError, ssl.SSLError) as exc:
                raise ConnectError(f"connection to TrueNAS lost: {exc}") from None
            if not chunk:
                raise ConnectError("TrueNAS closed the connection")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def send(self, data, opcode=1):
        payload = data.encode() if isinstance(data, str) else data
        mask, n = os.urandom(4), len(payload)
        if n < 126:
            head = bytes([0x80 | opcode, 0x80 | n])
        elif n < 65536:
            head = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack(">H", n)
        else:
            head = bytes([0x80 | opcode, 0x80 | 127]) + struct.pack(">Q", n)
        try:
            self.sock.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))
        except OSError as exc:
            raise ConnectError(f"cannot send to TrueNAS: {exc}") from None

    def recv(self):
        message = b""
        while True:
            b1, b2 = self._read(2)
            fin, opcode, n = b1 & 0x80, b1 & 0x0F, b2 & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._read(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._read(8))[0]
            if n > MAX_MESSAGE:
                raise TruenasError("TrueNAS sent an unexpectedly large message")
            payload = self._read(n)
            if opcode == 9:  # ping
                self.send(payload, 10)
                continue
            if opcode == 10:  # pong
                continue
            if opcode == 8:
                raise ConnectError("TrueNAS closed the connection")
            message += payload
            if len(message) > MAX_MESSAGE:
                raise TruenasError("TrueNAS sent an unexpectedly large message")
            if fin:
                return message.decode("utf-8", "replace")

    def close(self):
        try:
            self.send(b"", 8)
        except Exception:  # noqa: BLE001 - best effort
            pass
        try:
            self.sock.close()
        except OSError:
            pass


# ----------------------------------------------------------------------------- TrueNAS
def _mac(value):
    if not isinstance(value, str):
        return None
    text = value.strip().lower().replace("-", ":")
    return text if len(text) == 17 and text.count(":") == 5 and text != "00:00:00:00:00:00" else None


class TrueNAS:
    def __init__(self, config):
        url = str(config.get("url") or "").strip()
        if not url:
            raise ValueError("enter the TrueNAS address, for example https://192.168.0.200")
        if "://" not in url:
            url = "https://" + url
        parts = urllib.parse.urlsplit(url)
        if not parts.hostname:
            raise ValueError("that is not a valid TrueNAS address")
        self.host = parts.hostname
        # plain http would expose (and make TrueNAS revoke) the key: always TLS, on the HTTPS port unless one is given
        self.port = parts.port if parts.port and parts.scheme == "https" else 443 if parts.scheme in ("http", "https", "") else (parts.port or 443)
        self.key = str(config.get("api_key") or "").strip()
        if not self.key:
            raise ValueError("enter the API key")
        self.verify = bool(config.get("verify_tls"))
        self.ws = None
        self.counter = 0

    def open(self):
        self.ws = WebSocket(self.host, self.port, "/api/current", tls=USE_TLS, verify=self.verify)
        if self.call("auth.login_with_api_key", self.key) is not True:
            raise LoginRefused("login refused: TrueNAS did not accept the API key (it may be wrong, revoked or expired). Create a new key and save it again.")

    def close(self):
        if self.ws is not None:
            self.ws.close()
            self.ws = None

    def call(self, method, *params):
        self.counter += 1
        self.ws.send(json.dumps({"jsonrpc": "2.0", "id": self.counter, "method": method, "params": list(params)}))
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            try:
                message = json.loads(self.ws.recv())
            except ValueError:
                continue
            if not isinstance(message, dict) or message.get("id") != self.counter:
                continue  # a notification or another answer
            error = message.get("error")
            if error:
                code = error.get("code") if isinstance(error, dict) else None
                text = (error.get("message") if isinstance(error, dict) else str(error)) or "error"
                if code == -32601:
                    raise MethodMissing(f"{method}: {text}")
                if method == "auth.login_with_api_key":
                    raise LoginRefused(f"login refused: {text}")
                data = error.get("data") if isinstance(error, dict) else None
                reason = (data.get("reason") if isinstance(data, dict) else None) or text
                raise TruenasError(f"{method} failed: {str(reason)[:200]}")
            return message.get("result")
        raise TruenasError(f"TrueNAS did not answer {method} in time")

    def optional(self, method, notes, label, *params):
        """A list from a feature the box may not have (no apps pool, no virtualization): empty, with a note, when unavailable."""
        try:
            result = self.call(method, *params)
        except MethodMissing:
            notes.append(f"{label}: not available on this version")
            return []
        except TruenasError as exc:
            notes.append(f"{label}: {exc}")
            return []
        return result if isinstance(result, list) else []

    def boot_state(self, notes):
        """The boot pool as a dict (it is not part of pool.query), or {}."""
        try:
            result = self.call("boot.get_state")
        except MethodMissing:
            notes.append("boot pool: not available on this version")
            return {}
        except TruenasError as exc:
            notes.append(f"boot pool: {exc}")
            return {}
        return result if isinstance(result, dict) else {}

    def snapshot(self):
        info = self.call("system.info")
        if not isinstance(info, dict):
            raise TruenasError("unexpected answer from system.info")
        notes = []
        interfaces = self.optional("interface.query", notes, "network interfaces")
        return {
            "version": str(info.get("version") or ""),
            "hostname": str(info.get("hostname") or self.host),
            "interfaces": interfaces,
            "instances": self.optional("virt.instance.query", notes, "containers"),
            "vms": self.optional("vm.query", notes, "virtual machines"),
            "apps": self.optional("app.query", notes, "apps"),
            "pools": self.optional("pool.query", notes, "pools"),
            "disks": self.optional("disk.query", notes, "disks"),
            "alerts": self.optional("alert.list", notes, "alerts"),
            "nfs": self.optional("sharing.nfs.query", notes, "NFS shares"),
            "smb": self.optional("sharing.smb.query", notes, "SMB shares"),
            "extents": self.optional("iscsi.extent.query", notes, "iSCSI extents"),
            "iscsi_targets": self.optional("iscsi.target.query", notes, "iSCSI targets"),
            "targetextents": self.optional("iscsi.targetextent.query", notes, "iSCSI LUN mappings"),
            "sessions": self.optional("iscsi.global.sessions", notes, "iSCSI sessions"),
            "boot": self.boot_state(notes),
            "zvols": self.optional("pool.dataset.query", notes, "zvols", [["type", "=", "VOLUME"]]),
            "notes": notes,
        }


def _inet(interface):
    state = interface.get("state") if isinstance(interface.get("state"), dict) else {}
    out = [a.get("address") for a in state.get("aliases") or [] if isinstance(a, dict) and a.get("type") == "INET" and a.get("address")]
    out += [a.get("address") for a in interface.get("aliases") or [] if isinstance(a, dict) and a.get("type") == "INET" and a.get("address")]
    return [a for a in dict.fromkeys(out) if not a.startswith("127.")]


def _host(snapshot, connect_host):
    """The address and MAC of the box: the interface that holds the address Netlens connects to, else the first one with an address."""
    candidates = []
    for interface in snapshot["interfaces"]:
        if not isinstance(interface, dict):
            continue
        state = interface.get("state") if isinstance(interface.get("state"), dict) else {}
        addresses = _inet(interface)
        if addresses:
            candidates.append((addresses, _mac(state.get("link_address"))))
    chosen = next((c for c in candidates if connect_host in c[0]), candidates[0] if candidates else None)
    ip = connect_host if chosen is None or connect_host in chosen[0] else chosen[0][0]
    host = {"id": snapshot["hostname"].lower(), "name": snapshot["hostname"], "online": True}
    try:
        socket.inet_aton(ip)
        host["ip"] = ip
    except OSError:
        if chosen:
            host["ip"] = chosen[0][0]
    if chosen and chosen[1]:
        host["mac"] = chosen[1]
    return host


def _state(value):
    if isinstance(value, dict):
        value = value.get("state")
    return str(value).lower() if value else "unknown"


def _int(value):
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0 else None


def _bytes_to_mb(value):
    number = _int(value)
    return number // 1048576 if number else None


def _clean(details):
    return {k: v for k, v in details.items() if v not in (None, "", [])}


def _instance_details(item):
    image = item.get("image") if isinstance(item.get("image"), dict) else {}
    memory = item.get("memory")
    return _clean({
        "cpus": _int(item.get("vcpus")) or (_int(item.get("cpu")) if str(item.get("cpu") or "").isdigit() else None),
        "memory_mb": _bytes_to_mb(memory) if isinstance(memory, int) and memory > 100000 else _int(memory),
        "os": str(image.get("os") or image.get("description") or "")[:100],
        "version": str(image.get("release") or "")[:100],
        "autostart": bool(item["autostart"]) if "autostart" in item else None,
    })


def _vm_details(item):
    cpus = (_int(item.get("vcpus")) or 1) * (_int(item.get("cores")) or 1) * (_int(item.get("threads")) or 1) if item.get("vcpus") else None
    return _clean({"cpus": cpus, "memory_mb": _int(item.get("memory")), "autostart": bool(item["autostart"]) if "autostart" in item else None})


def _app_details(item):
    """Version, update available, the image of its first container and the ports it publishes on the host."""
    workloads = item.get("active_workloads") if isinstance(item.get("active_workloads"), dict) else {}
    containers = [c for c in workloads.get("container_details") or [] if isinstance(c, dict)]
    ports = []
    for entry in workloads.get("used_ports") or []:
        if not isinstance(entry, dict):
            continue
        for hp in entry.get("host_ports") or []:
            if isinstance(hp, dict) and _int(hp.get("host_port")):
                ports.append({"container_port": _int(entry.get("container_port")), "host_port": _int(hp.get("host_port")),
                              "proto": str(entry.get("protocol") or "tcp").lower(), "bind": str(hp.get("host_ip") or "")})
    details = {
        "image": str(containers[0].get("image") or "")[:200] if containers else "",
        "version": str(item.get("human_version") or item.get("version") or "")[:100],
        "update_available": bool(item.get("upgrade_available")) if "upgrade_available" in item else None,
        "ports": ports[:100],
    }
    details["exposed"] = any(p["bind"] in ("0.0.0.0", "::", "") for p in ports) if ports else None
    return _clean(details)


def to_hypervisor(snapshot, connect_host=""):
    host = _host(snapshot, connect_host)
    guests = []
    for item in snapshot["instances"]:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        is_vm = str(item.get("type") or "").upper() == "VM"
        guests.append({
            "id": f"instance:{item['name']}", "name": item["name"], "kind": "qemu" if is_vm else "lxc", "host_id": host["id"],
            "status": _state(item.get("status")),
            "ips": [a["address"] for a in item.get("aliases") or [] if isinstance(a, dict) and a.get("type") == "INET" and a.get("address")],
            "macs": [m for m in (_mac(a.get("hwaddr") or a.get("mac")) for a in item.get("aliases") or [] if isinstance(a, dict)) if m],
            "details": _instance_details(item),
        })
    for item in snapshot["vms"]:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        macs = []
        for device in item.get("devices") or []:
            attributes = device.get("attributes") if isinstance(device, dict) and isinstance(device.get("attributes"), dict) else device
            if isinstance(attributes, dict) and str(attributes.get("dtype") or "").upper() == "NIC" and _mac(attributes.get("mac")):
                macs.append(_mac(attributes["mac"]))
        guests.append({"id": f"vm:{item.get('id', item['name'])}", "name": item["name"], "kind": "qemu", "host_id": host["id"],
                       "status": _state(item.get("status")), "macs": macs, "ips": [], "details": _vm_details(item)})
    for item in snapshot["apps"]:
        if isinstance(item, dict) and (item.get("name") or item.get("id")):
            name = str(item.get("name") or item["id"])
            guests.append({"id": f"app:{name}", "name": name, "kind": "app", "host_id": host["id"], "status": _state(item.get("state")), "macs": [], "ips": [], "details": _app_details(item)})
    seen = set()
    unique = []
    for g in guests:
        if g["id"] not in seen:
            seen.add(g["id"])
            unique.append(g)
    return {"hosts": [host], "guests": unique}

# ----------------------------------------------------------------------------- storage (pools, disks, shares, alerts)
POOL_HEALTH = {"ONLINE": "ok", "DEGRADED": "warning", "FAULTED": "critical", "UNAVAIL": "critical", "OFFLINE": "critical", "REMOVED": "critical", "SUSPENDED": "critical"}
DISK_STATE = {"ONLINE": "ok", "DEGRADED": "degraded", "FAULTED": "failed", "UNAVAIL": "failed", "OFFLINE": "degraded", "REMOVED": "failed"}
ALERT_LEVEL = {"WARNING": "warning", "ERROR": "critical", "CRITICAL": "critical", "ALERT": "critical", "EMERGENCY": "critical"}
RANK = {"unknown": 0, "ok": 1, "warning": 2, "critical": 3}


def _vdev_disks(node, out):
    """The disk leaves of a pool topology (data, cache, log, spare, special, dedup groups)."""
    if not isinstance(node, dict):
        return
    children = node.get("children") or []
    if str(node.get("type") or "").upper() == "DISK" or not children:
        if node.get("disk") or node.get("name"):
            out.append(node)
        return
    for child in children:
        _vdev_disks(child, out)


def _parsed(value):
    """ZFS properties come as {"parsed": n, "rawvalue": "..."}."""
    if isinstance(value, dict):
        value = value.get("parsed", value.get("rawvalue"))
    try:
        number = int(float(str(value)))
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _client_ip(text):
    """'192.168.0.50' or '192.168.0.50:3260' or '[::1]' -> an IPv4 address or None."""
    host = str(text or "").strip().rsplit(":", 1)[0] if str(text or "").count(":") == 1 else str(text or "").strip()
    return host if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) else None


def _iscsi_luns(snapshot, sid, pool_ids):
    """iSCSI LUNs: one volume per extent, with the hosts that are logged in to a target that holds it."""
    zvols = {str(z.get("name")): z for z in snapshot.get("zvols") or [] if isinstance(z, dict)}
    targets = {t.get("id"): t for t in snapshot.get("iscsi_targets") or [] if isinstance(t, dict)}
    by_extent = {}
    for link in snapshot.get("targetextents") or []:
        if isinstance(link, dict):
            by_extent.setdefault(link.get("extent"), []).append(link.get("target"))
    clients_of_target = {}
    for session in snapshot.get("sessions") or []:
        if not isinstance(session, dict):
            continue
        ip = _client_ip(session.get("initiator_addr"))
        name = str(session.get("target") or "")
        for target in targets.values():
            short = str(target.get("name") or "")
            if short and (name == short or name.endswith(":" + short)) and ip:
                clients_of_target.setdefault(target.get("id"), [])
                if ip not in clients_of_target[target.get("id")]:
                    clients_of_target[target.get("id")].append(ip)
    out = []
    for extent in snapshot.get("extents") or []:
        if not isinstance(extent, dict) or not extent.get("name"):
            continue
        disk = str(extent.get("disk") or "")
        zname = disk[len("zvol/"):] if disk.startswith("zvol/") else ""
        zvol = zvols.get(zname, {})
        size = _parsed(zvol.get("volsize")) or _parsed(extent.get("filesize")) or None          # the file size of a file extent comes as text
        path = zname or str(extent.get("path") or "")
        clients, names = [], []
        for tid in by_extent.get(extent.get("id"), []):
            names.append(str((targets.get(tid) or {}).get("name") or ""))
            for ip in clients_of_target.get(tid, []):
                if ip not in clients:
                    clients.append(ip)
        pool = zname.split("/")[0] if zname else path.removeprefix("/mnt/").split("/")[0]
        out.append({"id": f"iscsi:extent:{extent.get('id', extent['name'])}", "system_id": sid, "pool_id": pool_ids.get(pool), "name": f"{extent['name']}"[:200], "kind": "lun", "protocol": "iscsi",
                    "size": size, "used": _parsed(zvol.get("used")), "health": "ok" if extent.get("enabled", True) is not False else "warning", "clients": clients})
    return out



def to_storage(snapshot, connect_host=""):
    """The storage part of the output: pools, their disks, shares and alerts (the Storage page)."""
    host = _host(snapshot, connect_host)
    sid = host["id"]
    sizes = {str(d.get("name")): d for d in snapshot.get("disks") or [] if isinstance(d, dict)}
    pools, disks, volumes, alerts, level = [], [], [], [], "ok"
    boot = snapshot.get("boot") if isinstance(snapshot.get("boot"), dict) else {}
    listed = [p for p in snapshot.get("pools") or [] if isinstance(p, dict)]
    if boot.get("name") and boot["name"] not in {p.get("name") for p in listed}:
        listed.append(boot)                                         # the pool the operating system lives on
    in_pool = set()
    for pool in listed:
        if not pool.get("name"):
            continue
        status = str(pool.get("status") or "").upper()
        health = POOL_HEALTH.get(status, "unknown")
        if health == "ok" and pool.get("healthy") is False:
            health = "warning"
        topology = pool.get("topology") if isinstance(pool.get("topology"), dict) else {}
        kinds = [str(v.get("type") or "") for v in topology.get("data") or [] if isinstance(v, dict)]
        raid = ", ".join(sorted({k for k in kinds if k})).lower()
        size, used, free = _int(pool.get("size")), _int(pool.get("allocated")), _int(pool.get("free"))
        pools.append({"id": f"pool:{pool['name']}", "system_id": sid, "name": str(pool["name"]), "total": size, "used": used, "avail": free, "health": health, "raid": raid[:60]})
        level = max(level, health, key=lambda x: RANK[x])
        if health != "ok":
            alerts.append({"id": f"pool:{pool['name']}:{status}", "system_id": sid, "severity": "critical" if health == "critical" else "warning", "text": f"Pool {pool['name']} is {status.lower() or 'not healthy'}"})
        leaves = []
        for group in ("data", "cache", "log", "spare", "special", "dedup"):
            for vdev in topology.get(group) or []:
                _vdev_disks(vdev, leaves)
        for leaf in leaves:
            name = str(leaf.get("disk") or leaf.get("name"))
            in_pool.add(name)
            state = DISK_STATE.get(str(leaf.get("status") or "").upper(), "unknown")
            info = sizes.get(name, {})
            disks.append({"id": f"{pool['name']}:{name}", "system_id": sid, "name": name, "slot": str(pool["name"])[:40], "model": str(info.get("model") or "")[:100],
                          "size": _int(info.get("size")), "state": state})
            if state in ("failed", "degraded"):
                alerts.append({"id": f"disk:{pool['name']}:{name}", "system_id": sid, "severity": "critical" if state == "failed" else "warning", "text": f"Disk {name} of pool {pool['name']}: {state}"})
    for name, info in sorted(sizes.items()):                          # disks that belong to no pool (an unused disk, or the boot disk when TrueNAS does not say)
        if name not in in_pool and not info.get("pool"):
            disks.append({"id": f"unassigned:{name}", "system_id": sid, "name": name, "slot": "not in a pool", "model": str(info.get("model") or "")[:100], "size": _int(info.get("size")), "state": "ok"})
    names = [p["name"] for p in pools]

    def pool_of(path):
        for name in names:
            if str(path or "").startswith(f"/mnt/{name}"):
                return f"pool:{name}"
        return None
    for kind, items in (("nfs", snapshot.get("nfs")), ("smb", snapshot.get("smb"))):
        for share in items or []:
            if isinstance(share, dict) and share.get("path") and share.get("enabled", True) is not False:
                label = str(share.get("name") or share["path"])
                volumes.append({"id": f"{kind}:{share.get('id', share['path'])}", "system_id": sid, "pool_id": pool_of(share["path"]), "name": label[:200], "kind": "share", "protocol": kind, "size": None, "used": None, "health": "ok", "clients": []})
    volumes += _iscsi_luns(snapshot, sid, {p["name"]: p["id"] for p in pools})
    for alert in snapshot.get("alerts") or []:
        if not isinstance(alert, dict) or alert.get("dismissed"):
            continue
        severity = ALERT_LEVEL.get(str(alert.get("level") or "").upper())
        if severity:
            alerts.append({"id": f"alert:{alert.get('uuid') or alert.get('id') or alert.get('klass')}", "system_id": sid, "severity": severity, "text": str(alert.get("formatted") or alert.get("klass") or "")[:300]})
            level = max(level, severity, key=lambda x: RANK[x])
    system = {"id": sid, "name": snapshot["hostname"], "ip": host.get("ip"), "vendor": "TrueNAS", "model": "", "version": snapshot["version"][:60], "serial": "", "online": True,
              "health": level if (pools or snapshot.get("alerts") or snapshot.get("extents")) else "unknown", "warnings": []}
    controllers = [{"id": f"{sid}:host", "system_id": sid, "name": snapshot["hostname"], "ip": host.get("ip"), "mac": host.get("mac"), "online": True, "health": "unknown"}] if host.get("ip") or host.get("mac") else []
    return {"systems": [system], "controllers": controllers, "pools": pools, "volumes": volumes, "disks": disks, "alerts": alerts[:200]}



def _servers(config):
    """One flat config per TrueNAS: the rows of the server list, or the single url and key of an older Netlens."""
    rows = config.get("servers")
    if not isinstance(rows, list):
        return [config]
    out = [{"url": r.get("host"), "api_key": r.get("api_key"), "verify_tls": config.get("verify_tls")} for r in rows if isinstance(r, dict) and (r.get("host") or r.get("api_key"))]
    if not out:
        raise ValueError("enter the address and API key of at least one TrueNAS")
    return out


def _label(one, many):
    return urllib.parse.urlsplit(str(one.get("url") or "")).netloc or str(one.get("url") or "") if many else ""


def _each(config, work):
    """Run `work(one_config)` on every server; the first failure stops with a message that names the server."""
    servers = _servers(config)
    results = []
    for one in servers:
        try:
            results.append(work(one))
        except Exception as exc:  # noqa: BLE001 - the exception keeps its type (a refused key must stay recognisable)
            label = _label(one, len(servers) > 1)
            if label and exc.args:
                exc.args = (f"{label}: {exc.args[0]}",) + tuple(exc.args[1:])
            raise
    return results


def _session(config):
    truenas = TrueNAS(config)
    truenas.open()
    return truenas


def _test_one(config):
    truenas = _session(config)
    try:
        snapshot = truenas.snapshot()
    finally:
        truenas.close()
    out = to_hypervisor(snapshot, truenas.host)
    kinds = [g["kind"] for g in out["guests"]]
    message = (f"Connected to TrueNAS {snapshot['version']} ({snapshot['hostname']}): {kinds.count('lxc')} container(s), "
               f"{kinds.count('qemu')} virtual machine(s), {kinds.count('app')} app(s)")
    if snapshot["notes"]:
        message += ". Not available: " + "; ".join(snapshot["notes"])
    return message


def test(config):
    messages = _each(config, _test_one)
    return {"message": messages[0] if len(messages) == 1 else f"{len(messages)} TrueNAS systems answered. " + " | ".join(messages)}


def _fetch_one(config):
    truenas = _session(config)
    try:
        snapshot = truenas.snapshot()
    finally:
        truenas.close()
    out = to_hypervisor(snapshot, truenas.host)
    if snapshot["pools"] or snapshot["alerts"] or snapshot["extents"]:
        out["storage"] = to_storage(snapshot, truenas.host)
    return out


def fetch(config):
    results = _each(config, _fetch_one)
    if len(results) == 1:
        return results[0]
    hosts, guests, taken = [], [], set()
    storage = {k: [] for k in ("systems", "controllers", "pools", "volumes", "disks", "alerts")}
    for out in results:
        for key in storage:
            storage[key] += (out.get("storage") or {}).get(key, [])
        hosts += out["hosts"]
        for g in out["guests"]:
            if g["id"] in taken:                      # the same name on two systems: keep both apart
                g = {**g, "id": f"{g['host_id']}/{g['id']}"}
            taken.add(g["id"])
            guests.append(g)
    out = {"hosts": hosts, "guests": guests}
    if storage["systems"]:
        out["storage"] = storage
    return out


# ----------------------------------------------------------------------------- diagnostic (for the plugin's author)
KEEP_WORDS = {"version", "type", "status", "state", "dev_type", "dtype", "nic_type", "link_state", "autostart", "model", "healthy", "level", "dismissed", "scan_function", "klass"}
SAMPLES = 2


def describe(value, key=""):
    """The shape of a value: types and sizes, never the content (except a few harmless enumerations)."""
    if isinstance(value, dict):
        return {k: describe(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [describe(v, key) for v in value[:2]] + ([f"... {len(value)} items"] if len(value) > 2 else [])
    if isinstance(value, bool) or value is None:
        return value
    if key in KEEP_WORDS:
        return value
    if isinstance(value, (int, float)):
        return f"<number {'negative' if value < 0 else 'positive' if value > 0 else 'zero'}, {len(str(abs(value)))} digits>"
    if isinstance(value, str):
        if re.fullmatch(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", value):
            return "<mac " + ("dashes" if "-" in value else "colons") + (", UPPER" if value.upper() == value and re.search("[A-F]", value) else "") + ">"
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value):
            return "<ipv4>"
        return f"<text {len(value)} chars>"
    return f"<{type(value).__name__}>"


def _problem(exc):
    """The error text for a diagnostic report, without any server address (URL, IP address, host:port or host name)."""
    text = re.sub(r"https?://\S+", "<url>", str(exc))
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<url>", text)
    text = re.sub(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*:\d{2,5}\b", "<url>", text)
    text = re.sub(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", "<url>", text)
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What this TrueNAS answers, described by field names and types, and what the plugin made of it (no names, MACs or IPs)."""
    truenas = _session(_servers(config)[0])  # a refused key is reported as such (and stops automatic syncing), like test(); the first system is described
    report = {"steps": {}}

    def step(name, method, *params):
        try:
            result = truenas.call(method, *params)
        except Exception as exc:  # noqa: BLE001 - the point is to record what failed
            report["steps"][name] = {"ok": False, "error": _problem(exc)}
            return None
        if isinstance(result, list):
            report["steps"][name] = {"ok": True, "shape": {"count": len(result), "first": [describe(x) for x in result[:SAMPLES]]}}
        else:
            report["steps"][name] = {"ok": True, "shape": describe(result)}
        return result

    try:
        step("system_info", "system.info")
        step("interfaces", "interface.query")
        instances = step("instances", "virt.instance.query")
        step("vms", "vm.query")
        step("apps", "app.query")
        step("pools", "pool.query")
        step("boot", "boot.get_state")
        step("disks", "disk.query")
        step("alerts", "alert.list")
        step("nfs_shares", "sharing.nfs.query")
        step("smb_shares", "sharing.smb.query")
        step("iscsi_extents", "iscsi.extent.query")
        step("iscsi_targets", "iscsi.target.query")
        step("iscsi_lun_mappings", "iscsi.targetextent.query")
        step("iscsi_sessions", "iscsi.global.sessions")
        step("zvols", "pool.dataset.query", [["type", "=", "VOLUME"]])
        first = next((i for i in instances or [] if isinstance(i, dict) and i.get("id")), None)
        if first:
            step("instance_devices", "virt.instance.device_list", first["id"])
        snapshot = truenas.snapshot()
        out = to_hypervisor(snapshot, truenas.host)
        report["result"] = {
            "host_has_ip": "ip" in out["hosts"][0], "host_has_mac": "mac" in out["hosts"][0],
            "guests": len(out["guests"]), "by_kind": {k: sum(1 for g in out["guests"] if g["kind"] == k) for k in ("lxc", "qemu", "app")},
            "guests_with_ip": sum(1 for g in out["guests"] if g["ips"]), "guests_with_mac": sum(1 for g in out["guests"] if g["macs"]),
            "not_available": snapshot["notes"],
        }
        if snapshot["pools"] or snapshot["alerts"] or snapshot["extents"]:
            st = to_storage(snapshot, truenas.host)
            report["result"]["storage"] = {"pools": len(st["pools"]), "disks": len(st["disks"]), "shares": len([v for v in st["volumes"] if v["kind"] == "share"]), "luns": len([v for v in st["volumes"] if v["kind"] == "lun"]),
                                           "luns_with_clients": len([v for v in st["volumes"] if v["kind"] == "lun" and v["clients"]]), "alerts": len(st["alerts"]), "health": st["systems"][0]["health"],
                                           "disk_states": {k: sum(1 for d in st["disks"] if d["state"] == k) for k in ("ok", "degraded", "failed", "spare", "unknown")}}
    except Exception as exc:  # noqa: BLE001
        report["error"] = _problem(exc)
    finally:
        truenas.close()
    return report
