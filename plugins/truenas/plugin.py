"""TrueNAS plugin (kind "hypervisor"): the TrueNAS box as a host, with its containers, virtual machines and apps as guests.

Talks to the TrueNAS middleware over its JSON-RPC 2.0 WebSocket API (`wss://<host>/api/current`, TrueNAS 25.04 and newer),
read-only:

    auth.login_with_api_key   one login with the API key
    system.info               host name and version
    interface.query           the interface that holds the address of the box (its IP and MAC)
    virt.instance.query       containers and VMs of the Instances / Containers feature
    vm.query                  classic virtual machines (with their network cards' MAC addresses)
    app.query                 the apps

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

    def optional(self, method, notes, label):
        """A list from a feature the box may not have (no apps pool, no virtualization): empty, with a note, when unavailable."""
        try:
            result = self.call(method)
        except MethodMissing:
            notes.append(f"{label}: not available on this version")
            return []
        except TruenasError as exc:
            notes.append(f"{label}: {exc}")
            return []
        return result if isinstance(result, list) else []

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
                       "status": _state(item.get("status")), "macs": macs, "ips": []})
    for item in snapshot["apps"]:
        if isinstance(item, dict) and (item.get("name") or item.get("id")):
            name = str(item.get("name") or item["id"])
            guests.append({"id": f"app:{name}", "name": name, "kind": "app", "host_id": host["id"], "status": _state(item.get("state")), "macs": [], "ips": []})
    seen = set()
    unique = []
    for g in guests:
        if g["id"] not in seen:
            seen.add(g["id"])
            unique.append(g)
    return {"hosts": [host], "guests": unique}


def _session(config):
    truenas = TrueNAS(config)
    truenas.open()
    return truenas


def test(config):
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
    return {"message": message}


def fetch(config):
    truenas = _session(config)
    try:
        snapshot = truenas.snapshot()
    finally:
        truenas.close()
    return to_hypervisor(snapshot, truenas.host)


# ----------------------------------------------------------------------------- diagnostic (for the plugin's author)
KEEP_WORDS = {"version", "type", "status", "state", "dev_type", "dtype", "nic_type", "link_state", "autostart", "model"}
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
    return type(exc).__name__ + ": " + re.sub(r"https?://\S+", "<url>", str(exc))[:300]


def diagnose(config):
    """What this TrueNAS answers, described by field names and types, and what the plugin made of it (no names, MACs or IPs)."""
    truenas = _session(config)  # a refused key is reported as such (and stops automatic syncing), like test()
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
    except Exception as exc:  # noqa: BLE001
        report["error"] = _problem(exc)
    finally:
        truenas.close()
    return report
