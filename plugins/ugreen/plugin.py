"""UGREEN plugin (kind "hypervisor"): a UGREEN NAS (UGOS / UGOS Pro) as a host, with its Docker containers as guests.

UGREEN publishes no API. This talks to the web API that the UGOS web page itself uses (port 9443), as documented by the
community (gitlab.com/K-22/nas-monitor-interface, docs/API.md; the login follows the Home Assistant integration
home-assistant_ugreen-nas). Read-only:

    POST /ugreen/v1/verify/check?token=      {"username": ...}  -> the NAS' RSA public key in the `x-rsa-token` header (base64 DER)
    POST /ugreen/v1/verify/login             the password encrypted with that key (RSA, PKCS#1 v1.5, base64) -> a token
    GET  /ugreen/v1/sysinfo/machine          model, host name, serial, firmware, network cards with MAC addresses
    GET  /ugreen/v1/ShowContainerDetailListV2   Docker containers

Requests carry `Authorization: Bearer <token>` and `App-Id: com.ugreen.nas`. Standard library only: the RSA encryption is done here.
Because the API is not official, a firmware update can change it; the plugin says what it could not read instead of failing.
A refused login is reported with `auth_failed` so Netlens stops retrying (UGOS locks an account for a few minutes after wrong passwords).
"""

import base64
import json
import re
import secrets
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAX_BODY = 8 * 1024 * 1024
APP_ID = "com.ugreen.nas"
LOGIN_ERRORS = {1003: "the user name or password is wrong", 1120: "the account is locked after too many wrong passwords; wait a few minutes", 1335: "this user does not exist",
                9404: "UGOS did not accept the request (unknown app id)"}
STATES = {"running": "running", "up": "running", "exited": "stopped", "stopped": "stopped", "created": "stopped", "paused": "paused", "restarting": "restarting", "dead": "failed"}


class UgreenError(Exception):
    pass


class ConnectError(UgreenError):
    """The NAS could not be reached (not a login problem)."""


class LoginRefused(UgreenError):
    auth_failed = True


# ----------------------------------------------------------------------------- RSA (public key encryption only)
def _der(data, pos=0):
    """One DER element: (tag, content bytes, position after it)."""
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    return tag, data[pos:pos + length], pos + length


def parse_public_key(blob):
    """(modulus, exponent) from a DER SubjectPublicKeyInfo or PKCS#1 RSAPublicKey, or a PEM of either."""
    text = bytes(blob).strip()
    if text.startswith(b"-----"):
        text = base64.b64decode(b"".join(line for line in text.splitlines() if not line.startswith(b"-----")))
    tag, body, _ = _der(text)
    if tag != 0x30:
        raise ValueError("not a public key")
    tag, first, after = _der(body)
    if tag == 0x30:                                       # SubjectPublicKeyInfo: algorithm, then BIT STRING holding the RSAPublicKey
        tag, bits, _ = _der(body, after)
        _, body, _ = _der(bits[1:])
        tag, first, after = _der(body)
    if tag != 0x02:
        raise ValueError("not an RSA public key")
    _, exponent, _ = _der(body, after)
    return int.from_bytes(first, "big"), int.from_bytes(exponent, "big")


def rsa_encrypt(blob, message):
    """RSAES-PKCS1-v1_5 (what UGOS' login expects), base64 encoded."""
    n, e = parse_public_key(blob)
    size = (n.bit_length() + 7) // 8
    data = message.encode()
    if len(data) > size - 11:
        raise ValueError("the password is too long for the NAS' key")
    padding = b""
    while len(padding) < size - 3 - len(data):
        padding += bytes(b for b in secrets.token_bytes(size) if b)[: size - 3 - len(data) - len(padding)]
    block = b"\x00\x02" + padding + b"\x00" + data
    return base64.b64encode(pow(int.from_bytes(block, "big"), e, n).to_bytes(size, "big")).decode()


# ----------------------------------------------------------------------------- the web API
def normalize(url):
    text = str(url or "").strip()
    if not text:
        raise ValueError("enter the address of the UGREEN NAS (for example https://192.168.0.50:9443)")
    if "://" not in text:
        text = "https://" + text
    parts = urllib.parse.urlsplit(text)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ValueError("the address must start with https:// (or http://) and name the NAS")
    host = parts.hostname
    shown = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{shown}:{parts.port or 9443}", host


class Ugreen:
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
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        self.token = None

    def _send(self, method, path, body=None, authed=True):
        headers = {"Accept": "application/json", "App-Id": APP_ID, "Content-Type": "application/json"}
        if authed and self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request(self.base + path, data=json.dumps(body).encode() if body is not None else None, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return response.headers, response.read(MAX_BODY)
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise LoginRefused("login refused: the NAS rejected the session") from None
            raise ConnectError(f"the NAS answered with HTTP {exc.code} for {path.split('?')[0]} (is this a UGREEN NAS, and is the address the UGOS port 9443?)") from None
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as exc:
            raise ConnectError(f"cannot reach the UGREEN NAS at {self.host}: {getattr(exc, 'reason', exc)}") from None

    def _json(self, method, path, body=None, authed=True):
        headers, raw = self._send(method, path, body, authed)
        try:
            answer = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            raise ConnectError("this does not look like UGOS (the answer is not JSON)") from None
        return headers, answer if isinstance(answer, dict) else {"code": 200, "data": answer}

    def open(self):
        headers, _ = self._json("POST", "/ugreen/v1/verify/check?token=", {"username": self.user}, authed=False)
        blob = headers.get("x-rsa-token")
        if not blob:                                                    # older firmware: the key comes as PEM in a JSON body
            _, answer = self._json("GET", "/ugreen/v1/verify/rsa_public_key", authed=False)
            blob = ((answer.get("data") or {}).get("public_key") or "").encode()
            if not blob:
                raise ConnectError("this does not look like UGOS (no public key for the login)")
        else:
            blob = base64.b64decode(blob)
        try:
            encrypted = rsa_encrypt(blob, self.password)
        except (ValueError, IndexError) as exc:
            raise ConnectError(f"cannot use the NAS' login key: {exc}") from None
        _, answer = self._json("POST", "/ugreen/v1/verify/login", {"is_simple": True, "keepalive": True, "otp": False, "username": self.user, "password": encrypted}, authed=False)
        if answer.get("code") != 200:
            code = answer.get("code")
            raise LoginRefused("login refused: " + LOGIN_ERRORS.get(code, f"UGOS answered with code {code}"))
        token = (answer.get("data") or {}).get("token")
        if not token:
            raise LoginRefused("login refused: UGOS gave no session")
        self.token = token

    def data(self, path):
        _, answer = self._json("GET", path)
        if answer.get("code") not in (200, None):
            raise UgreenError(f"{path.split('?')[0]}: UGOS answered with code {answer.get('code')}")
        return answer.get("data")

    def snapshot(self):
        notes = []
        try:
            machine = self.data("/ugreen/v1/sysinfo/machine")
        except LoginRefused:
            raise
        except UgreenError as exc:
            machine = None
            notes.append(f"system information: {exc}")
        containers = self.data("/ugreen/v1/ShowContainerDetailListV2")
        if isinstance(containers, dict):
            containers = containers.get("list") or containers.get("containers") or containers.get("data") or []
        return {"machine": machine if isinstance(machine, dict) else {}, "containers": [c for c in containers or [] if isinstance(c, dict)], "notes": notes}


# ----------------------------------------------------------------------------- turning UGOS' answers into Netlens' format
def _mac(value):
    text = str(value or "").strip().lower().replace("-", ":")
    return text if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", text) and text != "00:00:00:00:00:00" else None


def _ipv4(value):
    text = str(value or "").strip()
    return text if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", text) and text != "0.0.0.0" else None


def _int(value):
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0 else None


def _clean(details):
    return {k: v for k, v in details.items() if v not in (None, "", [])}


def _host(snapshot, connect_host):
    machine = snapshot["machine"]
    name = str(machine.get("hostname") or machine.get("model") or "").strip()
    host = {"id": (str(machine.get("serial_number") or "") or name or connect_host).lower(), "name": name or connect_host, "online": True}
    cards = [c for c in machine.get("network_interfaces") or [] if isinstance(c, dict)]
    ip = connect_host if _ipv4(connect_host) and not connect_host.startswith("127.") else None
    chosen = next((c for c in cards if ip and _ipv4(c.get("ip")) == ip and _mac(c.get("mac"))), None)
    if chosen is None and not ip:
        chosen = next((c for c in cards if _ipv4(c.get("ip")) and _mac(c.get("mac"))), None)
        ip = _ipv4(chosen.get("ip")) if chosen else None
    if ip:
        host["ip"] = ip
    if chosen:
        host["mac"] = _mac(chosen.get("mac"))
    return host


def _ports(item):
    out = []
    for port in item.get("ports") or []:
        host_port = container_port = None
        proto = "tcp"
        if isinstance(port, dict):
            host_port = _int(port.get("host_port") or port.get("hostPort") or port.get("public_port") or port.get("publicPort"))
            container_port = _int(port.get("container_port") or port.get("containerPort") or port.get("private_port") or port.get("privatePort"))
            proto = str(port.get("protocol") or port.get("type") or "tcp").lower()
        elif isinstance(port, str):
            m = re.match(r"(?:[\d.]+:)?(\d+)->(\d+)(?:/(\w+))?", port)
            if m:
                host_port, container_port, proto = int(m.group(1)), int(m.group(2)), (m.group(3) or "tcp").lower()
        if host_port:
            out.append({"container_port": container_port, "host_port": host_port, "proto": proto, "bind": ""})
    return out[:100]


def to_hypervisor(snapshot, connect_host=""):
    host = _host(snapshot, connect_host)
    guests = []
    for item in snapshot["containers"]:
        name = str(item.get("name") or "").lstrip("/").strip()
        if not name:
            continue
        ports = _ports(item)
        status = STATES.get(str(item.get("status") or item.get("state") or "").lower(), str(item.get("status") or "unknown").lower()[:30])
        details = {"image": str(item.get("image") or "")[:200], "ports": ports}
        details["exposed"] = True if ports else None
        guests.append({"id": f"container:{name}", "name": name, "kind": "container", "host_id": host["id"], "status": status, "macs": [], "ips": [], "details": _clean(details)})
    seen, unique = set(), []
    for g in guests:
        if g["id"] not in seen:
            seen.add(g["id"])
            unique.append(g)
    return {"hosts": [host], "guests": unique}


# ----------------------------------------------------------------------------- settings and entry points
def _servers(config):
    rows = config.get("servers")
    if not isinstance(rows, list):
        return [config]
    out = [{"url": r.get("host"), "username": r.get("username"), "password": r.get("password"), "verify_tls": config.get("verify_tls"), "timeout": config.get("timeout")}
           for r in rows if isinstance(r, dict) and (r.get("host") or r.get("username"))]
    if not out:
        raise ValueError("enter the address, user name and password of at least one UGREEN NAS")
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
    client = Ugreen(one)
    client.open()
    snapshot = client.snapshot()
    return to_hypervisor(snapshot, client.host), snapshot


def test(config):
    def one(row):
        out, snapshot = _fetch_one(row)
        model = str(snapshot["machine"].get("model") or "UGREEN")
        firmware = str(snapshot["machine"].get("firmware_version") or "").strip()
        message = f"Connected to {out['hosts'][0]['name']} ({model}{', UGOS ' + firmware if firmware else ''}): {len(out['guests'])} container(s)"
        if snapshot["notes"]:
            message += ". Not available: " + "; ".join(snapshot["notes"])
        return message
    messages = _each(config, one)
    return {"message": messages[0] if len(messages) == 1 else f"{len(messages)} UGREEN systems answered. " + " | ".join(messages)}


def fetch(config):
    results = [r[0] for r in _each(config, _fetch_one)]
    if len(results) == 1:
        return results[0]
    hosts, guests, taken = [], [], set()
    for out in results:
        hosts += out["hosts"]
        for g in out["guests"]:
            if g["id"] in taken:
                g = {**g, "id": f"{g['host_id']}/{g['id']}"}
            taken.add(g["id"])
            guests.append(g)
    return {"hosts": hosts, "guests": guests}


# ----------------------------------------------------------------------------- diagnostic (for the plugin's author)
KEEP_WORDS = {"code", "status", "state", "protocol", "type", "cpu_arch"}


def describe(value, key=""):
    """The shape of a value: types and sizes, never the content (except a few harmless enumerations)."""
    if isinstance(value, dict):
        return {k: describe(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [describe(v, key) for v in value[:2]] + ([f"... {len(value)} items"] if len(value) > 2 else [])
    if isinstance(value, bool) or value is None:
        return value
    if key in KEEP_WORDS and isinstance(value, (str, int)) and len(str(value)) < 24:
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
    """What this NAS answers, described by field names and types, and what the plugin made of it (no names, MACs or IPs)."""
    client = Ugreen(_servers(config)[0])
    client.open()                          # a refused login is reported as such (and stops automatic syncing), like test()
    report = {"steps": {}}
    for name, path in (("machine", "/ugreen/v1/sysinfo/machine"), ("containers", "/ugreen/v1/ShowContainerDetailListV2"), ("network", "/ugreen/v1/network/interfaces")):
        try:
            report["steps"][name] = {"ok": True, "shape": describe(client._json("GET", path)[1])}
        except Exception as exc:  # noqa: BLE001 - the point is to record what failed
            report["steps"][name] = {"ok": False, "error": _problem(exc, client)}
    try:
        snapshot = client.snapshot()
        out = to_hypervisor(snapshot, client.host)
        report["result"] = {"host_has_ip": "ip" in out["hosts"][0], "host_has_mac": "mac" in out["hosts"][0], "guests": len(out["guests"]),
                            "guests_with_ports": sum(1 for g in out["guests"] if g["details"].get("ports")), "not_available": [_problem(RuntimeError(n), client) for n in snapshot["notes"]]}
    except Exception as exc:  # noqa: BLE001
        report["error"] = _problem(exc, client)
    return report
