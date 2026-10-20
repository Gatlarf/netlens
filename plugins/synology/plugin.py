"""Synology plugin (kind "hypervisor"): a Synology NAS (DiskStation Manager) as a host, with its Container Manager containers,
Virtual Machine Manager machines and installed packages as guests.

Talks to the DSM web API over HTTPS, read-only:

    SYNO.API.Info                 which API versions this DSM has
    SYNO.API.Auth                 login (and logout) with a user name and password
    SYNO.DSM.Info                 model, DSM version, uptime
    SYNO.Core.Network             the name of the NAS
    SYNO.Core.Network.Interface   the address and MAC of its network cards
    SYNO.Docker.Container         containers of Container Manager (Docker on older DSM)
    SYNO.Virtualization.API.Guest virtual machines of Virtual Machine Manager
    SYNO.Core.Package             installed packages and whether they run

Standard library only. A refused login is reported with `auth_failed` so Netlens stops retrying until the user acts (that
protects the account from being blocked by DSM's auto-block). Every list is optional: a NAS without Virtual Machine Manager
simply reports no machines, with a note.
"""

import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAX_INSPECT = 60                  # containers whose details are read (one request each)
APIS = ("SYNO.DSM.Info", "SYNO.Core.Network", "SYNO.Core.Network.Interface", "SYNO.Docker.Container", "SYNO.Virtualization.API.Guest", "SYNO.Core.Package")
SESSION = "Netlens"

AUTH_ERRORS = {
    400: "the user name or password is wrong",
    401: "this account is disabled",
    402: "this account may not use the DSM web interface (check Control Panel > User > Applications)",
    403: "this account has two-step verification switched on; use a dedicated account without it (and limit it with the DSM firewall)",
    404: "the two-step verification code was refused",
    406: "DSM requires two-step verification for this account; use a dedicated account that is exempt",
    407: "DSM has blocked the address of this machine (Control Panel > Security > Protection > Allow/Block list)",
    408: "the password has expired; set a new one in DSM and save it here",
    409: "the password has expired; set a new one in DSM and save it here",
    410: "the password has to be changed in DSM first",
}
API_ERRORS = {
    100: "unknown error", 101: "invalid parameter", 102: "the API does not exist on this DSM", 103: "the method does not exist on this DSM",
    104: "this DSM version is not supported", 105: "this account has no permission for it (it needs to be in the administrators group)",
    106: "the session timed out", 107: "the session was interrupted", 119: "the session is not valid",
}


class SynologyError(Exception):
    pass


class ConnectError(SynologyError):
    """The NAS could not be reached (not a login problem)."""


class LoginRefused(SynologyError):
    auth_failed = True


class ApiMissing(SynologyError):
    """This DSM does not have the API (a package that is not installed, an older DSM)."""


def normalize(url):
    """'192.168.0.5' -> 'https://192.168.0.5:5001'; 'https://nas.local' stays; a plain http:// address (tests, trusted LANs) keeps its port."""
    text = str(url or "").strip()
    if not text:
        raise ValueError("enter the address of the Synology (for example https://192.168.0.5:5001)")
    if "://" not in text:
        text = "https://" + text
    parts = urllib.parse.urlsplit(text)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ValueError("the address must start with https:// (or http://) and name the NAS")
    port = parts.port or (5001 if parts.scheme == "https" else 5000)
    host = parts.hostname
    return f"{parts.scheme}://{host}:{port}", host


class DSM:
    def __init__(self, config):
        self.base, self.host = normalize(config.get("url") or config.get("host"))
        self.user = str(config.get("username") or "")
        self.password = str(config.get("password") or "")
        self.verify = bool(config.get("verify_tls"))
        self.timeout = int(config.get("timeout") or 30)
        if not self.user or not self.password:
            raise ValueError("enter the user name and the password")
        self.sid = None
        self.paths = {}
        context = ssl.create_default_context()
        if not self.verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))

    # ------------------------------------------------------------------ transport
    def _fetch(self, path, params, post=False):
        data = urllib.parse.urlencode(params).encode()
        url = f"{self.base}/webapi/{path}"
        request = urllib.request.Request(url, data=data) if post else urllib.request.Request(url + "?" + data.decode())
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(8 * 1024 * 1024)
        except urllib.error.HTTPError as exc:
            raise ConnectError(f"the Synology answered with HTTP {exc.code} (is this the DSM address and port, 5001 for https?)") from None
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise ConnectError(f"cannot reach the Synology at {self.host}: {reason}") from None
        try:
            answer = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            raise ConnectError("this does not look like a Synology DSM (the answer is not JSON)") from None
        if not isinstance(answer, dict):
            raise ConnectError("this does not look like a Synology DSM (unexpected answer)")
        return answer

    def _discover(self):
        if self.paths:
            return
        answer = self._fetch("query.cgi", {"api": "SYNO.API.Info", "version": 1, "method": "query", "query": ",".join(("SYNO.API.Auth",) + APIS)})
        data = answer.get("data") if answer.get("success") else None
        if not isinstance(data, dict) or "SYNO.API.Auth" not in data:
            raise ConnectError("this does not look like a Synology DSM (no SYNO.API.Auth)")
        self.paths = {name: info for name, info in data.items() if isinstance(info, dict) and info.get("path")}

    # ------------------------------------------------------------------ session
    def open(self):
        self._discover()
        auth = self.paths["SYNO.API.Auth"]
        version = max(3, min(int(auth.get("maxVersion") or 6), 6))
        answer = self._fetch(auth["path"], {"api": "SYNO.API.Auth", "version": version, "method": "login", "account": self.user, "passwd": self.password,
                                            "session": SESSION, "format": "sid"}, post=True)
        if not answer.get("success"):
            code = (answer.get("error") or {}).get("code") if isinstance(answer.get("error"), dict) else None
            raise LoginRefused("login refused: " + AUTH_ERRORS.get(code, f"DSM answered with error {code}"))
        sid = (answer.get("data") or {}).get("sid")
        if not sid:
            raise LoginRefused("login refused: DSM gave no session")
        self.sid = sid

    def close(self):
        if self.sid and "SYNO.API.Auth" in self.paths:
            try:
                self._fetch(self.paths["SYNO.API.Auth"]["path"], {"api": "SYNO.API.Auth", "version": 1, "method": "logout", "session": SESSION, "_sid": self.sid})
            except SynologyError:
                pass
        self.sid = None

    def call(self, api, method, version=1, **params):
        info = self.paths.get(api)
        if info is None:
            raise ApiMissing(f"{api}: not available on this DSM")
        use = max(int(info.get("minVersion") or 1), min(int(version), int(info.get("maxVersion") or version)))
        answer = self._fetch(info["path"], {"api": api, "version": use, "method": method, "_sid": self.sid, **params})
        if answer.get("success"):
            return answer.get("data")
        code = (answer.get("error") or {}).get("code") if isinstance(answer.get("error"), dict) else None
        if code in (102, 103, 104):
            raise ApiMissing(f"{api}: {API_ERRORS.get(code)}")
        raise SynologyError(f"{api}.{method}: {API_ERRORS.get(code, f'error {code}')}")

    def optional(self, notes, label, api, method, version=1, **params):
        """Data from a feature the NAS may not have (no Virtual Machine Manager) or the account may not read: None, with a note."""
        try:
            return self.call(api, method, version, **params)
        except SynologyError as exc:
            notes.append(f"{label}: {exc}")
            return None

    def inspect_containers(self, containers, notes):
        """DSM's container list has no ports or networks; `get` gives the full `docker inspect` of one container. Added to each list item as "_inspect"."""
        failed = 0
        for item in _listing(containers, "containers")[:MAX_INSPECT]:
            name = str(item.get("name") or "").lstrip("/")
            if not name or failed >= 3:
                continue
            try:
                got = self.call("SYNO.Docker.Container", "get", 1, name=name)
            except SynologyError as exc:
                failed += 1
                if failed == 1:
                    notes.append(f"container details: {exc}")
                continue
            if isinstance(got, dict) and isinstance(got.get("details"), dict):
                item["_inspect"] = got["details"]

    def snapshot(self):
        notes = []
        info = self.call("SYNO.DSM.Info", "getinfo", 2)
        if not isinstance(info, dict):
            raise SynologyError("unexpected answer from SYNO.DSM.Info")
        network = self.optional(notes, "network name", "SYNO.Core.Network", "get", 1)
        interfaces = self.optional(notes, "network cards", "SYNO.Core.Network.Interface", "list", 1)
        containers = self.optional(notes, "containers", "SYNO.Docker.Container", "list", 1, limit=-1, offset=0, type="all")
        self.inspect_containers(containers, notes)
        machines = self.optional(notes, "virtual machines", "SYNO.Virtualization.API.Guest", "list", 1)
        packages = self.optional(notes, "packages", "SYNO.Core.Package", "list", 1, additional=json.dumps(["status"]))
        return {"info": info, "network": network if isinstance(network, dict) else {}, "interfaces": interfaces, "containers": containers,
                "machines": machines, "packages": packages, "notes": notes}


# ----------------------------------------------------------------------------- turning DSM's answers into Netlens' format
def _mac(value):
    text = str(value or "").strip().lower().replace("-", ":")
    return text if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", text) and text != "00:00:00:00:00:00" else None


def _int(value):
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0 else None


def _clean(details):
    return {k: v for k, v in details.items() if v not in (None, "", [])}


def _listing(data, *keys):
    """DSM wraps lists in an object: {"containers": [...]} or {"guests": [...]} or the list itself."""
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in keys:
            if isinstance(data.get(key), list):
                return [x for x in data[key] if isinstance(x, dict)]
    return []


def _interface_list(snapshot):
    return _listing(snapshot.get("interfaces"), "interfaces", "ifaces", "items")


def _host(snapshot, connect_host):
    info = snapshot["info"]
    name = str(snapshot["network"].get("server_name") or info.get("hostname") or "").strip()
    model = str(info.get("model") or "").strip()
    serial = str(info.get("serial") or "").strip()
    chosen = None
    for card in _interface_list(snapshot):
        if str(card.get("ip") or "") == connect_host and _mac(card.get("mac") or card.get("hwaddr")):
            chosen = card
            break
    host = {"id": (serial or name or connect_host).lower(), "name": name or model or connect_host, "online": True}
    try:
        socket.inet_aton(connect_host)
        host["ip"] = connect_host
    except OSError:
        card = next((c for c in _interface_list(snapshot) if str(c.get("ip") or "").count(".") == 3), None)
        if card:
            host["ip"] = str(card["ip"])
    if chosen:
        host["mac"] = _mac(chosen.get("mac") or chosen.get("hwaddr"))
    return host


def _status(value):
    if isinstance(value, dict):
        value = value.get("status") or value.get("state")
    text = str(value or "unknown").lower()
    return {"shutdown": "stopped", "shut_down": "stopped", "poweroff": "stopped", "exited": "stopped", "up": "running", "stop": "stopped"}.get(text, text)


INTERNAL_NETWORKS = {"bridge", "host", "none", "ingress"}


def _inspect_ports(inspect):
    """The published ports from a `docker inspect`: HostConfig.PortBindings (also there for a stopped container), else NetworkSettings.Ports."""
    bindings = (inspect.get("HostConfig") or {}).get("PortBindings") or (inspect.get("NetworkSettings") or {}).get("Ports") or {}
    out = []
    for key, targets in bindings.items() if isinstance(bindings, dict) else []:
        container_port, _, proto = str(key).partition("/")
        for target in targets or []:
            if not isinstance(target, dict):
                continue
            host_port = _int(int(target["HostPort"])) if str(target.get("HostPort") or "").isdigit() else None
            if host_port:
                out.append({"container_port": _int(int(container_port)) if container_port.isdigit() else None, "host_port": host_port, "proto": (proto or "tcp").lower(),
                            "bind": str(target.get("HostIp") or "")})
    return out


def _lan_addresses(inspect):
    """MAC and IP addresses of a container that sits on the network itself (macvlan, ipvlan). Docker's own bridges (02:42:...) are internal and left out."""
    macs, ips = [], []
    for name, net in ((inspect.get("NetworkSettings") or {}).get("Networks") or {}).items():
        if name in INTERNAL_NETWORKS or not isinstance(net, dict):
            continue
        mac = _mac(net.get("MacAddress"))
        if mac and not mac.startswith("02:42:"):
            macs.append(mac)
            if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", str(net.get("IPAddress") or "")):
                ips.append(str(net["IPAddress"]))
    return macs, ips


def _container_ports(item):
    out = _inspect_ports(item["_inspect"]) if isinstance(item.get("_inspect"), dict) else []
    if out:
        return out[:100]
    for port in item.get("ports") or item.get("port_bindings") or []:
        if not isinstance(port, dict):
            continue
        host_port = _int(port.get("host_port") or port.get("HostPort"))
        if host_port:
            out.append({"container_port": _int(port.get("container_port") or port.get("ContainerPort")), "host_port": host_port,
                        "proto": str(port.get("type") or port.get("protocol") or "tcp").lower(), "bind": str(port.get("host_ip") or "")})
    return out[:100]


def to_hypervisor(snapshot, connect_host=""):
    host = _host(snapshot, connect_host)
    guests = []
    for item in _listing(snapshot["containers"], "containers"):
        name = str(item.get("name") or "").lstrip("/")
        if not name:
            continue
        ports = _container_ports(item)
        details = {"image": str(item.get("image") or "")[:200], "health": str(item.get("health") or "")[:40],
                   "started": str(item.get("up_time") or item.get("started") or "")[:40], "ports": ports}
        details["exposed"] = any(p["bind"] in ("0.0.0.0", "::", "") for p in ports) if ports else None
        macs, ips = _lan_addresses(item["_inspect"]) if isinstance(item.get("_inspect"), dict) else ([], [])
        guests.append({"id": f"container:{name}", "name": name, "kind": "container", "host_id": host["id"], "status": _status(item.get("status") or item.get("state")),
                       "macs": macs, "ips": ips, "details": _clean(details)})
    for item in _listing(snapshot["machines"], "guests", "vms", "machines"):
        name = str(item.get("guest_name") or item.get("name") or "").strip()
        ident = str(item.get("guest_id") or item.get("id") or name)
        if not name:
            continue
        macs = [m for m in (_mac(n.get("mac")) for n in item.get("vnics") or item.get("nics") or [] if isinstance(n, dict)) if m]
        memory = _int(item.get("vram_size") or item.get("memory"))
        details = {"cpus": _int(item.get("vcpu_num") or item.get("vcpus")), "memory_mb": memory // 1024 if memory and memory > 65536 * 16 else memory,
                   "autostart": bool(item["autorun"]) if "autorun" in item and not isinstance(item.get("autorun"), (int, float)) else None}
        guests.append({"id": f"vm:{ident}", "name": name, "kind": "qemu", "host_id": host["id"], "status": _status(item.get("status")),
                       "macs": macs, "ips": [], "details": _clean(details)})
    for item in _listing(snapshot["packages"], "packages"):
        name = str(item.get("name") or item.get("id") or "").strip()
        if not name:
            continue
        status = (item.get("additional") or {}).get("status") if isinstance(item.get("additional"), dict) else item.get("status")
        guests.append({"id": f"pkg:{item.get('id') or name}", "name": name, "kind": "app", "host_id": host["id"], "status": _status(status),
                       "macs": [], "ips": [], "details": _clean({"version": str(item.get("version") or "")[:60]})})
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
        raise ValueError("enter the address, user name and password of at least one Synology")
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


def _session(one):
    dsm = DSM(one)
    dsm.open()
    return dsm


def _test_one(one):
    dsm = _session(one)
    try:
        snapshot = dsm.snapshot()
    finally:
        dsm.close()
    out = to_hypervisor(snapshot, dsm.host)
    kinds = [g["kind"] for g in out["guests"]]
    info = snapshot["info"]
    message = (f"Connected to {out['hosts'][0]['name']} ({info.get('model') or 'Synology'}, {info.get('version_string') or 'DSM'}): "
               f"{kinds.count('container')} container(s), {kinds.count('qemu')} virtual machine(s), {kinds.count('app')} package(s)")
    if snapshot["notes"]:
        message += ". Not available: " + "; ".join(snapshot["notes"])
    return message


def test(config):
    messages = _each(config, _test_one)
    return {"message": messages[0] if len(messages) == 1 else f"{len(messages)} Synology systems answered. " + " | ".join(messages)}


def _fetch_one(one):
    dsm = _session(one)
    try:
        snapshot = dsm.snapshot()
    finally:
        dsm.close()
    return to_hypervisor(snapshot, dsm.host)


def fetch(config):
    results = _each(config, _fetch_one)
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
KEEP_WORDS = {"version", "type", "status", "state", "model", "version_string", "path", "minVersion", "maxVersion", "success"}
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
            return "<mac " + ("dashes" if "-" in value else "colons") + ">"
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
    """What this DSM answers, described by field names and types, and what the plugin made of it (no names, MACs or IPs)."""
    dsm = _session(_servers(config)[0])           # a refused login is reported as such (and stops automatic syncing), like test()
    report = {"steps": {}, "apis": sorted(dsm.paths)}

    def step(name, api, method, version=1, **params):
        try:
            result = dsm.call(api, method, version, **params)
        except Exception as exc:  # noqa: BLE001 - the point is to record what failed
            report["steps"][name] = {"ok": False, "error": _problem(exc)}
            return None
        report["steps"][name] = {"ok": True, "shape": describe(result)}
        return result

    try:
        step("dsm_info", "SYNO.DSM.Info", "getinfo", 2)
        step("network", "SYNO.Core.Network", "get", 1)
        step("interfaces", "SYNO.Core.Network.Interface", "list", 1)
        step("containers", "SYNO.Docker.Container", "list", 1, limit=-1, offset=0, type="all")
        step("virtual_machines", "SYNO.Virtualization.API.Guest", "list", 1)
        step("packages", "SYNO.Core.Package", "list", 1, additional=json.dumps(["status"]))
        snapshot = dsm.snapshot()
        out = to_hypervisor(snapshot, dsm.host)
        report["result"] = {
            "host_has_ip": "ip" in out["hosts"][0], "host_has_mac": "mac" in out["hosts"][0], "guests": len(out["guests"]),
            "by_kind": {k: sum(1 for g in out["guests"] if g["kind"] == k) for k in ("container", "qemu", "app")},
            "guests_with_mac": sum(1 for g in out["guests"] if g["macs"]), "not_available": snapshot["notes"],
        }
    except Exception as exc:  # noqa: BLE001
        report["error"] = _problem(exc)
    finally:
        dsm.close()
    return report
