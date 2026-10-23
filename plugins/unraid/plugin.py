"""Unraid plugin (kind "hypervisor"): an Unraid server as a host, with its Docker containers and virtual machines as guests.

Talks to the Unraid API (GraphQL, built into Unraid 7.2 and newer, an add-on plugin before that) over HTTP(S), read-only:

    POST /graphql   header x-api-key: <key>

    info { os { hostname distro release uptime } }       the name and version of the server
    primaryNetwork / networkInterfaces                   its address and MAC
    docker { containers { ... } }                        containers (older API: dockerContainers)
    vms { domains { id name state } }                    virtual machines (libvirt)

Standard library only. A refused key is reported with `auth_failed` so Netlens stops retrying until the user acts. Every list is
optional: a server whose key may not read VMs, or that has the VM manager switched off, simply reports no machines, with a note.
"""

import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAX_BODY = 8 * 1024 * 1024
VM_STATES = {"RUNNING": "running", "IDLE": "running", "PAUSED": "paused", "PMSUSPENDED": "paused", "SHUTOFF": "stopped", "SHUTDOWN": "stopped",
             "CRASHED": "crashed", "NOSTATE": "unknown"}
INTERNAL_NETWORKS = {"bridge", "host", "none", "ingress"}

Q_INFO = "{ info { os { hostname distro release uptime } } }"
Q_SERVER = "{ server { name lanip } }"
Q_NETWORK = "{ info { primaryNetwork { name macAddress ipAddress } networkInterfaces { name macAddress ipAddress virtual internal } } }"
Q_NETWORK_SIMPLE = "{ networkInterfaces { name macAddress ipAddress virtual internal } }"
CONTAINER_FIELDS = "id names image state status autoStart ports { ip privatePort publicPort type } hostConfig { networkMode } networkSettings"
Q_CONTAINERS = "{ docker { containers { %s } } }" % CONTAINER_FIELDS
Q_CONTAINERS_OLD = "{ dockerContainers { %s } }" % CONTAINER_FIELDS
Q_VMS = "{ vms { domains { id name state } } }"
DISK_FIELDS = "id idx name device size status temp type fsSize fsFree fsUsed fsType numErrors"
Q_ARRAY = "{ array { state capacity { kilobytes { free used total } } parities { %s } disks { %s } caches { %s } } }" % ((DISK_FIELDS,) * 3)
Q_SHARES = "{ shares { name free used size } }"
Q_VMS_OLD = "{ vms { domain { id name state } } }"


class UnraidError(Exception):
    pass


class ConnectError(UnraidError):
    """The server could not be reached (not a key problem)."""


class KeyRefused(UnraidError):
    auth_failed = True


class GraphQLError(UnraidError):
    """The server answered, but not with the data asked for (a field this Unraid version does not have, a permission the key lacks)."""


def normalize(url):
    text = str(url or "").strip()
    if not text:
        raise ValueError("enter the address of the Unraid server (for example https://192.168.0.10 or http://tower)")
    if "://" not in text:
        text = "http://" + text
    parts = urllib.parse.urlsplit(text)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ValueError("the address must start with http:// or https:// and name the server")
    host = parts.hostname
    shown = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{shown}" + (f":{parts.port}" if parts.port else ""), host


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Unraid:
    def __init__(self, config):
        self.base, self.host = normalize(config.get("url") or config.get("host"))
        self.key = str(config.get("api_key") or "").strip()
        self.verify = bool(config.get("verify_tls"))
        self.timeout = int(config.get("timeout") or 30)
        if not self.key:
            raise ValueError("enter the API key (Unraid: Settings > Management Access > API Keys)")
        context = ssl.create_default_context()
        if not self.verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        # redirects are followed by hand: Unraid sends http:// to https:// and a POST would not survive urllib's own redirect
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), _NoRedirect)

    def _post(self, query):
        body = json.dumps({"query": query}).encode()
        for _ in range(3):
            request = urllib.request.Request(self.base + "/graphql", data=body, headers={"Content-Type": "application/json", "Accept": "application/json", "x-api-key": self.key})
            try:
                with self.opener.open(request, timeout=self.timeout) as response:
                    raw = response.read(MAX_BODY)
                break
            except urllib.error.HTTPError as exc:
                where = exc.headers.get("Location") if exc.code in (301, 302, 307, 308) else None
                if where:
                    origin = urllib.parse.urlsplit(urllib.parse.urljoin(self.base + "/graphql", where))
                    if origin.hostname and origin.scheme in ("http", "https"):
                        self.base = f"{origin.scheme}://{origin.netloc}"
                        continue
                if exc.code in (401, 403):
                    raise KeyRefused("the key was refused: check the API key and that it has the Viewer role") from None
                raise ConnectError(f"the server answered with HTTP {exc.code} (is this an Unraid server with the API, version 7.2 or newer?)") from None
            except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as exc:
                raise ConnectError(f"cannot reach the Unraid server at {self.host}: {getattr(exc, 'reason', exc)}") from None
        else:
            raise ConnectError("too many redirects")
        try:
            answer = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            raise ConnectError("this does not look like the Unraid API (the answer is not JSON)") from None
        if not isinstance(answer, dict):
            raise ConnectError("this does not look like the Unraid API (unexpected answer)")
        return answer

    def query(self, text):
        answer = self._post(text)
        errors = answer.get("errors")
        if errors:
            first = errors[0] if isinstance(errors, list) and errors and isinstance(errors[0], dict) else {}
            message = str(first.get("message") or "error")[:200]
            code = str((first.get("extensions") or {}).get("code") or "")
            if code in ("UNAUTHENTICATED", "FORBIDDEN") or re.search(r"api key|unauthori|forbidden|not allowed|permission", message, re.I):
                if answer.get("data") in (None, {}):
                    raise KeyRefused("the key was refused or may not read this: " + message)
            raise GraphQLError(message)
        data = answer.get("data")
        if not isinstance(data, dict):
            raise GraphQLError("no data in the answer")
        return data

    def optional(self, notes, label, *queries):
        """The first of the queries that works, or None with a note (a feature this version lacks, a permission the key lacks)."""
        last = None
        for text in queries:
            try:
                return self.query(text)
            except KeyRefused:
                raise
            except GraphQLError as exc:
                last = exc
        notes.append(f"{label}: {last}")
        return None

    def snapshot(self):
        notes = []
        info = self.optional(notes, "server info", Q_INFO) or {}
        server = self.optional(notes, "server name", Q_SERVER) or {}
        network = self.optional(notes, "network", Q_NETWORK, Q_NETWORK_SIMPLE) or {}
        containers = self.optional(notes, "containers", Q_CONTAINERS, Q_CONTAINERS_OLD)
        machines = self.optional(notes, "virtual machines", Q_VMS, Q_VMS_OLD)
        array = self.optional(notes, "array", Q_ARRAY) or {}
        shares = self.optional(notes, "shares", Q_SHARES) or {}
        if containers is None and machines is None and not info:
            raise UnraidError("the server answered, but none of the queries worked: " + "; ".join(notes))
        return {"info": info, "server": server, "network": network, "containers": containers or {}, "machines": machines or {}, "array": array.get("array") if isinstance(array.get("array"), dict) else {},
                "shares": shares.get("shares") if isinstance(shares.get("shares"), list) else [], "notes": notes}


# ----------------------------------------------------------------------------- turning Unraid's answers into Netlens' format
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


def _interfaces(snapshot):
    net = snapshot["network"]
    cards = []
    primary = ((net.get("info") or {}).get("primaryNetwork")) if isinstance(net.get("info"), dict) else None
    if isinstance(net.get("info"), dict):
        cards += [c for c in net["info"].get("networkInterfaces") or [] if isinstance(c, dict)]
        if isinstance(primary, dict):
            cards.insert(0, primary)
    cards += [c for c in net.get("networkInterfaces") or [] if isinstance(c, dict)]
    return cards


def _host(snapshot, connect_host):
    os_info = ((snapshot["info"].get("info") or {}).get("os")) or {}
    name = str(os_info.get("hostname") or (snapshot["server"].get("server") or {}).get("name") or "").strip()
    host = {"id": (name or connect_host).lower(), "name": name or connect_host, "online": True}
    cards = _interfaces(snapshot)
    ip = connect_host if _ipv4(connect_host) and not connect_host.startswith("127.") else _ipv4((snapshot["server"].get("server") or {}).get("lanip"))
    chosen = next((c for c in cards if ip and _ipv4(c.get("ipAddress")) == ip and _mac(c.get("macAddress"))), None)
    if chosen is None and cards:
        chosen = next((c for c in cards if _mac(c.get("macAddress")) and not c.get("virtual") and not c.get("internal")
                       and _ipv4(c.get("ipAddress"))), None)
    if not ip and chosen:
        ip = _ipv4(chosen.get("ipAddress"))
    if ip:
        host["ip"] = ip
    if chosen:
        host["mac"] = _mac(chosen.get("macAddress"))
    return host


def _state(value):
    return {"RUNNING": "running", "PAUSED": "paused", "EXITED": "stopped"}.get(str(value or "").upper(), str(value or "unknown").lower())


def _lan_addresses(settings):
    """MAC and IP addresses of a container that sits on the network itself (br0, macvlan, ipvlan). Docker's own bridges (02:42:...) are internal."""
    macs, ips = [], []
    networks = settings.get("Networks") if isinstance(settings, dict) else None
    for name, net in (networks or {}).items():
        if name in INTERNAL_NETWORKS or not isinstance(net, dict):
            continue
        mac = _mac(net.get("MacAddress"))
        if mac and not mac.startswith("02:42:"):
            macs.append(mac)
            if _ipv4(net.get("IPAddress")):
                ips.append(net["IPAddress"])
    return macs, ips


def _container_ports(item):
    out, seen = [], set()
    for port in item.get("ports") or []:
        if not isinstance(port, dict):
            continue
        host_port = _int(port.get("publicPort"))
        if not host_port:
            continue
        proto = str(port.get("type") or "tcp").lower()
        key = (host_port, proto)
        if key in seen:        # the same port is listed once per address family
            continue
        seen.add(key)
        out.append({"container_port": _int(port.get("privatePort")), "host_port": host_port, "proto": proto, "bind": str(port.get("ip") or "")})
    return out[:100]


def to_hypervisor(snapshot, connect_host=""):
    host = _host(snapshot, connect_host)
    guests = []
    containers = snapshot["containers"]
    items = ((containers.get("docker") or {}).get("containers") if isinstance(containers.get("docker"), dict) else None) or containers.get("dockerContainers") or []
    for item in items:
        if not isinstance(item, dict):
            continue
        names = [str(n).lstrip("/") for n in item.get("names") or [] if n]
        if not names:
            continue
        name = names[0]
        ports = _container_ports(item)
        macs, ips = _lan_addresses(item.get("networkSettings"))
        details = {"image": str(item.get("image") or "")[:200], "ports": ports,
                   "network": str((item.get("hostConfig") or {}).get("networkMode") or "")[:40],
                   "autostart": bool(item["autoStart"]) if isinstance(item.get("autoStart"), bool) else None}
        details["exposed"] = any(p["bind"] in ("0.0.0.0", "::", "") for p in ports) if ports else None
        guests.append({"id": f"container:{name}", "name": name, "kind": "container", "host_id": host["id"], "status": _state(item.get("state")),
                       "macs": macs, "ips": ips, "details": _clean(details)})
    machines = snapshot["machines"].get("vms") if isinstance(snapshot["machines"].get("vms"), dict) else {}
    for item in (machines.get("domains") or machines.get("domain") or []):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        ident = str(item.get("id") or name)
        if not name:
            continue
        ident = ident.split(":", 1)[-1] if ":" in ident else ident          # "<server id>:<uuid>" -> the uuid
        guests.append({"id": f"vm:{ident}", "name": name, "kind": "qemu", "host_id": host["id"], "status": VM_STATES.get(str(item.get("state") or "").upper(), "unknown"),
                       "macs": [], "ips": [], "details": {}})
    seen, unique = set(), []
    for g in guests:
        if g["id"] not in seen:
            seen.add(g["id"])
            unique.append(g)
    return {"hosts": [host], "guests": unique}


# ----------------------------------------------------------------------------- storage (array, cache, shares)
RANK = {"unknown": 0, "ok": 1, "warning": 2, "critical": 3}
ARRAY_OK = {"STARTED"}
ARRAY_WARN = {"STOPPED", "NEW_ARRAY", "RECON_DISK", "NO_DATA_DISKS"}
DISK_STATE = {"DISK_OK": "ok", "DISK_NEW": "ok", "DISK_DSBL": "failed", "DISK_INVALID": "failed", "DISK_NP_MISSING": "failed", "DISK_WRONG": "degraded", "DISK_DSBL_NEW": "degraded"}


def _kb(value):
    try:
        number = int(str(value)) * 1024
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _big(value):
    try:
        number = int(str(value))
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def to_storage(snapshot, connect_host=""):
    """The storage part of the output: the array and the cache disks as pools, every disk with its state and the shares (the Storage page)."""
    host = _host(snapshot, connect_host)
    sid = host["id"]
    array = snapshot.get("array") or {}
    if not array:
        return {"systems": [], "controllers": [], "pools": [], "volumes": [], "disks": [], "alerts": []}
    pools, disks, volumes, alerts = [], [], [], []
    state = str(array.get("state") or "")
    level = "ok" if state in ARRAY_OK else "warning" if state in ARRAY_WARN else "critical"
    kb = (array.get("capacity") or {}).get("kilobytes") or {}
    if _kb(kb.get("total")):
        pools.append({"id": "array", "system_id": sid, "name": "Array", "total": _kb(kb.get("total")), "used": _kb(kb.get("used")), "avail": _kb(kb.get("free")), "health": level, "raid": "parity" if array.get("parities") else "no parity"})
    if level != "ok":
        alerts.append({"id": f"array:{state}", "system_id": sid, "severity": level, "text": f"The array is {state.lower().replace('_', ' ') or 'in an unknown state'}"})
    for group in ("parities", "disks", "caches"):
        for d in array.get(group) or []:
            if not isinstance(d, dict) or not (d.get("device") or d.get("name")):
                continue
            status = str(d.get("status") or "")
            if status in ("DISK_NP", "DISK_NP_DSBL"):
                continue                                                  # an empty slot
            mapped = DISK_STATE.get(status, "unknown")
            if mapped == "ok" and (_big(d.get("numErrors")) or 0) > 0:
                mapped = "degraded"
            name = str(d.get("name") or d.get("device"))
            disks.append({"id": f"disk:{d.get('id') or name}", "system_id": sid, "name": name[:100], "slot": str(d.get("device") or "")[:40], "model": str(d.get("type") or "").lower()[:100],
                          "size": _big(d.get("size")) and _big(d.get("size")) * 1024, "state": mapped})
            if mapped in ("failed", "degraded"):
                alerts.append({"id": f"disk:{d.get('id') or name}:{mapped}", "system_id": sid, "severity": "critical" if mapped == "failed" else "warning", "text": f"Disk {name}: {mapped}" + (f" ({d.get('numErrors')} errors)" if (_big(d.get("numErrors")) or 0) else "")})
                level = max(level, "critical" if mapped == "failed" else "warning", key=lambda x: RANK[x])
            if group == "caches" and _big(d.get("fsSize")):
                size, used = _big(d.get("fsSize")) * 1024, (_big(d.get("fsUsed")) or 0) * 1024
                pools.append({"id": f"cache:{d.get('id') or name}", "system_id": sid, "name": name[:100], "total": size, "used": used, "avail": (_big(d.get("fsFree")) or 0) * 1024,
                              "health": "ok" if mapped == "ok" else "critical" if mapped == "failed" else "warning", "raid": str(d.get("fsType") or "")[:60]})
    for share in snapshot.get("shares") or []:
        if isinstance(share, dict) and share.get("name"):
            used, free = _kb(share.get("used")), _kb(share.get("free"))
            volumes.append({"id": f"share:{share['name']}", "system_id": sid, "pool_id": "array" if pools and pools[0]["id"] == "array" else None, "name": str(share["name"])[:200], "kind": "share", "protocol": "",
                            "size": used + free if used is not None and free is not None else None, "used": used, "health": "ok", "clients": []})
    os_info = ((snapshot.get("info") or {}).get("info") or {}).get("os") or {}
    system = {"id": sid, "name": host["name"], "ip": host.get("ip"), "vendor": "Unraid", "model": "", "version": str(os_info.get("release") or "")[:60], "serial": "", "online": True, "health": level, "warnings": []}
    controllers = [{"id": f"{sid}:host", "system_id": sid, "name": host["name"], "ip": host.get("ip"), "mac": host.get("mac"), "online": True, "health": "unknown"}] if host.get("ip") or host.get("mac") else []
    return {"systems": [system], "controllers": controllers, "pools": pools, "volumes": volumes, "disks": disks, "alerts": alerts[:200]}


# ----------------------------------------------------------------------------- settings and entry points
def _servers(config):
    rows = config.get("servers")
    if not isinstance(rows, list):
        return [config]
    out = [{"url": r.get("host"), "api_key": r.get("api_key"), "verify_tls": config.get("verify_tls"), "timeout": config.get("timeout")}
           for r in rows if isinstance(r, dict) and (r.get("host") or r.get("api_key"))]
    if not out:
        raise ValueError("enter the address and the API key of at least one Unraid server")
    return out


def _each(config, work):
    servers = _servers(config)
    results = []
    for one in servers:
        try:
            results.append(work(one))
        except Exception as exc:  # noqa: BLE001 - the type stays (a refused key must stay recognisable)
            label = urllib.parse.urlsplit(str(one.get("url") or "")).netloc or str(one.get("url") or "") if len(servers) > 1 else ""
            if label and exc.args:
                exc.args = (f"{label}: {exc.args[0]}",) + tuple(exc.args[1:])
            raise
    return results


def _fetch_one(one):
    client = Unraid(one)
    snapshot = client.snapshot()
    out = to_hypervisor(snapshot, client.host)
    storage = to_storage(snapshot, client.host)
    if storage["systems"]:
        out["storage"] = storage
    return out, snapshot


def test(config):
    def one(row):
        out, snapshot = _fetch_one(row)
        kinds = [g["kind"] for g in out["guests"]]
        os_info = ((snapshot["info"].get("info") or {}).get("os")) or {}
        release = str(os_info.get("release") or "").strip()
        message = (f"Connected to {out['hosts'][0]['name']} (Unraid{' ' + release if release else ''}): "
                   f"{kinds.count('container')} container(s), {kinds.count('qemu')} virtual machine(s)")
        if snapshot["notes"]:
            message += ". Not available: " + "; ".join(snapshot["notes"])
        return message
    messages = _each(config, one)
    return {"message": messages[0] if len(messages) == 1 else f"{len(messages)} Unraid servers answered. " + " | ".join(messages)}


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
KEEP_WORDS = {"state", "status", "type", "networkMode", "distro", "release", "virtual", "internal", "autoStart", "fsType"}


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


def _problem(exc, client=None):
    """The error text for a diagnostic report, without any server address (URL, IP address, host:port or host name)."""
    text = str(exc)
    if client is not None:
        for secret in (getattr(client, "id", ""), getattr(client, "base", ""), getattr(client, "host", "")):
            if secret:
                text = text.replace(secret, "<url>")
    text = re.sub(r"https?://\S+", "<url>", text)
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<url>", text)
    text = re.sub(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*:\d{2,5}\b", "<url>", text)
    text = re.sub(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", "<url>", text)
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What this Unraid answers, described by field names and types, and what the plugin made of it (no names, MACs or IPs)."""
    client = Unraid(_servers(config)[0])
    report = {"steps": {}}
    for name, queries in (("info", (Q_INFO,)), ("server", (Q_SERVER,)), ("network", (Q_NETWORK, Q_NETWORK_SIMPLE)),
                          ("containers", (Q_CONTAINERS, Q_CONTAINERS_OLD)), ("virtual_machines", (Q_VMS, Q_VMS_OLD)),
                          ("array", (Q_ARRAY,)), ("shares", (Q_SHARES,))):
        for attempt, text in enumerate(queries):
            try:
                result = client.query(text)
            except Exception as exc:  # noqa: BLE001 - the point is to record what failed
                report["steps"][f"{name}{'' if attempt == 0 else '_fallback'}"] = {"ok": False, "error": _problem(exc, client)}
                if isinstance(exc, KeyRefused):
                    raise
                continue
            report["steps"][f"{name}{'' if attempt == 0 else '_fallback'}"] = {"ok": True, "shape": describe(result)}
            break
    try:
        snapshot = client.snapshot()
        out = to_hypervisor(snapshot, client.host)
        report["result"] = {
            "host_has_ip": "ip" in out["hosts"][0], "host_has_mac": "mac" in out["hosts"][0], "guests": len(out["guests"]),
            "by_kind": {k: sum(1 for g in out["guests"] if g["kind"] == k) for k in ("container", "qemu")},
            "guests_with_mac": sum(1 for g in out["guests"] if g["macs"]), "not_available": [_problem(RuntimeError(n), client) for n in snapshot["notes"]],
        }
        st = to_storage(snapshot, client.host)
        report["result"]["storage"] = {"pools": len(st["pools"]), "disks": len(st["disks"]), "shares": len(st["volumes"]), "alerts": len(st["alerts"]),
                                       "health": st["systems"][0]["health"] if st["systems"] else None}
    except Exception as exc:  # noqa: BLE001
        report["error"] = _problem(exc, client)
    return report
