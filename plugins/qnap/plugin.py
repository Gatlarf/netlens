"""QNAP plugin (kind "hypervisor"): a QNAP NAS (QTS or QuTS hero) as a host, with the containers of Container Station as guests.

Talks to the NAS over HTTP(S), read-only:

    POST /container-station/api/v1/login      user name and password as JSON, answers with a session cookie (Container Station 3)
    GET  /container-station/api/v1/container  Docker containers (and LXD containers) with state, image and published ports
    PUT  /container-station/api/v1/logout
    POST /cgi-bin/authLogin.cgi               QTS' own login (password base64 encoded, answer is XML) for the name and model of the NAS
    GET  /cgi-bin/management/manaRequest.cgi  ?subfunc=sysinfo (XML): host name, model, firmware
    GET  /cgi-bin/management/chartReq.cgi     ?chart_func=disk_usage (XML): volumes with size and free space (the Storage page)
    GET  /cgi-bin/disk/qsmart.cgi             ?func=all_hd_data (XML): disks with their S.M.A.R.T. health (the Storage page)

Standard library only. A refused login is reported with `auth_failed` so Netlens stops retrying until the user acts. The QTS part
is optional: without it the NAS is shown under the address Netlens connects to.
"""

import base64
import http.cookiejar
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

MAX_BODY = 8 * 1024 * 1024
API = "/container-station/api/v1"
STATES = {"running": "running", "up": "running", "exited": "stopped", "stopped": "stopped", "stop": "stopped", "created": "stopped", "paused": "paused",
          "restarting": "restarting", "dead": "failed"}


class QnapError(Exception):
    pass


class ConnectError(QnapError):
    """The NAS could not be reached (not a login problem)."""


class LoginRefused(QnapError):
    auth_failed = True


def normalize(url):
    text = str(url or "").strip()
    if not text:
        raise ValueError("enter the address of the QNAP (for example https://192.168.0.40:443 or http://192.168.0.40:8080)")
    if "://" not in text:
        text = "https://" + text
    parts = urllib.parse.urlsplit(text)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ValueError("the address must start with https:// (or http://) and name the NAS")
    host = parts.hostname
    shown = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{shown}" + (f":{parts.port}" if parts.port else ""), host


class Qnap:
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
        self.logged_in = False

    def _send(self, method, path, body=None, form=None, accept="application/json"):
        data, headers = None, {"Accept": accept}
        if body is not None:
            data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
        elif form is not None:
            data, headers["Content-Type"] = urllib.parse.urlencode(form).encode(), "application/x-www-form-urlencoded"
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return response.status, response.read(MAX_BODY)
        except urllib.error.HTTPError as exc:
            return exc.code, b""
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as exc:
            raise ConnectError(f"cannot reach the QNAP at {self.host}: {getattr(exc, 'reason', exc)}") from None

    def _json(self, method, path, body=None):
        status, raw = self._send(method, API + path, body=body)
        if status in (401, 403):
            raise LoginRefused("login refused: check the user name and password (Container Station needs an administrator account, and two-step verification has to be off for it)")
        if status == 404:
            raise ConnectError(f"{path}: not found. Is Container Station 3 installed and running (QuTS hero and QTS 5)?")
        if status >= 400:
            raise ConnectError(f"the QNAP answered with HTTP {status} for {path}")
        try:
            return json.loads(raw.decode("utf-8", "replace")) if raw.strip() else {}
        except ValueError:
            raise ConnectError("this does not look like QNAP Container Station (the answer is not JSON)") from None

    # ------------------------------------------------------------------ Container Station
    def open(self):
        self._json("POST", "/login", {"username": self.user, "password": self.password})
        self.logged_in = True

    def close(self):
        if self.logged_in:
            try:
                self._send("PUT", API + "/logout")
            except QnapError:
                pass
        self.logged_in = False

    # ------------------------------------------------------------------ QTS (optional): name, model and firmware
    def system(self):
        status, raw = self._send("POST", "/cgi-bin/authLogin.cgi", form={"user": self.user, "pwd": base64.b64encode(self.password.encode()).decode()}, accept="text/xml")
        if status != 200:
            raise QnapError(f"QTS login: HTTP {status}")
        sid = _xml_text(raw, "authSid")
        if not sid or _xml_text(raw, "authPassed") not in ("1", "true"):
            raise QnapError("QTS login refused")
        status, raw = self._send("GET", "/cgi-bin/management/manaRequest.cgi?" + urllib.parse.urlencode({"subfunc": "sysinfo", "hd": "no", "multicpu": "1", "sid": sid}), accept="text/xml")
        if status != 200:
            raise QnapError(f"system information: HTTP {status}")
        storage = {}
        for key, path, query in (("volumes_xml", "/cgi-bin/management/chartReq.cgi", {"chart_func": "disk_usage", "disk_select": "all", "include": "all", "sid": sid}),
                                 ("disks_xml", "/cgi-bin/disk/qsmart.cgi", {"func": "all_hd_data", "sid": sid})):
            try:
                code, body = self._send("GET", path + "?" + urllib.parse.urlencode(query), accept="text/xml")
                storage[key] = body if code == 200 else b""
            except QnapError:
                storage[key] = b""
        try:
            self._send("GET", "/cgi-bin/authLogout.cgi?" + urllib.parse.urlencode({"sid": sid}))
        except QnapError:
            pass
        self.storage_xml = storage
        return {"hostname": _xml_text(raw, "sysHostName") or _xml_text(raw, "hostname"), "model": _xml_text(raw, "modelName"), "firmware": _xml_text(raw, "version")}

    storage_xml = {}

    def snapshot(self):
        notes = []
        try:
            system = self.system()
        except LoginRefused:
            raise
        except QnapError as exc:
            system = {}
            notes.append(f"system information: {exc}")
        listing = self._json("GET", "/container")
        containers = listing if isinstance(listing, list) else (listing.get("containers") or listing.get("data") or []) if isinstance(listing, dict) else []
        return {"system": system, "containers": [c for c in containers if isinstance(c, dict)], "storage_xml": dict(self.storage_xml), "notes": notes}


def _xml_text(raw, tag):
    try:
        root = ET.fromstring(raw.decode("utf-8", "replace").strip())
    except ET.ParseError:
        return ""
    node = next((n for n in root.iter() if n.tag.lower() == tag.lower()), None)
    return (node.text or "").strip() if node is not None else ""


# ----------------------------------------------------------------------------- turning QNAP's answers into Netlens' format
def _ipv4(value):
    text = str(value or "").strip()
    return text if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", text) and text != "0.0.0.0" else None


def _int(value):
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0 else None


def _clean(details):
    return {k: v for k, v in details.items() if v not in (None, "", [])}


def _ports(item):
    """Published ports. Container Station gives `tcpPort` (and `udpPort`): numbers, or objects with the container and host port."""
    out = []
    for key, proto in (("tcpPort", "tcp"), ("udpPort", "udp")):
        for port in item.get(key) or []:
            host_port = container_port = None
            if isinstance(port, int) and not isinstance(port, bool):
                host_port = port
            elif isinstance(port, str) and port.split("/")[0].split(":")[0].isdigit():
                host_port = int(port.split("/")[0].split(":")[0])
            elif isinstance(port, dict):
                host_port = _int(port.get("hostPort") or port.get("host_port") or port.get("publicPort") or port.get("public") or port.get("port"))
                container_port = _int(port.get("containerPort") or port.get("container_port") or port.get("privatePort") or port.get("private"))
            if host_port:
                out.append({"container_port": container_port, "host_port": host_port, "proto": proto, "bind": ""})
    return out[:100]


def _host(snapshot, connect_host):
    system = snapshot["system"]
    name = str(system.get("hostname") or "").strip()
    host = {"id": (name or connect_host).lower(), "name": name or connect_host, "online": True}
    if _ipv4(connect_host) and not connect_host.startswith("127."):
        host["ip"] = connect_host
    return host


def to_hypervisor(snapshot, connect_host=""):
    host = _host(snapshot, connect_host)
    guests = []
    for item in snapshot["containers"]:
        name = str(item.get("name") or "").lstrip("/").strip()
        if not name:
            continue
        kind_text = str(item.get("type") or "docker").lower()
        ports = _ports(item)
        state = STATES.get(str(item.get("state") or item.get("status") or "").lower(), str(item.get("state") or "unknown").lower())
        ips = [ip for ip in (_ipv4(item.get("externalIP")),) if ip]
        details = {"image": str(item.get("image") or "")[:200], "project": str(item.get("project") or "")[:80], "ports": ports,
                   "network": str(item.get("networkMode") or "")[:40]}
        details["exposed"] = True if ports else None
        guests.append({"id": f"{'container' if kind_text == 'docker' else kind_text}:{name}", "name": name, "kind": "container" if kind_text == "docker" else "lxc",
                       "host_id": host["id"], "status": state, "macs": [], "ips": ips, "details": _clean(details)})
    seen, unique = set(), []
    for g in guests:
        if g["id"] not in seen:
            seen.add(g["id"])
            unique.append(g)
    return {"hosts": [host], "guests": unique}


# ----------------------------------------------------------------------------- settings and entry points


# ----------------------------------------------------------------------------- storage (volumes and disks from QTS' XML)
RANK = {"unknown": 0, "ok": 1, "warning": 2, "critical": 3}


def _children(node):
    return {c.tag.lower(): (c.text or "").strip() for c in node if len(c) == 0}


def _num(value):
    try:
        number = int(float(str(value).replace(",", "")))
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _pick(fields, *words):
    for tag, text in fields.items():
        if any(w in tag for w in words) and text:
            return text
    return ""


def _iter_xml(raw):
    try:
        return list(ET.fromstring((raw or b"").decode("utf-8", "replace").strip()).iter())
    except ET.ParseError:
        return []


def _xml_records(raw, wanted):
    """Every element whose own children (text only) contain all the wanted words in some tag name: a record with its fields. Tolerant of QTS versions."""
    try:
        root = ET.fromstring((raw or b"").decode("utf-8", "replace").strip())
    except ET.ParseError:
        return []
    out = []
    for node in root.iter():
        fields = _children(node)
        if fields and all(any(w in tag for tag in fields) for w in wanted):
            out.append(fields)
    return out


def to_storage(snapshot, connect_host=""):
    """The storage part of the output, read tolerantly from QTS' XML: volumes (size and free space) and disks (S.M.A.R.T. health)."""
    host = _host(snapshot, connect_host)
    sid = host["id"]
    xml = snapshot.get("storage_xml") or {}
    pools, disks, alerts, level = [], [], [], "ok"
    for rec in _xml_records(xml.get("volumes_xml"), ("total", "free")):
        total, free = _num(_pick(rec, "total_size", "totalsize", "total")), _num(_pick(rec, "free_size", "freesize", "free"))
        name = _pick(rec, "label", "folder", "name", "vol") or f"volume {len(pools) + 1}"
        if not total:
            continue
        pools.append({"id": f"volume:{name}"[:100], "system_id": sid, "name": name[:100], "total": total, "used": total - free if free is not None and free <= total else None,
                      "avail": free, "health": "ok", "raid": ""})
    for rec in _xml_records(xml.get("disks_xml"), ("model",)):
        name = _pick(rec, "hdno", "hd_no", "slot", "name", "dev") or f"disk {len(disks) + 1}"
        health = _pick(rec, "health", "smart", "status").lower()
        state = "ok" if health in ("good", "normal", "ok", "ready", "healthy", "pass", "passed") else "failed" if any(w in health for w in ("fail", "error", "bad", "abnormal", "critical")) else "unknown"
        disks.append({"id": f"disk:{name}:{_pick(rec, 'serial')}"[:100], "system_id": sid, "name": name[:100], "slot": name[:40], "model": _pick(rec, "model")[:100], "size": _num(_pick(rec, "capacity", "size")), "state": state})
        if state == "failed":
            alerts.append({"id": f"disk:{name}", "system_id": sid, "severity": "critical", "text": f"Disk {name}: {health}"})
            level = "critical"
    system_info = snapshot.get("system") or {}
    system = {"id": sid, "name": host["name"], "ip": host.get("ip"), "vendor": "QNAP", "model": str(system_info.get("model") or "")[:100], "version": str(system_info.get("firmware") or "")[:60], "serial": "",
              "online": True, "health": level if pools or disks else "unknown", "warnings": []}
    controllers = [{"id": f"{sid}:host", "system_id": sid, "name": host["name"], "ip": host.get("ip"), "mac": host.get("mac"), "online": True, "health": "unknown"}] if host.get("ip") or host.get("mac") else []
    return {"systems": [system], "controllers": controllers, "pools": pools, "volumes": [], "disks": disks, "alerts": alerts}


def _servers(config):
    rows = config.get("servers")
    if not isinstance(rows, list):
        return [config]
    out = [{"url": r.get("host"), "username": r.get("username"), "password": r.get("password"), "verify_tls": config.get("verify_tls"), "timeout": config.get("timeout")}
           for r in rows if isinstance(r, dict) and (r.get("host") or r.get("username"))]
    if not out:
        raise ValueError("enter the address, user name and password of at least one QNAP")
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
    client = Qnap(one)
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
        system = snapshot["system"]
        what = ", ".join(x for x in (system.get("model"), system.get("firmware")) if x) or "QNAP"
        message = f"Connected to {out['hosts'][0]['name']} ({what}): {len(out['guests'])} container(s)"
        if snapshot["notes"]:
            message += ". Not available: " + "; ".join(snapshot["notes"])
        return message
    messages = _each(config, one)
    return {"message": messages[0] if len(messages) == 1 else f"{len(messages)} QNAP systems answered. " + " | ".join(messages)}


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
KEEP_WORDS = {"state", "status", "type", "runtime", "networkMode", "privileged"}


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
    """What this QNAP answers, described by field names and types, and what the plugin made of it (no names, MACs or IPs)."""
    client = Qnap(_servers(config)[0])
    client.open()                          # a refused login is reported as such (and stops automatic syncing), like test()
    report = {"steps": {}}
    try:
        for name, path in (("containers", "/container"), ("apps", "/apps"), ("networks", "/networks")):
            try:
                report["steps"][name] = {"ok": True, "shape": describe(client._json("GET", path))}
            except Exception as exc:  # noqa: BLE001 - the point is to record what failed
                report["steps"][name] = {"ok": False, "error": _problem(exc, client)}
        try:
            report["steps"]["qts_system"] = {"ok": True, "fields_found": sorted(k for k, v in client.system().items() if v)}
        except Exception as exc:  # noqa: BLE001
            report["steps"]["qts_system"] = {"ok": False, "error": _problem(exc, client)}
        try:
            snapshot = client.snapshot()
            out = to_hypervisor(snapshot, client.host)
            report["result"] = {"guests": len(out["guests"]), "guests_with_ip": sum(1 for g in out["guests"] if g["ips"]),
                                "guests_with_ports": sum(1 for g in out["guests"] if g["details"].get("ports")), "not_available": [_problem(RuntimeError(n), client) for n in snapshot["notes"]]}
            st = to_storage(snapshot, client.host)
            report["result"]["storage"] = {"volumes": len(st["pools"]), "disks": len(st["disks"]), "alerts": len(st["alerts"]),
                                           "volumes_xml_bytes": len(snapshot["storage_xml"].get("volumes_xml") or b""), "disks_xml_bytes": len(snapshot["storage_xml"].get("disks_xml") or b""),
                                           "xml_tags": sorted({n.tag for raw in snapshot["storage_xml"].values() for n in _iter_xml(raw)})[:60]}
        except Exception as exc:  # noqa: BLE001
            report["error"] = _problem(exc, client)
    finally:
        client.close()
    return report
