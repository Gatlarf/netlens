"""Home Assistant plugin (kind "inventory"): the device registry, with availability and battery.

Uses the REST API of Home Assistant (read only):

    POST /auth/login_flow, /auth/login_flow/<id>, /auth/token   only without a long-lived token: sign in with a user name and password
    GET  /api/config                                            version, location name
    POST /api/template                                          one Jinja template that walks the device registry and returns JSON: name, manufacturer,
                                                                model, firmware, area, connections (MAC, Zigbee ...), the device it is paired through,
                                                                whether any of its entities is available, its battery and whether an update is waiting

The template endpoint is how the registry can be read over REST (the registry itself is only on the websocket API). Standard library only.
"""

import http.client
import ipaddress
import json
import re
import ssl
import urllib.parse

TEMPLATE = (
    "{% set ns = namespace(out=[]) %}"
    "{% for d in states | map(attribute='entity_id') | map('device_id') | reject('none') | unique %}"
    "{% set ns2 = namespace(avail=false, batt=none, low=false, upd=false, n=0) %}"
    "{% for e in device_entities(d) %}"
    "{% set s = states(e) %}{% set ns2.n = ns2.n + 1 %}"
    "{% if s != 'unavailable' %}{% set ns2.avail = true %}{% endif %}"
    "{% if state_attr(e, 'device_class') == 'battery' %}"
    "{% if is_number(s) %}{% set ns2.batt = s | float %}{% elif e.startswith('binary_sensor.') and s == 'on' %}{% set ns2.low = true %}{% endif %}{% endif %}"
    "{% if e.startswith('update.') and s == 'on' %}{% set ns2.upd = true %}{% endif %}"
    "{% endfor %}"
    "{% set ns.out = ns.out + [{'id': d, 'name': device_attr(d, 'name_by_user') or device_attr(d, 'name'), 'manufacturer': device_attr(d, 'manufacturer'), "
    "'model': device_attr(d, 'model'), 'sw': device_attr(d, 'sw_version'), 'area': area_name(d), 'connections': device_attr(d, 'connections') | list, "
    "'via': device_attr(d, 'via_device_id'), 'identifiers': device_attr(d, 'identifiers') | list, 'url': device_attr(d, 'configuration_url'), "
    "'entry_type': device_attr(d, 'entry_type'), 'disabled': device_attr(d, 'disabled_by'), 'avail': ns2.avail, 'batt': ns2.batt, 'low': ns2.low, "
    "'upd': ns2.upd, 'entities': ns2.n}] %}"
    "{% endfor %}{{ ns.out | to_json }}"
)


class HaError(Exception):
    pass


class AuthRefused(HaError):
    auth_failed = True


def _text(value, limit=200):
    return str(value).strip()[:limit] if value not in (None, "") else None


def _mac(value):
    text = str(value or "").strip().lower().replace("-", ":")
    return text if re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", text) else None


def _ipv4(value):
    try:
        addr = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


class Server:
    def __init__(self, config):
        url = str(config.get("url") or "").strip().rstrip("/")
        if "://" not in url:
            url = "http://" + url
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise HaError(f"{url!r} is not an address like https://ha.example.com or http://192.168.0.20:8123")
        self.scheme, self.host = parts.scheme, parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.base = f"{self.scheme}://{parts.netloc}"
        self.id = f"{self.host}:{self.port}"
        self.timeout = float(config.get("timeout") or 30)
        self.token = str(config.get("token") or "").strip()
        self.username = str(config.get("username") or "").strip()
        self.password = str(config.get("password") or "")
        if not self.token and not (self.username and self.password):
            raise HaError("enter a long-lived access token, or a user name and a password")
        self.context = ssl.create_default_context()
        if not config.get("verify_tls", True):
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE
        self.ip = _ipv4(self.host)

    def _request(self, method, path, body=None, headers=None, form=False):
        conn = (http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self.context) if self.scheme == "https"
                else http.client.HTTPConnection(self.host, self.port, timeout=self.timeout))
        head = {"Accept": "application/json", **(headers or {})}
        data = None
        if body is not None:
            data = urllib.parse.urlencode(body) if form else json.dumps(body)
            head["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
        try:
            conn.request(method, path, body=data, headers=head)
            response = conn.getresponse()
            raw = response.read(50_000_000).decode("utf-8", "replace")
            return response.status, raw
        except ssl.SSLError as exc:
            raise HaError(f"cannot make a secure connection to {self.id}: {exc.reason or exc}")
        except (OSError, http.client.HTTPException) as exc:
            raise HaError(f"cannot reach {self.id}: {exc}")
        finally:
            conn.close()

    def login(self):
        """An access token from a user name and password (the normal sign-in flow of Home Assistant)."""
        if self.token:
            return self.token
        client = self.base + "/"
        status, raw = self._request("POST", "/auth/login_flow", {"client_id": client, "handler": ["homeassistant", None], "redirect_uri": client})
        try:
            flow = json.loads(raw)["flow_id"]
        except (ValueError, KeyError, TypeError):
            raise HaError(f"{self.id} did not start a sign-in (is this Home Assistant?)")
        status, raw = self._request("POST", f"/auth/login_flow/{flow}", {"username": self.username, "password": self.password, "client_id": client})
        try:
            doc = json.loads(raw)
        except ValueError:
            raise HaError(f"{self.id} did not answer the sign-in properly")
        if doc.get("type") != "create_entry":
            if doc.get("errors", {}).get("base") == "invalid_auth" or status in (401, 403):
                raise AuthRefused(f"{self.id} refused the user name or password")
            raise HaError(f"{self.id} did not accept the sign-in (two-factor sign-in needs a long-lived access token instead)")
        status, raw = self._request("POST", "/auth/token", {"grant_type": "authorization_code", "code": doc["result"], "client_id": client}, form=True)
        try:
            self.token = json.loads(raw)["access_token"]
        except (ValueError, KeyError, TypeError):
            raise HaError(f"{self.id} did not give an access token")
        return self.token

    def call(self, method, path, body=None):
        status, raw = self._request(method, path, body, {"Authorization": f"Bearer {self.login()}"})
        if status in (401, 403):
            raise AuthRefused(f"{self.id} refused the access token (wrong, expired or revoked)")
        if status != 200:
            raise HaError(f"{self.id} answered HTTP {status} for {path}" + (" (the template request needs an administrator user)" if status == 400 and path == "/api/template" else ""))
        return raw


def protocol_of(item):
    kinds = [c[0] for c in item.get("connections") or [] if isinstance(c, (list, tuple)) and c]
    for wanted in ("zigbee", "bluetooth"):
        if wanted in kinds:
            return wanted
    ids = [i[0] for i in item.get("identifiers") or [] if isinstance(i, (list, tuple)) and i]
    return _text(ids[0], 40).lower() if ids else None


def read(server, config):
    raw = server.call("GET", "/api/config")
    try:
        info = json.loads(raw)
    except ValueError:
        raise HaError(f"{server.id} did not answer properly (is this Home Assistant?)")
    registry = server.call("POST", "/api/template", {"template": TEMPLATE})
    try:
        items = json.loads(registry)
    except ValueError:
        raise HaError(f"{server.id} returned something that is not the device list (the template could not be rendered)")
    if not isinstance(items, list):
        raise HaError(f"{server.id} returned something that is not the device list")
    return info, items


def convert(server, info, items, config):
    include_services = bool(config.get("include_services"))
    threshold = float(config.get("battery_low") or 20)
    ids = {str(i.get("id")) for i in items if isinstance(i, dict)}
    devices = []
    for item in items:
        if not isinstance(item, dict) or item.get("disabled") or not item.get("id"):
            continue
        if item.get("entry_type") == "service" and not include_services:
            continue
        mac = None
        for c in item.get("connections") or []:
            if isinstance(c, (list, tuple)) and len(c) == 2 and c[0] in ("mac", "network_mac") and _mac(c[1]):
                mac = _mac(c[1])
                break
        url = _text(item.get("url"), 300)
        ip = None
        if url and url.startswith(("http://", "https://")):
            ip = _ipv4(urllib.parse.urlsplit(url).hostname)
        else:
            url = None
        battery = item.get("batt")
        battery = int(round(battery)) if isinstance(battery, (int, float)) and not isinstance(battery, bool) and 0 <= battery <= 100 else None
        via = str(item["via"]) if item.get("via") and str(item["via"]) in ids else None
        devices.append({"id": str(item["id"]), "server_id": server.id, "name": _text(item.get("name")) or _text(item.get("model")) or "device", "manufacturer": _text(item.get("manufacturer"), 80),
                        "model": _text(item.get("model"), 120), "area": _text(item.get("area"), 80), "sw": _text(item.get("sw"), 60), "protocol": protocol_of(item), "mac": mac, "ip": ip,
                        "via_id": via, "available": bool(item.get("avail")), "battery": battery, "battery_low": bool(item.get("low")) or (battery is not None and battery < threshold),
                        "update": bool(item.get("upd")), "url": url, "entities": int(item["entities"]) if isinstance(item.get("entities"), int) else None})
    server_doc = {"id": server.id, "name": _text(info.get("location_name"), 80) or server.host, "ip": server.ip, "version": _text(info.get("version"), 40), "online": True, "warnings": []}
    return server_doc, devices


def connect(config):
    server = Server(config)
    info, items = read(server, config)
    return convert(server, info, items, config)


def test(config):
    server, devices = connect(config)
    gone = sum(1 for d in devices if not d["available"])
    low = sum(1 for d in devices if d["battery_low"])
    matched = sum(1 for d in devices if d["mac"])
    message = f"Connected to Home Assistant {server['version'] or ''} ({server['name']}): {len(devices)} device(s), {matched} with a MAC address"
    if gone:
        message += f", {gone} unavailable"
    if low:
        message += f", {low} with a low battery"
    return {"message": message}


def fetch(config):
    server, devices = connect(config)
    return {"servers": [server], "devices": devices}


def _problem(exc, server=None):
    text = re.sub(r"https?://[^\s/]+", "<server>", str(exc))
    if server is not None:
        text = text.replace(server.id, "<server>").replace(server.host, "<server>")
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<server>", text)
    text = re.sub(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*:\d{2,5}\b", "<server>", text)
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What Home Assistant answers, as counts (no names, addresses, MAC addresses or areas)."""
    try:
        server = Server(config)
    except HaError as exc:
        return {"error": str(exc)}
    entry = {"steps": {}}
    try:
        info, items = read(server, config)
        entry["steps"]["config"] = {"ok": True, "version": _text(info.get("version"), 40)}
        entry["steps"]["registry"] = {"ok": True, "devices": len(items), "with_mac": sum(1 for i in items if any(isinstance(c, (list, tuple)) and c and c[0] in ("mac", "network_mac") for c in i.get("connections") or [])),
                                      "connection_types": sorted({str(c[0]) for i in items for c in i.get("connections") or [] if isinstance(c, (list, tuple)) and c})[:20],
                                      "entry_types": sorted({str(i.get("entry_type")) for i in items}), "with_via": sum(1 for i in items if i.get("via")), "with_area": sum(1 for i in items if i.get("area")),
                                      "with_battery": sum(1 for i in items if i.get("batt") is not None), "unavailable": sum(1 for i in items if not i.get("avail"))}
    except AuthRefused:
        raise
    except HaError as exc:
        entry["steps"]["error"] = {"ok": False, "error": _problem(exc, server)}
    return {"servers": [entry]}
