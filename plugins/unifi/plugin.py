"""Ubiquiti UniFi plugin (kind "topology"): which device and which client hangs below which, read from the controller.

Works with the UniFi Network application on a UniFi OS console (Dream Machine, Cloud Key Gen2+, Cloud Gateway, ...)
and with a classic self-hosted controller. Read-only:

    POST /api/auth/login   (UniFi OS)  or  /api/login  (classic)    one login; the session is a cookie
    GET  <prefix>/api/self/sites                                      the sites the account may see
    GET  <prefix>/api/s/<site>/stat/device                            gateway, switches and access points, with their uplink
    GET  <prefix>/api/s/<site>/stat/sta                               the connected clients
    POST /api/auth/logout  (UniFi OS)  or  /api/logout  (classic)    best effort, so no session is left open

`<prefix>` is `/proxy/network` on a UniFi OS console and empty on a classic controller. Standard library only. A refused
login is reported with `auth_failed`, so Netlens stops retrying until the user acts (this protects the account from lockout).
"""

import http.cookiejar
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

ROLES = {"uap": "ap", "ubb": "ap", "usw": "switch", "ugw": "gateway", "udm": "gateway", "uxg": "gateway", "udr": "gateway"}
BANDS = {"ng": "2.4 GHz", "na": "5 GHz", "6e": "6 GHz"}


class UnifiError(Exception):
    pass


class ConnectError(UnifiError):
    """The controller could not be reached (not a login problem)."""


class LoginRefused(UnifiError):
    auth_failed = True


def _mac(value):
    if not isinstance(value, str):
        return None
    text = value.strip().lower().replace("-", ":")
    return text if len(text) == 17 and text.count(":") == 5 else None


def _number(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _json_or_none(raw):
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return None


class Controller:
    def __init__(self, config):
        url = str(config.get("url") or "").strip()
        if not url:
            raise ValueError("enter the controller address, for example https://192.168.1.1")
        if "://" not in url:
            url = "https://" + url
        parts = urllib.parse.urlsplit(url)
        if not parts.hostname:
            raise ValueError("that is not a valid controller address")
        self.base = f"{parts.scheme}://{parts.netloc}"
        self.username = str(config.get("username") or "").strip()
        self.password = str(config.get("password") or "")
        if not self.username or not self.password:
            raise ValueError("enter the username and password")
        self.mode = str(config.get("mode") or "auto")
        if self.mode not in ("auto", "unifi_os", "classic"):
            raise ValueError("the type of controller must be auto, unifi_os or classic")
        self.site_filter = str(config.get("site") or "").strip().lower()
        context = ssl.create_default_context()
        if not config.get("verify_tls"):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=context),
        )
        self.os = False
        self.csrf = None

    @property
    def prefix(self):
        return "/proxy/network" if self.os else ""

    # ---- plumbing ------------------------------------------------------------------------------------------
    def _call(self, method, path, body=None, expect_ok=True):
        """One request. Returns (HTTP status, parsed JSON or None); raises ConnectError when nothing answers."""
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=20) as response:
                raw, status = response.read(16_000_000), response.status
                token = response.headers.get("X-CSRF-Token") or response.headers.get("X-Updated-CSRF-Token")
        except urllib.error.HTTPError as exc:
            raw, status, token = exc.read(200_000), exc.code, None
        except urllib.error.URLError as exc:
            raise ConnectError(f"cannot reach the controller: {exc.reason}") from None
        except (TimeoutError, OSError) as exc:
            raise ConnectError(f"cannot reach the controller: {exc}") from None
        if token:
            self.csrf = token
        return status, _json_or_none(raw)

    def _get(self, path):
        status, payload = self._call("GET", self.prefix + path)
        if status in (401, 403):
            raise UnifiError("the controller ended the session or refused the read (the account needs at least read-only access)")
        if status >= 400:
            raise UnifiError(f"the controller answered HTTP {status} for {path}")
        meta = payload.get("meta") if isinstance(payload, dict) else None
        if isinstance(meta, dict) and meta.get("rc") not in (None, "ok"):
            raise UnifiError(f"the controller refused {path}: {meta.get('msg') or meta.get('rc')}")
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, list):
            raise UnifiError(f"unexpected answer for {path} (is the address right?)")
        return data

    # ---- session -------------------------------------------------------------------------------------------
    def login(self):
        order = {"auto": (True, False), "unifi_os": (True,), "classic": (False,)}[self.mode]
        last_status = None
        for is_os in order:
            self.os = is_os
            path = "/api/auth/login" if is_os else "/api/login"
            body = {"username": self.username, "password": self.password}
            body.update({"rememberMe": False} if is_os else {"remember": False})
            status, payload = self._call("POST", path, body)
            last_status = status
            if status == 404:
                continue  # not this kind of controller (auto: try the other one)
            if status == 200 and not (isinstance(payload, dict) and isinstance(payload.get("meta"), dict) and payload["meta"].get("rc") == "error"):
                return
            if status == 429:
                raise UnifiError("the controller says too many login attempts; wait a while")
            if status == 499:
                raise LoginRefused("login refused: this account needs two-factor authentication; use a local account without it")
            if status >= 500:
                raise ConnectError(f"the controller has a problem (HTTP {status})")
            msg = ""
            if isinstance(payload, dict):
                msg = str((payload.get("meta") or {}).get("msg") or payload.get("message") or "")
            raise LoginRefused("login refused" + (f" ({msg})" if msg else "") + ". Check the username and password; a Ubiquiti cloud account does not work, use a local one.")
        raise UnifiError(f"this does not look like a UniFi controller (HTTP {last_status}); check the address and the type of controller")

    def logout(self):
        try:
            self._call("POST", "/api/auth/logout" if self.os else "/api/logout")
        except Exception:  # noqa: BLE001 - best effort; the session also expires by itself
            pass

    # ---- data ----------------------------------------------------------------------------------------------
    def sites(self):
        sites = [{"name": str(s["name"]), "desc": str(s.get("desc") or s["name"])} for s in self._get("/api/self/sites") if isinstance(s, dict) and s.get("name")]
        if self.site_filter:
            sites = [s for s in sites if self.site_filter in (s["name"].lower(), s["desc"].lower())]
            if not sites:
                raise UnifiError(f"no site named {self.site_filter!r} is visible to this account")
        if not sites:
            raise UnifiError("this account cannot see any site")
        return sites

    def snapshot(self):
        nodes, clients, have_gateway, seen_nodes, seen_clients = [], [], False, set(), set()
        for site in self.sites():
            for device in self._get(f"/api/s/{urllib.parse.quote(site['name'])}/stat/device"):
                mac = _mac(device.get("mac")) if isinstance(device, dict) else None
                if not mac or mac in seen_nodes or device.get("adopted") is False:
                    continue
                seen_nodes.add(mac)
                role = ROLES.get(device.get("type"), "node")
                if role == "gateway":
                    role = "node" if have_gateway else "gateway"  # the contract allows one gateway
                    have_gateway = True
                uplink = device.get("uplink") if isinstance(device.get("uplink"), dict) else {}
                nodes.append({
                    "mac": mac, "ip": device.get("ip") or None, "role": role,
                    "name": device.get("name") or device.get("model") or mac,
                    "model": device.get("model") or "",
                    "parent_mac": _mac(uplink.get("uplink_mac")) or _mac(device.get("uplink_mac")),
                })
            for client in self._get(f"/api/s/{urllib.parse.quote(site['name'])}/stat/sta"):
                mac = _mac(client.get("mac")) if isinstance(client, dict) else None
                if mac and mac not in seen_clients:
                    seen_clients.add(mac)
                    clients.append((client, mac))
        return nodes, clients


def _rate_mbps(value):
    """UniFi reports link rates in kilobits per second."""
    value = _number(value)
    return round(value / 1000, 1) if value is not None and value > 0 else None


def to_topology(nodes, raw_clients):
    known = {n["mac"] for n in nodes}
    for n in nodes:
        if n["parent_mac"] not in known or n["parent_mac"] == n["mac"]:
            n["parent_mac"] = None
    out_clients = []
    for client, mac in raw_clients:
        wired = bool(client.get("is_wired"))
        if wired:
            node_mac = next((m for m in (_mac(client.get(k)) for k in ("sw_mac", "uplink_mac", "last_uplink_mac", "gw_mac")) if m in known), None)
        else:
            node_mac = next((m for m in (_mac(client.get(k)) for k in ("ap_mac", "uplink_mac", "last_uplink_mac")) if m in known), None)
        name = client.get("name") or client.get("hostname") or None
        if name and _mac(name) == mac:
            name = None
        signal = _number(client.get("signal"))
        out_clients.append({
            "mac": mac, "ip": client.get("ip") or client.get("last_ip") or None, "name": name,
            "node_mac": node_mac,
            "medium": "wired" if wired else "wifi",
            "band": BANDS.get(client.get("radio")) if not wired else None,
            "rssi": int(signal) if signal is not None and -127 <= signal <= 0 else None,
            "tx_mbps": None if wired else _rate_mbps(client.get("tx_rate")),
            "rx_mbps": None if wired else _rate_mbps(client.get("rx_rate")),
        })
    return {"nodes": nodes, "clients": out_clients}


def test(config):
    controller = Controller(config)
    controller.login()
    try:
        sites = controller.sites()
        nodes, clients = controller.snapshot()
    finally:
        controller.logout()
    kind = "UniFi OS console" if controller.os else "classic controller"
    return {"message": f"Connected to UniFi ({kind}): {len(sites)} site(s), {len(nodes)} device(s), {len(clients)} client(s)"}


def fetch(config):
    controller = Controller(config)
    controller.login()
    try:
        nodes, clients = controller.snapshot()
    finally:
        controller.logout()
    return to_topology(nodes, clients)


# ----------------------------------------------------------------------------- diagnostic (for the plugin's author)
KEEP_WORDS = {"type", "state", "adopted", "radio", "radio_proto", "is_wired", "is_guest", "rc", "model"}
SAMPLES = 3


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
    """What this controller answers, described by field names and types, and what the plugin made of it (no names, MACs or IPs)."""
    controller = Controller(config)
    report = {"steps": {}}

    def step(name, call):
        try:
            report["steps"][name] = {"ok": True, "shape": call()}
        except Exception as exc:  # noqa: BLE001 - the point is to record what failed
            report["steps"][name] = {"ok": False, "error": _problem(exc)}

    controller.login()  # a refused login is reported as such (and stops automatic syncing), like test()
    try:
        report["controller_kind"] = "unifi_os" if controller.os else "classic"
        sites = controller.sites()
        report["site_count"] = len(sites)
        site = urllib.parse.quote(sites[0]["name"])
        step("devices", lambda: (lambda rows: {"count": len(rows), "first": [describe(r) for r in rows[:SAMPLES]]})(controller._get(f"/api/s/{site}/stat/device")))
        step("clients", lambda: (lambda rows: {"count": len(rows), "first": [describe(r) for r in rows[:SAMPLES]]})(controller._get(f"/api/s/{site}/stat/sta")))
        nodes, clients = controller.snapshot()
        out = to_topology(nodes, clients)
        report["result"] = {
            "nodes": len(out["nodes"]), "nodes_with_parent": sum(1 for n in out["nodes"] if n["parent_mac"]),
            "roles": sorted({n["role"] for n in out["nodes"]}),
            "clients": len(out["clients"]), "clients_with_node": sum(1 for c in out["clients"] if c["node_mac"]),
            "wifi_clients": sum(1 for c in out["clients"] if c["medium"] == "wifi"), "with_rssi": sum(1 for c in out["clients"] if c["rssi"] is not None),
            "with_rates": sum(1 for c in out["clients"] if c["tx_mbps"] is not None),
        }
    except LoginRefused:
        raise
    except Exception as exc:  # noqa: BLE001
        report["error"] = _problem(exc)
    finally:
        controller.logout()
    return report
