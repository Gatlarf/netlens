"""TP-Link Omada plugin (kind "topology"): which device and which client hangs below which, read from the controller.

Talks to the controller's web interface API (the one the Omada web page itself uses), read-only:

    GET  /api/info                                        controller version and id (no login)
    POST /<id>/api/v2/login                               one login; the answer holds a CSRF token, the session is a cookie
    GET  /<id>/api/v2/users/current                       the sites the account may see
    GET  /<id>/api/v2/sites/<site>/devices                gateway, switches and access points
    GET  /<id>/api/v2/sites/<site>/switches/<mac>         a switch's uplink      (one small read per switch)
    GET  /<id>/api/v2/sites/<site>/eaps/<mac>             an access point's uplink (one small read per access point)
    GET  /<id>/api/v2/sites/<site>/clients?currentPage=   the connected clients (paged)
    POST /<id>/api/v2/logout                              best effort, so no session is left open

Application statistics (optional, only when an Open API client id and secret are entered) come from the controller's Open API, which
has its own login (OAuth client credentials) and needs DPI switched on at the gateway:

    POST /openapi/authorize/token?grant_type=client_credentials     body: omadacId, client_id, client_secret
    GET  /openapi/v1/<id>/sites                                     the site ids
    GET  /openapi/v1/<id>/sites/<site>/dashboard/specificClientInfo/<client mac>?start=&end=    one read per client: its applications

Standard library only. A refused login is reported with `auth_failed`, so Netlens stops retrying until the user acts
(this protects the account from being locked).
"""

import http.cookiejar
import json
import re
import ssl
import urllib.error
import urllib.parse
import time
import urllib.request
from datetime import datetime

PAGE_SIZE = 100
MAX_PAGES = 200
MIN_VERSION = (5, 1, 0)
USAGE_BUDGET = 60       # seconds the per-client application reads may take in one sync
USAGE_MAX_CLIENTS = 300
BANDS = {0: "2.4 GHz", 1: "5 GHz", 2: "5 GHz", 3: "6 GHz"}  # Omada radioId
ROLES = {"gateway": "gateway", "switch": "switch", "ap": "ap"}


class OmadaError(Exception):
    pass


class ConnectError(OmadaError):
    """The controller could not be reached (not a login problem)."""


class LoginRefused(OmadaError):
    auth_failed = True


def _version(text):
    parts = []
    for piece in str(text).split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple((parts + [0, 0, 0])[:3])


def _mac(value):
    if not isinstance(value, str):
        return None
    text = value.strip().lower().replace("-", ":")
    return text if len(text) == 17 and text.count(":") == 5 else None


def _number(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


class Controller:
    def __init__(self, config):
        url = str(config.get("url") or "").strip()
        if not url:
            raise ValueError("enter the controller address, for example https://192.168.0.10:8043")
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
        self.site_filter = str(config.get("site") or "").strip().lower()
        context = ssl.create_default_context()
        if not config.get("verify_tls"):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.client_id = str(config.get("client_id") or "").strip()
        self.client_secret = str(config.get("client_secret") or "").strip()
        self.allowed = bool(config.get("collect_usage", True))      # Netlens' own switch (Settings > Statistics) has the last word
        self.context = context
        self.targets = []       # (site, client as the controller wrote it) for the application statistics
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            urllib.request.HTTPSHandler(context=context),
        )
        self.controller_id = None
        self.version = ""
        self.csrf = None

    # ---- plumbing ------------------------------------------------------------------------------------------
    def _call(self, method, url, body=None, params=None, headers=None, opener=None):
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Accept": "application/json", **(headers or {})}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.csrf and opener is None:
            headers["Csrf-Token"] = self.csrf
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with (opener or self.opener).open(request, timeout=20) as response:
                raw = response.read(8_000_000)
        except urllib.error.HTTPError as exc:
            payload = _json_or_none(exc.read(200_000))
            if exc.code >= 500:
                raise ConnectError(f"the controller has a problem (HTTP {exc.code})") from None
            if isinstance(payload, dict) and payload.get("msg"):
                raise OmadaError(f"{payload['msg']} (error {payload.get('errorCode')})") from None
            raise OmadaError(f"the controller answered HTTP {exc.code}") from None
        except urllib.error.URLError as exc:
            raise ConnectError(f"cannot reach the controller: {exc.reason}") from None
        except (TimeoutError, OSError) as exc:
            raise ConnectError(f"cannot reach the controller: {exc}") from None
        payload = _json_or_none(raw)
        if payload is None:
            # a lost session answers with the HTML login page and a 200
            raise OmadaError("the controller did not answer with data (is the address right, and is the session still valid?)")
        if isinstance(payload, dict) and "errorCode" in payload and payload["errorCode"] != 0:
            raise OmadaError(f"{payload.get('msg') or 'request failed'} (error {payload['errorCode']})")
        return payload.get("result", payload) if isinstance(payload, dict) else payload

    def _api(self, path, params=None):
        try:
            return self._call("GET", f"{self.base}/{self.controller_id}/api/v2/{path}", params=params)
        except ConnectError:
            raise
        except OmadaError as exc:
            # say which request failed (the site id and MAC addresses are left out of the text)
            parts = ["<site>" if i and segments[i - 1] == "sites" else "<id>" if i and segments[i - 1] in ("switches", "eaps") else p
                     for segments in [path.split("/")] for i, p in enumerate(segments)]
            raise OmadaError(f"{'/'.join(parts)}: {exc}") from None

    # ---- session -------------------------------------------------------------------------------------------
    def login(self):
        info = self._call("GET", f"{self.base}/api/info")
        self.version = str(info.get("controllerVer", "")) if isinstance(info, dict) else ""
        self.controller_id = info.get("omadacId") if isinstance(info, dict) else None
        if not self.controller_id:
            raise OmadaError("this does not look like an Omada controller (no controller id)")
        if self.version and _version(self.version) < MIN_VERSION:
            raise OmadaError(f"Omada controller {self.version} is too old; this plugin needs 5.1 or newer")
        try:
            result = self._call("POST", f"{self.base}/{self.controller_id}/api/v2/login", {"username": self.username, "password": self.password})
        except ConnectError:
            raise  # an unreachable controller is not a refused login
        except OmadaError as exc:
            raise LoginRefused(f"login refused: {exc}. Check the username and password.") from None
        token = result.get("token") if isinstance(result, dict) else None
        if not token:
            raise LoginRefused("login refused: the controller returned no session token")
        self.csrf = token

    def logout(self):
        try:
            self._call("POST", f"{self.base}/{self.controller_id}/api/v2/logout")
        except Exception:  # noqa: BLE001 - best effort; the session also expires by itself
            pass

    # ---- data ----------------------------------------------------------------------------------------------
    def sites(self):
        current = self._api("users/current")
        entries = (((current or {}).get("privilege") or {}).get("sites")) if isinstance(current, dict) else None
        sites = [{"name": str(s.get("name") or s.get("key")), "key": s["key"]} for s in entries or [] if isinstance(s, dict) and s.get("key")]
        if self.site_filter:
            sites = [s for s in sites if s["name"].lower() == self.site_filter or str(s["key"]).lower() == self.site_filter]
            if not sites:
                raise OmadaError(f"no site named {self.site_filter!r} is visible to this account")
        if not sites:
            raise OmadaError("this account cannot see any site")
        return sites

    # Controller versions differ in what the client list wants: the filter the open-source client always sends first,
    # then the other values, then none at all. The first variant the controller accepts is used for every page.
    CLIENT_FILTERS = ({"filters.active": "false"}, {"filters.active": "true"}, {})

    def paged(self, path, variants=None):
        variants = list(variants if variants is not None else [{}])
        for position, extra in enumerate(variants):
            try:
                yield from self._pages(path, extra)
                return
            except OmadaError as exc:
                if position == len(variants) - 1 or isinstance(exc, ConnectError):
                    raise
                # a rejected request ("general error", -1) on the first page: try the next variant. A failure after rows
                # were produced cannot be retried without duplicates, so only the very first page may fall through.
                if getattr(exc, "after_rows", False):
                    raise

    def _pages(self, path, extra):
        page, seen = 1, 0
        while page <= MAX_PAGES:
            try:
                result = self._api(path, {**extra, "currentPage": page, "currentPageSize": PAGE_SIZE})
            except ConnectError:
                raise
            except OmadaError as exc:
                exc.after_rows = seen > 0
                raise
            rows = result.get("data") if isinstance(result, dict) else result
            if not isinstance(rows, list) or not rows:
                return
            yield from (r for r in rows if isinstance(r, dict))
            seen += len(rows)
            total = result.get("totalRows") if isinstance(result, dict) else None
            if not isinstance(total, int) or seen >= total:
                return
            page += 1

    def detail_of(self, site, device):
        """(MAC of the device this switch or access point is plugged into, its ports) from one small read; (None, []) when it cannot be read."""
        kind = device.get("type")
        if kind == "switch":
            path, keys = f"sites/{site['key']}/switches/{device['mac']}", ("uplink",)
        elif kind == "ap":
            path, keys = f"sites/{site['key']}/eaps/{device['mac']}", ("wiredUplink", "uplink")
        else:
            return None, []
        try:
            detail = self._api(path)
        except OmadaError:
            return None, []  # one device that cannot be read must not fail the whole sync
        parent = None
        for key in keys:
            link = detail.get(key) if isinstance(detail, dict) else None
            if isinstance(link, dict):
                parent = _mac(link.get("mac") or link.get("uplinkMac"))
                if parent:
                    break
        ports = detail.get("ports") if kind == "switch" and isinstance(detail, dict) else None
        return parent, [p for p in (_port(raw) for raw in ports or []) if p]

    def snapshot(self):
        nodes, clients, have_gateway, seen_nodes, seen_clients = [], [], False, set(), set()
        for site in self.sites():
            raw_devices = self._api(f"sites/{site['key']}/devices")
            for device in raw_devices if isinstance(raw_devices, list) else []:
                mac = _mac(device.get("mac")) if isinstance(device, dict) else None
                if not mac or mac in seen_nodes:
                    continue
                seen_nodes.add(mac)
                role = ROLES.get(device.get("type"), "node")
                if role == "gateway":
                    role = "node" if have_gateway else "gateway"  # the contract allows one gateway
                    have_gateway = True
                nodes.append({
                    "mac": mac, "ip": device.get("ip") or None, "role": role,
                    "name": device.get("name") or device.get("showModel") or device.get("model") or mac,
                    "model": device.get("showModel") or device.get("model") or "",
                })
                nodes[-1]["parent_mac"], ports = self.detail_of(site, device)      # asked for with the MAC exactly as the controller wrote it
                if ports:
                    nodes[-1]["ports"] = ports
            for client in self.paged(f"sites/{site['key']}/clients", self.CLIENT_FILTERS):
                mac = _mac(client.get("mac"))
                if not mac or mac in seen_clients or client.get("active") is False:
                    continue
                seen_clients.add(mac)
                clients.append((client, mac))
                self.targets.append((site, client))
        return nodes, clients

    # ---- application statistics (Open API) -----------------------------------------------------------------
    @property
    def wants_usage(self):
        return bool(self.allowed and self.client_id and self.client_secret)

    def open_login(self):
        """The Open API access token (a separate login from the web session: OAuth client credentials)."""
        self.plain = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self.context))
        try:
            result = self._call("POST", f"{self.base}/openapi/authorize/token", {"omadacId": self.controller_id, "client_id": self.client_id, "client_secret": self.client_secret},
                                params={"grant_type": "client_credentials"}, opener=self.plain)
        except ConnectError:
            raise
        except OmadaError as exc:
            raise OmadaError(f"the Open API refused the client id and secret: {exc}") from None
        token = result.get("accessToken") if isinstance(result, dict) else None
        if not token:
            raise OmadaError("the Open API returned no access token")
        self.access = f"AccessToken={token}"

    def _open(self, path, params=None):
        return self._call("GET", f"{self.base}/openapi/v1/{self.controller_id}/{path}", params=params, headers={"Authorization": self.access}, opener=self.plain)

    def open_sites(self):
        """{site key in the web API: site id in the Open API}. The two are normally the same value; a name match is the fallback."""
        result = self._open("sites", {"page": 1, "pageSize": 100})
        rows = [r for r in (result.get("data") if isinstance(result, dict) else None) or [] if isinstance(r, dict) and r.get("siteId")]
        ids = {str(r["siteId"]): str(r["siteId"]) for r in rows}
        names = {str(r.get("name") or "").lower(): str(r["siteId"]) for r in rows}
        return ids, names

    def client_applications_raw(self, site_id, mac, start, end):
        return self._open(f"sites/{site_id}/dashboard/specificClientInfo/{mac}", {"start": start, "end": end})

    def client_applications(self, site_id, mac, start, end):
        rows = self.client_applications_raw(site_id, mac, start, end)
        return [r for r in (rows if isinstance(rows, list) else []) if isinstance(r, dict)]

    @staticmethod
    def _forms(mac):
        """The same MAC address written the two ways the controller APIs use: AA-BB-... (the web interface) and AA:BB:... (the Open API's client list)."""
        plain = mac.replace(":", "").replace("-", "").upper()
        pairs = [plain[i:i + 2] for i in range(0, 12, 2)]
        return {"dashes": "-".join(pairs), "colons": ":".join(pairs)}

    def _pick_form(self, ids, names, start, end, targets):
        """Which way of writing a MAC address the application read understands: the one that returns rows for one of the busiest clients (a wrong one
        gives an empty list, not an error). Dashes when none returns anything."""
        for site, client in targets[:3]:
            site_id = ids.get(str(site["key"])) or names.get(str(site["name"]).lower())
            if not site_id or not _mac(client.get("mac")):
                continue
            for form, text in self._forms(client["mac"]).items():
                try:
                    if self.client_applications(site_id, text, start, end):
                        return form
                except ConnectError:
                    raise
                except OmadaError:
                    continue
        return "dashes"

    def usage(self):
        """(today's traffic per application and per client as the contract wants it, a problem text or None). Never raises: the topology must not
        depend on the statistics. Each figure is the day's total so far."""
        if not self.wants_usage:
            return [], None
        try:
            self.open_login()
            ids, names = self.open_sites()
            now = datetime.now().astimezone()
            midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
            start, end = int(midnight.timestamp()), int(now.timestamp())
            apps, per_client, per_client_apps, failed, deadline = {}, {}, {}, 0, time.monotonic() + USAGE_BUDGET
            targets = sorted(self.targets, key=_traffic_of)[:USAGE_MAX_CLIENTS]
            form = self._pick_form(ids, names, start, end, targets)
            for site, client in targets:
                site_id = ids.get(str(site["key"])) or names.get(str(site["name"]).lower())
                mac = _mac(client.get("mac"))
                if not site_id or not mac:
                    continue
                if time.monotonic() > deadline:
                    return self._day(midnight, apps, per_client, per_client_apps), f"stopped after {USAGE_BUDGET} seconds; not every client was read (the busiest were read first)"
                try:
                    rows = self.client_applications(site_id, self._forms(client["mac"])[form], start, end)
                except ConnectError:
                    raise
                except OmadaError:
                    failed += 1
                    continue
                for row in rows:
                    name = row.get("applicationName")
                    up, down = _number(row.get("upload")), _number(row.get("download"))
                    if not isinstance(name, str) or not name or (not up and not down):
                        continue
                    for bucket, key in ((apps, name[:80]), (per_client, mac), (per_client_apps, (mac, name[:80]))):
                        entry = bucket.setdefault(key, [0, 0])
                        entry[0] += int(up or 0)
                        entry[1] += int(down or 0)
            problem = f"{failed} client(s) could not be read" if failed else None
            return self._day(midnight, apps, per_client, per_client_apps), problem
        except (OmadaError, ValueError) as exc:
            return [], str(exc)

    @staticmethod
    def _day(midnight, apps, per_client, per_client_apps):
        if not apps and not per_client:
            return []
        by_client = {}
        for (mac, name), v in per_client_apps.items():
            by_client.setdefault(mac, []).append({"name": name, "tx_bytes": v[0], "rx_bytes": v[1]})
        return [{"day": midnight.strftime("%Y-%m-%d"),
                 "applications": [{"name": n, "tx_bytes": v[0], "rx_bytes": v[1]} for n, v in sorted(apps.items(), key=lambda i: -sum(i[1]))],
                 "clients": [{"mac": m, "tx_bytes": v[0], "rx_bytes": v[1], "applications": by_client.get(m, [])} for m, v in sorted(per_client.items(), key=lambda i: -sum(i[1]))]}]


SPEEDS = {1: 10, 2: 100, 3: 1000, 4: 2500, 5: 10000, 6: 25000}      # the controller's link speed codes, in Mbit/s


def _port(raw):
    """One switch port as the contract wants it: link state, speed, duplex and the byte counters (None when the entry is unusable)."""
    if not isinstance(raw, dict):
        return None
    number = raw.get("port")
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        return None
    status = raw.get("portStatus") if isinstance(raw.get("portStatus"), dict) else {}
    up = status.get("linkStatus") in (1, True)
    out = {"port": number, "name": raw.get("name") if isinstance(raw.get("name"), str) and raw.get("name") != f"Port{number}" else None,
           "enabled": not raw.get("disable", False), "up": bool(up)}
    if up:
        out["speed_mbps"] = SPEEDS.get(status.get("linkSpeed"))
        out["duplex"] = {1: "half", 2: "full"}.get(status.get("duplex"))
    for key, field in (("tx_bytes", "tx"), ("rx_bytes", "rx")):
        value = _number(status.get(field))
        if value is not None and value >= 0:
            out[key] = int(value)
    return out


def _traffic_of(target):
    """Sort key: the clients that moved the most data first (the totals the controller keeps per client; the current rate is zero for most)."""
    client = target[1]
    return -((_number(client.get("trafficDown")) or 0) + (_number(client.get("trafficUp")) or 0) + (_number(client.get("activity")) or 0))


def _json_or_none(raw):
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return None


def _rate_mbps(value):
    """Link rates: Omada reports kilobits per second on current firmware; values this small are already Mbps."""
    value = _number(value)
    if value is None or value <= 0:
        return None
    return round(value / 1000, 1) if value > 20000 else float(value)


def to_topology(nodes, raw_clients, usage=None):
    known = {n["mac"] for n in nodes}
    for n in nodes:
        if n["parent_mac"] not in known or n["parent_mac"] == n["mac"]:
            n["parent_mac"] = None
    out_clients = []
    for client, mac in raw_clients:
        wireless = bool(client.get("wireless"))
        node_mac = _mac(client.get("apMac")) if wireless else (_mac(client.get("switchMac")) or _mac(client.get("apMac")))
        name = client.get("hostName") or client.get("name") or None
        if name and _mac(name) == mac:
            name = None  # an unnamed client is called by its MAC
        rssi = _number(client.get("rssi"))
        out_clients.append({
            "mac": mac, "ip": client.get("ip") or None, "name": name,
            "node_mac": node_mac if node_mac in known else None,
            "medium": "wifi" if wireless else "wired",
            "band": BANDS.get(client.get("radioId")) if wireless else None,
            "rssi": int(rssi) if rssi is not None and -127 <= rssi <= 0 else None,
            "tx_mbps": _rate_mbps(client.get("txRate")) if wireless else None,
            "rx_mbps": _rate_mbps(client.get("rxRate")) if wireless else None,
            "port": str(client["port"]) if not wireless and node_mac in known and isinstance(client.get("port"), int) and client["port"] > 0 else None,
        })
    return {"nodes": nodes, "clients": out_clients, "usage": usage or []}


def test(config):
    controller = Controller(config)
    controller.login()
    try:
        sites = controller.sites()
        nodes, clients = controller.snapshot()
    finally:
        controller.logout()
    message = f"Connected to Omada controller {controller.version or '?'}: {len(sites)} site(s), {len(nodes)} device(s), {len(clients)} client(s)"
    if controller.wants_usage:
        # one client is enough to prove the Open API login, the site ids and the DPI read
        controller.targets = controller.targets[:1]
        days, problem = controller.usage()
        message += ". Application statistics: " + (f"not available ({problem})" if problem and not days else "working" if days else "the Open API works, but no application traffic was reported (is DPI switched on at the gateway?)")
    elif controller.client_id and controller.client_secret and not controller.allowed:
        message += ". Application statistics are switched off in Netlens (Settings > Statistics), so none are read"
    return {"message": message}


def fetch(config):
    controller = Controller(config)
    controller.login()
    try:
        nodes, clients = controller.snapshot()
    finally:
        controller.logout()
    days, _problem_text = controller.usage()
    return to_topology(nodes, clients, days)


# ----------------------------------------------------------------------------- diagnostic (for the plugin's author)
KEEP_WORDS = {"type", "status", "statusCategory", "connectDevType", "connectType", "radioId", "wireless", "active", "wifiMode", "controllerVer"}
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
    """The error text for a diagnostic report, without any server address (URL, IP address, host:port or host name)."""
    text = re.sub(r"https?://\S+", "<url>", str(exc))
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<url>", text)
    text = re.sub(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*:\d{2,5}\b", "<url>", text)
    text = re.sub(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", "<url>", text)
    return type(exc).__name__ + ": " + text[:300]


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
        report["controller_version"] = controller.version
        sites = controller.sites()
        report["site_count"] = len(sites)
        site = sites[0]
        devices = []

        def read_devices():
            nonlocal devices
            devices = controller._api(f"sites/{site['key']}/devices") or []
            return {"count": len(devices), "first": [describe(d) for d in devices[:SAMPLES]]}

        step("devices", read_devices)
        for kind, path in (("switch", "switches"), ("ap", "eaps")):
            first = next((d for d in devices if isinstance(d, dict) and d.get("type") == kind), None)
            if first:
                step(f"{kind}_detail", lambda first=first, path=path: describe(controller._api(f"sites/{site['key']}/{path}/{first['mac']}")))

        def read_clients():
            attempts = []
            for extra in controller.CLIENT_FILTERS:
                try:
                    rows = list(controller.paged(f"sites/{site['key']}/clients", [extra]))
                    return {"filter_used": extra or "none", "count": len(rows), "first": [describe(r) for r in rows[:SAMPLES]], "rejected": attempts}
                except OmadaError as exc:
                    attempts.append({"filter": extra or "none", "error": _problem(exc)})
            raise OmadaError("every variant of the client request was rejected: " + json.dumps(attempts))

        step("clients", read_clients)
        nodes, clients = controller.snapshot()
        if controller.wants_usage:
            def read_usage():
                controller.open_login()
                ids, names = controller.open_sites()
                now = datetime.now().astimezone()
                now_s = int(now.timestamp())
                today = int(now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
                shape = {"sites_seen_by_open_api": len(ids), "site_ids_match_web_keys": all(str(s["key"]) in ids for s in sites), "clients_tried": 0, "rows": [], "attempts": []}
                first_site = next((ids.get(str(s["key"])) or names.get(str(s["name"]).lower()) for s in sites), None)
                if first_site:
                    try:   # does the gateway know any applications at all (DPI on)?
                        catalogue = controller._open(f"sites/{first_site}/applicationControl/applications", {"page": 1, "pageSize": 1})
                        shape["application_catalogue"] = {"type": type(catalogue).__name__, "total": catalogue.get("totalRows") if isinstance(catalogue, dict) else None}
                    except OmadaError as exc:
                        shape["application_catalogue"] = {"error": _problem(exc)}
                variants = (("today_seconds", today, now_s), ("24h_seconds", now_s - 86400, now_s), ("24h_milliseconds", (now_s - 86400) * 1000, now_s * 1000))
                for site, client in sorted(controller.targets, key=_traffic_of)[:3]:
                    site_id = ids.get(str(site["key"])) or names.get(str(site["name"]).lower())
                    if not site_id:
                        continue
                    shape["clients_tried"] += 1
                    for form, text in controller._forms(client["mac"]).items():
                        for label, start, end in variants:
                            try:
                                raw = controller.client_applications_raw(site_id, text, start, end)
                            except OmadaError as exc:
                                shape["attempts"].append({"mac_form": form, "window": label, "error": _problem(exc)})
                                continue
                            count = len(raw) if isinstance(raw, (list, dict)) else None
                            shape["attempts"].append({"mac_form": form, "window": label, "type": type(raw).__name__, "count": count, **({"keys": sorted(raw)[:12]} if isinstance(raw, dict) else {})})
                            if isinstance(raw, list) and raw and not shape["rows"]:
                                shape["rows"] = [describe(r) for r in raw[:SAMPLES]]
                                shape["row_count"] = len(raw)
                                shape["window_that_worked"] = label
                                shape["mac_form_that_worked"] = form
                return shape

            step("application_traffic", read_usage)
        else:
            report["steps"]["application_traffic"] = {"ok": True, "shape": "not asked for: no Open API client entered"}
        days, usage_problem = controller.usage()
        out = to_topology(nodes, clients, days)
        report["result"] = {
            "nodes": len(out["nodes"]), "nodes_with_parent": sum(1 for n in out["nodes"] if n["parent_mac"]),
            "roles": sorted({n["role"] for n in out["nodes"]}),
            "clients": len(out["clients"]), "clients_with_node": sum(1 for c in out["clients"] if c["node_mac"]),
            "wifi_clients": sum(1 for c in out["clients"] if c["medium"] == "wifi"), "with_rssi": sum(1 for c in out["clients"] if c["rssi"] is not None),
            "with_rates": sum(1 for c in out["clients"] if c["tx_mbps"] is not None),
            "switches_with_ports": sum(1 for n in out["nodes"] if n.get("ports")), "ports": sum(len(n.get("ports") or []) for n in out["nodes"]),
            "ports_up": sum(1 for n in out["nodes"] for p in n.get("ports") or [] if p["up"]), "ports_with_counters": sum(1 for n in out["nodes"] for p in n.get("ports") or [] if p.get("rx_bytes") is not None),
            "wired_clients_with_port": sum(1 for c in out["clients"] if c.get("port")),
            "application_days": len(days), "applications": sum(len(d["applications"]) for d in days), "clients_with_applications": sum(len(d["clients"]) for d in days),
            "application_problem": _problem(OmadaError(usage_problem)) if usage_problem else None,
        }
    except LoginRefused:
        raise
    except Exception as exc:  # noqa: BLE001
        report["error"] = _problem(exc)
    finally:
        controller.logout()
    return report
