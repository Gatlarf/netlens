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

Standard library only. A refused login is reported with `auth_failed`, so Netlens stops retrying until the user acts
(this protects the account from being locked).
"""

import http.cookiejar
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

PAGE_SIZE = 100
MAX_PAGES = 200
MIN_VERSION = (5, 1, 0)
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
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            urllib.request.HTTPSHandler(context=context),
        )
        self.controller_id = None
        self.version = ""
        self.csrf = None

    # ---- plumbing ------------------------------------------------------------------------------------------
    def _call(self, method, url, body=None, params=None):
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.csrf:
            headers["Csrf-Token"] = self.csrf
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=20) as response:
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

    def uplink_of(self, site, device):
        """MAC of the device this switch or access point is plugged into (None when unknown; one small read)."""
        kind = device.get("type")
        if kind == "switch":
            path, keys = f"sites/{site['key']}/switches/{device['mac']}", ("uplink",)
        elif kind == "ap":
            path, keys = f"sites/{site['key']}/eaps/{device['mac']}", ("wiredUplink", "uplink")
        else:
            return None
        try:
            detail = self._api(path)
        except OmadaError:
            return None  # one device that cannot be read must not fail the whole sync
        for key in keys:
            link = detail.get(key) if isinstance(detail, dict) else None
            if isinstance(link, dict):
                mac = _mac(link.get("mac") or link.get("uplinkMac"))
                if mac:
                    return mac
        return None

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
                    "parent_mac": self.uplink_of(site, device),  # asked for with the MAC exactly as the controller wrote it
                })
            for client in self.paged(f"sites/{site['key']}/clients", self.CLIENT_FILTERS):
                mac = _mac(client.get("mac"))
                if not mac or mac in seen_clients or client.get("active") is False:
                    continue
                seen_clients.add(mac)
                clients.append((client, mac))
        return nodes, clients


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


def to_topology(nodes, raw_clients):
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
    return {"message": f"Connected to Omada controller {controller.version or '?'}: {len(sites)} site(s), {len(nodes)} device(s), {len(clients)} client(s)"}


def fetch(config):
    controller = Controller(config)
    controller.login()
    try:
        nodes, clients = controller.snapshot()
    finally:
        controller.logout()
    return to_topology(nodes, clients)
