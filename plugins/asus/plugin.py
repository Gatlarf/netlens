"""ASUS router / AiMesh plugin: which client is connected to which mesh node (stock ASUSWRT, read-only)."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import re
import socket
import ssl
import time
from typing import Any, Callable
import urllib.error
from urllib.parse import urlparse
import urllib.parse
import urllib.request


# ----------------------------------------------------------------------------- diagnostic helpers
KEEP_WORDS = {"type", "status", "state", "online", "template", "kind", "version", "release", "role", "model"}
MAC_RE = re.compile(r"(?i)^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$")
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
SAMPLES = 3


def describe(value: Any, key: str = "") -> Any:
    """The shape of a value: types and sizes, never the content (except a few harmless enumerations)."""
    if isinstance(value, dict):
        macs = [k for k in value if isinstance(k, str) and MAC_RE.match(k)]
        out = {k: describe(v, k) for k, v in value.items() if k not in macs}
        if macs:  # rows keyed by MAC address: the addresses are not written down, one example row is described
            out[f"<mac> x {len(macs)}"] = describe(value[macs[0]])
        return out
    if isinstance(value, list):
        return [describe(v, key) for v in value[:2]] + ([f"... {len(value)} items"] if len(value) > 2 else [])
    if isinstance(value, bool) or value is None:
        return value
    if key in KEEP_WORDS and not isinstance(value, (dict, list)):
        return value
    if isinstance(value, (int, float)):
        return f"<number {'negative' if value < 0 else 'positive' if value > 0 else 'zero'}, {len(str(abs(value)))} digits>"
    if isinstance(value, str):
        if MAC_RE.match(value):
            return "<mac " + ("dashes" if "-" in value else "colons") + (", UPPER" if value.upper() == value and re.search("[A-F]", value) else "") + ">"
        if IPV4_RE.match(value):
            return "<ipv4>"
        return f"<text {len(value)} chars>"
    return f"<{type(value).__name__}>"


def mask(text: str) -> str:
    """A configuration string with its structure kept and MAC / IPv4 addresses hidden (for example `virtio=<mac>,bridge=vmbr0`)."""
    text = re.sub(r"(?i)\b([0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", "<mac>", text)
    return re.sub(r"\b\d{1,3}(\.\d{1,3}){3}(/\d+)?\b", "<ipv4>", text)


def problem(exc: Exception) -> str:
    return type(exc).__name__ + ": " + re.sub(r"https?://\S+", "<url>", str(exc))[:300]


def make_step(report: dict) -> Callable[[str, Callable[[], Any]], Any]:
    """step(name, call): run one read, record its shape or its failure, return the raw value (or None)."""

    def step(name: str, call: Callable[[], Any], shape: Callable[[Any], Any] = describe) -> Any:
        try:
            raw = call()
        except Exception as exc:  # noqa: BLE001 - the point is to record what failed
            report["steps"][name] = {"ok": False, "error": problem(exc)}
            return None
        report["steps"][name] = {"ok": True, "shape": shape(raw)}
        return raw

    return step


# ----------------------------------------------------------------------------- configuration
@dataclass
class AsusConfig:
    enabled: bool = False
    url: str = ""
    verify_tls: bool = False  # ASUS routers ship a self-signed certificate
    username: str = ""
    password: str = ""
    traffic: bool = True      # also read the Traffic Analyzer statistics (applications and devices)
    interfaces: bool = True   # also read the byte counters of the router's interfaces (internet, wired, Wi-Fi), for the speed graphs


def normalize_url(url: str) -> str:
    """'192.168.0.1' -> 'https://192.168.0.1:8443' (the stock HTTPS port); 'http://host' keeps port 80."""
    url = url.strip().rstrip("/")
    if not url:
        return ""
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("invalid router address")
    if parsed.path not in ("", "/") or parsed.query:
        raise ValueError("enter only the router address, without a path")
    if parsed.port is None and parsed.scheme == "https":
        url += ":8443"
    return url


# ----------------------------------------------------------------------------- client
USER_AGENT = "asusrouter-Android-DUTUtil-1.0.0.245"
MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
# error_status values of login.cgi that mean "stop trying" rather than "wrong password"
CLIENT_APPS_MAX = 25         # devices whose applications are read (the busiest); one request each
CLIENT_APPS_BUDGET = 40      # seconds those requests may take
LOCKED_STATUS = {"7", "8", "9", "10"}

Transport = Callable[[str, str, dict, bytes | None], tuple[int, bytes]]


class AsusError(Exception):
    """Human-readable failure talking to the router."""


class AsusAuthError(AsusError):
    """The router refused the login; do not retry automatically."""

    auth_failed = True  # Netlens pauses the plugin until the user saves or syncs again


def norm_mac(value: Any) -> str | None:
    if isinstance(value, str) and MAC_RE.match(value.strip()):
        return value.strip().lower()
    return None


def _int(value: Any, low: int, high: int) -> int | None:
    try:
        number = int(float(str(value).strip()))
    except (TypeError, ValueError):
        return None
    return number if low <= number <= high else None


def _number(value: Any) -> float | None:
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def parse_onboarding(text: str) -> list[dict]:
    """Pull the node list out of ajax_onboarding.asp ('get_cfg_clientlist = [[{...}, ...]];')."""
    text = text.lstrip("﻿")
    marker = "get_cfg_clientlist = "
    pos = text.find(marker)
    if pos < 0:
        raise AsusError("unexpected response from the router (no AiMesh node list; is AiMesh enabled?)")
    try:
        data, _ = json.JSONDecoder().raw_decode(text[pos + len(marker):])
    except ValueError as exc:
        raise AsusError("unexpected AiMesh node list from the router") from exc
    nodes = data[0] if isinstance(data, list) and data and isinstance(data[0], list) else data
    if not isinstance(nodes, list):
        raise AsusError("unexpected AiMesh node list from the router")
    return [n for n in nodes if isinstance(n, dict)]


def build_snapshot(clientlist: Any, onboarding_nodes: list[dict]) -> dict:
    """Reduce the router's raw answers to what Netlens needs: the nodes and the online clients with their node."""
    nodes = []
    for raw in onboarding_nodes:
        mac = norm_mac(raw.get("mac"))
        if not mac:
            continue
        macs = {mac}
        for key in ("ap2g", "ap5g", "ap5g1", "ap6g", "ap6g1", "apdwb", "ap2g_fh", "ap5g_fh", "ap5g1_fh", "ap6g_fh"):
            m = norm_mac(raw.get(key))
            if m:
                macs.add(m)
        wired = [m for m in (norm_mac(x) for x in raw.get("wired_mac") or []) if m]
        nodes.append({
            "mac": mac,
            "macs": sorted(macs),
            "ip": raw.get("ip") or None,
            "name": raw.get("alias") or raw.get("model_name") or mac,
            "model": raw.get("model_name") or None,
            "main": str(raw.get("re_path", "0")) == "0",
            "wired_macs": wired,
        })
    clients = []
    entries = clientlist.get("get_clientlist") if isinstance(clientlist, dict) else None
    for key, c in (entries or {}).items():
        if not isinstance(c, dict):
            continue
        mac = norm_mac(c.get("mac") or key)
        if not mac or str(c.get("isOnline")) != "1":
            continue
        wl = str(c.get("isWL", "0"))
        clients.append({
            "mac": mac,
            "ip": c.get("ip") or None,
            "name": (c.get("nickName") or c.get("name") or "").strip() or None,
            "wired": wl == "0",
            "band": {"1": "2.4 GHz", "2": "5 GHz", "3": "5 GHz", "4": "6 GHz"}.get(wl),
            "node_mac": norm_mac(c.get("amesh_papMac")),
            "vendor": (c.get("vendor") or "").strip() or None,
            "printer": str(c.get("isPrinter")) == "1",
            "rssi": _int(c.get("rssi"), -127, -1) if wl != "0" else None,
            "tx_mbps": _number(c.get("curTx")) if wl != "0" else None,
            "rx_mbps": _number(c.get("curRx")) if wl != "0" else None,
        })
    return {"nodes": nodes, "clients": clients}


class AsusClient:
    def __init__(self, cfg: AsusConfig, *, transport: Transport | None = None, timeout: float = 15.0):
        self.cfg = cfg
        self.base = normalize_url(cfg.url)
        self.timeout = timeout
        self._transport = transport or self._urllib_transport
        self._token: str | None = None

    def _urllib_transport(self, method: str, url: str, headers: dict, data: bytes | None) -> tuple[int, bytes]:
        ctx = ssl.create_default_context()
        if not self.cfg.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, ssl.SSLCertVerificationError):
                raise AsusError("the TLS certificate could not be verified; turn off 'Verify TLS certificate' (routers use a self-signed one)") from exc
            if isinstance(reason, (socket.timeout, TimeoutError)):
                raise AsusError(f"connection to {self.cfg.url} timed out") from exc
            raise AsusError(f"cannot connect to {self.cfg.url}: {reason}") from exc
        except (socket.timeout, TimeoutError) as exc:
            raise AsusError(f"connection to {self.cfg.url} timed out") from exc
        except OSError as exc:
            raise AsusError(f"cannot connect to {self.cfg.url}: {exc}") from exc

    def _send(self, path: str, data: str | None = None) -> tuple[int, str]:
        headers = {"User-Agent": USER_AGENT}
        if self._token:
            headers["Cookie"] = f"asus_token={self._token}"
        body = None
        method = "GET"
        if data is not None:
            method = "POST"
            body = data.encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        status, raw = self._transport(method, self.base + path, headers, body)
        return status, raw.decode("utf-8", errors="replace")

    def login(self) -> None:
        creds = base64.b64encode(f"{self.cfg.username}:{self.cfg.password}".encode()).decode()
        status, text = self._send("/login.cgi", "login_authorization=" + urllib.parse.quote(creds))
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        if not isinstance(data, dict):
            raise AsusError(f"unexpected response from the router (HTTP {status}); is this an ASUS router address?")
        token = data.get("asus_token")
        if not token:
            err = str(data.get("error_status", ""))
            if err in LOCKED_STATUS:
                raise AsusAuthError("the router blocked the login (too many attempts or a captcha is required); log in on the router's web page once, then try again")
            raise AsusAuthError("login refused (check the username and password; an account for the router's web interface is required)")
        self._token = token

    def logout(self) -> None:
        if not self._token:
            return
        try:
            self._send("/Logout.asp")
        except AsusError:
            pass
        finally:
            self._token = None

    # --- Traffic Analyzer (Adaptive QoS / Traffic Analyzer > Statistic): bytes per application and per device ---
    def router_now(self) -> datetime:
        """The router's own clock with its UTC offset (so a day ends at the router's midnight)."""
        status, text = self._send("/appGet.cgi?hook=uptime()")
        match = re.search(r"\w{3}, (\d{1,2} \w{3} \d{4} \d{2}:\d{2}:\d{2}) ([+-])(\d{2})(\d{2})", text) if status == 200 else None
        if not match:
            return datetime.now(timezone.utc)
        sign = 1 if match.group(2) == "+" else -1
        zone = timezone(sign * timedelta(hours=int(match.group(3)), minutes=int(match.group(4))))
        return datetime.strptime(match.group(1), "%d %b %Y %H:%M:%S").replace(tzinfo=zone)

    def _statistics(self, page: str, client: str, mode: str, duration: int, end: datetime) -> list | None:
        """One answer of the router's traffic pages: a script that sets `array_statistics` (None when the page is missing)."""
        status, text = self._send(f"/{page}.asp?client={client}&mode={mode}&dura={duration}&date={int(end.timestamp())}")
        if status != 200:
            return None
        match = re.search(r"array_statistics\s*=\s*(\[.*\])\s*;?\s*$", text.strip(), re.S)
        if not match:
            return None
        try:
            rows = json.loads(match.group(1))
        except ValueError:
            return None
        return rows if isinstance(rows, list) else None

    def usage(self, days: int = 2) -> list[dict]:
        """Traffic per application and per client for today and the days before (each figure is the day's total so far). Empty when the Traffic
        Analyzer is off or this model does not have it; never raises, because the rest of the sync must not depend on it."""
        out: list[dict] = []
        try:
            now = self.router_now()
            midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
            for back in range(days):
                start = midnight - timedelta(days=back)
                end = start + timedelta(days=1)
                apps = self._statistics("getWanTraffic", "all", "detail", 24, end)       # (sic) the router calls the per-application list "WAN traffic"
                clients = self._statistics("getAppTraffic", "all", "detail", 24, end)    # and the per-device list "app traffic"
                if apps is None and clients is None:
                    break
                entry = {"day": start.strftime("%Y-%m-%d"), "applications": [], "clients": []}
                for row in apps or []:
                    if isinstance(row, list) and len(row) >= 3 and isinstance(row[0], str) and all(isinstance(v, (int, float)) for v in row[1:3]):
                        if row[1] or row[2]:
                            entry["applications"].append({"name": row[0], "tx_bytes": int(row[1]), "rx_bytes": int(row[2])})
                for row in clients or []:
                    mac = norm_mac(row[0]) if isinstance(row, list) and row and isinstance(row[0], str) else None
                    if mac and len(row) >= 3 and all(isinstance(v, (int, float)) for v in row[1:3]) and (row[1] or row[2]):
                        entry["clients"].append({"mac": mac, "tx_bytes": int(row[1]), "rx_bytes": int(row[2]), "_raw": row[0]})
                if back == 0:
                    self._client_applications(entry, end)
                for client in entry["clients"]:
                    client.pop("_raw", None)
                if entry["applications"] or entry["clients"]:
                    out.append(entry)
        except (AsusError, ValueError):
            return out
        return out

    def _client_applications(self, entry: dict, end: datetime) -> None:
        """The applications each of the busiest devices used (today only; one read per device, within a time budget)."""
        deadline = time.monotonic() + CLIENT_APPS_BUDGET
        for client in sorted(entry["clients"], key=lambda c: -(c["tx_bytes"] + c["rx_bytes"]))[:CLIENT_APPS_MAX]:
            if time.monotonic() > deadline:
                break
            try:
                rows = self._statistics("getWanTraffic", client["_raw"], "detail", 24, end)       # the same page with one device's address instead of "all"
            except AsusError:
                continue
            apps = [{"name": r[0], "tx_bytes": int(r[1]), "rx_bytes": int(r[2])} for r in rows or []
                    if isinstance(r, list) and len(r) >= 3 and isinstance(r[0], str) and all(isinstance(v, (int, float)) for v in r[1:3]) and (r[1] or r[2])]
            if rows is not None:
                client["applications"] = apps

    # --- the interface counters: what the router has sent and received since it started, per interface ---
    NETDEV = (("INTERNET", 1, "WAN"), ("WIRED", 2, "LAN"), ("WIRELESS0", 3, "Wi-Fi radio 1"), ("WIRELESS1", 4, "Wi-Fi radio 2"), ("WIRELESS2", 5, "Wi-Fi radio 3"))

    def interfaces(self) -> list[dict]:
        """The router's interfaces as ports with byte counters (`INTERNET` is the internet connection). [] when the router does not say; never an error:
        the sync is about the topology and this is an extra."""
        try:
            status, text = self._send("/appGet.cgi?hook=netdev(appobj)")
            data = json.loads(text).get("netdev") if status == 200 else None
        except (AsusError, ValueError, AttributeError):
            return []
        if not isinstance(data, dict):
            return []
        ports = []
        for key, number, name in self.NETDEV:
            try:
                rx, tx = int(str(data[f"{key}_rx"]), 16), int(str(data[f"{key}_tx"]), 16)
            except (KeyError, ValueError):
                continue
            ports.append({"port": number, "name": name, "up": True, "enabled": True, "rx_bytes": rx, "tx_bytes": tx})
        return ports

    def snapshot(self) -> dict:
        self.login()
        try:
            status, text = self._send("/appGet.cgi?hook=get_clientlist()")
            if status != 200:
                raise AsusError(f"the router returned HTTP {status} for the client list")
            try:
                clientlist = json.loads(text)
            except ValueError as exc:
                raise AsusError("unexpected client list from the router") from exc
            status, text = self._send("/ajax_onboarding.asp")
            if status != 200:
                raise AsusError(f"the router returned HTTP {status} for the AiMesh node list")
            snapshot = build_snapshot(clientlist, parse_onboarding(text))
            snapshot["usage"] = self.usage() if self.cfg.traffic else []
            snapshot["interfaces"] = self.interfaces() if self.cfg.interfaces else []
            return snapshot
        finally:
            self.logout()


# ----------------------------------------------------------------------------- plugin entry points
CLIENT_FACTORY = AsusClient  # replaced by tests


def _client(config: dict):

    cfg = AsusConfig(
        url=config.get("url", ""),
        verify_tls=bool(config.get("verify_tls", False)),
        username=config.get("username", ""),
        password=config.get("password", ""),
        traffic=bool(config.get("traffic", True)) and bool(config.get("collect_usage", True)),     # Netlens' own switch (Settings > Statistics) has the last word
        interfaces=bool(config.get("interfaces", True)),
    )
    if not (cfg.url and cfg.username and cfg.password):
        raise ValueError("enter the router address, username and password")
    return CLIENT_FACTORY(cfg)


def to_topology(snapshot: dict) -> dict:
    """Turn the router's raw view into the plugin contract (kind 'topology')."""
    nodes = snapshot["nodes"]
    main = next((n for n in nodes if n["main"]), None)
    out_nodes = []
    for n in nodes:
        parent = None
        if main is not None and n is not main:
            holder = next((p for p in nodes if p is not n and n["mac"] in p["wired_macs"]), None)  # the node it is wired to
            parent = (holder or main)["mac"]
        out_nodes.append({
            "mac": n["mac"], "macs": n["macs"], "ip": n["ip"], "name": n["name"], "model": n["model"],
            "role": "gateway" if n is main else "node", "parent_mac": parent,
            **({"ports": snapshot["interfaces"]} if n is main and snapshot.get("interfaces") else {}),        # the router's own interfaces; Netlens turns the counters into speeds
        })
    known = {m for n in nodes for m in n["macs"]}
    clients = []
    for c in snapshot["clients"]:
        node = c["node_mac"] if c["node_mac"] in known else (main["mac"] if main else None)
        clients.append({
            "mac": c["mac"], "ip": c["ip"], "name": c["name"], "node_mac": node,
            "medium": "wired" if c["wired"] else "wifi", "band": c["band"],
            "rssi": c.get("rssi"), "tx_mbps": c.get("tx_mbps"), "rx_mbps": c.get("rx_mbps"),
            "vendor": c.get("vendor"), "device_type": "printer" if c.get("printer") else None,
        })
    return {"nodes": out_nodes, "clients": clients, "usage": snapshot.get("usage") or []}


def test(config: dict) -> dict:
    snapshot = _client(config).snapshot()
    return {"message": f"Connected: {len(snapshot['nodes'])} mesh node(s), {len(snapshot['clients'])} online client(s)"}


def fetch(config: dict) -> dict:
    return to_topology(_client(config).snapshot())


def diagnose(config: dict) -> dict:
    """What this router answers, described by field names and types (no names, addresses or MACs), for the plugin's author."""



    client = _client(config)
    report: dict = {"steps": {}}
    step = make_step(report)
    client.login()  # a refused login is reported as such (and stops automatic syncing), like test()
    clientlist = onboarding = None
    try:
        def read_clientlist():
            status, text = client._send("/appGet.cgi?hook=get_clientlist()")
            if status != 200:
                raise AsusError(f"HTTP {status}")
            return json.loads(text)

        def read_onboarding():
            status, text = client._send("/ajax_onboarding.asp")
            if status != 200:
                raise AsusError(f"HTTP {status}")
            return text

        clientlist = step("clientlist", read_clientlist)
        raw = step("onboarding", read_onboarding, lambda t: {"length": len(t), "lines": t.count("\n") + 1})
        if raw is not None:
            nodes = parse_onboarding(raw)
            onboarding = nodes
            report["steps"]["onboarding"]["nodes_parsed"] = len(nodes)
            report["steps"]["onboarding"]["first_node"] = [describe(n) for n in nodes[:SAMPLES]]
        def read_traffic():
            now = client.router_now()
            end = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
            apps = client._statistics("getWanTraffic", "all", "detail", 24, end)
            devices = client._statistics("getAppTraffic", "all", "detail", 24, end)
            return {"applications_page": apps is not None, "devices_page": devices is not None,
                    "applications": len(apps or []), "devices": len(devices or []),
                    "application_row": describe((apps or [None])[0]), "device_row": describe((devices or [None])[0]),
                    "days_parsed": len(client.usage(1))}

        step("traffic_analyzer", read_traffic)
        step("interfaces", lambda: client.interfaces(), lambda ports: {"ports": [p["name"] for p in ports], "counters_ok": all(isinstance(p["rx_bytes"], int) and isinstance(p["tx_bytes"], int) for p in ports)})
        if clientlist is not None and onboarding is not None:
            snapshot = build_snapshot(clientlist, onboarding)
            report["result"] = {
                "nodes": len(snapshot["nodes"]), "main_nodes": sum(1 for n in snapshot["nodes"] if n["main"]),
                "clients": len(snapshot["clients"]), "wired": sum(1 for c in snapshot["clients"] if c["wired"]),
                "with_rssi": sum(1 for c in snapshot["clients"] if c.get("rssi") is not None), "with_rates": sum(1 for c in snapshot["clients"] if c.get("tx_mbps") is not None),
                "with_node": sum(1 for c in snapshot["clients"] if c["node_mac"]),
            }
    except AsusAuthError:
        raise
    except Exception as exc:  # noqa: BLE001
        report["error"] = problem(exc)
    finally:
        client.logout()
    return report
