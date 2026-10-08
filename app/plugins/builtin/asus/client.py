"""Minimal read-only client for an ASUS router's web interface (stock ASUSWRT / AiMesh; standard library only; blocking).

One fetch = one login, two reads, one logout (always, even after an error), so the router never keeps a session open.
It never retries a failed login: repeated wrong passwords make the router show a captcha or lock the login.
"""

from __future__ import annotations

import base64
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from .config import AsusConfig, normalize_url

USER_AGENT = "asusrouter-Android-DUTUtil-1.0.0.245"
MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
# error_status values of login.cgi that mean "stop trying" rather than "wrong password"
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
            return build_snapshot(clientlist, parse_onboarding(text))
        finally:
            self.logout()
