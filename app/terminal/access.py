"""Where the web terminal may be used from.

A terminal is a shell on your network, so by default it works only on a **direct** connection from the local network
(http://<netlens>:8080). A request that came through a reverse proxy (it carries X-Forwarded-* or similar headers) is
treated as coming from outside, because those are the requests an HTTPS address on the internet produces.

`NETLENS_TERMINAL_REMOTE` (environment only, so nobody can change it from the web interface) widens that:
  off  (default)  direct local connections only
  lan             also through a proxy, when the client address the proxy reports is a private one
  any             from anywhere (only sensible behind a VPN or another login in front of Netlens)
"""

from __future__ import annotations

import ipaddress
from typing import Optional

from starlette.requests import HTTPConnection

PROXY_HEADERS = (
    "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-forwarded-port", "x-real-ip", "forwarded", "via",
    "cf-connecting-ip", "cf-ray", "true-client-ip", "x-original-forwarded-for",
)
MODES = ("off", "lan", "any")
# Only the ranges meant for local networks (Python's is_private also covers documentation and reserved ranges)
_LOCAL = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # private networks
    "127.0.0.0/8", "169.254.0.0/16",                   # loopback, link-local
    "100.64.0.0/10",                                   # carrier-grade NAT, also used by Tailscale
    "::1/128", "fc00::/7", "fe80::/10",                # IPv6 loopback, unique-local, link-local
))


def parse_mode(value: Optional[str]) -> str:
    mode = (value or "off").strip().lower()
    return mode if mode in MODES else "off"


def _address(text: Optional[str]) -> Optional[ipaddress._BaseAddress]:
    if not text:
        return None
    text = text.strip().strip('"')
    if text.startswith("[") and "]" in text:
        text = text[1:text.index("]")]
    elif text.count(":") == 1:  # 1.2.3.4:5678
        text = text.split(":")[0]
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr


def is_local_address(addr: ipaddress._BaseAddress) -> bool:
    return any(addr.version == n.version and addr in n for n in _LOCAL)


def _forwarded_client(conn: HTTPConnection, trusted: bool = False) -> Optional[ipaddress._BaseAddress]:
    """The client address the nearest proxy saw: the LAST entry of X-Forwarded-For (earlier ones can be made up by the client).
    X-Real-IP and CF-Connecting-IP are only believed from a proxy named in NETLENS_TRUSTED_PROXIES: from any other sender the client could have written them itself."""
    xff = conn.headers.get("x-forwarded-for")
    if xff:
        return _address(xff.split(",")[-1])
    if not trusted:
        return None
    return _address(conn.headers.get("x-real-ip")) or _address(conn.headers.get("cf-connecting-ip"))


def _from_trusted_proxy(conn: HTTPConnection, peer) -> bool:
    """The connection comes from a reverse proxy the administrator named (NETLENS_TRUSTED_PROXIES). Such a connection counts as proxied even when the proxy adds no header
    that gives it away (nginx adds none by default): without this, a request from the internet could look like a direct one from the local network."""
    if peer is None:
        return False
    try:
        listed = getattr(conn.app.state.settings, "trusted_proxies", ()) or ()
    except (KeyError, AttributeError):                 # a connection without an application (unit tests)
        return False
    for item in listed:
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            continue
        if net.version == peer.version and peer in net:
            return True
    return False


def classify(conn: HTTPConnection, mode: str) -> tuple[bool, str]:
    """(allowed, why) for this request."""
    if mode == "any":
        return True, "allowed from anywhere (NETLENS_TERMINAL_REMOTE=any)"
    peer = _address(conn.client.host) if conn.client else None
    if peer is not None and not is_local_address(peer):
        return False, "the connection does not come from the local network"
    trusted = _from_trusted_proxy(conn, peer)
    proxied = trusted or any(h in conn.headers for h in PROXY_HEADERS)
    if not proxied:
        return True, "direct connection from the local network"
    if mode == "lan":
        client = _forwarded_client(conn, trusted)
        if client is not None and is_local_address(client):
            return True, "through a proxy, from the local network (NETLENS_TERMINAL_REMOTE=lan)"
        return False, "the connection comes through a proxy from outside the local network"
    return False, "the connection comes through a reverse proxy; the terminal only works on a direct connection (set NETLENS_TERMINAL_REMOTE to change that)"


def ensure_allowed(conn: HTTPConnection) -> None:
    """For routes that act on hosts with stored logins (set up monitoring, install a probe, change the credential store): the same rule as the terminal.
    Used as a route dependency; a refusal is written to the audit log."""
    from fastapi import HTTPException

    from app import audit
    from app.auth import client_ip, identify
    from app.db import connect

    allowed, why = classify(conn, conn.app.state.settings.terminal_remote)
    if allowed:
        return
    try:
        db = connect(conn.app.state.db_path)
        try:
            audit.record_by(db, getattr(conn.state, "user", None) or identify(conn), client_ip(conn), conn.scope.get("method", "WS"), conn.url.path, 403,
                            f"Refused: this action is only allowed from the local network ({why})")
        finally:
            db.close()
    except Exception:  # noqa: BLE001 - the refusal matters, not the log line
        pass
    raise HTTPException(status_code=403, detail=f"this action is not available here: {why}")
