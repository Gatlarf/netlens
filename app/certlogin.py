"""Sign in with a client certificate, through a reverse proxy that checks it (Enterprise).

Netlens does not read the certificate itself (its web server does not expose the client certificate of a connection). The reverse proxy in front of it (nginx, Traefik, Caddy,
HAProxy, an F5 or a cloud load balancer) asks the browser for a certificate, checks it against your CA, and tells Netlens who it was in two headers. That is only safe if
Netlens believes those headers from the proxy and from nobody else, so:

  * the headers count only when the **network peer** of the request (not a forwarded address) is in the list of proxies you gave;
  * the proxy must **overwrite** the headers (a client cannot send its own: documented per proxy);
  * the "verify" header must have the value the proxy sets for a good certificate (`SUCCESS` for nginx);
  * the identity (the subject DN, a SAN e-mail, or a fingerprint: whatever the proxy puts in the identity header) must match, exactly, the identity an administrator stored on a user;
  * a user with a second factor still gives it; the certificate replaces only the password.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from typing import Any

from app.db import get_setting, set_setting

KEY = "security.certlogin"
DEFAULTS = {"enabled": False, "proxies": [], "verify_header": "X-SSL-Client-Verify", "verify_value": "SUCCESS", "identity_header": "X-SSL-Client-S-DN"}
_HEADER_RE = re.compile(r"^[A-Za-z0-9-]{1,60}$")


class CertLoginError(ValueError):
    """A sentence the administrator can act on."""


def get(conn: sqlite3.Connection) -> dict[str, Any]:
    out = dict(DEFAULTS)
    try:
        saved = json.loads(get_setting(conn, KEY) or "{}")
    except ValueError:
        saved = {}
    if isinstance(saved, dict):
        out.update({k: saved[k] for k in DEFAULTS if k in saved})
    return out


def save(conn: sqlite3.Connection, data: dict[str, Any]) -> dict[str, Any]:
    cur = get(conn)
    new = dict(cur)
    if "enabled" in data:
        if not isinstance(data["enabled"], bool):
            raise CertLoginError("enabled must be true or false")
        new["enabled"] = data["enabled"]
    if "proxies" in data:
        v = data["proxies"]
        if not isinstance(v, list) or len(v) > 20 or any(not isinstance(x, str) for x in v):
            raise CertLoginError("proxies must be a list of up to 20 addresses or networks")
        nets = []
        for text in v:
            try:
                nets.append(str(ipaddress.ip_network(text.strip(), strict=False)))
            except ValueError:
                raise CertLoginError(f"{text!r} is not an address or network") from None
        if any(n in ("0.0.0.0/0", "::/0") for n in nets):
            raise CertLoginError("a proxy list that contains every address would let anybody send these headers")
        new["proxies"] = sorted(set(nets))
    for field in ("verify_header", "identity_header"):
        if field in data:
            if not isinstance(data[field], str) or not _HEADER_RE.match(data[field]):
                raise CertLoginError(f"{field} must be a header name (letters, digits and -)")
            new[field] = data[field]
    if "verify_value" in data:
        v = data["verify_value"]
        if not isinstance(v, str) or not 1 <= len(v) <= 60 or re.search(r"[\x00-\x1f\x7f]", v):
            raise CertLoginError("verify_value must be the text the proxy sends for a good certificate")
        new["verify_value"] = v
    if new["enabled"] and not new["proxies"]:
        raise CertLoginError("name the reverse proxy (its address) first: the headers are believed only from there")
    if new["verify_header"].lower() == new["identity_header"].lower():
        raise CertLoginError("the two headers must be different")
    set_setting(conn, KEY, json.dumps(new))
    conn.commit()
    return new


def identity_from(request, policy: dict[str, Any]) -> str | None:
    """Who the proxy says the certificate belongs to, or None (not enabled, not from a listed proxy, certificate not verified, or no identity)."""
    if not policy["enabled"]:
        return None
    peer = getattr(getattr(request, "client", None), "host", "") or ""
    try:
        addr = ipaddress.ip_address(peer.split("%")[0])
    except ValueError:
        return None
    if not any(addr in ipaddress.ip_network(n, strict=False) for n in policy["proxies"]):
        return None
    if request.headers.get(policy["verify_header"]) != policy["verify_value"]:
        return None
    ident = (request.headers.get(policy["identity_header"]) or "").strip()
    if not ident or len(ident) > 300 or re.search(r"[\x00-\x1f\x7f]", ident):
        return None
    return ident


def user_for(conn: sqlite3.Connection, identity: str):
    return conn.execute("SELECT * FROM users WHERE cert_identity = ? AND cert_identity IS NOT NULL AND disabled = 0", (identity,)).fetchone()


def set_identity(conn: sqlite3.Connection, user_id: int, identity: str | None) -> None:
    identity = (identity or "").strip()
    if len(identity) > 300 or re.search(r"[\x00-\x1f\x7f]", identity):
        raise CertLoginError("the identity is too long or contains a control character")
    if identity and conn.execute("SELECT 1 FROM users WHERE cert_identity = ? AND id != ?", (identity, user_id)).fetchone():
        raise CertLoginError("another user already has that certificate identity")
    conn.execute("UPDATE users SET cert_identity = ? WHERE id = ?", (identity or None, user_id))
    conn.commit()
