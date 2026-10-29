"""Single sign-on with OpenID Connect (a paid feature): sign in with the company's identity provider (Entra ID, Keycloak, Authentik, Google, Okta ...).

Authorization-code flow with PKCE, a one-time `state` and a `nonce`. The ID token is verified here (signature against the provider's published keys, issuer,
audience, expiry, nonce) with the standard library and `cryptography`; only RS256 and ES256 are accepted. A person is recognised by the provider's stable
`sub`, never by a user name, so nobody can take over a local account by choosing its name at the provider. The first sign-in creates a Netlens user with an
unusable password; the role is `admin` when the provider's groups claim contains one of the admin groups, otherwise the default role, and follows the
provider at every sign-in.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import ipaddress
import json
import re
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from app import licence, users
from app.db import get_setting, set_setting

KEYS = ("enabled", "issuer", "client_id", "client_secret", "scopes", "admin_groups", "groups_claim", "default_role", "label", "redirect_base")
PENDING_SECONDS = 600
_pending: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()
_cache: dict[str, tuple[float, Any]] = {}


class OidcError(Exception):
    pass


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _get(key: str) -> str:
    return key


def settings(conn: sqlite3.Connection) -> dict[str, Any]:
    g = lambda k: get_setting(conn, f"oidc.{k}") or ""    # noqa: E731
    return {"enabled": g("enabled") == "1", "issuer": g("issuer"), "client_id": g("client_id"), "has_secret": bool(g("client_secret")), "scopes": g("scopes") or "openid email profile",
            "admin_groups": g("admin_groups"), "groups_claim": g("groups_claim") or "groups", "default_role": g("default_role") or "viewer", "label": g("label") or "Single sign-on",
            "redirect_base": g("redirect_base"), "group_map": group_map(conn)}


RANK = {"viewer": 0, "operator": 1, "admin": 2}


def group_map(conn: sqlite3.Connection) -> list[dict[str, str]]:
    try:
        data = json.loads(get_setting(conn, "oidc.group_map") or "[]")
    except ValueError:
        return []
    return [m for m in data if isinstance(m, dict) and m.get("group") and m.get("role")] if isinstance(data, list) else []


def _check_group_map(conn: sqlite3.Connection, value: Any) -> list[dict[str, str]]:
    from app import roles

    if not isinstance(value, list) or len(value) > 50:
        raise OidcError("the group map is a list of up to 50 lines: group = role")
    custom = {r["id"] for r in roles.load(conn)}
    out, seen = [], set()
    for item in value:
        group, role = str((item or {}).get("group", "")).strip(), str((item or {}).get("role", "")).strip()
        if not group or len(group) > 200 or re.search(r"[\x00-\x1f\x7f]", group):
            raise OidcError("a group name is empty, too long or has a control character")
        if role not in RANK and not (role.startswith("custom:") and role[7:] in custom):
            raise OidcError(f"the role {role!r} is not viewer, operator, admin or a custom role that exists (custom:<id>)")
        if group.lower() in seen:
            raise OidcError(f"the group {group!r} is mapped twice")
        seen.add(group.lower())
        out.append({"group": group, "role": role})
    return out


def resolve_role(conn: sqlite3.Connection, cfg: dict, groups: list[str]) -> tuple[str, str | None]:
    """The role a sign-in gets: the most privileged of the roles its groups map to (the admin groups and, with the Enterprise edition, the group map); else the default role.
    Returns (base role, custom role id or None)."""
    have = {g.lower() for g in groups}
    best: tuple[int, str, str | None] | None = None
    wanted = {g.strip().lower() for g in cfg["admin_groups"].split(",") if g.strip()}
    if wanted & have:
        best = (RANK["admin"], "admin", None)
    if licence.allows(conn, "privileged"):
        from app import roles

        bases = {r["id"]: r["base"] for r in roles.load(conn)}
        for m in cfg.get("group_map") or []:
            if m["group"].lower() not in have:
                continue
            if m["role"] in RANK:
                cand = (RANK[m["role"]], m["role"], None)
            elif m["role"].startswith("custom:") and m["role"][7:] in bases:
                cand = (RANK[bases[m["role"][7:]]] - 0.5, bases[m["role"][7:]], m["role"][7:])             # a custom role ranks just under its base: it is the narrower choice
            else:
                continue
            if best is None or cand[0] > best[0]:
                best = cand
    if best is None:
        return cfg["default_role"], None
    return best[1], best[2]


def save_settings(conn: sqlite3.Connection, data: dict) -> dict[str, Any]:
    if "group_map" in data:
        set_setting(conn, "oidc.group_map", json.dumps(_check_group_map(conn, data["group_map"])))
    if "issuer" in data:
        issuer = str(data["issuer"] or "").strip().rstrip("/")
        if issuer:
            parts = urllib.parse.urlsplit(issuer)
            local = False
            try:
                ip = ipaddress.ip_address(parts.hostname or "")
                local = ip.is_private or ip.is_loopback
            except ValueError:
                local = (parts.hostname or "") == "localhost"
            if parts.scheme != "https" and not (parts.scheme == "http" and local):
                raise OidcError("the provider's address must start with https:// (http:// only for a server on your own network)")
        set_setting(conn, "oidc.issuer", issuer)
    for key in ("client_id", "scopes", "admin_groups", "groups_claim", "label", "redirect_base"):
        if key in data:
            value = str(data[key] or "").strip()[:300]
            if key == "redirect_base" and value and not re.match(r"^https?://[^\s/]+$", value.rstrip("/")):
                raise OidcError("the address of Netlens must look like https://netlens.example.com")
            set_setting(conn, f"oidc.{key}", value.rstrip("/") if key == "redirect_base" else value)
    if data.get("client_secret"):
        set_setting(conn, "oidc.client_secret", str(data["client_secret"]).strip())
    if "default_role" in data:
        if data["default_role"] not in ("viewer", "operator", "admin"):
            raise OidcError("the default role is viewer, operator or admin")
        set_setting(conn, "oidc.default_role", data["default_role"])
    if "enabled" in data:
        set_setting(conn, "oidc.enabled", "1" if data["enabled"] else "0")
    return settings(conn)


def public(conn: sqlite3.Connection) -> dict[str, Any]:
    """What the sign-in dialog may know without being signed in."""
    cfg = settings(conn)
    ready = cfg["enabled"] and cfg["issuer"] and cfg["client_id"] and get_setting(conn, "oidc.client_secret") and licence.allows(conn, "sso")
    return {"enabled": bool(ready), "label": cfg["label"]}


# ----------------------------------------------------------------------------- talking to the provider
def _fetch(url: str, data: bytes | None = None, timeout: float = 15.0) -> Any:
    from app import safenet

    try:
        safenet.check_url(url, what="an address of the identity provider")
    except safenet.BlockedAddress as exc:
        raise OidcError(str(exc)) from None
    request = urllib.request.Request(url, data=data, headers={"Accept": "application/json", "User-Agent": "Netlens-sso", **({"Content-Type": "application/x-www-form-urlencoded"} if data else {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:        # noqa: S310 - the address is the administrator's own setting
            return json.loads(resp.read(1_000_000).decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = json.loads(exc.read(2000).decode("utf-8", "replace")).get("error_description") or ""
        except (ValueError, AttributeError):
            pass
        raise OidcError(f"the provider answered HTTP {exc.code}" + (f": {detail[:120]}" if detail else "")) from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise OidcError(f"cannot reach the provider: {getattr(exc, 'reason', exc)}") from None


def _cached(key: str, ttl: float, loader):
    with _lock:
        hit = _cache.get(key)
        if hit and hit[0] > time.monotonic():
            return hit[1]
    value = loader()
    with _lock:
        _cache[key] = (time.monotonic() + ttl, value)
    return value


def discovery(issuer: str) -> dict[str, Any]:
    doc = _cached("disc:" + issuer, 3600, lambda: _fetch(issuer + "/.well-known/openid-configuration"))
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
        if not isinstance(doc.get(field), str):
            raise OidcError(f"the provider's configuration has no {field}: is this an OpenID Connect address?")
    if doc["issuer"].rstrip("/") != issuer.rstrip("/"):
        raise OidcError("the provider reports a different issuer than the address you entered")
    return doc


def _public_key(jwk: dict):
    if jwk.get("kty") == "RSA":
        return rsa.RSAPublicNumbers(int.from_bytes(_b64d(jwk["e"]), "big"), int.from_bytes(_b64d(jwk["n"]), "big")).public_key()
    if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        return ec.EllipticCurvePublicNumbers(int.from_bytes(_b64d(jwk["x"]), "big"), int.from_bytes(_b64d(jwk["y"]), "big"), ec.SECP256R1()).public_key()
    raise OidcError("unsupported signing key")


def verify_id_token(token: str, jwks: dict, *, issuer: str, audience: str, nonce: str, now: float | None = None) -> dict[str, Any]:
    """The claims of a genuine ID token; OidcError otherwise."""
    try:
        head_b64, body_b64, sig_b64 = token.split(".")
        header = json.loads(_b64d(head_b64))
        claims = json.loads(_b64d(body_b64))
        signature = _b64d(sig_b64)
    except (ValueError, TypeError):
        raise OidcError("the ID token is not valid") from None
    alg = header.get("alg")
    if alg not in ("RS256", "ES256"):
        raise OidcError("the ID token is signed in a way Netlens does not accept")
    keys = [k for k in jwks.get("keys", []) if isinstance(k, dict) and (not header.get("kid") or k.get("kid") == header.get("kid")) and k.get("use", "sig") == "sig"]
    signed = f"{head_b64}.{body_b64}".encode()
    for jwk in keys:
        try:
            key = _public_key(jwk)
            if alg == "RS256" and isinstance(key, rsa.RSAPublicKey):
                key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
            elif alg == "ES256" and isinstance(key, ec.EllipticCurvePublicKey) and len(signature) == 64:
                key.verify(utils.encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")), signed, ec.ECDSA(hashes.SHA256()))
            else:
                continue
            break
        except (InvalidSignature, KeyError, ValueError, OidcError):
            continue
    else:
        raise OidcError("the signature of the ID token is not valid")
    now = now if now is not None else time.time()
    aud = claims.get("aud")
    if str(claims.get("iss", "")).rstrip("/") != issuer.rstrip("/"):
        raise OidcError("the ID token comes from another issuer")
    if audience not in (aud if isinstance(aud, list) else [aud]):
        raise OidcError("the ID token is for another application")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] < now - 60:
        raise OidcError("the ID token has expired")
    if claims.get("nbf") and claims["nbf"] > now + 60:
        raise OidcError("the ID token is not valid yet")
    if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise OidcError("the sign-in does not match the request (nonce)")
    if not claims.get("sub"):
        raise OidcError("the ID token has no subject")
    return claims


# ----------------------------------------------------------------------------- the flow
def redirect_uri(conn: sqlite3.Connection, base_url: str) -> str:
    return (settings(conn)["redirect_base"] or base_url.rstrip("/")) + "/api/auth/oidc/callback"


@dataclass(frozen=True)
class StepUp:
    """The result of a sign-in that was a step-up: the user has proved who they are again at the identity provider; `session` is the session to mark."""

    user_id: int
    session: str
    back: str


def begin(conn: sqlite3.Connection, base_url: str, stepup: tuple[int, str, str] | None = None) -> str:
    """The address to send the browser to. `stepup` = (user id, session hash, where to go back to): a fresh sign-in at the provider (prompt=login, max_age=0) to confirm a privileged action."""
    cfg = settings(conn)
    secret = get_setting(conn, "oidc.client_secret")
    if not (cfg["enabled"] and cfg["issuer"] and cfg["client_id"] and secret) or not licence.allows(conn, "sso"):
        raise OidcError("single sign-on is not set up")
    doc = discovery(cfg["issuer"])
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    now = time.monotonic()
    with _lock:
        for k in [k for k, v in _pending.items() if v["until"] < now]:
            del _pending[k]
        if len(_pending) > 500:
            raise OidcError("too many sign-ins at once")
        _pending[state] = {"nonce": nonce, "verifier": verifier, "until": now + PENDING_SECONDS, "redirect": redirect_uri(conn, base_url), "stepup": stepup}
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    query = urllib.parse.urlencode({"response_type": "code", "client_id": cfg["client_id"], "redirect_uri": _pending[state]["redirect"], "scope": cfg["scopes"], "state": state, "nonce": nonce,
                                    "code_challenge": challenge, "code_challenge_method": "S256", **({"prompt": "login", "max_age": "0"} if stepup else {})})
    return doc["authorization_endpoint"] + ("&" if "?" in doc["authorization_endpoint"] else "?") + query


def finish(conn: sqlite3.Connection, state: str, code: str, ip: str = "", user_agent: str = "") -> str:
    """Exchange the code, verify the ID token, find or make the user. Returns a Netlens session cookie value."""
    with _lock:
        pending = _pending.pop(state or "", None)
    if pending is None or pending["until"] < time.monotonic():
        raise OidcError("this sign-in has expired or was not started here; try again")
    cfg = settings(conn)
    doc = discovery(cfg["issuer"])
    tokens = _fetch(doc["token_endpoint"], urllib.parse.urlencode({"grant_type": "authorization_code", "code": code, "redirect_uri": pending["redirect"], "client_id": cfg["client_id"],
                                                                   "client_secret": get_setting(conn, "oidc.client_secret") or "", "code_verifier": pending["verifier"]}).encode())
    id_token = tokens.get("id_token") if isinstance(tokens, dict) else None
    if not isinstance(id_token, str):
        raise OidcError("the provider did not return an ID token")
    jwks = _fetch(doc["jwks_uri"])
    claims = verify_id_token(id_token, jwks, issuer=doc["issuer"], audience=cfg["client_id"], nonce=pending["nonce"])
    if pending.get("stepup"):
        user_id, session, back = pending["stepup"]
        row = conn.execute("SELECT oidc_sub FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None or not row["oidc_sub"] or not secrets.compare_digest(str(claims.get("sub", "")), row["oidc_sub"]):
            raise OidcError("the identity provider confirmed another account than the one signed in here")
        auth_time = claims.get("auth_time")
        if not isinstance(auth_time, (int, float)) or abs(time.time() - auth_time) > 180:
            raise OidcError("the identity provider did not confirm a fresh sign-in (no recent auth_time): it must honour prompt=login")
        return StepUp(user_id, session, back)
    return sign_in(conn, claims, cfg, ip, user_agent)


def sign_in(conn: sqlite3.Connection, claims: dict, cfg: dict, ip: str = "", user_agent: str = "") -> str:
    groups = claims.get(cfg["groups_claim"]) or []
    groups = [groups] if isinstance(groups, str) else [str(g) for g in groups] if isinstance(groups, list) else []
    role, custom = resolve_role(conn, cfg, groups)
    sub = str(claims["sub"])[:200]
    row = conn.execute("SELECT id, disabled FROM users WHERE oidc_sub = ?", (sub,)).fetchone()
    if row is None:
        from app import scim

        adopted = scim.adopt(conn, claims)             # the provider may have made this person's account already (SCIM)
        row = conn.execute("SELECT id, disabled FROM users WHERE id = ?", (adopted,)).fetchone() if adopted else None
    if row is None:
        base = re.sub(r"[^A-Za-z0-9._@-]", "", str(claims.get("preferred_username") or claims.get("email") or claims.get("name") or "sso-user"))[:30] or "sso-user"
        name, n = base, 1
        while conn.execute("SELECT 1 FROM users WHERE LOWER(username) = LOWER(?)", (name,)).fetchone():
            n += 1
            name = f"{base[:26]}-{n}"
        try:
            name = users.check_username(name)
        except users.UserError:
            name = f"sso-{secrets.token_hex(3)}"
        user_id = users.create_user(conn, name, secrets.token_urlsafe(24) + "Aa1", role)
        conn.execute("UPDATE users SET oidc_sub = ?, custom_role = ? WHERE id = ?", (sub, custom, user_id))
        conn.commit()
    else:
        if row["disabled"]:
            raise OidcError("this account has been disabled in Netlens")
        user_id = row["id"]
        conn.execute("UPDATE users SET role = ?, custom_role = ? WHERE id = ?", (role, custom, user_id))          # the identity provider decides the role, every time
        conn.commit()
    return users.start_session(conn, user_id, ip, user_agent, "oidc")
