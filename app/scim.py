"""SCIM 2.0 user provisioning (Enterprise): the identity provider creates, deactivates and removes Netlens accounts by itself.

Joiners get an account (the default role of the SCIM settings: viewer or operator, never administrator), leavers are deactivated within minutes of leaving the directory, with
their sessions ended. Sign-in itself stays with single sign-on (OpenID Connect): the person signs in at the provider; Netlens matches the sign-in to the account the provider made.

Safety rails, because this is a door that the identity provider opens by itself:
  * its own bearer token (shown once, stored as a hash), only for /scim/v2, only from the networks you list if you list any; wrong tokens are rate-limited like sign-ins;
  * it can only see and change accounts it created itself: a local administrator cannot be deactivated, changed or deleted by the provider;
  * it can never give the role administrator (the group map at sign-in can, with its own safeguards); the last administrator can never be removed;
  * without the Enterprise edition it can still deactivate and delete (leavers must always go), but not create.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import time
from typing import Any

from app import users
from app.db import get_setting, insert_id, set_setting, utcnow

KEY = "scim.config"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
DEFAULTS = {"enabled": False, "role": "viewer", "networks": [], "token_hash": "", "token_name": "", "token_created": "", "last_used": ""}
_last_touch = {"t": 0.0}


class ScimError(Exception):
    def __init__(self, status: int, detail: str, scim_type: str | None = None) -> None:
        super().__init__(detail)
        self.status, self.detail, self.scim_type = status, detail, scim_type


def get(conn: sqlite3.Connection) -> dict[str, Any]:
    out = dict(DEFAULTS)
    try:
        saved = json.loads(get_setting(conn, KEY) or "{}")
    except ValueError:
        saved = {}
    if isinstance(saved, dict):
        out.update({k: saved[k] for k in DEFAULTS if k in saved})
    return out


def _save(conn: sqlite3.Connection, cfg: dict[str, Any]) -> None:
    set_setting(conn, KEY, json.dumps({k: cfg[k] for k in DEFAULTS}))
    conn.commit()


def public(conn: sqlite3.Connection) -> dict[str, Any]:
    cfg = get(conn)
    return {"enabled": cfg["enabled"], "role": cfg["role"], "networks": cfg["networks"], "has_token": bool(cfg["token_hash"]), "token_name": cfg["token_name"], "token_created": cfg["token_created"],
            "last_used": cfg["last_used"], "users": conn.execute("SELECT COUNT(*) FROM users WHERE scim_managed = 1").fetchone()[0]}


def configure(conn: sqlite3.Connection, data: dict[str, Any]) -> dict[str, Any]:
    import ipaddress

    cfg = get(conn)
    if "enabled" in data:
        if not isinstance(data["enabled"], bool):
            raise ValueError("enabled must be true or false")
        cfg["enabled"] = data["enabled"]
    if "role" in data:
        if data["role"] not in ("viewer", "operator"):
            raise ValueError("accounts made by SCIM are viewers or operators; the provider can never make an administrator")
        cfg["role"] = data["role"]
    if "networks" in data:
        nets = data["networks"]
        if not isinstance(nets, list) or len(nets) > 20 or any(not isinstance(n, str) for n in nets):
            raise ValueError("networks must be a list of up to 20 addresses or networks")
        try:
            cfg["networks"] = sorted({str(ipaddress.ip_network(n.strip(), strict=False)) for n in nets})
        except ValueError:
            raise ValueError("one of the networks is not an address or network") from None
    if cfg["enabled"] and not cfg["token_hash"]:
        raise ValueError("make a token first: the provider needs it to sign in")
    _save(conn, cfg)
    return public(conn)


def new_token(conn: sqlite3.Connection, name: str) -> str:
    token = "nlscim_" + secrets.token_urlsafe(32)
    cfg = get(conn)
    cfg.update(token_hash=hashlib.sha256(token.encode()).hexdigest(), token_name=" ".join(str(name or "identity provider").split())[:60] or "identity provider", token_created=utcnow(), last_used="")
    _save(conn, cfg)
    return token


def revoke_token(conn: sqlite3.Connection) -> None:
    cfg = get(conn)
    cfg.update(token_hash="", token_name="", token_created="", enabled=False)
    _save(conn, cfg)


def authenticate(conn: sqlite3.Connection, bearer: str | None, ip: str) -> bool:
    import ipaddress

    cfg = get(conn)
    if not cfg["enabled"] or not cfg["token_hash"] or not bearer:
        return False
    if not secrets.compare_digest(hashlib.sha256(bearer.encode()).hexdigest(), cfg["token_hash"]):
        return False
    if cfg["networks"]:
        try:
            addr = ipaddress.ip_address((ip or "").split("%")[0])
        except ValueError:
            return False
        if not any(addr in ipaddress.ip_network(n, strict=False) for n in cfg["networks"]):
            return False
    if time.time() - _last_touch["t"] > 60:
        _last_touch["t"] = time.time()
        cfg["last_used"] = utcnow()
        _save(conn, cfg)
    return True


# ----------------------------------------------------------------------------- resources
def resource(row) -> dict[str, Any]:
    emails = [{"value": row["scim_email"], "primary": True}] if row["scim_email"] else []
    return {"schemas": [USER_SCHEMA], "id": str(row["id"]), "externalId": row["scim_external"] or None, "userName": row["scim_user_name"] or row["username"], "displayName": row["scim_display"] or None,
            "emails": emails, "active": not row["disabled"], "meta": {"resourceType": "User", "created": row["created"]}}


def _managed(conn: sqlite3.Connection, user_id: str):
    if not str(user_id).isdigit():
        raise ScimError(404, "no such user")
    row = conn.execute("SELECT * FROM users WHERE id = ? AND scim_managed = 1", (int(user_id),)).fetchone()
    if row is None:
        raise ScimError(404, "no such user")
    return row


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    raise ScimError(400, "active must be true or false", "invalidValue")


def _text(value: Any, what: str, limit: int = 200) -> str:
    if not isinstance(value, str) or len(value) > limit or re.search(r"[\x00-\x1f\x7f]", value):
        raise ScimError(400, f"{what} is not valid", "invalidValue")
    return value.strip()


def _email_of(body: dict) -> str:
    emails = body.get("emails")
    if isinstance(emails, list) and emails:
        pick = next((e for e in emails if isinstance(e, dict) and e.get("primary")), emails[0])
        if isinstance(pick, dict) and pick.get("value"):
            return _text(pick["value"], "the e-mail address", 254)
    return ""


def _free_name(conn: sqlite3.Connection, wish: str) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]", "", wish.split("@")[0])[:28] or "user"
    name, n = base, 1
    while conn.execute("SELECT 1 FROM users WHERE LOWER(username) = LOWER(?)", (name,)).fetchone():
        n += 1
        name = f"{base[:26]}-{n}"
    try:
        return users.check_username(name)
    except users.UserError:
        return f"user-{secrets.token_hex(3)}"


def create(conn: sqlite3.Connection, body: dict, allowed: bool) -> dict[str, Any]:
    if not allowed:
        raise ScimError(403, "creating accounts by SCIM is part of the Enterprise edition (or the free trial); deactivating and removing still work")
    user_name = _text(body.get("userName"), "userName")
    if not user_name:
        raise ScimError(400, "userName is required", "invalidValue")
    if conn.execute("SELECT 1 FROM users WHERE scim_user_name = ? COLLATE NOCASE", (user_name,)).fetchone():
        raise ScimError(409, "a user with that userName exists", "uniqueness")
    external = _text(body.get("externalId") or "", "externalId")
    if external and conn.execute("SELECT 1 FROM users WHERE scim_external = ?", (external,)).fetchone():
        raise ScimError(409, "a user with that externalId exists", "uniqueness")
    name = _free_name(conn, user_name)
    cfg = get(conn)
    try:
        user_id = users.create_user(conn, name, secrets.token_urlsafe(24) + "Aa1", cfg["role"])           # nobody knows this password: the person signs in through the provider
    except users.UserError as exc:
        raise ScimError(400, str(exc), "invalidValue") from None
    display = _text(body.get("displayName") or (body.get("name") or {}).get("formatted") or "", "displayName") if isinstance(body.get("name") or {}, dict) else ""
    conn.execute("UPDATE users SET scim_managed = 1, scim_external = ?, scim_user_name = ?, scim_email = ?, scim_display = ?, disabled = ? WHERE id = ?",
                 (external or None, user_name, _email_of(body) or None, display or None, 0 if _bool(body.get("active", True)) else 1, user_id))
    conn.commit()
    return resource(conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())


def apply(conn: sqlite3.Connection, row, changes: dict[str, Any]) -> None:
    """Change what the provider owns: active, userName, externalId, e-mail, display name."""
    sets: dict[str, Any] = {}
    if "active" in changes:
        sets["disabled"] = 0 if _bool(changes["active"]) else 1
    if "userName" in changes:
        value = _text(changes["userName"], "userName")
        if conn.execute("SELECT 1 FROM users WHERE scim_user_name = ? COLLATE NOCASE AND id != ?", (value, row["id"])).fetchone():
            raise ScimError(409, "a user with that userName exists", "uniqueness")
        sets["scim_user_name"] = value
    if "externalId" in changes:
        value = _text(changes["externalId"] or "", "externalId")
        if value and conn.execute("SELECT 1 FROM users WHERE scim_external = ? AND id != ?", (value, row["id"])).fetchone():
            raise ScimError(409, "a user with that externalId exists", "uniqueness")
        sets["scim_external"] = value or None
    if "emails" in changes:
        sets["scim_email"] = _email_of({"emails": changes["emails"]}) or None
    if "displayName" in changes:
        sets["scim_display"] = _text(changes["displayName"] or "", "displayName") or None
    if "name" in changes and isinstance(changes["name"], dict) and "displayName" not in changes:
        sets["scim_display"] = _text(changes["name"].get("formatted") or "", "name") or None
    if "disabled" in sets and sets["disabled"] and users.is_last_admin(conn, row["id"]):
        raise ScimError(409, "this is the last administrator and cannot be deactivated")
    for column, value in sets.items():
        conn.execute(f"UPDATE users SET {column} = ? WHERE id = ?", (value, row["id"]))        # column names come from the fixed set above
    if sets.get("disabled") == 1:
        users.end_sessions(conn, row["id"])
    conn.commit()


def patch(conn: sqlite3.Connection, user_id: str, body: dict) -> dict[str, Any]:
    row = _managed(conn, user_id)
    ops = body.get("Operations")
    if not isinstance(ops, list) or not ops or len(ops) > 50:
        raise ScimError(400, "Operations is a list of up to 50 operations", "invalidSyntax")
    changes: dict[str, Any] = {}
    for op in ops:
        kind = str((op or {}).get("op", "")).lower()
        path, value = (op or {}).get("path"), (op or {}).get("value")
        if kind not in ("add", "replace", "remove"):
            raise ScimError(400, "op must be add, replace or remove", "invalidSyntax")
        if kind == "remove":
            if path in ("externalId", "emails", "displayName"):
                changes[path] = None if path != "emails" else []
            continue
        if path:
            changes[str(path).split("[")[0]] = value
        elif isinstance(value, dict):
            changes.update({k: v for k, v in value.items() if k in ("active", "userName", "externalId", "emails", "displayName", "name")})
    apply(conn, row, changes)
    return resource(conn.execute("SELECT * FROM users WHERE id = ?", (row["id"],)).fetchone())


def replace(conn: sqlite3.Connection, user_id: str, body: dict) -> dict[str, Any]:
    row = _managed(conn, user_id)
    apply(conn, row, {k: body[k] for k in ("active", "userName", "externalId", "emails", "displayName", "name") if k in body})
    return resource(conn.execute("SELECT * FROM users WHERE id = ?", (row["id"],)).fetchone())


def delete(conn: sqlite3.Connection, user_id: str) -> None:
    row = _managed(conn, user_id)
    try:
        users.delete_user(conn, row["id"])
    except users.LastAdminError:
        raise ScimError(409, "this is the last administrator and cannot be removed") from None


def listing(conn: sqlite3.Connection, filter_text: str, start: int, count: int) -> dict[str, Any]:
    where, args = "scim_managed = 1", []
    if filter_text:
        m = re.fullmatch(r'\s*(userName|externalId)\s+eq\s+"([^"\\]{1,200})"\s*', filter_text)
        if not m:
            raise ScimError(400, 'only the filters userName eq "x" and externalId eq "x" are supported', "invalidFilter")
        where += " AND " + ("scim_user_name = ? COLLATE NOCASE" if m.group(1) == "userName" else "scim_external = ?")
        args.append(m.group(2))
    total = conn.execute(f"SELECT COUNT(*) FROM users WHERE {where}", args).fetchone()[0]
    start, count = max(1, start), max(0, min(count, 100))
    rows = conn.execute(f"SELECT * FROM users WHERE {where} ORDER BY id LIMIT ? OFFSET ?", (*args, count, start - 1)).fetchall()
    return {"schemas": [LIST_SCHEMA], "totalResults": total, "startIndex": start, "itemsPerPage": len(rows), "Resources": [resource(r) for r in rows]}


def adopt(conn: sqlite3.Connection, claims: dict) -> int | None:
    """At a single-sign-on sign-in: the account the provider already made for this person, matched by the externalId (equal to the `sub` claim) or, when the provider vouches for the
    e-mail address, by that address. Links it to the sign-in and returns its id."""
    sub = str(claims.get("sub", ""))[:200]
    row = conn.execute("SELECT id FROM users WHERE scim_managed = 1 AND oidc_sub IS NULL AND scim_external = ?", (sub,)).fetchone() if sub else None
    email = str(claims.get("email") or "").strip().lower()
    if row is None and email and claims.get("email_verified") is True:
        row = conn.execute("SELECT id FROM users WHERE scim_managed = 1 AND oidc_sub IS NULL AND (LOWER(scim_email) = ? OR LOWER(scim_user_name) = ?)", (email, email)).fetchone()
    if row is None:
        return None
    conn.execute("UPDATE users SET oidc_sub = ? WHERE id = ?", (sub, row["id"]))
    conn.commit()
    return row["id"]
