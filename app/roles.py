"""Custom roles (Enterprise): a **base role** (viewer or operator) plus a few **read-only capabilities**.

A custom role never has more than a viewer or operator plus extra *reading*: "auditor" is a viewer who may also read the audit log and the availability reports; "network
reader" is a viewer who may also see DNS, storage and vulnerabilities. There are no write capabilities and nothing that reaches credentials, users, remote access or any
setting: those stay with the administrator, because granting them in pieces is how a role becomes an unnoticed way to administrator.

How it is kept safe:
  * the catalogue is in the code: a role names capabilities from it and cannot define a path of its own;
  * a capability is a list of exact GET paths; a test fails if one of them matches a path that needs step-up, or that the assistant may never reach, or is not a read;
  * the base role stays the user's `role`, so every check that looks at the role keeps working and denies by default;
  * a user limited to some groups or sites (a customer view) never gets extra capabilities;
  * the extra capabilities need the Enterprise edition (or the trial) *at the time of the request*: without it the user is simply their base role again (nothing is deleted),
    the way an operator becomes a viewer without the teams licence.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from app.db import get_setting, set_setting

KEY = "roles.custom"
BASES = ("viewer", "operator")
MAX_ROLES = 20
CATALOG: dict[str, dict[str, Any]] = {
    "audit": {"label": "Read the audit log", "text": "Who changed what, when; and whether the log is intact.", "get": r"^/api/(audit|audit\.csv|audit/integrity)$"},
    "reports": {"label": "Read the reports", "text": "Availability, weekly and monthly reports.", "get": r"^/api/reports/(availability|availability\.csv|weekly|monthly)$"},
    "backups": {"label": "See the backups page", "text": "Which backups ran and which failed (no restore, no download).", "get": r"^/api/backups$"},
    "vulnerabilities": {"label": "See vulnerabilities", "text": "The findings of the vulnerability scanners.", "get": r"^/api/vulns$"},
    "storage": {"label": "See storage systems", "text": "Pools, volumes, disks and their health.", "get": r"^/api/storage$"},
    "dns": {"label": "See DNS", "text": "The DNS records and conflicts Netlens knows.", "get": r"^/api/dns$"},
    "inventory": {"label": "See the inventory", "text": "Servers and their hardware from the inventory plugin.", "get": r"^/api/inventory$"},
}
_COMPILED = {cap: re.compile(spec["get"]) for cap, spec in CATALOG.items()}


class RoleError(ValueError):
    """A sentence the user can act on."""


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40]


def load(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    try:
        data = json.loads(get_setting(conn, KEY) or "[]")
    except ValueError:
        return []
    return [r for r in data if isinstance(r, dict) and r.get("id") and r.get("base") in BASES] if isinstance(data, list) else []


def public(conn: sqlite3.Connection) -> dict[str, Any]:
    counts = {r[0]: r[1] for r in conn.execute("SELECT custom_role, COUNT(*) FROM users WHERE custom_role IS NOT NULL GROUP BY custom_role")}
    return {"roles": [{**r, "users": counts.get(r["id"], 0)} for r in load(conn)], "catalogue": [{"id": k, "label": v["label"], "text": v["text"]} for k, v in CATALOG.items()], "bases": list(BASES)}


def save(conn: sqlite3.Connection, name: str, base: str, grants: list[str], role_id: str | None = None) -> dict[str, Any]:
    """Create a role (`role_id` None) or change one. Returns the role."""
    name = " ".join(str(name or "").split())
    if not name or len(name) > 40:
        raise RoleError("give the role a name (up to 40 characters)")
    if base not in BASES:
        raise RoleError("a custom role is based on viewer or operator")
    if not isinstance(grants, list) or any(not isinstance(g, str) for g in grants):
        raise RoleError("the capabilities must be a list")
    unknown = sorted(set(grants) - set(CATALOG))
    if unknown:
        raise RoleError("unknown capability: " + ", ".join(unknown))
    roles = load(conn)
    if role_id is None:
        if len(roles) >= MAX_ROLES:
            raise RoleError(f"at most {MAX_ROLES} custom roles")
        role_id = _slug(name)
        if not role_id or role_id in ("admin", "operator", "viewer") or any(r["id"] == role_id for r in roles):
            raise RoleError("a role with that name exists (or the name is reserved)")
        role = {"id": role_id, "name": name, "base": base, "grants": sorted(set(grants))}
        roles.append(role)
    else:
        role = next((r for r in roles if r["id"] == role_id), None)
        if role is None:
            raise RoleError("no such role")
        if any(r["id"] != role_id and r["name"].lower() == name.lower() for r in roles):
            raise RoleError("a role with that name exists")
        role.update(name=name, base=base, grants=sorted(set(grants)))
        conn.execute("UPDATE users SET role = ? WHERE custom_role = ? AND role != 'admin'", (base, role_id))          # users of the role follow its base
    set_setting(conn, KEY, json.dumps(roles))
    conn.commit()
    return role


def delete(conn: sqlite3.Connection, role_id: str) -> None:
    roles = load(conn)
    if not any(r["id"] == role_id for r in roles):
        raise RoleError("no such role")
    set_setting(conn, KEY, json.dumps([r for r in roles if r["id"] != role_id]))
    conn.execute("UPDATE users SET custom_role = NULL WHERE custom_role = ?", (role_id,))          # they keep their base role
    conn.commit()


def assign(conn: sqlite3.Connection, user_id: int, role_id: str | None) -> None:
    """Give a user a custom role (their role becomes its base), or take it away (they keep the base). Never for an administrator, and never for a user limited to groups or sites."""
    user = conn.execute("SELECT role, scope, site_scope FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        raise RoleError("no such user")
    if not role_id:
        conn.execute("UPDATE users SET custom_role = NULL WHERE id = ?", (user_id,))
        conn.commit()
        return
    role = next((r for r in load(conn) if r["id"] == role_id), None)
    if role is None:
        raise RoleError("no such role")
    if user["role"] == "admin":
        raise RoleError("an administrator already may do everything: change the user to viewer or operator first")
    if user["scope"] or user["site_scope"]:
        raise RoleError("a user limited to some groups or remote sites (a customer view) cannot have a custom role")
    conn.execute("UPDATE users SET custom_role = ?, role = ? WHERE id = ?", (role_id, role["base"], user_id))
    conn.commit()


def grants_of(conn: sqlite3.Connection, role_id: str | None) -> tuple[str, ...]:
    """The capabilities a user has now: those of the role, if the licence allows them (Enterprise or the trial), else none (the user is their base role)."""
    if not role_id:
        return ()
    from app import licence

    if not licence.allows(conn, "privileged"):
        return ()
    role = next((r for r in load(conn) if r["id"] == role_id), None)
    return tuple(g for g in (role or {}).get("grants", []) if g in CATALOG)


def allows(grants: tuple[str, ...], method: str, path: str) -> bool:
    return method in ("GET", "HEAD") and any(_COMPILED[g].match(path) for g in grants if g in _COMPILED)


def has(request, capability: str) -> bool:
    principal = getattr(request.state, "user", None)
    return bool(principal) and (principal.is_admin or capability in (principal.grants or ()))
