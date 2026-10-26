"""The credential store: every login Netlens uses for a host (remote desktop, SSH, health monitoring, host probes) lives here once.

An entry has a name, a kind, an owner and a `shared` flag. Entries are private to their owner; an administrator may share one so that other
administrators can use it. The secret is stored encrypted (the whole value is a secret setting, see app/vault.py), never leaves the server and is
never returned by the API: you can replace it or delete the entry, not read it. Every create, change, use and delete is written to the audit log.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
from typing import Any

from app.db import get_setting, set_setting, utcnow

KEY = "credstore.entries"
SYSTEM = "system"                       # the owner of entries that were moved here from the older places
KINDS = {
    "login": ("username", "password", "domain"),                         # a user name and password (RDP, SSH, WinRM, the install login)
    "ssh_key": ("username", "private_key", "passphrase"),                # a private key
}
SECRET_FIELDS = ("password", "private_key", "passphrase")
LIMITS = {"name": 80, "username": 256, "domain": 256, "password": 1024, "private_key": 16384, "passphrase": 1024}


class CredentialError(ValueError):
    pass


def _load(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    try:
        data = json.loads(get_setting(conn, KEY) or "{}")
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _save(conn: sqlite3.Connection, data: dict[str, dict[str, Any]]) -> None:
    set_setting(conn, KEY, json.dumps(data))
    conn.commit()


def _visible(entry: dict[str, Any], user: str) -> bool:
    return entry.get("owner") == user or bool(entry.get("shared"))


def public(entry: dict[str, Any], user: str) -> dict[str, Any]:
    """What the API may show: never a secret, only whether one is set."""
    return {"id": entry["id"], "name": entry["name"], "kind": entry["kind"], "owner": entry["owner"], "shared": bool(entry.get("shared")), "mine": entry["owner"] == user,
            "username": entry.get("username", ""), "domain": entry.get("domain", ""), "has_secret": any(entry.get(f) for f in SECRET_FIELDS),
            "created": entry.get("created"), "updated": entry.get("updated"), "last_used": entry.get("last_used"), "used_for": entry.get("used_for", "")}


def listing(conn: sqlite3.Connection, user: str) -> list[dict[str, Any]]:
    return sorted((public(e, user) for e in _load(conn).values() if _visible(e, user)), key=lambda e: e["name"].lower())


def _clean(kind: str, fields: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in KINDS[kind]:
        if name in fields and fields[name] is not None:
            value = str(fields[name])
            if len(value) > LIMITS[name]:
                raise CredentialError(f"{name} is too long")
            out[name] = value
    return out


def create(conn: sqlite3.Connection, user: str, name: str, kind: str, fields: dict[str, Any], shared: bool = False, owner: str | None = None) -> dict[str, Any]:
    name = (name or "").strip()
    if not name or len(name) > LIMITS["name"]:
        raise CredentialError("give the login a name (up to 80 characters)")
    if kind not in KINDS:
        raise CredentialError("the kind must be one of: " + ", ".join(KINDS))
    data = _load(conn)
    owner = owner or user
    if any(e["owner"] == owner and e["name"].lower() == name.lower() for e in data.values()):
        raise CredentialError("you already have a login with that name")
    values = _clean(kind, fields)
    if kind == "ssh_key" and not values.get("username"):
        raise CredentialError("a user name is needed")
    if not any(values.get(f) for f in SECRET_FIELDS):
        raise CredentialError("a password or a key is needed")
    entry = {"id": secrets.token_hex(6), "name": name, "kind": kind, "owner": owner, "shared": bool(shared), "created": utcnow(), "updated": utcnow(), **values}
    data[entry["id"]] = entry
    _save(conn, data)
    return public(entry, user)


def update(conn: sqlite3.Connection, user: str, cred_id: str, fields: dict[str, Any], is_admin: bool) -> dict[str, Any]:
    """Change a login you own (or, as an administrator, a shared one). A secret that is left out or empty stays as it was."""
    data = _load(conn)
    entry = data.get(cred_id)
    if entry is None or not _visible(entry, user):
        raise CredentialError("no such login")
    if entry["owner"] != user and not is_admin:
        raise CredentialError("only its owner or an administrator can change this login")
    if "name" in fields:
        name = str(fields["name"] or "").strip()
        if not name or len(name) > LIMITS["name"]:
            raise CredentialError("give the login a name (up to 80 characters)")
        if any(e["id"] != cred_id and e["owner"] == entry["owner"] and e["name"].lower() == name.lower() for e in data.values()):
            raise CredentialError("that owner already has a login with that name")
        entry["name"] = name
    for key, value in _clean(entry["kind"], {k: v for k, v in fields.items() if k not in SECRET_FIELDS or v}).items():
        entry[key] = value
    if "shared" in fields:
        entry["shared"] = bool(fields["shared"])
    entry["updated"] = utcnow()
    _save(conn, data)
    return public(entry, user)


def delete(conn: sqlite3.Connection, user: str, cred_id: str, is_admin: bool) -> dict[str, Any]:
    data = _load(conn)
    entry = data.get(cred_id)
    if entry is None or not _visible(entry, user):
        raise CredentialError("no such login")
    if entry["owner"] != user and not is_admin:
        raise CredentialError("only its owner or an administrator can delete this login")
    del data[cred_id]
    _save(conn, data)
    return entry


def resolve(conn: sqlite3.Connection, user: str, cred_id: str, used_for: str = "") -> dict[str, Any]:
    """The full login (secret included) for code on the server, if `user` may use it. Records when and what it was used for."""
    data = _load(conn)
    entry = data.get(cred_id)
    if entry is None or not _visible(entry, user):
        raise CredentialError("no such login")
    entry["last_used"], entry["used_for"] = utcnow(), used_for[:120]
    _save(conn, data)
    return dict(entry)


def peek(conn: sqlite3.Connection, user: str, cred_id: str) -> dict[str, Any] | None:
    """Like resolve, but for showing a name: nothing is recorded as used."""
    entry = _load(conn).get(cred_id)
    return dict(entry) if entry and _visible(entry, user) else None


def peek_bound(conn: sqlite3.Connection, cred_id: str) -> dict[str, Any] | None:
    """For background jobs (a monitor, a probe): the login a person chose to bind to a host. Who may bind it was checked when they did."""
    entry = _load(conn).get(cred_id)
    return dict(entry) if entry else None


def find(conn: sqlite3.Connection, user: str, name: str) -> dict[str, Any] | None:
    for e in _load(conn).values():
        if e["name"].lower() == name.lower() and _visible(e, user):
            return e
    return None


def adopt(conn: sqlite3.Connection, name: str, kind: str, fields: dict[str, Any], used_for: str = "") -> str:
    """Move a login from one of the older places into the store (owned by the system, shared). Returns its id."""
    base, n = name, 1
    taken = {e["name"].lower() for e in _load(conn).values() if e["owner"] == SYSTEM}
    while name.lower() in taken:
        n += 1
        name = f"{base} ({n})"
    made = create(conn, SYSTEM, name, kind, fields, shared=True, owner=SYSTEM)
    data = _load(conn)
    data[made["id"]]["used_for"] = used_for
    _save(conn, data)
    return made["id"]


MIGRATED_KEY = "credstore.migrated"


def migrate_monitors(conn: sqlite3.Connection) -> int:
    """Once: the logins typed into SSH and WinRM health monitors move into the store. Monitors with the same login share one entry (owned by the system, shared), so a changed password is changed once.
    Returns how many monitors now point at a stored login."""
    from app import vault
    from app.hostmetrics import service as hm

    if get_setting(conn, MIGRATED_KEY):
        return 0
    made: dict[tuple, str] = {}
    moved = 0
    for row in conn.execute("SELECT * FROM host_monitors WHERE method IN ('ssh', 'winrm') AND COALESCE(source, '') != 'central'").fetchall():
        secret = hm.raw_secret(conn, row)
        if not secret or secret.get("credential_id") or not secret.get("username"):
            continue
        kind = "ssh_key" if secret.get("private_key") else "login"
        fields = {k: secret[k] for k in ("username", "password", "private_key", "passphrase") if secret.get(k)}
        if not any(fields.get(f) for f in SECRET_FIELDS):
            continue
        fingerprint = (kind, tuple(sorted(fields.items())))
        if fingerprint not in made:
            label = ("WinRM " if row["method"] == "winrm" else "SSH ") + fields["username"]
            try:
                made[fingerprint] = adopt(conn, label, kind, fields, f"moved from the {row['method'].upper()} health monitors")
            except CredentialError:
                continue
        rest = {k: v for k, v in secret.items() if k in ("platform", "auth", "verify_tls")}
        conn.execute("UPDATE host_monitors SET credential = ? WHERE id = ?", (vault.encrypt(conn, json.dumps({**rest, "credential_id": made[fingerprint]})), row["id"]))
        moved += 1
    set_setting(conn, MIGRATED_KEY, utcnow())
    conn.commit()
    return moved
