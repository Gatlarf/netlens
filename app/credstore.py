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

from app import dbengine
from app.db import get_setting, set_setting, utcnow

KEY = "credstore.entries"
SYSTEM = "system"                       # the owner of entries that were moved here from the older places
KINDS = {
    "login": ("username", "password", "domain"),                         # a user name and password (RDP, SSH, WinRM, the install login)
    "ssh_key": ("username", "private_key", "passphrase"),                # a private key
    # Enterprise: the login lives in the customer's PAM; only where it is, and how Netlens signs in to the PAM, is stored here (app/pam)
    "pam": ("provider", "url", "namespace", "mount", "kv_version", "path", "approle_mount", "role_id", "secret_id", "token", "ca_cert", "username", "domain",
            "username_field", "password_field", "key_field", "passphrase_field", "domain_field", "reason_required",
            "appid", "safe", "folder", "object", "account_user", "account_address", "content_as", "client_cert", "client_key",
            "secret_id_ref", "app_user", "app_password", "app_domain", "api_key", "run_as", "run_as_password", "ps_system", "ps_account"),
}
SECRET_FIELDS = ("password", "private_key", "passphrase", "token", "secret_id", "client_key", "app_password", "api_key", "run_as_password")
BOOL_FIELDS = ("reason_required",)
LIMITS = {"name": 80, "username": 256, "domain": 256, "password": 1024, "private_key": 16384, "passphrase": 1024, "provider": 40, "url": 512, "namespace": 200, "mount": 200,
          "kv_version": 2, "path": 512, "approle_mount": 100, "role_id": 200, "secret_id": 512, "token": 4096, "ca_cert": 16384, "username_field": 100, "password_field": 100,
          "key_field": 100, "passphrase_field": 100, "domain_field": 100,
          "appid": 200, "safe": 200, "folder": 200, "object": 200, "account_user": 256, "account_address": 256, "content_as": 20, "client_cert": 16384, "client_key": 16384,
          "secret_id_ref": 12, "app_user": 256, "app_password": 1024, "app_domain": 100, "api_key": 512, "run_as": 256, "run_as_password": 1024, "ps_system": 256, "ps_account": 256}


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
            "created": entry.get("created"), "updated": entry.get("updated"), "last_used": entry.get("last_used"), "used_for": entry.get("used_for", "")} | _pam_public(entry)


def _pam_public(entry: dict[str, Any]) -> dict[str, Any]:
    """For a `pam` entry: where the secret lives (no secret), and how the latest check-out went."""
    if entry.get("kind") != "pam":
        return {}
    from app import pam

    provider = pam.PROVIDERS.get(entry.get("provider", ""))
    base = {"provider": entry.get("provider", ""), "provider_name": pam.providers().get(entry.get("provider", ""), entry.get("provider", "")), "url": entry.get("url", ""),
            "where": provider.where(entry) if provider else "", "reason_required": bool(entry.get("reason_required")), "last": pam.last_status(entry["id"])}
    return {"pam": {**base, **(provider.public(entry) if provider else {})}}


def listing(conn: sqlite3.Connection, user: str) -> list[dict[str, Any]]:
    return sorted((public(e, user) for e in _load(conn).values() if _visible(e, user)), key=lambda e: e["name"].lower())


def _clean(kind: str, fields: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in KINDS[kind]:
        if name in BOOL_FIELDS and name in fields:
            out[name] = bool(fields[name])
        elif name in fields and fields[name] is not None:
            value = str(fields[name])
            if len(value) > LIMITS[name]:
                raise CredentialError(f"{name} is too long")
            out[name] = value
    return out


def _check_pam(values: dict[str, Any]) -> None:
    from app import pam

    try:
        pam.validate(values)
    except pam.PamError as exc:
        raise CredentialError(str(exc)) from None


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
    if kind == "pam":
        _check_pam(values)
    elif not any(values.get(f) for f in SECRET_FIELDS):
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
    changes = _clean(entry["kind"], {k: v for k, v in fields.items() if k not in SECRET_FIELDS or v})
    if entry["kind"] == "pam":
        if fields.get("token") and not fields.get("secret_id"):
            entry.pop("secret_id", None)                       # switching to a token: the old AppRole secret goes
        if (fields.get("role_id") or fields.get("secret_id")) and not fields.get("token"):
            entry.pop("token", None)
        _check_pam({**entry, **changes})
    for key, value in changes.items():
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


def _login_from_pam(conn: sqlite3.Connection, entry: dict[str, Any], user: str, purpose: str, reason: str, interactive: bool, device: str = "") -> dict[str, Any]:
    """Ask the customer's PAM for the login of a `pam` entry. Fail closed: any problem is a CredentialError with a sentence. One audit line per check-out (a
    background job that repeats it, such as a monitor, writes one line an hour per entry and purpose, and always one for a refusal). The secret is returned to the
    caller and kept nowhere else."""
    from app import audit, pam

    ctx = pam.Context(purpose=purpose, user=user or "netlens", reason=reason, device=device)
    try:
        fetched = pam.checkout(entry, ctx, interactive)
    except pam.PamError as exc:
        audit.record(conn, user or "netlens", "", "", "PAM", "/pam/checkout", 403, pam.audit_line(entry, ctx, "", False, str(exc)))
        raise CredentialError(str(exc)) from None
    values = dict(fetched.values)
    if getattr(pam.PROVIDERS.get(entry.get("provider", "")), "holds", False):
        pam.release_later(fetched)                  # checked out: checked in after the login attempt, not before
    else:
        fetched.done()
    if interactive or _due(entry["id"], purpose):
        audit.record(conn, user or "netlens", "", "", "PAM", "/pam/checkout", 200, pam.audit_line(entry, ctx, fetched.lease, True))
    return {"id": entry["id"], "name": entry["name"], "kind": "ssh_key" if values.get("private_key") and not values.get("password") else "login", **values}


_AUDITED: dict[tuple[str, str], float] = {}


def _due(cred_id: str, purpose: str, every_s: float = 3600.0) -> bool:
    import time

    now, key = time.time(), (cred_id, purpose[:60])
    if now - _AUDITED.get(key, 0.0) < every_s:
        return False
    if len(_AUDITED) > 5000:
        _AUDITED.clear()
    _AUDITED[key] = now
    return True


def resolve(conn: sqlite3.Connection, user: str, cred_id: str, used_for: str = "", reason: str = "", device: str = "") -> dict[str, Any]:
    """The full login (secret included) for code on the server, if `user` may use it. Records when and what it was used for. A login in the customer's PAM is fetched
    now (and needs a reason if the entry says so); this is for a person's action."""
    data = _load(conn)
    entry = data.get(cred_id)
    if entry is None or not _visible(entry, user):
        raise CredentialError("no such login")
    if entry.get("kind") == "pam":
        found = _login_from_pam(conn, entry, user, used_for or "use", reason, True, device)
        entry["last_used"], entry["used_for"] = utcnow(), used_for[:120]
        _save(conn, data)
        return found
    entry["last_used"], entry["used_for"] = utcnow(), used_for[:120]
    _save(conn, data)
    return dict(entry)


def pam_problems(conn: sqlite3.Connection) -> list[dict[str, str]]:
    """Logins in the customer's PAM whose latest check-out was refused or failed (memory of this run; nothing secret). For the dashboard, the answers and the reports."""
    from app import pam

    out = []
    for entry in _load(conn).values():
        if entry.get("kind") == "pam":
            last = pam.last_status(entry["id"])
            if last and not last["ok"]:
                out.append({"id": entry["id"], "text": f"The PAM system did not hand out the login \"{entry['name']}\": {last['message']}"})
    return sorted(out, key=lambda p: p["text"])


async def resolve_async(conn: sqlite3.Connection, user: str, cred_id: str, used_for: str = "", reason: str = "", device: str = "") -> dict[str, Any]:
    """`resolve` for code that runs on the event loop. A login in the PAM is a network call, so it runs in a thread with a connection of its own; the others are as before."""
    import asyncio

    entry = _load(conn).get(cred_id)
    path = dbengine.database_path(conn)
    if entry is None or entry.get("kind") != "pam" or not path:
        return resolve(conn, user, cred_id, used_for, reason, device)
    from app.db import connect

    def work() -> dict[str, Any]:
        own = connect(path)
        try:
            return resolve(own, user, cred_id, used_for, reason, device)
        finally:
            own.close()
    return await asyncio.to_thread(work)


def peek(conn: sqlite3.Connection, user: str, cred_id: str) -> dict[str, Any] | None:
    """Like resolve, but for showing a name: nothing is recorded as used and the PAM is not asked."""
    entry = _load(conn).get(cred_id)
    return dict(entry) if entry and _visible(entry, user) else None


def peek_bound(conn: sqlite3.Connection, cred_id: str) -> dict[str, Any] | None:
    """For showing the login a person bound to a host (its name, its user): never the PAM. To use it, see use_bound."""
    entry = _load(conn).get(cred_id)
    return dict(entry) if entry else None


def use_bound(conn: sqlite3.Connection, cred_id: str, purpose: str, device: str = "") -> dict[str, Any] | None:
    """For background jobs (a monitor, a probe): the login a person chose to bind to a host, with its secret. Who may bind it was checked when they did. A login in the
    PAM is fetched now and may not need a reason (a job cannot give one). None when the login is gone."""
    entry = _load(conn).get(cred_id)
    if entry is None:
        return None
    if entry.get("kind") == "pam":
        return _login_from_pam(conn, entry, "", purpose, "", False, device)
    return dict(entry)


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
