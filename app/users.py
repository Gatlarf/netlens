"""Users, sessions and API tokens.

The built-in NETLENS_TOKEN keeps working as an administrator without a user record. Users added here have a role:
`admin` (everything), `operator` (looks and acts: scans, acknowledges, snoozes, maintenance, approves fixes; no settings) or `viewer` (read-only, see
app/auth.py for what each may do). A viewer can be limited to some groups (`scope`), which makes it a customer view: only those devices.
Passwords are stored as scrypt hashes; session and API tokens only as SHA-256 hashes of random values.
"""

import base64
import hashlib
import json
import hmac
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from app.db import IntegrityError as db_IntegrityError, insert_id

ROLES = ("admin", "operator", "viewer")
SESSION_DAYS = 30
SESSION_PREFIX = "s."
TOKEN_PREFIX = "nl_"
MIN_PASSWORD = 8
MAX_PASSWORD = 200
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
_SCRYPT = (2**14, 8, 1)


class UserError(ValueError):
    """A problem the user can fix; the text is shown to them."""


class LastAdminError(UserError):
    """The change would leave no enabled administrator: nobody could sign in to fix it except through the command line."""


LAST_ADMIN = ("This is the last administrator. Make another user an administrator first: without one nobody could manage Netlens "
              "from the web interface (the only way back is the command line).")


def _other_admins(conn: sqlite3.Connection, user_id: int) -> int:
    return conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND id != ?", (user_id,)).fetchone()[0]


def is_last_admin(conn: sqlite3.Connection, user_id: int) -> bool:
    row = conn.execute("SELECT role, disabled FROM users WHERE id = ?", (user_id,)).fetchone()
    return bool(row) and row["role"] == "admin" and not row["disabled"] and _other_admins(conn, user_id) == 0


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    n, r, p = _SCRYPT
    digest = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return "scrypt${}${}${}${}${}".format(n, r, p, base64.b64encode(salt).decode(), base64.b64encode(digest).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest)
        actual = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


_DUMMY = hash_password("not-a-real-password")


def check_username(name: str) -> str:
    name = (name or "").strip()
    if not USERNAME_RE.match(name):
        raise UserError("a user name is 1 to 32 letters, digits, dots, dashes or underscores")
    return name


def check_password(password: str, username: str = "", minimum: int | None = None) -> str:
    need = max(MIN_PASSWORD, minimum or 0)
    if not isinstance(password, str) or len(password) < need:
        raise UserError(f"the password needs at least {need} characters")
    if len(password) > MAX_PASSWORD:
        raise UserError("the password is too long")
    from app import passwords

    try:
        passwords.check(password, username)
    except passwords.WeakPassword as exc:
        raise UserError(str(exc)) from None
    return password


def _policy_minimum(conn) -> int:
    """The longest minimum the sign-in security policy asks for (Enterprise); never below the built-in 8."""
    from app import secpolicy

    return secpolicy.get(conn)["min_password"]


def check_role(role: str) -> str:
    if role not in ROLES:
        raise UserError("the role must be administrator, operator or viewer")
    return role


def _digest(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def check_scope(conn: sqlite3.Connection, scope, role: str) -> str | None:
    """The group ids a user is limited to, as stored JSON (None = no limit). Only a viewer can be limited, and only to groups that exist."""
    if scope in (None, []):
        return None
    if role != "viewer":
        raise UserError("only a viewer can be limited to some groups")
    if not isinstance(scope, list) or any(isinstance(g, bool) or not isinstance(g, int) for g in scope):
        raise UserError("the groups must be a list of group ids")
    known = {r[0] for r in conn.execute("SELECT id FROM device_groups")}
    if any(g not in known for g in scope):
        raise UserError("that group does not exist")
    return json.dumps(sorted(set(scope)))


def parse_scope(value) -> list[int] | None:
    try:
        data = json.loads(value) if value else None
    except ValueError:
        return None
    return [int(g) for g in data] if isinstance(data, list) and data else None


def check_sites(conn: sqlite3.Connection, sites, role: str) -> str | None:
    """The remote sites a viewer is limited to, as stored JSON (None = not limited to sites). Only a viewer, and only sites that exist."""
    if sites in (None, []):
        return None
    if role != "viewer":
        raise UserError("only a viewer can be limited to some remote sites")
    if not isinstance(sites, list) or any(isinstance(g, bool) or not isinstance(g, int) for g in sites):
        raise UserError("the remote sites must be a list of site ids")
    known = {r[0] for r in conn.execute("SELECT id FROM probes")}
    if any(g not in known for g in sites):
        raise UserError("that remote site does not exist")
    return json.dumps(sorted(set(sites)))


def forget_site(conn: sqlite3.Connection, probe_id: int) -> int:
    """A removed remote site leaves the customer logins that listed it. A login that had nothing else to see is disabled (it must not turn into an unlimited one)."""
    changed = 0
    for u in conn.execute("SELECT id, scope, site_scope FROM users WHERE site_scope IS NOT NULL").fetchall():
        sites = parse_scope(u["site_scope"]) or []
        if probe_id not in sites:
            continue
        changed += 1
        rest = [x for x in sites if x != probe_id]
        if rest:
            conn.execute("UPDATE users SET site_scope = ? WHERE id = ?", (json.dumps(rest), u["id"]))
        else:
            conn.execute("UPDATE users SET site_scope = NULL" + (", disabled = 1" if not parse_scope(u["scope"]) else "") + " WHERE id = ?", (u["id"],))
    return changed


def create_user(conn: sqlite3.Connection, username: str, password: str, role: str, scope=None, sites=None) -> int:
    username = check_username(username)
    password, role = check_password(password, username, _policy_minimum(conn)), check_role(role)
    stored_scope = check_scope(conn, scope, role)
    stored_sites = check_sites(conn, sites, role)
    try:
        new_id = insert_id(
            conn,
            "INSERT INTO users (username, password_hash, role, created, scope, site_scope) VALUES (?, ?, ?, ?, ?, ?)",
            (username, hash_password(password), role, _iso(_now()), stored_scope, stored_sites),
        )
    except db_IntegrityError:
        raise UserError("that user name is taken")
    conn.commit()
    return new_id


def has_users(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None


def create_first_admin(conn: sqlite3.Connection, username: str, password: str) -> int | None:
    """Create the first administrator, but only if there is no user yet (atomic: two setups at once cannot both win).

    Returns the new id, or None when somebody else was first.
    """
    username = check_username(username)
    password = check_password(password, username, _policy_minimum(conn))
    new_id = insert_id(
        conn,
        "INSERT INTO users (username, password_hash, role, created) SELECT ?, ?, 'admin', ? WHERE NOT EXISTS (SELECT 1 FROM users)",
        (username, hash_password(password), _iso(_now())),
    )
    conn.commit()
    return new_id


def get_user(conn: sqlite3.Connection, user_id: int):
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


_UNSET = object()


def update_user(conn: sqlite3.Connection, user_id: int, *, role: str | None = None, password: str | None = None, disabled: bool | None = None, scope=_UNSET, sites=_UNSET) -> None:
    current = get_user(conn, user_id)
    if current is None:
        raise UserError("no such user")
    final_role = check_role(role) if role is not None else current["role"]
    if is_last_admin(conn, user_id) and (final_role != "admin" or disabled):
        raise LastAdminError(LAST_ADMIN)             # neither a role change nor disabling may take away the last administrator, not even the user's own
    if scope is not _UNSET:
        conn.execute("UPDATE users SET scope = ? WHERE id = ?", (check_scope(conn, scope, final_role), user_id))
    elif role is not None and final_role != "viewer":
        conn.execute("UPDATE users SET scope = NULL, site_scope = NULL WHERE id = ?", (user_id,))       # a limit only makes sense for a viewer
    if sites is not _UNSET:
        conn.execute("UPDATE users SET site_scope = ? WHERE id = ?", (check_sites(conn, sites, final_role), user_id))
    if role is not None:
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (final_role, user_id))
    if password is not None:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(check_password(password, current["username"], _policy_minimum(conn))), user_id))
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))  # a new password ends every login
    if disabled is not None:
        conn.execute("UPDATE users SET disabled = ? WHERE id = ?", (1 if disabled else 0, user_id))
        if disabled:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    conn.commit()


def delete_user(conn: sqlite3.Connection, user_id: int) -> None:
    if is_last_admin(conn, user_id):
        raise LastAdminError(LAST_ADMIN)
    if conn.execute("DELETE FROM users WHERE id = ?", (user_id,)).rowcount == 0:
        raise UserError("no such user")
    conn.commit()  # sessions and tokens go with the user (foreign keys)


def list_users(conn: sqlite3.Connection) -> list[dict]:
    users = []
    for u in conn.execute("SELECT id, username, role, custom_role, cert_identity, disabled, created, last_login, scope, site_scope, totp_enabled, webauthn_enabled, break_glass FROM users ORDER BY LOWER(username)"):
        tokens = conn.execute("SELECT id, name, created, last_used, readonly, assistant, expires, allowed_ips FROM api_tokens WHERE user_id = ? ORDER BY id", (u["id"],)).fetchall()
        users.append({**{k: v for k, v in dict(u).items() if k not in ("scope", "site_scope", "totp_enabled", "webauthn_enabled", "break_glass")}, "scope": parse_scope(u["scope"]), "sites": parse_scope(u["site_scope"]), "disabled": bool(u["disabled"]), "totp": bool(u["totp_enabled"]), "webauthn": bool(u["webauthn_enabled"]), "second_factor": bool(u["totp_enabled"] or u["webauthn_enabled"]), "break_glass": bool(u["break_glass"]), "last_admin": u["role"] == "admin" and not u["disabled"] and _other_admins(conn, u["id"]) == 0, "tokens": [{**dict(t), "readonly": bool(t["readonly"])} for t in tokens]})
    return users


def authenticate(conn: sqlite3.Connection, username: str, password: str):
    """The user row when the user name and password are right and the account is not disabled, else None. Takes equally long for unknown users. This is only the
    FIRST factor: a user whose second factor is on (app/totp.py) still has to give a code before a session is started."""
    row = conn.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username or "",)).fetchone()
    ok = verify_password(password or "", row["password_hash"] if row else _DUMMY)
    if not row or not ok or row["disabled"]:
        return None
    return row


def login(conn: sqlite3.Connection, username: str, password: str) -> str | None:
    """Check a password; returns a new session cookie value, or None. A user with a second factor never gets a session from here: the login goes through
    `authenticate`, the challenge and the code (so no caller can skip the second factor by accident)."""
    row = authenticate(conn, username, password)
    if row is None or row["totp_enabled"] or row["webauthn_enabled"]:
        return None
    return start_session(conn, row["id"])


def start_session(conn: sqlite3.Connection, user_id: int, ip: str = "", user_agent: str = "", method: str = "password") -> str:
    """A new session for a user who has proved who they are (a password and a code, or the identity provider); returns the cookie value.
    `method` is how (password, totp, recovery, oidc): the step-up of privileged actions looks at it and at `auth_at`. The oldest sessions end when the policy
    limits how many a user may have."""
    from app import secpolicy

    secret = secrets.token_urlsafe(32)
    now = _now()
    conn.execute("DELETE FROM sessions WHERE expires < ?", (_iso(now),))
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, created, expires, last_seen, ip, user_agent, auth_at, auth_method, seq) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, (SELECT COALESCE(MAX(seq), 0) + 1 FROM sessions))",
        (_digest(secret), user_id, _iso(now), _iso(now + timedelta(days=SESSION_DAYS)), _iso(now), (ip or "")[:60], re.sub(r"[\x00-\x1f\x7f]", "", user_agent or "")[:200], _iso(now), method),
    )
    limit = secpolicy.get(conn)["max_sessions"]
    if limit:
        old = [r["token_hash"] for r in conn.execute("SELECT token_hash FROM sessions WHERE user_id = ? ORDER BY seq DESC", (user_id,)).fetchall()][limit:]
        for h in old:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (h,))
    conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (_iso(now), user_id))
    conn.commit()
    return SESSION_PREFIX + secret


def user_for_session(conn: sqlite3.Connection, cookie: str):
    """The user of a session cookie, or None: unknown, ended, disabled, past its end, or past the idle or absolute limit of the policy. Writes `last_seen` at most once a minute."""
    from app import secpolicy

    if not cookie or not cookie.startswith(SESSION_PREFIX):
        return None
    digest = _digest(cookie[len(SESSION_PREFIX):])
    row = conn.execute(
        "SELECT u.id, u.username, u.role, u.custom_role, u.break_glass, u.scope, u.site_scope, u.created AS user_created, u.oidc_sub, u.totp_enabled, u.webauthn_enabled, s.created AS session_created, s.last_seen, s.auth_at, s.auth_method "
        "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires > ? AND u.disabled = 0",
        (digest, _iso(_now())),
    ).fetchone()
    if row is None:
        return None
    pol = secpolicy.get(conn)
    now = _now()
    created = _parse_iso(row["session_created"]) or now
    seen = _parse_iso(row["last_seen"]) or created
    if (pol["absolute_hours"] and now - created > timedelta(hours=pol["absolute_hours"])) or (pol["idle_minutes"] and now - seen > timedelta(minutes=pol["idle_minutes"])):
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (digest,))
        conn.commit()
        return None
    if now - seen > timedelta(seconds=60):
        conn.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (_iso(now), digest))
        conn.commit()
    return row


def _parse_iso(text) -> datetime | None:
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) if text else None
    except ValueError:
        return None


def session_id(token_hash: str) -> str:
    return token_hash[:16]


def list_sessions(conn: sqlite3.Connection, user_id: int, current_cookie: str | None = None) -> list[dict]:
    """The sessions of a user (never the secret): an id that can end it, when it started and was last seen, from where, with what."""
    current = _digest(current_cookie[len(SESSION_PREFIX):]) if current_cookie and current_cookie.startswith(SESSION_PREFIX) else None
    out = []
    for r in conn.execute("SELECT token_hash, created, last_seen, ip, user_agent, auth_method FROM sessions WHERE user_id = ? AND expires > ? ORDER BY COALESCE(last_seen, created) DESC", (user_id, _iso(_now()))):
        out.append({"id": session_id(r["token_hash"]), "created": r["created"], "last_seen": r["last_seen"] or r["created"], "ip": r["ip"] or "", "user_agent": r["user_agent"] or "",
                    "method": r["auth_method"] or "", "current": r["token_hash"] == current})
    return out


def end_sessions(conn: sqlite3.Connection, user_id: int, sid: str | None = None, keep_cookie: str | None = None) -> int:
    """End one session (by its id), or all of a user's sessions except `keep_cookie`. Returns how many ended."""
    keep = _digest(keep_cookie[len(SESSION_PREFIX):]) if keep_cookie and keep_cookie.startswith(SESSION_PREFIX) else None
    n = 0
    for r in conn.execute("SELECT token_hash FROM sessions WHERE user_id = ?", (user_id,)).fetchall():
        if (sid is None or session_id(r["token_hash"]) == sid) and r["token_hash"] != keep:
            n += conn.execute("DELETE FROM sessions WHERE token_hash = ?", (r["token_hash"],)).rowcount
    conn.commit()
    return n


def end_session(conn: sqlite3.Connection, cookie: str | None) -> None:
    if cookie and cookie.startswith(SESSION_PREFIX):
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_digest(cookie[len(SESSION_PREFIX):]),))
        conn.commit()


def _check_ips(allowed) -> str | None:
    """A list of addresses or networks (CIDR) a token may be used from, stored as text; None = anywhere."""
    import ipaddress

    if not allowed:
        return None
    if not isinstance(allowed, (list, tuple)) or len(allowed) > 20:
        raise UserError("the allowed addresses are a list of at most 20 addresses or networks")
    out = []
    for item in allowed:
        try:
            out.append(str(ipaddress.ip_network(str(item).strip(), strict=False)))
        except ValueError:
            raise UserError(f"'{item}' is not an IP address or network like 10.0.0.0/24") from None
    return ",".join(out)


def create_api_token(conn: sqlite3.Connection, user_id: int, name: str, readonly: bool = False, assistant: str | None = None,
                     expires_days: int | None = None, allowed_ips=None) -> tuple[int, str]:
    """A long-lived token for scripts, Home Assistant or Prometheus. Returns (id, the token, shown only once). The policy may cap its life (`api_token_max_days`); a token
    may also be limited to some addresses."""
    from app import secpolicy

    if get_user(conn, user_id) is None:
        raise UserError("no such user")
    name = (name or "").strip()[:60]
    if not name:
        raise UserError("give the token a name, for example Home Assistant")
    longest = secpolicy.get(conn)["api_token_max_days"]
    if expires_days is not None and (isinstance(expires_days, bool) or not isinstance(expires_days, int) or not 1 <= expires_days <= 3650):
        raise UserError("the life of a token is 1 to 3650 days")
    if longest:
        if expires_days is None:
            expires_days = longest
        if expires_days > longest:
            raise UserError(f"the policy limits the life of a token to {longest} days")
    ips = _check_ips(allowed_ips)
    secret = TOKEN_PREFIX + secrets.token_urlsafe(32)
    new_id = insert_id(
        conn,
        "INSERT INTO api_tokens (user_id, name, token_hash, created, readonly, assistant, expires, allowed_ips) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (user_id, name, _digest(secret), _iso(_now()), 1 if (readonly or assistant == "read") else 0, assistant, _iso(_now() + timedelta(days=expires_days)) if expires_days else None, ips),
    )
    conn.commit()
    return new_id, secret


def delete_api_token(conn: sqlite3.Connection, user_id: int, token_id: int) -> None:
    if conn.execute("DELETE FROM api_tokens WHERE id = ? AND user_id = ?", (token_id, user_id)).rowcount == 0:
        raise UserError("no such token")
    conn.commit()


def user_for_token(conn: sqlite3.Connection, bearer: str, ip: str = ""):
    """The user and token of a bearer token, or None: unknown, disabled, past its end, or used from an address it is not allowed from."""
    import ipaddress

    if not bearer or not bearer.startswith(TOKEN_PREFIX):
        return None
    row = conn.execute(
        "SELECT t.id AS token_id, t.readonly, t.assistant, t.name AS token_name, t.expires, t.allowed_ips, u.id, u.username, u.role, u.custom_role, u.break_glass, u.scope, u.site_scope FROM api_tokens t JOIN users u ON u.id = t.user_id "
        "WHERE t.token_hash = ? AND u.disabled = 0",
        (_digest(bearer),),
    ).fetchone()
    if row is None:
        return None
    if row["expires"] and (_parse_iso(row["expires"]) or _now()) <= _now():
        return None
    if row["allowed_ips"]:
        try:
            addr = ipaddress.ip_address((ip or "").strip())
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
                addr = addr.ipv4_mapped
            ok = any(addr.version == n.version and addr in n for n in (ipaddress.ip_network(x, strict=False) for x in row["allowed_ips"].split(",") if x))
        except ValueError:
            ok = False
        if not ok:
            return None
    conn.execute("UPDATE api_tokens SET last_used = ? WHERE id = ?", (_iso(_now()), row["token_id"]))
    conn.commit()
    return row


def mark_auth(conn: sqlite3.Connection, cookie: str | None, method: str | None = None) -> bool:
    """A session has proved the user's identity again (step-up): `auth_at` is now."""
    if not cookie or not cookie.startswith(SESSION_PREFIX):
        return False
    n = conn.execute("UPDATE sessions SET auth_at = ?" + (", auth_method = ?" if method else "") + " WHERE token_hash = ?",
                     (_iso(_now()),) + ((method,) if method else ()) + (_digest(cookie[len(SESSION_PREFIX):]),)).rowcount
    conn.commit()
    return bool(n)
