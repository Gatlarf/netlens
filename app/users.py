"""Users, sessions and API tokens.

The built-in NETLENS_TOKEN keeps working as an administrator without a user record. Users added here have a role:
`admin` (everything) or `viewer` (read-only, see app/auth.py for what a viewer may read).
Passwords are stored as scrypt hashes; session and API tokens only as SHA-256 hashes of random values.
"""

import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

ROLES = ("admin", "viewer")
SESSION_DAYS = 30
SESSION_PREFIX = "s."
TOKEN_PREFIX = "nl_"
MIN_PASSWORD = 8
MAX_PASSWORD = 200
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
_SCRYPT = (2**14, 8, 1)


class UserError(ValueError):
    """A problem the user can fix; the text is shown to them."""


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


def check_password(password: str) -> str:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD:
        raise UserError(f"the password needs at least {MIN_PASSWORD} characters")
    if len(password) > MAX_PASSWORD:
        raise UserError("the password is too long")
    return password


def check_role(role: str) -> str:
    if role not in ROLES:
        raise UserError("the role must be admin or viewer")
    return role


def _digest(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def create_user(conn: sqlite3.Connection, username: str, password: str, role: str) -> int:
    username, password, role = check_username(username), check_password(password), check_role(role)
    try:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role, created) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), role, _iso(_now())),
        )
    except sqlite3.IntegrityError:
        raise UserError("that user name is taken")
    conn.commit()
    return cur.lastrowid


def has_users(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None


def create_first_admin(conn: sqlite3.Connection, username: str, password: str) -> int | None:
    """Create the first administrator, but only if there is no user yet (atomic: two setups at once cannot both win).

    Returns the new id, or None when somebody else was first.
    """
    username, password = check_username(username), check_password(password)
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, role, created) SELECT ?, ?, 'admin', ? WHERE NOT EXISTS (SELECT 1 FROM users)",
        (username, hash_password(password), _iso(_now())),
    )
    conn.commit()
    return cur.lastrowid if cur.rowcount == 1 else None


def get_user(conn: sqlite3.Connection, user_id: int):
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def update_user(conn: sqlite3.Connection, user_id: int, *, role: str | None = None, password: str | None = None, disabled: bool | None = None) -> None:
    if get_user(conn, user_id) is None:
        raise UserError("no such user")
    if role is not None:
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (check_role(role), user_id))
    if password is not None:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(check_password(password)), user_id))
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))  # a new password ends every login
    if disabled is not None:
        conn.execute("UPDATE users SET disabled = ? WHERE id = ?", (1 if disabled else 0, user_id))
        if disabled:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    conn.commit()


def delete_user(conn: sqlite3.Connection, user_id: int) -> None:
    if conn.execute("DELETE FROM users WHERE id = ?", (user_id,)).rowcount == 0:
        raise UserError("no such user")
    conn.commit()  # sessions and tokens go with the user (foreign keys)


def list_users(conn: sqlite3.Connection) -> list[dict]:
    users = []
    for u in conn.execute("SELECT id, username, role, disabled, created, last_login FROM users ORDER BY username COLLATE NOCASE"):
        tokens = conn.execute("SELECT id, name, created, last_used FROM api_tokens WHERE user_id = ? ORDER BY id", (u["id"],)).fetchall()
        users.append({**dict(u), "disabled": bool(u["disabled"]), "tokens": [dict(t) for t in tokens]})
    return users


def login(conn: sqlite3.Connection, username: str, password: str) -> str | None:
    """Check a password; returns a new session cookie value, or None. Takes equally long for unknown users."""
    row = conn.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username or "",)).fetchone()
    ok = verify_password(password or "", row["password_hash"] if row else _DUMMY)
    if not row or not ok or row["disabled"]:
        return None
    secret = secrets.token_urlsafe(32)
    now = _now()
    conn.execute("DELETE FROM sessions WHERE expires < ?", (_iso(now),))
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, created, expires) VALUES (?, ?, ?, ?)",
        (_digest(secret), row["id"], _iso(now), _iso(now + timedelta(days=SESSION_DAYS))),
    )
    conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (_iso(now), row["id"]))
    conn.commit()
    return SESSION_PREFIX + secret


def user_for_session(conn: sqlite3.Connection, cookie: str):
    if not cookie or not cookie.startswith(SESSION_PREFIX):
        return None
    return conn.execute(
        "SELECT u.id, u.username, u.role FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.token_hash = ? AND s.expires > ? AND u.disabled = 0",
        (_digest(cookie[len(SESSION_PREFIX):]), _iso(_now())),
    ).fetchone()


def end_session(conn: sqlite3.Connection, cookie: str | None) -> None:
    if cookie and cookie.startswith(SESSION_PREFIX):
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_digest(cookie[len(SESSION_PREFIX):]),))
        conn.commit()


def create_api_token(conn: sqlite3.Connection, user_id: int, name: str) -> tuple[int, str]:
    """A long-lived token for scripts, Home Assistant or Prometheus. Returns (id, the token, shown only once)."""
    if get_user(conn, user_id) is None:
        raise UserError("no such user")
    name = (name or "").strip()[:60]
    if not name:
        raise UserError("give the token a name, for example Home Assistant")
    secret = TOKEN_PREFIX + secrets.token_urlsafe(32)
    cur = conn.execute(
        "INSERT INTO api_tokens (user_id, name, token_hash, created) VALUES (?, ?, ?, ?)",
        (user_id, name, _digest(secret), _iso(_now())),
    )
    conn.commit()
    return cur.lastrowid, secret


def delete_api_token(conn: sqlite3.Connection, user_id: int, token_id: int) -> None:
    if conn.execute("DELETE FROM api_tokens WHERE id = ? AND user_id = ?", (token_id, user_id)).rowcount == 0:
        raise UserError("no such token")
    conn.commit()


def user_for_token(conn: sqlite3.Connection, bearer: str):
    if not bearer or not bearer.startswith(TOKEN_PREFIX):
        return None
    row = conn.execute(
        "SELECT t.id AS token_id, u.id, u.username, u.role FROM api_tokens t JOIN users u ON u.id = t.user_id "
        "WHERE t.token_hash = ? AND u.disabled = 0",
        (_digest(bearer),),
    ).fetchone()
    if row:
        conn.execute("UPDATE api_tokens SET last_used = ? WHERE id = ?", (_iso(_now()), row["token_id"]))
        conn.commit()
    return row
