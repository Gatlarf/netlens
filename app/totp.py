"""A second factor for local accounts: time-based one-time passwords (TOTP, RFC 6238).

Netlens is **not** a TOTP provider. It only *verifies* codes that the user's own authenticator makes (Google or Microsoft Authenticator, Authy, 1Password, a hardware
token ...): the standard algorithm (HMAC-SHA1, 6 digits, 30 seconds), standard library only.

What makes it safe:
  * the secret is 160 random bits, stored encrypted with the vault key (app/vault.py), and shown once, at enrolment;
  * a code works **once**: the newest accepted time step is stored per user (updated atomically), so an observed code cannot be replayed;
  * a code is compared in constant time against every step of the allowed window;
  * the second step of a login is a single-use **challenge**, not a session: five wrong codes end it;
  * ten recovery codes (80 bits each) are stored only as hashes and work once.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
import struct
import threading
import time
import urllib.parse

from app import vault
from app.db import utcnow

STEP = 30
DIGITS = 6
WINDOW = 1                 # one step either side: a phone clock a few seconds off still works
SECRET_BYTES = 20
RECOVERY_COUNT = 10
CHALLENGE_SECONDS = 300
CHALLENGE_TRIES = 5
_RECOVERY_RE = re.compile(r"^[a-z2-7]{16}$")


class TotpError(ValueError):
    """A problem the user can fix; the text is shown to them."""


# ----------------------------------------------------------------------------- the algorithm
def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    text = re.sub(r"[\s-]", "", secret or "").upper()
    return base64.b32decode(text + "=" * (-len(text) % 8))


def hotp(key: bytes, counter: int, digits: int = DIGITS) -> str:
    """RFC 4226."""
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    number = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(number).zfill(digits)


def counter_at(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // STEP)


def code_at(secret: str, now: float | None = None) -> str:
    return hotp(_key(secret), counter_at(now))


def normalise_code(code: str) -> str | None:
    text = re.sub(r"[\s-]", "", str(code or ""))
    return text if re.fullmatch(r"\d{%d}" % DIGITS, text) else None


def verify(secret: str, code: str, last_counter: int = 0, now: float | None = None, window: int = WINDOW) -> int | None:
    """The time step the code belongs to, or None. A step that is not newer than `last_counter` is refused (a code is used once). Every step of the window is compared,
    in constant time, whatever matches."""
    wanted = normalise_code(code)
    if wanted is None:
        return None
    key = _key(secret)
    current = counter_at(now)
    found = None
    for c in range(current - window, current + window + 1):
        if hmac.compare_digest(hotp(key, c), wanted) and c > last_counter and (found is None or c > found):
            found = c
    return found


def otpauth_uri(secret: str, account: str, issuer: str = "Netlens") -> str:
    label = urllib.parse.quote(f"{issuer}:{account}", safe="")
    return f"otpauth://totp/{label}?secret={secret}&issuer={urllib.parse.quote(issuer, safe='')}&algorithm=SHA1&digits={DIGITS}&period={STEP}"


# ----------------------------------------------------------------------------- recovery codes
def _recovery_hash(code: str) -> str:
    return hashlib.sha256(re.sub(r"[\s-]", "", code or "").lower().encode()).hexdigest()


def _new_recovery_code() -> str:
    raw = base64.b32encode(secrets.token_bytes(10)).decode().rstrip("=").lower()          # 80 bits = 16 characters
    return "-".join(raw[i:i + 4] for i in range(0, 16, 4))


def normalise_recovery(code: str) -> str | None:
    text = re.sub(r"[\s-]", "", str(code or "")).lower()
    return text if _RECOVERY_RE.match(text) else None


# ----------------------------------------------------------------------------- per user state (database)
def _row(conn: sqlite3.Connection, user_id: int):
    return conn.execute("SELECT id, username, totp_secret, totp_enabled, webauthn_enabled, totp_counter, totp_since FROM users WHERE id = ?", (user_id,)).fetchone()


def enabled(row) -> bool:
    try:
        return bool(row["totp_enabled"])
    except (KeyError, IndexError, TypeError):
        return False


def status(conn: sqlite3.Connection, user_id: int) -> dict:
    row = _row(conn, user_id)
    if row is None:
        raise TotpError("no such user")
    left = conn.execute("SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = ? AND used = 0", (user_id,)).fetchone()[0]
    return {"enabled": bool(row["totp_enabled"]), "since": row["totp_since"], "recovery_left": left if (row["totp_enabled"] or row["webauthn_enabled"]) else 0,
            "pending": bool(row["totp_secret"] and not row["totp_enabled"]), "webauthn": bool(row["webauthn_enabled"])}


def begin(conn: sqlite3.Connection, user_id: int) -> tuple[str, str]:
    """Start (or restart) enrolment: a new secret that does not count until a correct code confirms it. Returns (secret, otpauth link)."""
    row = _row(conn, user_id)
    if row is None:
        raise TotpError("no such user")
    if row["totp_enabled"]:
        raise TotpError("a second factor is already set up; remove it first to set up another")
    secret = new_secret()
    conn.execute("UPDATE users SET totp_secret = ?, totp_enabled = 0, totp_counter = 0 WHERE id = ?", (vault.encrypt(conn, secret), user_id))
    conn.commit()
    return secret, otpauth_uri(secret, row["username"])


def _secret_of(conn: sqlite3.Connection, row) -> str | None:
    if not row["totp_secret"]:
        return None
    try:
        return vault.decrypt(conn, row["totp_secret"])
    except vault.VaultError:
        return None


def confirm(conn: sqlite3.Connection, user_id: int, code: str, now: float | None = None) -> list[str]:
    """A correct code from the new authenticator switches the factor on. Returns the recovery codes (shown once)."""
    row = _row(conn, user_id)
    if row is None or not row["totp_secret"] or row["totp_enabled"]:
        raise TotpError("start the set-up first")
    secret = _secret_of(conn, row)
    counter = verify(secret, code, 0, now) if secret else None
    if counter is None:
        raise TotpError("that code is not right: check the code in your authenticator and that the clock of your phone is correct")
    conn.execute("UPDATE users SET totp_enabled = 1, totp_counter = ?, totp_since = ? WHERE id = ?", (counter, utcnow(), user_id))
    conn.commit()
    return new_recovery_codes(conn, user_id)


def new_recovery_codes(conn: sqlite3.Connection, user_id: int) -> list[str]:
    """A new set of ten codes; the old set stops working."""
    codes = [_new_recovery_code() for _ in range(RECOVERY_COUNT)]
    conn.execute("DELETE FROM user_recovery_codes WHERE user_id = ?", (user_id,))
    conn.executemany("INSERT INTO user_recovery_codes (user_id, code_hash, created, used) VALUES (?,?,?,0)", [(user_id, _recovery_hash(c), utcnow()) for c in codes])
    conn.commit()
    return codes


def remove(conn: sqlite3.Connection, user_id: int) -> None:
    """Switch the factor off and forget its secret and recovery codes (the user, an administrator, or the console)."""
    conn.execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_counter = 0, totp_since = NULL WHERE id = ?", (user_id,))
    conn.execute("DELETE FROM user_recovery_codes WHERE user_id = ?", (user_id,))
    conn.commit()


def check_second_factor(conn: sqlite3.Connection, user_id: int, code: str, now: float | None = None) -> str | None:
    """Verify a code or a recovery code for a user whose factor is on. Returns "totp", "recovery" or None. Each code works once; the claim on a time step or a
    recovery code is a single conditional UPDATE, so two requests at the same moment cannot both use it."""
    row = _row(conn, user_id)
    if row is None or not (row["totp_enabled"] or row["webauthn_enabled"]):
        return None
    secret = _secret_of(conn, row) if row["totp_enabled"] else None          # a user with only security keys still has recovery codes
    if secret:
        counter = verify(secret, code, row["totp_counter"], now)
        if counter is not None:
            claimed = conn.execute("UPDATE users SET totp_counter = ? WHERE id = ? AND totp_counter < ?", (counter, user_id, counter)).rowcount
            conn.commit()
            if claimed:
                return "totp"
            return None
    rec = normalise_recovery(code)
    if rec is not None:
        used = conn.execute("UPDATE user_recovery_codes SET used = 1 WHERE user_id = ? AND code_hash = ? AND used = 0", (user_id, _recovery_hash(rec))).rowcount
        conn.commit()
        if used:
            return "recovery"
    return None


# ----------------------------------------------------------------------------- the challenge between the password and the code
class Challenges:
    """Between a correct password and a correct code there is no session, only one of these: random, single use, five minutes, five tries. Kept in memory: a
    restart only means the user types the password again."""

    def __init__(self) -> None:
        self._items: dict[str, dict] = {}
        self._lock = threading.Lock()

    def issue(self, user_id: int, username: str, now: float | None = None) -> str:
        now = time.time() if now is None else now
        token = secrets.token_urlsafe(32)
        with self._lock:
            if len(self._items) > 1000:
                self._items = {k: v for k, v in self._items.items() if v["expires"] > now}
            self._items[token] = {"user_id": user_id, "username": username, "expires": now + CHALLENGE_SECONDS, "tries": 0}
        return token

    def get(self, token: str, now: float | None = None) -> dict | None:
        now = time.time() if now is None else now
        with self._lock:
            item = self._items.get(token or "")
            if item is None or item["expires"] <= now:
                self._items.pop(token or "", None)
                return None
            return dict(item)

    def fail(self, token: str) -> int:
        """Count a wrong code; returns the tries left (the challenge ends at zero)."""
        with self._lock:
            item = self._items.get(token or "")
            if item is None:
                return 0
            item["tries"] += 1
            left = CHALLENGE_TRIES - item["tries"]
            if left <= 0:
                self._items.pop(token, None)
                return 0
            return left

    def done(self, token: str) -> None:
        with self._lock:
            self._items.pop(token or "", None)
