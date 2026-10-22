"""Encryption of the stored secrets (plugin passwords and tokens, notification channel secrets, saved credentials).

The values of the settings that hold secrets are encrypted with AES-256-GCM before they are written to the database and
decrypted when they are read, so a copy of the database or of a backup file does not give anyone the passwords in it.

The key is 32 random bytes. It is taken from the environment variable NETLENS_SECRET_KEY when that is set (then it lives outside the
data volume, which is the stronger arrangement), otherwise from the file `secret.key` next to the database (created on first use,
readable by the Netlens user only). Backups contain the encrypted values but not the key: keep a copy of it (Settings -> Backup &
restore shows it to an administrator on the local network). Without the right key the encrypted values cannot be read; Netlens then
keeps working, the affected passwords are simply empty and have to be entered again.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
import secrets
import sqlite3
import threading
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import dbengine

log = logging.getLogger(__name__)
PREFIX = "enc:v1:"
KEY_FILE = "secret.key"
ENV_KEY = "NETLENS_SECRET_KEY"
_AAD = b"netlens-secret-v1"
_PLUGIN_CONFIG = re.compile(r"^plugin\.[A-Za-z0-9_-]+$")          # a plugin's saved configuration (not its .status, .data ...)
_PROBE_CONFIG = re.compile(r"^probe\.config\.\d+$")              # what the central Netlens will have a remote site check (holds logins)
SECRET_KEYS = frozenset({"notify.channels", "remote.credentials", "central.link", "engineer.api_key", "oidc.client_secret", "cvecheck.api_key"})

_lock = threading.Lock()
_keys: dict[str, bytes] = {}
_unreadable: dict[str, int] = {}


class VaultError(Exception):
    """A stored value could not be decrypted (the key is missing or not the one it was written with)."""


def is_secret_key(key: str) -> bool:
    return key in SECRET_KEYS or bool(_PLUGIN_CONFIG.match(key)) or bool(_PROBE_CONFIG.match(key))


def is_encrypted(value: str | None) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def _db_file(conn: sqlite3.Connection) -> str:
    from app.db import main_file

    return main_file(conn)


def parse_key(text: str) -> bytes:
    """The raw 32 bytes from a key given as base64 (what the key file holds) or as hex."""
    text = (text or "").strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", text):
        return bytes.fromhex(text)
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError):
        raw = b""
    if len(raw) != 32:
        raise ValueError("that is not a Netlens encryption key (32 bytes, as base64 or hex)")
    return raw


def encode_key(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def key_source(conn: sqlite3.Connection) -> str:
    """"env" (NETLENS_SECRET_KEY), "file" (secret.key next to the database) or "memory" (a database without a file: tests)."""
    if os.environ.get(ENV_KEY, "").strip():
        return "env"
    return "file" if _db_file(conn) else "memory"


def _key(conn: sqlite3.Connection) -> bytes:
    path = _db_file(conn)
    env = os.environ.get(ENV_KEY, "").strip()
    cache_id = f"env:{env}" if env else f"file:{path}"
    with _lock:
        if cache_id in _keys:
            return _keys[cache_id]
        if env:
            try:
                key = parse_key(env)
            except ValueError:
                key = hashlib.scrypt(env.encode(), salt=b"netlens-secret-key", n=2 ** 14, r=8, p=1, dklen=32)   # a passphrase works as well
        elif path:
            key_path = Path(path).parent / KEY_FILE
            if key_path.exists():
                key = parse_key(key_path.read_text())
            else:
                key = secrets.token_bytes(32)
                fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as fh:
                    fh.write(encode_key(key) + "\n")
                log.info("created the encryption key for stored passwords: %s", key_path)
        else:
            key = _keys.setdefault("memory", secrets.token_bytes(32))
        _keys[cache_id] = key
        return key


def forget_cached_key(conn: sqlite3.Connection) -> None:
    with _lock:
        _keys.pop(f"file:{_db_file(conn)}", None)
        _unreadable.pop(_db_file(conn), None)


def encrypt(conn: sqlite3.Connection, text: str) -> str:
    if is_encrypted(text):
        return text
    nonce = secrets.token_bytes(12)
    return PREFIX + base64.b64encode(nonce + AESGCM(_key(conn)).encrypt(nonce, text.encode(), _AAD)).decode()


def decrypt(conn: sqlite3.Connection, value: str) -> str:
    if not is_encrypted(value):
        return value
    try:
        raw = base64.b64decode(value[len(PREFIX):])
        return AESGCM(_key(conn)).decrypt(raw[:12], raw[12:], _AAD).decode()
    except (InvalidTag, ValueError, UnicodeDecodeError, OSError):
        raise VaultError("the stored value cannot be decrypted with the current key") from None


def note_unreadable(conn: sqlite3.Connection, key: str) -> None:
    path = _db_file(conn)
    with _lock:
        first = _unreadable.get(path, 0) == 0
        _unreadable[path] = _unreadable.get(path, 0) + 1
    if first:
        log.warning("stored passwords cannot be decrypted (secret key missing or different); enter them again or restore secret.key (first: %s)", key)


# ---------- recovery passphrase: the key, wrapped with a passphrase, kept inside the database (so inside every backup)
RECOVERY_KEY = "vault.recovery"
_RECOVERY_AAD = b"netlens-recovery-v1"


def _kek(passphrase: str, salt: bytes) -> bytes:
    return hashlib.scrypt(passphrase.encode(), salt=salt, n=2 ** 15, r=8, p=1, dklen=32, maxmem=96 * 1024 * 1024)


def has_recovery(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT 1 FROM settings WHERE key = ?", (RECOVERY_KEY,)).fetchone() is not None


def set_recovery(conn: sqlite3.Connection, passphrase: str) -> None:
    """Keep the current key in the database wrapped with this passphrase. The passphrase itself is not stored, so the backup alone is
    not enough to read the passwords, but a restore on a new machine can get the key back by entering it."""
    import json

    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    wrapped = AESGCM(_kek(passphrase, salt)).encrypt(nonce, _key(conn), _RECOVERY_AAD)
    value = json.dumps({"v": 1, "salt": base64.b64encode(salt).decode(), "wrapped": base64.b64encode(nonce + wrapped).decode()})
    conn.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (RECOVERY_KEY, value))
    conn.commit()


def recover(conn: sqlite3.Connection, passphrase: str) -> bytes:
    import json

    row = conn.execute("SELECT value FROM settings WHERE key = ?", (RECOVERY_KEY,)).fetchone()
    if row is None:
        raise VaultError("this database has no recovery passphrase")
    try:
        data = json.loads(row["value"])
        raw = base64.b64decode(data["wrapped"])
        return AESGCM(_kek(passphrase, base64.b64decode(data["salt"]))).decrypt(raw[:12], raw[12:], _RECOVERY_AAD)
    except (InvalidTag, ValueError, KeyError, TypeError):
        raise VaultError("that is not the recovery passphrase") from None


def status(conn: sqlite3.Connection) -> dict:
    """How many stored secrets there are and how many of them the current key can read."""
    total = bad = 0
    for row in conn.execute("SELECT key, value FROM settings").fetchall():
        if is_encrypted(row["value"]):
            total += 1
            try:
                decrypt(conn, row["value"])
            except VaultError:
                bad += 1
    plain = sum(1 for r in conn.execute("SELECT key, value FROM settings").fetchall() if is_secret_key(r["key"]) and r["value"] and not is_encrypted(r["value"]))
    return {"encrypted": total, "unreadable": bad, "plaintext": plain, "source": key_source(conn), "recovery": has_recovery(conn)}


def migrate(conn: sqlite3.Connection) -> int:
    """Encrypt every secret setting that is still plain text. A copy of the database is kept the first time (netlens.db.pre-encryption)."""
    rows = [r for r in conn.execute("SELECT key, value FROM settings").fetchall() if is_secret_key(r["key"]) and r["value"] and not is_encrypted(r["value"])]
    if not rows:
        return 0
    path = _db_file(conn)
    if path:
        copy = Path(path).with_name(Path(path).name + ".pre-encryption")
        if not copy.exists():
            dbengine.copy_database(conn, copy)
            os.chmod(copy, 0o600)
    for r in rows:
        conn.execute("UPDATE settings SET value = ? WHERE key = ?", (encrypt(conn, r["value"]), r["key"]))
    conn.commit()
    log.info("encrypted %d stored secret setting(s)", len(rows))
    return len(rows)
