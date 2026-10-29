"""WebAuthn (security keys and passkeys) as a second factor for local accounts.

Netlens is the *relying party*: it verifies what the user's authenticator (a security key, a phone, a laptop's platform authenticator) signs. Standard library plus
`cryptography` only; no attestation is requested (`attestation: "none"`), so no authenticator can be refused for its make, and the statement is not checked.

What makes it safe:
  * a **challenge** of 256 random bits per ceremony, kept in memory, single use, five minutes, tied to one user and one purpose (adding a key, signing in, confirming);
  * the signature covers the challenge, the **origin** (the page that asked) and the **relying party id** (the host name), so a look-alike site gets nothing it can replay:
    this is the phishing resistance that a typed code does not have;
  * the **signature counter** is checked (an authenticator that goes backwards may have been cloned: refused), except for authenticators that always report 0;
  * the public key is kept, never a secret: a stolen database holds nothing that can sign in.

Browsers offer WebAuthn only on https pages (and on localhost).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from app.db import insert_id, utcnow

CHALLENGE_SECONDS = 300
MAX_KEYS = 10
RP_NAME = "Netlens"
ALGORITHMS = (-7, -257, -8)             # ES256, RS256, EdDSA
FLAG_UP, FLAG_UV, FLAG_AT, FLAG_ED = 0x01, 0x04, 0x40, 0x80


class WebAuthnError(ValueError):
    """A problem the user can understand; never contains a secret."""


# ----------------------------------------------------------------------------- base64url and CBOR (the subset WebAuthn uses)
def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64d(text: str) -> bytes:
    if not isinstance(text, str) or len(text) > 20000:
        raise WebAuthnError("a value from the browser is not valid")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError):
        raise WebAuthnError("a value from the browser is not valid") from None


def cbor_decode(data: bytes, depth: int = 0) -> tuple[Any, int]:
    """(value, bytes used). Definite lengths only (what authenticators send); small depth and size limits."""
    if depth > 8 or not data:
        raise WebAuthnError("the authenticator's answer is not valid")
    first = data[0]
    major, info = first >> 5, first & 0x1F
    pos = 1
    if info < 24:
        arg = info
    elif info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        if len(data) < pos + size:
            raise WebAuthnError("the authenticator's answer is cut short")
        arg = int.from_bytes(data[pos:pos + size], "big")
        pos += size
    else:
        raise WebAuthnError("the authenticator's answer uses a form that is not supported")
    if major == 0:
        return arg, pos
    if major == 1:
        return -1 - arg, pos
    if major in (2, 3):
        if arg > 20000 or len(data) < pos + arg:
            raise WebAuthnError("the authenticator's answer is cut short")
        raw = data[pos:pos + arg]
        return (raw if major == 2 else raw.decode("utf-8", "strict")), pos + arg
    if major == 4:
        if arg > 64:
            raise WebAuthnError("the authenticator's answer is too large")
        items = []
        for _ in range(arg):
            value, used = cbor_decode(data[pos:], depth + 1)
            items.append(value)
            pos += used
        return items, pos
    if major == 5:
        if arg > 64:
            raise WebAuthnError("the authenticator's answer is too large")
        out = {}
        for _ in range(arg):
            key, used = cbor_decode(data[pos:], depth + 1)
            pos += used
            value, used = cbor_decode(data[pos:], depth + 1)
            pos += used
            out[key] = value
        return out, pos
    if major == 7 and info in (20, 21, 22):
        return {20: False, 21: True, 22: None}[info], pos
    raise WebAuthnError("the authenticator's answer uses a form that is not supported")


# ----------------------------------------------------------------------------- authenticator data and keys
@dataclass
class AuthData:
    rp_id_hash: bytes
    flags: int
    counter: int
    credential_id: bytes = b""
    public_key: bytes = b""            # the COSE key exactly as sent (CBOR)
    aaguid: bytes = b""


def parse_auth_data(data: bytes) -> AuthData:
    if len(data) < 37:
        raise WebAuthnError("the authenticator data is too short")
    rp_hash, flags, counter = data[:32], data[32], struct.unpack(">I", data[33:37])[0]
    out = AuthData(rp_hash, flags, counter)
    if flags & FLAG_AT:
        if len(data) < 55:
            raise WebAuthnError("the authenticator data is too short")
        out.aaguid = data[37:53]
        length = struct.unpack(">H", data[53:55])[0]
        if length == 0 or length > 1023 or len(data) < 55 + length:
            raise WebAuthnError("the credential id is not valid")
        out.credential_id = data[55:55 + length]
        _key, used = cbor_decode(data[55 + length:])
        out.public_key = data[55 + length:55 + length + used]
    return out


def _public_key(cose: bytes):
    key, _ = cbor_decode(cose)
    if not isinstance(key, dict):
        raise WebAuthnError("the public key is not valid")
    kty, alg = key.get(1), key.get(3)
    if kty == 2 and alg == -7 and key.get(-1) == 1 and isinstance(key.get(-2), bytes) and isinstance(key.get(-3), bytes) and len(key[-2]) == 32 and len(key[-3]) == 32:
        try:
            return ec.EllipticCurvePublicNumbers(int.from_bytes(key[-2], "big"), int.from_bytes(key[-3], "big"), ec.SECP256R1()).public_key(), alg
        except ValueError:
            raise WebAuthnError("the public key is not valid") from None
    if kty == 3 and alg == -257 and isinstance(key.get(-1), bytes) and isinstance(key.get(-2), bytes) and 128 <= len(key[-1]) <= 1024:
        return rsa.RSAPublicNumbers(int.from_bytes(key[-2], "big"), int.from_bytes(key[-1], "big")).public_key(), alg
    if kty == 1 and alg == -8 and key.get(-1) == 6 and isinstance(key.get(-2), bytes) and len(key[-2]) == 32:
        return ed25519.Ed25519PublicKey.from_public_bytes(key[-2]), alg
    raise WebAuthnError("this kind of key is not supported (use ES256, RS256 or Ed25519)")


def _verify_signature(cose: bytes, signature: bytes, signed: bytes) -> bool:
    key, alg = _public_key(cose)
    try:
        if alg == -7:
            key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif alg == -257:
            key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            key.verify(signature, signed)
        return True
    except (InvalidSignature, ValueError):
        return False


# ----------------------------------------------------------------------------- the relying party: who we are, from the request
def rp_for(host: str, origin: str | None, forwarded_proto: str | None = None) -> tuple[str, str]:
    """(rp id, expected origin). The relying party id is the host name the browser used. The origin is the one the browser sent with this request, which must be https (or
    http on localhost) and for the same host: a page on another site cannot get a signature that is good here."""
    name = (host or "").split(":")[0] if not (host or "").startswith("[") else (host or "").split("]")[0] + "]"
    if not name:
        raise WebAuthnError("the host name of this request is missing")
    parsed = urlparse(origin or "")
    if not parsed.scheme or not parsed.hostname:
        raise WebAuthnError("the browser did not say which page asked")
    local = parsed.hostname in ("localhost", "127.0.0.1", "[::1]", "::1")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
        raise WebAuthnError("security keys work only on pages served over https (or on localhost): put Netlens behind HTTPS first")
    if parsed.hostname.lower() != name.strip("[]").lower():
        raise WebAuthnError("the page and the server do not agree on the host name")
    return name.strip("[]").lower(), f"{parsed.scheme}://{parsed.netloc}"


# ----------------------------------------------------------------------------- challenges
class Challenges:
    """One challenge per ceremony: random, in memory, single use, five minutes. Keyed by what the ceremony belongs to."""

    def __init__(self) -> None:
        self._items: dict[str, dict] = {}
        self._lock = threading.Lock()

    def issue(self, key: str, user_id: int, kind: str, now: float | None = None) -> str:
        now = time.time() if now is None else now
        challenge = b64e(secrets.token_bytes(32))
        with self._lock:
            if len(self._items) > 2000:
                self._items = {k: v for k, v in self._items.items() if v["expires"] > now}
            self._items[key] = {"challenge": challenge, "user_id": user_id, "kind": kind, "expires": now + CHALLENGE_SECONDS}
        return challenge

    def take(self, key: str, user_id: int, kind: str, now: float | None = None) -> str:
        """The challenge for this ceremony, removed (single use). Raises when there is none, it has expired, or it belongs to something else."""
        now = time.time() if now is None else now
        with self._lock:
            item = self._items.pop(key, None)
        if item is None or item["expires"] <= now or item["user_id"] != user_id or item["kind"] != kind:
            raise WebAuthnError("this request has expired: start again")
        return item["challenge"]


# ----------------------------------------------------------------------------- the ceremonies
def _client_data(raw: bytes, kind: str, challenge: str, origin: str) -> None:
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise WebAuthnError("the browser's answer is not valid") from None
    if not isinstance(data, dict) or data.get("type") != kind:
        raise WebAuthnError("the browser's answer is for something else")
    if not hmac.compare_digest(str(data.get("challenge") or "").encode(), challenge.encode()):
        raise WebAuthnError("the browser's answer does not match this request (it may be old)")
    if data.get("origin") != origin:
        raise WebAuthnError("the answer was made for another site")
    if data.get("crossOrigin") is True:
        raise WebAuthnError("the answer came from a page inside another page, which is refused")


def creation_options(user_id: int, username: str, existing: list[str], rp_id: str, challenge: str) -> dict:
    return {"challenge": challenge, "rp": {"id": rp_id, "name": RP_NAME}, "user": {"id": b64e(hashlib.sha256(f"netlens-user-{user_id}".encode()).digest()), "name": username, "displayName": username},
            "pubKeyCredParams": [{"type": "public-key", "alg": a} for a in ALGORITHMS], "timeout": 120000, "attestation": "none",
            "excludeCredentials": [{"type": "public-key", "id": c} for c in existing], "authenticatorSelection": {"residentKey": "preferred", "userVerification": "preferred"}}


def request_options(credential_ids: list[str], rp_id: str, challenge: str) -> dict:
    return {"challenge": challenge, "rpId": rp_id, "timeout": 120000, "userVerification": "preferred", "allowCredentials": [{"type": "public-key", "id": c} for c in credential_ids]}


def verify_registration(response: dict, challenge: str, rp_id: str, origin: str) -> dict:
    """Check what the browser returned after `navigator.credentials.create`. Returns {"credential_id", "public_key", "counter", "aaguid", "transports"} (all text, base64url)."""
    if not isinstance(response, dict) or not isinstance(response.get("response"), dict):
        raise WebAuthnError("the browser's answer is not valid")
    inner = response["response"]
    _client_data(b64d(inner.get("clientDataJSON")), "webauthn.create", challenge, origin)
    attestation, _ = cbor_decode(b64d(inner.get("attestationObject")))
    if not isinstance(attestation, dict) or not isinstance(attestation.get("authData"), bytes):
        raise WebAuthnError("the attestation is not valid")
    auth = parse_auth_data(attestation["authData"])           # the attestation statement is not checked: no attestation was asked for
    if not hmac.compare_digest(auth.rp_id_hash, hashlib.sha256(rp_id.encode()).digest()):
        raise WebAuthnError("the key was made for another site")
    if not auth.flags & FLAG_UP:
        raise WebAuthnError("the key was not touched")
    if not auth.flags & FLAG_AT or not auth.credential_id or not auth.public_key:
        raise WebAuthnError("the key did not return a credential")
    _public_key(auth.public_key)                                # refuses a kind of key that cannot be used later
    if b64e(auth.credential_id) != response.get("id") and b64e(auth.credential_id) != response.get("rawId"):
        raise WebAuthnError("the credential id does not match")
    transports = [t for t in (inner.get("transports") or []) if isinstance(t, str) and t.isalpha()][:6] if isinstance(inner.get("transports"), list) else []
    return {"credential_id": b64e(auth.credential_id), "public_key": b64e(auth.public_key), "counter": auth.counter, "aaguid": b64e(auth.aaguid), "transports": transports}


def verify_assertion(response: dict, keys: list[sqlite3.Row], challenge: str, rp_id: str, origin: str) -> tuple[sqlite3.Row, int]:
    """Check what the browser returned after `navigator.credentials.get`, against the user's keys. Returns (the key row, the new counter)."""
    if not isinstance(response, dict) or not isinstance(response.get("response"), dict) or not isinstance(response.get("id"), str):
        raise WebAuthnError("the browser's answer is not valid")
    inner = response["response"]
    key = next((k for k in keys if hmac.compare_digest(k["credential_id"].encode(), response["id"].encode())), None)
    if key is None:
        raise WebAuthnError("this key is not set up for this account")
    client_data = b64d(inner.get("clientDataJSON"))
    _client_data(client_data, "webauthn.get", challenge, origin)
    auth_bytes = b64d(inner.get("authenticatorData"))
    auth = parse_auth_data(auth_bytes)
    if not hmac.compare_digest(auth.rp_id_hash, hashlib.sha256(rp_id.encode()).digest()):
        raise WebAuthnError("the key answered for another site")
    if not auth.flags & FLAG_UP:
        raise WebAuthnError("the key was not touched")
    if not _verify_signature(b64d(key["public_key"]), b64d(inner.get("signature")), auth_bytes + hashlib.sha256(client_data).digest()):
        raise WebAuthnError("the key's signature is not valid")
    stored = int(key["sign_count"] or 0)
    if (auth.counter or stored) and auth.counter <= stored:
        raise WebAuthnError("this key's counter went backwards: it may have been copied, so it was refused")
    return key, auth.counter


# ----------------------------------------------------------------------------- the keys of a user (database)
def keys_of(conn: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM user_webauthn WHERE user_id = ? ORDER BY id", (user_id,)).fetchall()


def listing(conn: sqlite3.Connection, user_id: int) -> list[dict]:
    return [{"id": k["id"], "name": k["name"], "created": k["created"], "last_used": k["last_used"], "transports": json.loads(k["transports"] or "[]")} for k in keys_of(conn, user_id)]


def add_key(conn: sqlite3.Connection, user_id: int, name: str, verified: dict) -> int:
    name = " ".join(str(name or "").split())[:60] or "Security key"
    if len(keys_of(conn, user_id)) >= MAX_KEYS:
        raise WebAuthnError(f"at most {MAX_KEYS} keys per account")
    if conn.execute("SELECT 1 FROM user_webauthn WHERE credential_id = ?", (verified["credential_id"],)).fetchone():
        raise WebAuthnError("this key is already registered")
    new_id = insert_id(conn, "INSERT INTO user_webauthn (user_id, name, credential_id, public_key, sign_count, aaguid, transports, created) VALUES (?,?,?,?,?,?,?,?)",
                       (user_id, name, verified["credential_id"], verified["public_key"], verified["counter"], verified["aaguid"], json.dumps(verified["transports"]), utcnow()))
    conn.execute("UPDATE users SET webauthn_enabled = 1 WHERE id = ?", (user_id,))
    conn.commit()
    return new_id or 0


def remove_key(conn: sqlite3.Connection, user_id: int, key_id: int) -> bool:
    removed = conn.execute("DELETE FROM user_webauthn WHERE id = ? AND user_id = ?", (key_id, user_id)).rowcount
    if not conn.execute("SELECT 1 FROM user_webauthn WHERE user_id = ?", (user_id,)).fetchone():
        conn.execute("UPDATE users SET webauthn_enabled = 0 WHERE id = ?", (user_id,))
    conn.commit()
    return bool(removed)


def remove_all(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute("DELETE FROM user_webauthn WHERE user_id = ?", (user_id,))
    conn.execute("UPDATE users SET webauthn_enabled = 0 WHERE id = ?", (user_id,))
    conn.commit()


def used(conn: sqlite3.Connection, key_id: int, counter: int) -> None:
    conn.execute("UPDATE user_webauthn SET sign_count = ?, last_used = ? WHERE id = ?", (counter, utcnow(), key_id))
    conn.commit()
