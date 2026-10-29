"""A software authenticator for the tests: makes the same bytes a real security key makes (CBOR attestation objects, authenticator data, signatures), so the server code is
checked with real cryptography. The browser test (tests/test_webauthn_browser.py) uses Chromium's own virtual authenticator for the real thing."""

import hashlib
import json
import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from app.webauthn import b64e


def cbor(value) -> bytes:
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        major, n = (0, value) if value >= 0 else (1, -1 - value)
        return _head(major, n)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return _head(3, len(raw)) + raw
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(cbor(v) for v in value)
    if isinstance(value, dict):
        return _head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    raise TypeError(value)


def _head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | info]) + n.to_bytes(size, "big")
    raise ValueError


class Authenticator:
    def __init__(self, kind="es256", counter_start=0):
        self.kind = kind
        self.counter = counter_start
        self.credential_id = os.urandom(32)
        if kind == "es256":
            self.key = ec.generate_private_key(ec.SECP256R1())
        elif kind == "rs256":
            self.key = rsa.generate_private_key(65537, 2048)
        else:
            self.key = ed25519.Ed25519PrivateKey.generate()

    @property
    def cose(self) -> bytes:
        pub = self.key.public_key()
        if self.kind == "es256":
            n = pub.public_numbers()
            return cbor({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})
        if self.kind == "rs256":
            n = pub.public_numbers()
            return cbor({1: 3, 3: -257, -1: n.n.to_bytes(256, "big"), -2: n.e.to_bytes(3, "big")})
        from cryptography.hazmat.primitives import serialization

        return cbor({1: 1, 3: -8, -1: 6, -2: pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)})

    def _sign(self, data: bytes) -> bytes:
        if self.kind == "es256":
            return self.key.sign(data, ec.ECDSA(hashes.SHA256()))
        if self.kind == "rs256":
            return self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        return self.key.sign(data)

    def _auth_data(self, rp_id, flags, attested):
        data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", self.counter)
        if attested:
            data += b"\x00" * 16 + struct.pack(">H", len(self.credential_id)) + self.credential_id + self.cose
        return data

    def create(self, challenge, rp_id, origin, *, flags=0x41 | 0x40, fmt="none", cred_type="webauthn.create", bad_rp=False, cross_origin=False):
        client = {"type": cred_type, "challenge": challenge, "origin": origin, **({"crossOrigin": True} if cross_origin else {})}
        raw = json.dumps(client).encode()
        auth = self._auth_data("evil.example" if bad_rp else rp_id, flags | 0x40, True)
        att = cbor({"fmt": fmt, "attStmt": {}, "authData": auth})
        return {"id": b64e(self.credential_id), "rawId": b64e(self.credential_id), "type": "public-key",
                "response": {"clientDataJSON": b64e(raw), "attestationObject": b64e(att), "transports": ["usb"]}}

    def get(self, challenge, rp_id, origin, *, flags=0x01, bump=True, bad_rp=False, tamper=False, cred_type="webauthn.get"):
        if bump:
            self.counter += 1
        client = {"type": cred_type, "challenge": challenge, "origin": origin}
        raw = json.dumps(client).encode()
        auth = self._auth_data("evil.example" if bad_rp else rp_id, flags, False)
        sig = self._sign(auth + hashlib.sha256(raw).digest())
        if tamper:
            sig = sig[:-1] + bytes([sig[-1] ^ 1])
        return {"id": b64e(self.credential_id), "rawId": b64e(self.credential_id), "type": "public-key",
                "response": {"clientDataJSON": b64e(raw), "authenticatorData": b64e(auth), "signature": b64e(sig), "userHandle": None}}
