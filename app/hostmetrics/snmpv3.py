"""SNMPv3 with the user-based security model (RFC 3414, AES in RFC 3826): authentication and privacy for the health readings.

Only what reading needs: a GET / GETBULK / GETNEXT with authentication (MD5, SHA-1, SHA-2) and optionally encryption
(AES-128 or DES). The engine id and the clock of the device are learned with a discovery request, and again when the
device says the clock is off. Nothing is ever written to a device.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time

from app.hostmetrics import snmp
from app.hostmetrics.snmp import SnmpError, Timeout, _int, _oid, _read, _tlv, _decode_int, GET, GETBULK, GETNEXT

AUTH = {            # name: (hash, length of the digest that is sent)
    "MD5": ("md5", 12), "SHA": ("sha1", 12), "SHA224": ("sha224", 16), "SHA256": ("sha256", 24), "SHA384": ("sha384", 32), "SHA512": ("sha512", 48),
}
PRIV = ("AES", "DES")
REPORT = 0xA8
MAX_SIZE = 65507

_REPORT_TEXT = {
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0): "the device does not allow this security level",
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0): "the clocks differ",
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0): "the user name is not known to the device",
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0): "the engine id is not known",
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0): "the authentication failed (wrong password or protocol)",
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 6, 0): "the device could not decrypt the request (wrong privacy password or protocol)",
}
NOT_IN_WINDOW = (1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0)
UNKNOWN_ENGINE = (1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0)


def password_to_key(password: bytes, algo: str) -> bytes:
    """RFC 3414 A.2: the password stretched over one megabyte and hashed."""
    h = hashlib.new(algo)
    h.update((password * (1048576 // len(password) + 1))[:1048576])
    return h.digest()


def localize(key: bytes, engine_id: bytes, algo: str) -> bytes:
    return hashlib.new(algo, key + engine_id + key).digest()


def _cipher(kind: str, key: bytes, iv: bytes):
    from cryptography.hazmat.primitives.ciphers import Cipher, modes

    if kind == "AES":
        from cryptography.hazmat.primitives.ciphers import algorithms

        try:
            from cryptography.hazmat.decrepit.ciphers.modes import CFB       # where newer versions keep it
        except ImportError:
            CFB = modes.CFB
        return Cipher(algorithms.AES(key[:16]), CFB(iv))
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:                                           # an older cryptography
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    return Cipher(TripleDES(key[:8] * 3), modes.CBC(iv))


def _octets(value: bytes) -> bytes:
    return _tlv(0x04, value)


def _sequence(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


class AgentV3(snmp.Agent):
    """The Agent interface (get, walk) over SNMPv3."""

    def __init__(self, host, user, auth_proto="", auth_password="", priv_proto="", priv_password="", timeout=3.0, retries=2):
        super().__init__(host, "", "2c", timeout, retries)
        if auth_proto and auth_proto not in AUTH:
            raise SnmpError("the authentication protocol must be one of " + ", ".join(AUTH))
        if priv_proto and priv_proto not in PRIV:
            raise SnmpError("the privacy protocol must be AES or DES")
        if priv_proto and not auth_proto:
            raise SnmpError("encryption needs authentication as well")
        if (auth_proto and len(auth_password) < 8) or (priv_proto and len(priv_password) < 8):
            raise SnmpError("SNMPv3 passwords are at least 8 characters")
        self.user = user.encode()
        self.auth_proto, self.priv_proto = auth_proto, priv_proto
        self._auth_pw, self._priv_pw = auth_password.encode(), priv_password.encode()
        self._ku_auth = self._ku_priv = None
        self._engine = None                      # (engine id, boots, time at learning, monotonic at learning)
        self._auth_key = self._priv_key = None
        self._salt = int.from_bytes(os.urandom(8), "big")

    # ------------------------------------------------------------------ keys and clock
    def _keys(self, engine_id: bytes) -> None:
        if not self.auth_proto:
            return
        algo = AUTH[self.auth_proto][0]
        if self._ku_auth is None:
            self._ku_auth = password_to_key(self._auth_pw, algo)
            self._ku_priv = password_to_key(self._priv_pw, algo) if self.priv_proto else None
        self._auth_key = localize(self._ku_auth, engine_id, algo)
        self._priv_key = localize(self._ku_priv, engine_id, algo) if self._ku_priv else None

    def _now(self) -> tuple[int, int]:
        _eid, boots, learned, mono = self._engine
        return boots, int(learned + (time.monotonic() - mono))

    # ------------------------------------------------------------------ messages
    def _message(self, pdu: bytes, *, discover: bool = False) -> tuple[bytes, int]:
        msg_id = int.from_bytes(os.urandom(3), "big") + 1
        if discover:
            engine, boots, secs, flags, auth, priv_params, user = b"", 0, 0, 0x04, b"", b"", b""
        else:
            engine = self._engine[0]
            boots, secs = self._now()
            flags = 0x04 | (1 if self.auth_proto else 0) | (2 if self.priv_proto else 0)
            auth = b"\x00" * AUTH[self.auth_proto][1] if self.auth_proto else b""
            priv_params, user = b"", self.user
        scoped = _sequence(_octets(engine), _octets(b""), pdu)
        if self.priv_proto and not discover:
            if self.priv_proto == "AES":
                self._salt = (self._salt + 1) % (1 << 64)
                priv_params = struct.pack(">Q", self._salt)
                iv = struct.pack(">II", boots, secs) + priv_params
                enc = _cipher("AES", self._priv_key, iv).encryptor()
                data = enc.update(scoped) + enc.finalize()
            else:
                self._salt = (self._salt + 1) % (1 << 32)
                priv_params = struct.pack(">II", boots & 0xFFFFFFFF, self._salt)
                pre = self._priv_key[8:16]
                iv = bytes(a ^ b for a, b in zip(pre, priv_params))
                padded = scoped + b"\x00" * (-len(scoped) % 8)
                enc = _cipher("DES", self._priv_key, iv).encryptor()
                data = enc.update(padded) + enc.finalize()
            payload = _octets(data)
        else:
            payload = scoped
        usm = _sequence(_octets(engine), _int(boots), _int(secs), _octets(user), _octets(auth), _octets(priv_params))
        header = _sequence(_int(msg_id), _int(MAX_SIZE), _octets(bytes([flags])), _int(3))
        message = _sequence(_int(3), header, _octets(usm), payload)
        if self.auth_proto and not discover:
            algo, size = AUTH[self.auth_proto]
            digest = hmac.new(self._auth_key, message, algo).digest()[:size]
            at = message.rfind(b"\x00" * size)
            message = message[:at] + digest + message[at + size:]
        return message, msg_id

    def _parse(self, data: bytes, msg_id: int):
        """-> (pdu tag, request id, error status, binds, (engine id, boots, time))"""
        tag, start, end = _read(data, 0)
        if tag != 0x30:
            raise SnmpError("this is not an SNMP answer")
        pos = start
        _t, a, b = _read(data, pos)                       # version
        if _decode_int(data[a:b]) != 3:
            raise SnmpError("the device answered with another SNMP version")
        pos = b
        _t, hs, he = _read(data, pos)                     # global data
        p = hs
        _t, a, b = _read(data, p)
        got_id = _decode_int(data[a:b])
        p = b
        _t, a, b = _read(data, p)                         # max size
        p = b
        _t, a, b = _read(data, p)
        flags = data[a] if b > a else 0
        pos = he
        _t, a, b = _read(data, pos)                       # security parameters (an octet string holding a sequence)
        sec_start, sec_end = a, b
        pos = b
        t, ds, de = _read(data, sec_start)
        q = ds
        parts = []
        for _ in range(6):
            tt, x, y = _read(data, q)
            parts.append((tt, x, y))
            q = y
        engine = bytes(data[parts[0][1]:parts[0][2]])
        boots, secs = _decode_int(data[parts[1][1]:parts[1][2]]), _decode_int(data[parts[2][1]:parts[2][2]])
        auth_at = (parts[4][1], parts[4][2])
        priv_params = bytes(data[parts[5][1]:parts[5][2]])
        if flags & 0x01 and self._auth_key is not None:
            algo, size = AUTH[self.auth_proto]
            if auth_at[1] - auth_at[0] != size:
                raise SnmpError("the answer could not be verified")
            zeroed = data[:auth_at[0]] + b"\x00" * size + data[auth_at[1]:]
            if not hmac.compare_digest(hmac.new(self._auth_key, zeroed, algo).digest()[:size], bytes(data[auth_at[0]:auth_at[1]])):
                raise SnmpError("the answer failed its authentication check (wrong password?)")
        tag, ps, pe = _read(data, pos)                    # scoped PDU (plain) or an encrypted octet string
        if tag == 0x04:
            if not (flags & 0x02) or self._priv_key is None:
                raise SnmpError("the device answered with an encrypted message we cannot read")
            cipher_text = bytes(data[ps:pe])
            if self.priv_proto == "AES":
                iv = struct.pack(">II", boots, secs) + priv_params
            else:
                iv = bytes(a ^ b for a, b in zip(self._priv_key[8:16], priv_params))
                cipher_text = cipher_text[:len(cipher_text) // 8 * 8]
            dec = _cipher(self.priv_proto, self._priv_key, iv).decryptor()
            scoped = dec.update(cipher_text) + dec.finalize()
        else:
            scoped = bytes(data[pos:pe])
        tag, ss, se = _read(scoped, 0)
        if tag != 0x30:
            raise SnmpError("the answer could not be decrypted (wrong privacy password?)")
        q = ss
        _t, x, y = _read(scoped, q)                       # context engine id
        q = y
        _t, x, y = _read(scoped, q)                       # context name
        q = y
        pdu_tag, x, y = _read(scoped, q)
        q = x
        ids = []
        for _ in range(3):
            _t, a, b = _read(scoped, q)
            ids.append(_decode_int(scoped[a:b]))
            q = b
        _t, a, b = _read(scoped, q)
        binds, q = [], a
        while q < b:
            _t, vs, ve = _read(scoped, q)
            ot, os_, oe = _read(scoped, vs)
            vt, v1, v2 = _read(scoped, oe)
            binds.append((snmp._decode_oid(scoped[os_:oe]), snmp._decode_value(vt, scoped[v1:v2])))
            q = ve
        if got_id != msg_id and pdu_tag != REPORT:
            raise _Stale()
        return pdu_tag, ids[0], ids[1], binds, (engine, boots, secs)

    def _discover(self) -> None:
        request = _tlv(GET, _int(0) + _int(0) + _int(0) + _sequence())
        last: Exception | None = None
        for _ in range(self.retries + 1):
            message, msg_id = self._message(request, discover=True)
            try:
                raw = snmp.SEND(self.address, message, self.timeout)
                tag, _rid, _st, _binds, (engine, boots, secs) = self._parse(raw, msg_id)
            except _Stale:
                continue
            except Timeout as exc:
                last = exc
                continue
            if not engine:
                raise SnmpError(f"{self.host} did not tell its SNMPv3 engine id")
            self._engine = (engine, boots, secs, time.monotonic())
            self._keys(engine)
            return
        raise last or Timeout(f"no answer from {self.host}")

    # ------------------------------------------------------------------ the Agent interface
    def _ask(self, pdu_type, oids, max_repetitions=20):
        if self._engine is None:
            self._discover()
        binds = b"".join(_sequence(_oid(o), _tlv(0x05, b"")) for o in oids)
        resynced = False
        last: Exception | None = None
        for _ in range(self.retries + 2):
            self._next_id = (self._next_id + 1) % 0x7FFFFFFF
            if pdu_type == GETBULK:
                head = _int(self._next_id) + _int(0) + _int(max_repetitions)
            else:
                head = _int(self._next_id) + _int(0) + _int(0)
            message, msg_id = self._message(_tlv(pdu_type, head + _sequence(binds)))
            try:
                raw = snmp.SEND(self.address, message, self.timeout)
                tag, request_id, status, answer, _t = self._parse(raw, msg_id)
            except _Stale:
                continue
            except Timeout as exc:
                last = exc
                continue
            if tag == REPORT:
                what = answer[0][0] if answer else None
                if what in (NOT_IN_WINDOW, UNKNOWN_ENGINE) and not resynced:
                    resynced = True
                    self._engine = None
                    self._discover()
                    continue
                raise SnmpError(f"{self.host}: {_REPORT_TEXT.get(what, 'the device refused the request')}")
            if status:
                raise SnmpError(f"{self.host} answered with SNMP error {status}")
            return answer
        raise last or Timeout(f"no answer from {self.host}")


class _Stale(Exception):
    """An answer to an earlier request."""
