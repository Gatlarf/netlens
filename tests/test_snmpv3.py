"""SNMPv3: key localisation against the RFC 3414 vectors, and the client against a simulated device that checks the
authentication, decrypts, answers (encrypted when asked) and says "not in time window" when the clocks drift."""

import hashlib
import hmac
import struct
import time

import pytest

from app.hostmetrics import service as hm
from app.hostmetrics import snmp, snmpv3
from app.hostmetrics.snmp import _decode_int, _int, _oid, _read, _tlv
from tests.test_hostmetrics import oid, oid_values  # noqa: F401  (the fixture teaches the simulator object identifiers)
from tests import test_plugin_snmp as sim

ENGINE = bytes.fromhex("80001f8880e9bd0c1d12667a5100000000")


def test_rfc3414_key_vectors():
    eid = bytes.fromhex("000000000000000000000002")
    assert snmpv3.localize(snmpv3.password_to_key(b"maplesyrup", "md5"), eid, "md5").hex() == "526f5eed9fcce26f8964c2930787d82b"
    assert snmpv3.localize(snmpv3.password_to_key(b"maplesyrup", "sha1"), eid, "sha1").hex() == "6695febc9288e36282235fc7151f128497b38f3f"


def seq(*parts):
    return _tlv(0x30, b"".join(parts))


def octets(b):
    return _tlv(0x04, b)


class Device:
    """A v3 agent with one user. Mirrors RFC 3414 in its own words, so a mistake in the client is not copied here."""

    def __init__(self, mib, user="monitor", auth=("sha1", "authpass1234"), priv="aes", priv_pw="privpass1234"):
        self.mib, self.user = mib, user.encode()
        self.auth, self.priv = auth, priv
        self.boots, self.clock = 5, 1_000_000
        self.drift = 0
        eng = ENGINE
        self.auth_key = snmpv3.localize(snmpv3.password_to_key(auth[1].encode(), auth[0]), eng, auth[0]) if auth else None
        self.priv_key = snmpv3.localize(snmpv3.password_to_key(priv_pw.encode(), auth[0]), eng, auth[0]) if priv else None
        self.started = time.monotonic()
        self.requests = 0

    def now(self):
        return self.clock + int(time.monotonic() - self.started) + self.drift

    def _usm(self, user=b"", auth=b"", priv=b""):
        return octets(seq(octets(ENGINE), _int(self.boots), _int(self.now()), octets(user), octets(auth), octets(priv)))

    def _report(self, msg_id, oid_):
        pdu = _tlv(0xA8, _int(0) + _int(0) + _int(0) + seq(seq(_oid(oid_), _int(1))))
        scoped = seq(octets(ENGINE), octets(b""), pdu)
        hdr = seq(_int(msg_id), _int(65507), octets(b"\x00"), _int(3))
        return seq(_int(3), hdr, self._usm(), scoped)

    def handle(self, address, payload, timeout=None):
        self.requests += 1
        _t, s, _e = _read(payload, 0)
        pos = s
        _t, a, b = _read(payload, pos); pos = b                       # version
        _t, hs, he = _read(payload, pos)
        q = hs
        _t, a, b = _read(payload, q); msg_id = _decode_int(payload[a:b]); q = b
        _t, a, b = _read(payload, q); q = b
        _t, a, b = _read(payload, q); flags = payload[a]
        pos = he
        _t, a, b = _read(payload, pos)                                 # usm
        usm_start = a
        pos = b
        _t, ds, de = _read(payload, usm_start)
        q = ds
        fields = []
        for _ in range(6):
            t, x, y = _read(payload, q)
            fields.append((x, y))
            q = y
        engine = payload[fields[0][0]:fields[0][1]]
        boots = _decode_int(payload[fields[1][0]:fields[1][1]])
        secs = _decode_int(payload[fields[2][0]:fields[2][1]])
        user = payload[fields[3][0]:fields[3][1]]
        auth_params = payload[fields[4][0]:fields[4][1]]
        priv_params = payload[fields[5][0]:fields[5][1]]
        if not engine and not user:                                    # discovery
            return self._report(msg_id, (1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0))
        assert engine == ENGINE and user == self.user
        if flags & 1:
            algo, size = snmpv3.AUTH[{"md5": "MD5", "sha1": "SHA", "sha256": "SHA256"}[self.auth[0]]]
            zeroed = payload[:fields[4][0]] + b"\x00" * size + payload[fields[4][1]:]
            expect = hmac.new(self.auth_key, zeroed, algo).digest()[:size]
            if expect != auth_params:
                return self._report(msg_id, (1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0))
            if boots != self.boots or abs(secs - self.now()) > 150:
                return self._report(msg_id, (1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0))
        t, ps, pe = _read(payload, pos)
        if t == 0x04:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
            from app.hostmetrics.snmpv3 import _cipher
            iv = struct.pack(">II", boots, secs) + priv_params
            dec = _cipher('AES', self.priv_key, iv).decryptor()
            scoped = dec.update(payload[ps:pe]) + dec.finalize()
        else:
            scoped = payload[pos:pe]
        _t, ss, se = _read(scoped, 0)
        q = ss
        _t, a, b = _read(scoped, q); q = b
        _t, a, b = _read(scoped, q); q = b
        tag, a, b = _read(scoped, q)
        q = a
        ids = []
        for _ in range(3):
            _t, x, y = _read(scoped, q); ids.append(_decode_int(scoped[x:y])); q = y
        _t, a, b = _read(scoped, q)
        oids = []
        r = a
        while r < b:
            _t, vs, ve = _read(scoped, r)
            _t, os_, oe = _read(scoped, vs)
            oids.append(snmp._decode_oid(scoped[os_:oe]))
            r = ve
        keys = sorted(self.mib.values)
        binds = []
        for o in oids:
            if tag == snmp.GET:
                v = self.mib.values.get(o)
                binds.append((o, v))
            else:                                                     # GETNEXT / GETBULK: the next few
                nxt = [k for k in keys if k > o][: (ids[2] if tag == snmp.GETBULK else 1)]
                binds += [(k, self.mib.values[k]) for k in nxt] or [(o, sim.plugin.NoSuch("endOfMibView"))]
        body = b"".join(seq(_oid(o), sim.encode_value(v)) for o, v in binds)
        pdu = _tlv(snmp.RESPONSE, _int(ids[0]) + _int(0) + _int(0) + seq(body))
        scoped_out = seq(octets(ENGINE), octets(b""), pdu)
        out_flags = flags & 0x03
        boots_out, secs_out = self.boots, self.now()
        priv_out = b""
        data = scoped_out
        if out_flags & 2:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            priv_out = b"\x01\x02\x03\x04\x05\x06\x07\x08"
            iv = struct.pack(">II", boots_out, secs_out) + priv_out
            enc = _cipher('AES', self.priv_key, iv).encryptor()
            data = octets(enc.update(scoped_out) + enc.finalize())
        algo, size = snmpv3.AUTH[{"md5": "MD5", "sha1": "SHA", "sha256": "SHA256"}[self.auth[0]]] if out_flags & 1 else (None, 0)
        usm = octets(seq(octets(ENGINE), _int(boots_out), _int(secs_out), octets(self.user), octets(b"\x00" * size), octets(priv_out)))
        hdr = seq(_int(msg_id), _int(65507), octets(bytes([out_flags])), _int(3))
        message = seq(_int(3), hdr, usm, data)
        if size:
            digest = hmac.new(self.auth_key, message, algo).digest()[:size]
            at = message.rfind(b"\x00" * size)
            message = message[:at] + digest + message[at + size:]
        return message


def mib():
    m = sim.Mib()
    m.set(snmp.HR_UPTIME, 360000)
    m.set(oid(snmp.HR_PROC_LOAD, 1), 42)
    return m


@pytest.fixture
def device(monkeypatch):
    d = Device(mib())
    monkeypatch.setattr(snmp, "SEND", d.handle)
    return d


def agent(**kw):
    args = dict(user="monitor", auth_proto="SHA", auth_password="authpass1234", priv_proto="AES", priv_password="privpass1234", timeout=1, retries=1)
    args.update(kw)
    return snmpv3.AgentV3("10.0.0.9", **args)


def test_get_and_walk_with_authentication_and_encryption(device):
    a = agent()
    assert a.get(snmp.HR_UPTIME) == {snmp.HR_UPTIME: 360000}
    pts, found = snmp.collect(a, ["cpu", "uptime"], {}, now=100)
    got = {(m, label): v for m, label, v, _u in pts}
    assert got[("cpu_pct", "")] == 42 and got[("uptime_s", "")] == 3600
    assert device.requests >= 3


def test_wrong_authentication_password_is_explained(device):
    with pytest.raises(snmp.SnmpError, match="authentication failed"):
        agent(auth_password="not-the-password").get(snmp.HR_UPTIME)


def test_a_clock_that_drifts_is_resynchronised(device):
    a = agent()
    a.get(snmp.HR_UPTIME)
    device.drift = 5000                                              # the device clock jumps
    assert a.get(snmp.HR_UPTIME) == {snmp.HR_UPTIME: 360000}


def test_settings_are_checked():
    with pytest.raises(snmp.SnmpError):
        snmpv3.AgentV3("10.0.0.9", "u", "SHA", "short", "", "")
    with pytest.raises(snmp.SnmpError):
        snmpv3.AgentV3("10.0.0.9", "u", "", "", "AES", "privpass1234")
    with pytest.raises(snmp.SnmpError):
        snmpv3.AgentV3("10.0.0.9", "u", "WHIRLPOOL", "authpass1234", "", "")


def test_monitor_definition_for_v3():
    d = hm.validate({"method": "snmp", "address": "10.0.0.9", "version": "3", "username": "monitor", "auth_proto": "SHA", "auth_password": "authpass1234",
                     "priv_proto": "AES", "priv_password": "privpass1234"})
    assert d["secret"]["version"] == "3" and "community" not in d["secret"]
    with pytest.raises(hm.MonitorError):
        hm.validate({"method": "snmp", "address": "10.0.0.9", "version": "3"})
    with pytest.raises(hm.MonitorError):
        hm.validate({"method": "snmp", "address": "10.0.0.9", "version": "3", "username": "u", "priv_proto": "AES", "priv_password": "privpass1234"})
    v2 = hm.validate({"method": "snmp", "address": "10.0.0.9", "version": "2c", "community": "x"}, {"secret": d["secret"]})
    assert "username" not in v2["secret"] and v2["secret"]["community"] == "x"
