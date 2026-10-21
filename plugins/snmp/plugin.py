"""SNMP switch plugin (kind "topology"): which device is plugged into which switch port, read from managed switches.

Read-only SNMP v1 / v2c over UDP (standard library only, the protocol is encoded by hand below). Per switch:

    SNMPv2-MIB      sysDescr, sysName                                          what it is
    BRIDGE-MIB      dot1dBaseBridgeAddress, dot1dBasePortIfIndex               its own MAC, bridge port -> interface
    IF-MIB          ifName / ifDescr, ifPhysAddress                            port names and the MACs the switch itself uses
    Q-BRIDGE-MIB    dot1qTpFdbPort (else BRIDGE-MIB dot1dTpFdbPort)            the MAC address table: which MAC was learned on which port
    LLDP-MIB        lldpRemChassisId, lldpRemPortId, lldpRemSysName            what is plugged into each port (other switches in particular)
    CISCO-CDP-MIB   cdpCacheDeviceId, cdpCacheDevicePort, cdpCacheAddress      the same for Cisco neighbours that only speak CDP
    CISCO-VTP-MIB   vtpVlanState                                               which VLANs exist (Cisco keeps one MAC table per VLAN)

Cisco IOS has one BRIDGE-MIB per VLAN, reached by adding "@<vlan>" to the community string (public@25). Without that a Catalyst shows only
VLAN 1. When the switch is a Cisco and has no Q-BRIDGE table, every VLAN is read that way (setting "Cisco VLAN indexing").

Netlens turns that into: every polled switch is a node, switches hang below each other following LLDP (from the core switch),
and every MAC found on an ordinary port is a wired client of that switch, with the port name. A MAC that was learned on a
port that leads to another switch (an uplink) is ignored there, so a device is attributed to the switch it is really plugged
into, not to every switch above it.
"""

import copy
import hashlib
import hmac
import ipaddress
import os
import re
import socket
import struct
import time
from collections import Counter, defaultdict

# ----------------------------------------------------------------------------- OIDs
SYS_DESCR = (1, 3, 6, 1, 2, 1, 1, 1, 0)
SYS_NAME = (1, 3, 6, 1, 2, 1, 1, 5, 0)
SYS_OBJECT_ID = (1, 3, 6, 1, 2, 1, 1, 2, 0)
CISCO_ENTERPRISE = (1, 3, 6, 1, 4, 1, 9)
VTP_VLAN_STATE = (1, 3, 6, 1, 4, 1, 9, 9, 46, 1, 3, 1, 1, 2)    # .<management domain>.<vlan>; 1 = operational
CDP_CACHE = (1, 3, 6, 1, 4, 1, 9, 9, 23, 1, 2, 1, 1)             # cdpCacheEntry; column .<ifIndex>.<neighbour index>
CDP_ADDRESS, CDP_DEVICE_ID, CDP_DEVICE_PORT = (CDP_CACHE + (c,) for c in (4, 6, 7))
BRIDGE_ADDRESS = (1, 3, 6, 1, 2, 1, 17, 1, 1, 0)
BASE_PORT_IFINDEX = (1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 2)
IF_NAME = (1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1)
IF_DESCR = (1, 3, 6, 1, 2, 1, 2, 2, 1, 2)
IF_PHYS = (1, 3, 6, 1, 2, 1, 2, 2, 1, 6)
QBRIDGE_FDB_PORT = (1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2)    # .<vlan>.<mac, 6 numbers>
QBRIDGE_FDB_STATUS = (1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 3)
BRIDGE_FDB_PORT = (1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2)           # .<mac, 6 numbers>
BRIDGE_FDB_STATUS = (1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 3)
LLDP = (1, 0, 8802, 1, 1, 2, 1, 4, 1, 1)                       # lldpRemEntry; column .<timeMark>.<localPort>.<index>
LLDP_CHASSIS_SUBTYPE, LLDP_CHASSIS_ID, LLDP_PORT_SUBTYPE, LLDP_PORT_ID, LLDP_SYS_NAME = (LLDP + (c,) for c in (4, 5, 6, 7, 9))
LLDP_LOCAL_PORT = (1, 0, 8802, 1, 1, 2, 1, 3, 7, 1)            # lldpLocPortEntry; columns .2 subtype, .3 id

FDB_LEARNED = 3          # dot1qTpFdbStatus / dot1dTpFdbStatus: learned (self = 4 and mgmt = 5 are the switch's own addresses)
MAX_VLANS = 300          # VLANs read one by one on a Cisco (each is a separate walk)
RESERVED_VLANS = range(1002, 1006)     # FDDI / Token Ring defaults every Catalyst lists
MAX_ROWS = 40000         # a table longer than this is cut off instead of walked forever
SAMPLES = 3


class SnmpError(Exception):
    pass


class AuthRefused(SnmpError):
    """The device refused our SNMPv3 user (unknown user, wrong password or privacy settings): asking again would not help."""
    auth_failed = True


class Timeout(SnmpError):
    pass


class NoSuch:
    """noSuchObject / noSuchInstance / endOfMibView in an answer."""

    def __init__(self, kind):
        self.kind = kind

    def __repr__(self):
        return f"<{self.kind}>"


# ----------------------------------------------------------------------------- BER encoding (just what SNMP needs)
def _length(n):
    if n < 128:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag, content):
    return bytes([tag]) + _length(len(content)) + content


def _int(value):
    size = max(1, (value.bit_length() + 8) // 8) if value >= 0 else max(1, ((-value - 1).bit_length() + 8) // 8)
    return _tlv(0x02, value.to_bytes(size, "big", signed=True))


def _oid(oid):
    first = 40 * oid[0] + oid[1]
    out = bytearray()
    for number in (first,) + tuple(oid[2:]):
        chunk = [number & 0x7F]
        number >>= 7
        while number:
            chunk.append(0x80 | (number & 0x7F))
            number >>= 7
        out += bytes(reversed(chunk))
    return _tlv(0x06, bytes(out))


GET, GETNEXT, RESPONSE, GETBULK = 0xA0, 0xA1, 0xA2, 0xA5


def build_request(pdu_type, version, community, request_id, oids, max_repetitions=20):
    """version 0 = SNMPv1, 1 = SNMPv2c. GETBULK (v2c only) asks for `max_repetitions` rows after each OID."""
    binds = b"".join(_tlv(0x30, _oid(oid) + _tlv(0x05, b"")) for oid in oids)
    if pdu_type == GETBULK:
        head = _int(request_id) + _int(0) + _int(max_repetitions)
    else:
        head = _int(request_id) + _int(0) + _int(0)
    pdu = _tlv(pdu_type, head + _tlv(0x30, binds))
    return _tlv(0x30, _int(version) + _tlv(0x04, community.encode("utf-8")) + pdu)


def _read(data, pos):
    """(tag, content start, content end) of the element at `pos`."""
    if pos + 2 > len(data):
        raise SnmpError("the answer is cut off")
    tag, first = data[pos], data[pos + 1]
    pos += 2
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            raise SnmpError("the answer has a bad length")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    else:
        length = first
    if pos + length > len(data):
        raise SnmpError("the answer is cut off")
    return tag, pos, pos + length


def _decode_int(raw, signed=True):
    return int.from_bytes(raw, "big", signed=signed) if raw else 0


def _decode_oid(raw):
    if not raw:
        raise SnmpError("empty object identifier")
    numbers, value = [], 0
    for byte in raw:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            numbers.append(value)
            value = 0
    first = numbers[0]
    head = (first // 40, first % 40) if first < 80 else (2, first - 80)
    return head + tuple(numbers[1:])


def _decode_value(tag, raw):
    if tag == 0x02:
        return _decode_int(raw)
    if tag == 0x04:
        return bytes(raw)
    if tag == 0x05:
        return None
    if tag == 0x06:
        return _decode_oid(raw)
    if tag == 0x40:
        return ".".join(str(b) for b in raw)
    if tag in (0x41, 0x42, 0x43, 0x46):
        return _decode_int(raw, signed=False)
    if tag == 0x80:
        return NoSuch("noSuchObject")
    if tag == 0x81:
        return NoSuch("noSuchInstance")
    if tag == 0x82:
        return NoSuch("endOfMibView")
    return bytes(raw)


def parse_response(data):
    """(request id, error status, [(oid, value), ...]) of an SNMP answer."""
    tag, start, end = _read(data, 0)
    if tag != 0x30:
        raise SnmpError("this is not an SNMP answer")
    pos = start
    tag, s, e = _read(data, pos)                  # version
    pos = e
    tag, s, e = _read(data, pos)                  # community
    pos = e
    tag, s, e = _read(data, pos)                  # PDU
    if tag != RESPONSE:
        raise SnmpError(f"unexpected SNMP message type 0x{tag:02x}")
    pos = s
    ids = []
    for _ in range(3):                            # request id, error status, error index
        tag, a, b = _read(data, pos)
        ids.append(_decode_int(data[a:b]))
        pos = b
    tag, a, b = _read(data, pos)                  # variable bindings
    binds, pos = [], a
    while pos < b:
        tag, vs, ve = _read(data, pos)
        inner = vs
        otag, os_, oe = _read(data, inner)
        vtag, vs2, ve2 = _read(data, oe)
        binds.append((_decode_oid(data[os_:oe]), _decode_value(vtag, data[vs2:ve2])))
        pos = ve
    return ids[0], ids[1], binds


# ----------------------------------------------------------------------------- UDP
def udp_send(address, payload, timeout):
    """Send one datagram and return the next datagram that comes back (tests replace this function)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(payload, address)
        while True:
            try:
                data, source = sock.recvfrom(65535)
            except socket.timeout:
                raise Timeout(f"no answer from {address[0]} within {timeout:g} s (check the address, the community string and that SNMP is switched on)")
            except OSError as exc:
                raise SnmpError(f"cannot reach {address[0]}: {exc}")
            if source[0] == address[0]:
                return data


SEND = udp_send


class Agent:
    """One switch: GET, GETNEXT / GETBULK and table walks."""

    def __init__(self, host, community, version="2c", timeout=3.0, retries=2):
        host = host.strip()
        port = 161
        if ":" in host:
            host, _, text = host.rpartition(":")
            port = int(text)
        self.host = host
        self.address = (_resolve(host), port)
        self.community = community
        self.v1 = str(version) == "1"
        self.timeout = float(timeout)
        self.retries = int(retries)
        self._next_id = int.from_bytes(os.urandom(3), "big")

    def for_vlan(self, vlan):
        """The same switch, asked about one VLAN: Cisco IOS answers the BRIDGE-MIB of that VLAN to "community@vlan". One retry is enough:
        a VLAN the switch does not know is simply not answered."""
        other = copy.copy(self)
        other.community = f"{self.community}@{vlan}"
        other.retries = min(self.retries, 1)
        return other

    def _ask(self, pdu_type, oids, max_repetitions=20):
        last = None
        for _ in range(self.retries + 1):
            self._next_id = (self._next_id + 1) % 0x7FFFFFFF
            payload = build_request(pdu_type, 0 if self.v1 else 1, self.community, self._next_id, oids, max_repetitions)
            try:
                raw = SEND(self.address, payload, self.timeout)
                request_id, status, binds = parse_response(raw)
            except Timeout as exc:
                last = exc
                continue
            if request_id != self._next_id:
                continue  # an answer to an earlier, repeated request
            if status == 2 and self.v1:
                return []  # v1: noSuchName means "no next object", the end of the table
            if status:
                raise SnmpError(f"{self.host} answered with SNMP error {status}")
            return binds
        raise last or Timeout(f"no answer from {self.host}")

    def get(self, *oids):
        """{oid: value} for the OIDs that exist (a missing one is left out)."""
        if self.v1:  # v1 refuses the whole request when one OID is missing: ask one by one
            out = {}
            for oid in oids:
                for found, value in self._ask(GET, [oid]):
                    if not isinstance(value, NoSuch):
                        out[found] = value
            return out
        return {oid: value for oid, value in self._ask(GET, oids) if not isinstance(value, NoSuch)}

    def walk(self, base):
        """[(oid suffix after `base`, value)] for the whole subtree below `base`."""
        rows, cursor = [], base
        while len(rows) < MAX_ROWS:
            binds = self._ask(GETNEXT if self.v1 else GETBULK, [cursor])
            if not binds:
                break
            progressed = False
            for oid, value in binds:
                if isinstance(value, NoSuch) or oid[:len(base)] != base:
                    return rows
                if oid <= cursor:
                    return rows  # an agent that goes backwards would loop us forever
                rows.append((oid[len(base):], value))
                cursor, progressed = oid, True
            if not progressed:
                break
        return rows


def _resolve(host):
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        try:
            return socket.gethostbyname(host)
        except OSError as exc:
            raise SnmpError(f"cannot resolve {host}: {exc}")


# ----------------------------------------------------------------------------- SNMPv3 (RFC 3414 user-based security, RFC 3826 AES)
# Plugins may only use the standard library, so the two ciphers are written out here: AES-128 (CFB mode, what every modern device
# offers) and DES (CBC mode, what older devices still default to). Messages are tiny, so speed does not matter; correctness is
# checked in the tests against the FIPS test vectors and against a reference implementation.
def _aes_tables():
    sbox, p, q = [0] * 256, 1, 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)         # p times 3 in GF(2^8)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09                                                 # q divided by 3
        rot = lambda x, n: ((x << n) | (x >> (8 - n))) & 0xFF
        sbox[p] = q ^ rot(q, 1) ^ rot(q, 2) ^ rot(q, 3) ^ rot(q, 4) ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


_SBOX = _aes_tables()


def _xtime(x):
    return ((x << 1) ^ 0x1B) & 0xFF if x & 0x80 else x << 1


def _aes_key_schedule(key):
    if len(key) not in (16, 24, 32):
        raise SnmpError("an AES key is 16, 24 or 32 bytes")
    words = [list(key[i:i + 4]) for i in range(0, len(key), 4)]
    n, rounds, rcon = len(key) // 4, len(key) // 4 + 6, 1
    for i in range(n, 4 * (rounds + 1)):
        word = list(words[i - 1])
        if i % n == 0:
            word = [_SBOX[b] for b in word[1:] + word[:1]]
            word[0] ^= rcon
            rcon = _xtime(rcon)
        elif n > 6 and i % n == 4:
            word = [_SBOX[b] for b in word]
        words.append([a ^ b for a, b in zip(words[i - n], word)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(rounds + 1)]


def aes_encrypt_block(round_keys, block):
    state = [b ^ k for b, k in zip(block, round_keys[0])]
    for r in range(1, len(round_keys)):
        state = [_SBOX[b] for b in state]
        state = [state[(i + 4 * (i % 4)) % 16] for i in range(16)]    # ShiftRows (column-major state)
        if r < len(round_keys) - 1:                                    # MixColumns, not in the last round
            mixed = []
            for c in range(0, 16, 4):
                a = state[c:c + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                mixed += [a[i] ^ t ^ _xtime(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
            state = mixed
        state = [b ^ k for b, k in zip(state, round_keys[r])]
    return bytes(state)


def aes_cfb(key, iv, data, decrypt=False):
    """AES in 128-bit cipher feedback mode (the same block function encrypts and decrypts)."""
    round_keys, out, feedback = _aes_key_schedule(key), bytearray(), bytes(iv)
    for at in range(0, len(data), 16):
        chunk = data[at:at + 16]
        stream = aes_encrypt_block(round_keys, feedback)
        piece = bytes(a ^ b for a, b in zip(chunk, stream))
        out += piece
        feedback = chunk if decrypt else piece
    return bytes(out)


_IP = (58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
       57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7)
_FP = (40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
       36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25)
_E = (32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
      16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1)
_P = (16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25)
_PC1 = (57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4)
_PC2 = (14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32)
_SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)
_S = (
    (14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13),
    (15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9),
    (10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12),
    (7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14),
    (2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3),
    (12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13),
    (4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12),
    (13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11),
)


def _bits(data, width):
    return [(data >> (width - 1 - i)) & 1 for i in range(width)]


def _number(bits):
    value = 0
    for b in bits:
        value = (value << 1) | b
    return value


def _des_subkeys(key):
    bits = _bits(int.from_bytes(key, "big"), 64)
    permuted = [bits[i - 1] for i in _PC1]
    left, right, keys = permuted[:28], permuted[28:], []
    for shift in _SHIFTS:
        left, right = left[shift:] + left[:shift], right[shift:] + right[:shift]
        merged = left + right
        keys.append([merged[i - 1] for i in _PC2])
    return keys


def des_block(subkeys, block, decrypt=False):
    bits = [b for b in _bits(int.from_bytes(block, "big"), 64)]
    bits = [bits[i - 1] for i in _IP]
    left, right = bits[:32], bits[32:]
    for key in (reversed(subkeys) if decrypt else subkeys):
        expanded = [right[i - 1] ^ k for i, k in zip(_E, key)]
        out = []
        for box in range(8):
            chunk = expanded[box * 6:box * 6 + 6]
            row, col = (chunk[0] << 1) | chunk[5], _number(chunk[1:5])
            out += _bits(_S[box][row * 16 + col], 4)
        mixed = [out[i - 1] for i in _P]
        left, right = right, [a ^ b for a, b in zip(left, mixed)]
    final = right + left
    return _number([final[i - 1] for i in _FP]).to_bytes(8, "big")


def des_cbc(key, iv, data, decrypt=False):
    if len(data) % 8:
        raise SnmpError("DES needs whole 8-byte blocks")
    subkeys, out, previous = _des_subkeys(key), bytearray(), bytes(iv)
    for at in range(0, len(data), 8):
        chunk = data[at:at + 8]
        if decrypt:
            out += bytes(a ^ b for a, b in zip(des_block(subkeys, chunk, True), previous))
            previous = chunk
        else:
            previous = des_block(subkeys, bytes(a ^ b for a, b in zip(chunk, previous)))
            out += previous
    return bytes(out)


V3_AUTH = {          # name: (hash, length of the digest that is sent)
    "MD5": ("md5", 12), "SHA": ("sha1", 12), "SHA224": ("sha224", 16), "SHA256": ("sha256", 24), "SHA384": ("sha384", 32), "SHA512": ("sha512", 48),
}
V3_PRIV = ("AES", "DES")
REPORT = 0xA8
MAX_MESSAGE = 65507
_REPORT_TEXT = {
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0): "the device does not allow this security level (check the authentication and privacy settings)",
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0): "the clocks differ",
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0): "the user name is not known to the device",
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0): "the engine id is not known",
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0): "the authentication failed (wrong password or protocol)",
    (1, 3, 6, 1, 6, 3, 15, 1, 1, 6, 0): "the device could not decrypt the request (wrong privacy password or protocol)",
}
NOT_IN_WINDOW = (1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0)
UNKNOWN_ENGINE = (1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0)


def password_to_key(password, algo):
    """RFC 3414 A.2: the password repeated up to one megabyte and hashed."""
    h = hashlib.new(algo)
    h.update((password * (1048576 // len(password) + 1))[:1048576])
    return h.digest()


def localize(key, engine_id, algo):
    return hashlib.new(algo, key + engine_id + key).digest()


def _octets(value):
    return _tlv(0x04, value)


def _sequence(*parts):
    return _tlv(0x30, b"".join(parts))


class _Stale(Exception):
    """An answer to an earlier request."""


class AgentV3(Agent):
    """The Agent interface (get, walk) over SNMPv3 with a user name, optional authentication and optional privacy."""

    def __init__(self, host, user, auth_proto="", auth_password="", priv_proto="", priv_password="", timeout=3.0, retries=2):
        super().__init__(host, "", "2c", timeout, retries)
        if not user:
            raise SnmpError("enter the SNMPv3 user name")
        if auth_proto and auth_proto not in V3_AUTH:
            raise SnmpError("the authentication protocol must be one of " + ", ".join(V3_AUTH))
        if priv_proto and priv_proto not in V3_PRIV:
            raise SnmpError("the privacy protocol must be AES or DES")
        if priv_proto and not auth_proto:
            raise SnmpError("encryption needs authentication as well")
        if (auth_proto and len(auth_password) < 8) or (priv_proto and len(priv_password) < 8):
            raise SnmpError("SNMPv3 passwords are at least 8 characters")
        self.v1 = False
        self.user = user.encode()
        self.auth_proto, self.priv_proto = auth_proto, priv_proto
        self._auth_pw, self._priv_pw = auth_password.encode(), priv_password.encode()
        self._ku_auth = self._ku_priv = None
        self._engine = None                      # (engine id, boots, time at learning, monotonic at learning)
        self._auth_key = self._priv_key = None
        self._salt = int.from_bytes(os.urandom(8), "big")
        self.context = b""

    def for_vlan(self, vlan):
        """Cisco reaches the BRIDGE-MIB of one VLAN in SNMPv3 through the context "vlan-<n>"."""
        other = copy.copy(self)
        other.context = f"vlan-{vlan}".encode()
        other.retries = min(self.retries, 1)
        return other

    # ------------------------------------------------------------------ keys and clock
    def _keys(self, engine_id):
        if not self.auth_proto:
            return
        algo = V3_AUTH[self.auth_proto][0]
        if self._ku_auth is None:
            self._ku_auth = password_to_key(self._auth_pw, algo)
            self._ku_priv = password_to_key(self._priv_pw, algo) if self.priv_proto else None
        self._auth_key = localize(self._ku_auth, engine_id, algo)
        self._priv_key = localize(self._ku_priv, engine_id, algo) if self._ku_priv else None

    def _now(self):
        _eid, boots, learned, mono = self._engine
        return boots, int(learned + (time.monotonic() - mono))

    # ------------------------------------------------------------------ messages
    def _message(self, pdu, discover=False):
        msg_id = int.from_bytes(os.urandom(3), "big") + 1
        if discover:
            engine, boots, secs, flags, auth, priv_params, user = b"", 0, 0, 0x04, b"", b"", b""
        else:
            engine = self._engine[0]
            boots, secs = self._now()
            flags = 0x04 | (1 if self.auth_proto else 0) | (2 if self.priv_proto else 0)
            auth = b"\x00" * V3_AUTH[self.auth_proto][1] if self.auth_proto else b""
            priv_params, user = b"", self.user
        scoped = _sequence(_octets(engine), _octets(b"" if discover else self.context), pdu)
        if self.priv_proto and not discover:
            if self.priv_proto == "AES":
                self._salt = (self._salt + 1) % (1 << 64)
                priv_params = struct.pack(">Q", self._salt)
                data = aes_cfb(self._priv_key[:16], struct.pack(">II", boots, secs) + priv_params, scoped)
            else:
                self._salt = (self._salt + 1) % (1 << 32)
                priv_params = struct.pack(">II", boots & 0xFFFFFFFF, self._salt)
                iv = bytes(a ^ b for a, b in zip(self._priv_key[8:16], priv_params))
                data = des_cbc(self._priv_key[:8], iv, scoped + b"\x00" * (-len(scoped) % 8))
            payload = _octets(data)
        else:
            payload = scoped
        usm = _sequence(_octets(engine), _int(boots), _int(secs), _octets(user), _octets(auth), _octets(priv_params))
        header = _sequence(_int(msg_id), _int(MAX_MESSAGE), _octets(bytes([flags])), _int(3))
        message = _sequence(_int(3), header, _octets(usm), payload)
        if self.auth_proto and not discover:
            algo, size = V3_AUTH[self.auth_proto]
            digest = hmac.new(self._auth_key, message, algo).digest()[:size]
            at = message.rfind(b"\x00" * size)
            message = message[:at] + digest + message[at + size:]
        return message, msg_id

    def _parse(self, data, msg_id):
        """(pdu tag, request id, error status, binds, (engine id, boots, time)) of an SNMPv3 answer."""
        tag, start, end = _read(data, 0)
        if tag != 0x30:
            raise SnmpError("this is not an SNMP answer")
        _t, a, b = _read(data, start)                     # version
        if _decode_int(data[a:b]) != 3:
            raise SnmpError("the device answered with another SNMP version")
        _t, hs, he = _read(data, b)                       # global data: message id, max size, flags, security model
        _t, a, b = _read(data, hs)
        got_id = _decode_int(data[a:b])
        _t, a, b = _read(data, b)
        _t, a, b = _read(data, b)
        flags = data[a] if b > a else 0
        _t, a, b = _read(data, he)                        # security parameters: an octet string holding a sequence
        pos = b
        _t, q, _e = _read(data, a)
        parts = []
        for _ in range(6):
            tt, x, y = _read(data, q)
            parts.append((x, y))
            q = y
        engine = bytes(data[parts[0][0]:parts[0][1]])
        boots, secs = _decode_int(data[parts[1][0]:parts[1][1]]), _decode_int(data[parts[2][0]:parts[2][1]])
        auth_at, priv_params = parts[4], bytes(data[parts[5][0]:parts[5][1]])
        if flags & 0x01 and self._auth_key is not None:
            algo, size = V3_AUTH[self.auth_proto]
            if auth_at[1] - auth_at[0] != size:
                raise SnmpError("the answer could not be verified")
            zeroed = data[:auth_at[0]] + b"\x00" * size + data[auth_at[1]:]
            if not hmac.compare_digest(hmac.new(self._auth_key, zeroed, algo).digest()[:size], bytes(data[auth_at[0]:auth_at[1]])):
                raise SnmpError("the answer failed its authentication check (wrong password?)")
        tag, ps, pe = _read(data, pos)                    # the scoped PDU (plain) or an encrypted octet string
        if tag == 0x04:
            if not (flags & 0x02) or self._priv_key is None:
                raise SnmpError("the device answered with an encrypted message we cannot read")
            cipher_text = bytes(data[ps:pe])
            if self.priv_proto == "AES":
                scoped = aes_cfb(self._priv_key[:16], struct.pack(">II", boots, secs) + priv_params, cipher_text, decrypt=True)
            else:
                iv = bytes(x ^ y for x, y in zip(self._priv_key[8:16], priv_params))
                scoped = des_cbc(self._priv_key[:8], iv, cipher_text[:len(cipher_text) // 8 * 8], decrypt=True)
        else:
            scoped = bytes(data[pos:pe])
        tag, ss, se = _read(scoped, 0)
        if tag != 0x30:
            raise SnmpError("the answer could not be decrypted (wrong privacy password?)")
        _t, x, y = _read(scoped, ss)                      # context engine id
        _t, x, y = _read(scoped, y)                       # context name
        pdu_tag, x, y = _read(scoped, y)
        q, ids = x, []
        for _ in range(3):
            _t, a, b = _read(scoped, q)
            ids.append(_decode_int(scoped[a:b]))
            q = b
        _t, a, b = _read(scoped, q)
        binds, q = [], a
        while q < b:
            _t, vs, ve = _read(scoped, q)
            _ot, os_, oe = _read(scoped, vs)
            vt, v1, v2 = _read(scoped, oe)
            binds.append((_decode_oid(scoped[os_:oe]), _decode_value(vt, scoped[v1:v2])))
            q = ve
        if got_id != msg_id and pdu_tag != REPORT:
            raise _Stale()
        return pdu_tag, ids[0], ids[1], binds, (engine, boots, secs)

    def _discover(self):
        request = _tlv(GET, _int(0) + _int(0) + _int(0) + _sequence())
        last = None
        for _ in range(self.retries + 1):
            message, msg_id = self._message(request, discover=True)
            try:
                raw = SEND(self.address, message, self.timeout)
                _tag, _rid, _st, _binds, (engine, boots, secs) = self._parse(raw, msg_id)
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

    def _ask(self, pdu_type, oids, max_repetitions=20):
        if self._engine is None:
            self._discover()
        binds = b"".join(_sequence(_oid(o), _tlv(0x05, b"")) for o in oids)
        resynced, last = False, None
        for _ in range(self.retries + 2):
            self._next_id = (self._next_id + 1) % 0x7FFFFFFF
            head = _int(self._next_id) + _int(0) + _int(max_repetitions if pdu_type == GETBULK else 0)
            message, msg_id = self._message(_tlv(pdu_type, head + _sequence(binds)))
            try:
                raw = SEND(self.address, message, self.timeout)
                tag, _rid, status, answer, _t = self._parse(raw, msg_id)
            except _Stale:
                continue
            except Timeout as exc:
                last = exc
                continue
            if tag == REPORT:
                what = answer[0][0] if answer else None
                if what in (NOT_IN_WINDOW, UNKNOWN_ENGINE) and not resynced:
                    resynced, self._engine = True, None
                    self._discover()
                    continue
                text = f"{self.host}: {_REPORT_TEXT.get(what, 'the device refused the request')}"
                raise (AuthRefused if what in _AUTH_REPORTS else SnmpError)(text)
            if status == 16:
                raise AuthRefused(f"{self.host}: the user is not allowed to read (its security level or view on the device does not permit it)")
            if status:
                raise SnmpError(f"{self.host} answered with SNMP error {status}")
            return answer
        raise Timeout(f"no answer from {self.host} within {self.timeout:g} s. For SNMPv3 check the address, the user name and both passwords: a device does not answer at all when the encryption password is wrong")


_AUTH_REPORTS = {k for k in _REPORT_TEXT if k[-2] in (1, 3, 5, 6)}   # unsupported level, unknown user, wrong password, cannot decrypt


def make_agent(host, community, config, timeout):
    """The right client for the plugin's SNMP version setting: v1 / v2c with a community, or v3 with a user."""
    version = str(config.get("version") or "2c")
    if version == "3":
        auth, priv = (str(config.get(k) or "") for k in ("v3_auth", "v3_priv"))
        return AgentV3(host, str(config.get("v3_user") or "").strip(), "" if auth == "none" else auth, str(config.get("v3_auth_password") or ""),
                       "" if priv == "none" else priv, str(config.get("v3_priv_password") or ""), timeout)
    return Agent(host, community, version, timeout)


# ----------------------------------------------------------------------------- reading one switch
def _mac(raw):
    """"aa:bb:..." for a 6-byte value; all-zero and broadcast addresses are not real ones."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 6 or set(raw) in ({0}, {255}):
        return None
    return ":".join(f"{b:02x}" for b in raw)


def _text(raw, limit=100):
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).decode("utf-8", "replace").replace("\x00", "").strip()[:limit]
    return ""


class Switch:
    """What one switch tells: identity, ports, the MAC address table and its LLDP neighbours."""

    def __init__(self, agent, vlan_indexing="auto"):
        self.agent = agent
        self.vlan_indexing = vlan_indexing
        self.cisco = False
        self.vlans_read = 0
        self.cdp_ok = False
        self.host = agent.host
        self.descr = self.name = ""
        self.mac = None
        self.macs = set()
        self.ports = {}            # ifIndex -> name
        self.bridge_port = {}      # bridge port number -> ifIndex
        self.fdb = {}              # mac -> ifIndex (learned addresses only)
        self.neighbours = {}       # ifIndex -> {"mac": chassis MAC or None, "name": system name, "port": remote port}
        self.fdb_source = None
        self.lldp_ok = False

    def read(self):
        got = self.agent.get(SYS_DESCR, SYS_NAME, BRIDGE_ADDRESS, SYS_OBJECT_ID)
        self.descr, self.name = _text(got.get(SYS_DESCR), 200), _text(got.get(SYS_NAME), 100)
        object_id = got.get(SYS_OBJECT_ID)
        self.cisco = isinstance(object_id, tuple) and object_id[:len(CISCO_ENTERPRISE)] == CISCO_ENTERPRISE
        self.mac = _mac(got.get(BRIDGE_ADDRESS))
        self.ports = {suffix[0]: _text(value, 60) for suffix, value in self.agent.walk(IF_NAME) if suffix and _text(value, 60)}
        for suffix, value in self.agent.walk(IF_DESCR):
            self.ports.setdefault(suffix[0], _text(value, 60))
        for suffix, value in self.agent.walk(IF_PHYS):
            if _mac(value):
                self.macs.add(_mac(value))
        if self.mac:
            self.macs.add(self.mac)
        self.bridge_port = {suffix[0]: value for suffix, value in self.agent.walk(BASE_PORT_IFINDEX) if suffix and isinstance(value, int)}
        self._read_fdb()
        if self.vlan_indexing == "always" or (self.vlan_indexing == "auto" and self.cisco and self.fdb_source != "Q-BRIDGE-MIB"):
            self._read_vlan_fdb()
        self._read_lldp()
        self._read_cdp()
        return self

    def _if_of(self, bridge_port):
        return self.bridge_port.get(bridge_port, bridge_port)  # without the mapping table the numbers are usually the same

    def _read_fdb(self):
        rows = [((s[-6:], v)) for s, v in self.agent.walk(QBRIDGE_FDB_PORT) if len(s) == 7 and isinstance(v, int)]
        status = {tuple(s[-6:]): v for s, v in self.agent.walk(QBRIDGE_FDB_STATUS) if len(s) == 7}
        self.fdb_source = "Q-BRIDGE-MIB"
        if not rows:
            rows = [(s[-6:], v) for s, v in self.agent.walk(BRIDGE_FDB_PORT) if len(s) == 6 and isinstance(v, int)]
            status = {tuple(s[-6:]): v for s, v in self.agent.walk(BRIDGE_FDB_STATUS) if len(s) == 6}
            self.fdb_source = "BRIDGE-MIB"
        for octets, port in rows:
            mac = _mac(bytes(octets))
            if not mac or port <= 0 or status.get(tuple(octets), FDB_LEARNED) != FDB_LEARNED:
                continue
            self.fdb.setdefault(mac, self._if_of(port))

    def _vlans(self):
        """The VLANs of a Cisco switch: the operational ones of CISCO-VTP-MIB, else the VLAN interfaces (Vlan25) it has, always VLAN 1."""
        found = {s[-1] for s, v in self.agent.walk(VTP_VLAN_STATE) if len(s) >= 2 and v == 1}
        if not found:
            found = {int(m.group(1)) for name in self.ports.values() for m in [re.fullmatch(r"(?i)vl(?:an)?\s?(\d+)", name)] if m}
        found.add(1)
        return sorted(v for v in found if 1 <= v <= 4094 and v not in RESERVED_VLANS)[:MAX_VLANS]

    def _read_vlan_fdb(self):
        """The MAC address table of every VLAN, through community@vlan (Cisco IOS has no single table). A VLAN that does not answer is skipped."""
        silent = 0
        for vlan in self._vlans():
            agent = self.agent.for_vlan(vlan)
            try:
                mapping = {s[0]: v for s, v in agent.walk(BASE_PORT_IFINDEX) if s and isinstance(v, int)}
                rows = [(s[-6:], v) for s, v in agent.walk(BRIDGE_FDB_PORT) if len(s) == 6 and isinstance(v, int)]
                status = {tuple(s[-6:]): v for s, v in agent.walk(BRIDGE_FDB_STATUS) if len(s) == 6}
            except Timeout:
                silent += 1
                if silent >= 3:          # three in a row: this switch does not do community indexing, do not wait for every VLAN
                    break
                continue
            silent = 0
            self.vlans_read += 1
            for octets, port in rows:
                mac = _mac(bytes(octets))
                if not mac or port <= 0 or status.get(tuple(octets), FDB_LEARNED) != FDB_LEARNED:
                    continue
                self.fdb.setdefault(mac, mapping.get(port, self._if_of(port)))
        if self.vlans_read:
            self.fdb_source = f"BRIDGE-MIB per VLAN ({self.vlans_read} VLANs)"

    def _read_cdp(self):
        """Cisco Discovery Protocol neighbours. CDP names the neighbour (device id, management address) but gives no MAC address."""
        ids = {s: _text(v, 80) for s, v in self.agent.walk(CDP_DEVICE_ID) if len(s) == 2}
        if not ids:
            return
        self.cdp_ok = True
        ports = {s: _text(v, 60) for s, v in self.agent.walk(CDP_DEVICE_PORT) if len(s) == 2}
        addresses = {s: ".".join(str(b) for b in v) for s, v in self.agent.walk(CDP_ADDRESS) if len(s) == 2 and isinstance(v, (bytes, bytearray)) and len(v) == 4}
        for key, name in sorted(ids.items()):
            index = key[0]
            known = self.neighbours.get(index)
            ip = addresses.get(key)
            if known is None:
                self.neighbours[index] = {"mac": None, "name": name, "port": ports.get(key, ""), "ip": ip}
            elif ip and not known.get("ip"):
                known["ip"] = ip
                known["name"] = known.get("name") or name

    def _read_lldp(self):
        chassis = {s[1:]: v for s, v in self.agent.walk(LLDP_CHASSIS_ID) if len(s) >= 3}
        if not chassis:
            return
        self.lldp_ok = True
        subtype = {s[1:]: v for s, v in self.agent.walk(LLDP_CHASSIS_SUBTYPE) if len(s) >= 3}
        remote_port = {s[1:]: _text(v, 60) for s, v in self.agent.walk(LLDP_PORT_ID) if len(s) >= 3}
        names = {s[1:]: _text(v, 60) for s, v in self.agent.walk(LLDP_SYS_NAME) if len(s) >= 3}
        # lldpLocPortId says which interface a local LLDP port number is; fall back to "the same number"
        local = {s[0]: _text(v, 60) for s, v in self.agent.walk(LLDP_LOCAL_PORT + (3,)) if len(s) >= 1}
        by_name = {name: index for index, name in self.ports.items()}
        for key, raw in chassis.items():
            port_number = key[0]
            index = by_name.get(local.get(port_number, ""), port_number)
            mac = _mac(raw) if subtype.get(key) in (4, None) else None
            self.neighbours[index] = {"mac": mac, "name": names.get(key, ""), "port": remote_port.get(key, "")}

    def port_name(self, index):
        return self.ports.get(index) or f"port {index}"


# ----------------------------------------------------------------------------- turning several switches into a topology
def parse_hosts(config):
    """[(switch address, read community)]: the rows of the server list (a row without its own community uses the default one),
    or the list of addresses of an older Netlens."""
    default = str(config.get("community") or "")
    rows = config.get("servers")
    if isinstance(rows, list):
        return [(str(r["host"]).strip(), str(r.get("community") or "") or default) for r in rows if isinstance(r, dict) and str(r.get("host") or "").strip()]
    return [(h, default) for h in re.split(r"[,;\s]+", str(config.get("hosts") or "").strip()) if h]


def read_switches(config):
    hosts = parse_hosts(config)
    if not hosts:
        raise ValueError("enter the address of at least one switch")
    for host, community in hosts:
        if not community and str(config.get("version") or "2c") != "3":
            raise ValueError(f"{host}: enter the read community (on the switch's line or as the default one)")
    timeout = config.get("timeout") or 3
    switches, problems, refused = [], [], []
    for host, community in hosts:
        try:
            switches.append(Switch(make_agent(host, community, config, timeout), config.get("vlan_indexing") or "auto").read())
        except (SnmpError, ValueError) as exc:
            problems.append(f"{host}: {exc}")
            refused.append(isinstance(exc, AuthRefused))
    if not switches:
        raise (AuthRefused if refused and all(refused) else SnmpError)("; ".join(problems) or "no switch answered")
    return switches, problems


def _short(name):
    """A device name as CDP and LLDP spell it, reduced for comparing: "Core-SW.example.net" and "core-sw(FOC1234)" both give "core-sw"."""
    return re.split(r"[.(]", str(name or "").strip().lower(), maxsplit=1)[0]


def to_topology(switches, root_host=None):
    nodes, owner, switch_of = [], {}, {}
    by_name, by_ip = {}, {}
    for sw in switches:
        mac = sw.mac or next(iter(sorted(sw.macs)), None)
        if not mac:
            continue
        node = {"mac": mac, "macs": sorted(sw.macs | {mac}), "ip": sw.agent.address[0], "name": sw.name or sw.host, "model": sw.descr[:100] or None, "role": "switch", "parent_mac": None}
        nodes.append(node)
        switch_of[id(node)] = sw
        for m in node["macs"]:
            owner.setdefault(m, node)
        if _short(node["name"]):
            by_name.setdefault(_short(node["name"]), node)
        by_ip.setdefault(node["ip"], node)

    # which switches face each other (LLDP), and which ports are those uplinks / downlinks
    links = defaultdict(set)      # node mac -> {neighbour node mac}
    trunk = defaultdict(set)      # node mac -> {ifIndex that leads to another polled switch}
    for node in nodes:
        sw = switch_of[id(node)]
        for index, neighbour in sw.neighbours.items():
            other = owner.get(neighbour["mac"]) if neighbour["mac"] else None
            if other is None and neighbour.get("ip"):                  # CDP: the neighbour's management address
                other = by_ip.get(neighbour["ip"])
            if other is None and _short(neighbour.get("name")):        # CDP / LLDP without a usable address: the name
                other = by_name.get(_short(neighbour["name"]))
            if other is not None and other is not node:
                links[node["mac"]].add(other["mac"])
                trunk[node["mac"]].add(index)

    # the tree: from the core switch (configured, else the one with most neighbours), breadth first over the LLDP links
    by_mac = {n["mac"]: n for n in nodes}
    root = None
    if root_host:
        root = next((n for n in nodes if switch_of[id(n)].host == root_host or n["ip"] == root_host), None)
    if root is None and nodes:
        root = max(nodes, key=lambda n: (len(links[n["mac"]]), -nodes.index(n)))
    seen = {root["mac"]} if root else set()
    queue = [root["mac"]] if root else []
    while queue:
        current = queue.pop(0)
        for other in sorted(links[current]):
            if other not in seen:
                seen.add(other)
                by_mac[other]["parent_mac"] = current
                queue.append(other)

    # clients: a MAC on a port that is not an uplink; seen on several switches, the port with the fewest MACs is the real one
    node_macs = set(owner)
    seen_on = defaultdict(list)       # mac -> [(node, ifIndex, MACs on that port)]
    for node in nodes:
        sw = switch_of[id(node)]
        per_port = Counter(index for mac, index in sw.fdb.items() if index not in trunk[node["mac"]])
        for mac, index in sw.fdb.items():
            if index in trunk[node["mac"]] or mac in node_macs or int(mac[:2], 16) & 1:
                continue
            seen_on[mac].append((node, index, per_port[index], sw))
    clients = []
    for mac in sorted(seen_on):
        node, index, _, sw = min(seen_on[mac], key=lambda c: (c[2], nodes.index(c[0])))
        clients.append({"mac": mac, "node_mac": node["mac"], "medium": "wired", "port": sw.port_name(index)})
    return {"nodes": nodes, "clients": clients}


# ----------------------------------------------------------------------------- plugin entry points
def test(config):
    switches, problems = read_switches(config)
    macs = sum(len(s.fdb) for s in switches)
    text = f"Connected to {len(switches)} switch(es), {macs} learned MAC address(es)"
    if any(not s.fdb for s in switches):
        text += "; one switch has an empty address table"
    if problems:
        text += ". Not reachable: " + "; ".join(problems)
    return {"message": text}


def fetch(config):
    switches, problems = read_switches(config)
    if problems and len(problems) == len(parse_hosts(config)):
        raise SnmpError("; ".join(problems))
    return to_topology(switches, (config.get("root") or "").strip() or None)


# ----------------------------------------------------------------------------- diagnostic (for the plugin's author)
def _problem(exc):
    """The error text for a diagnostic report, without any server address (URL, IP address, host:port or host name)."""
    text = re.sub(r"https?://\S+", "<ip>", str(exc))
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", "<ip>", text)
    text = re.sub(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*:\d{2,5}\b", "<ip>", text)
    text = re.sub(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", "<ip>", text)
    return type(exc).__name__ + ": " + text[:300]


def diagnose(config):
    """What each switch answers, counted and typed; names, MAC addresses and IP addresses are left out."""
    report = {"switches": []}
    hosts = parse_hosts(config)
    report["host_count"] = len(hosts)
    switches = []
    for host, community in hosts:
        entry = {"steps": {}}
        report["switches"].append(entry)
        try:
            agent = make_agent(host, community, config, config.get("timeout") or 3)
        except (SnmpError, ValueError) as exc:
            entry["error"] = _problem(exc)
            continue

        def step(name, call):
            try:
                entry["steps"][name] = {"ok": True, "result": call()}
            except Exception as exc:  # noqa: BLE001 - the point is to record what failed
                entry["steps"][name] = {"ok": False, "error": _problem(exc)}

        step("system", lambda: (lambda got: {"sysDescr": SYS_DESCR in got, "sysName": SYS_NAME in got, "bridge_mac": BRIDGE_ADDRESS in got,
                                              "enterprise": (got.get(SYS_OBJECT_ID) or ())[6:7] if isinstance(got.get(SYS_OBJECT_ID), tuple) else None})(agent.get(SYS_DESCR, SYS_NAME, BRIDGE_ADDRESS, SYS_OBJECT_ID)))
        step("sysDescr", lambda: re.sub(r"[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}", "<mac>", _text(agent.get(SYS_DESCR).get(SYS_DESCR), 120)))
        for name, base in (("ifName", IF_NAME), ("ifDescr", IF_DESCR), ("ifPhysAddress", IF_PHYS), ("dot1dBasePortIfIndex", BASE_PORT_IFINDEX),
                           ("dot1qTpFdbPort", QBRIDGE_FDB_PORT), ("dot1qTpFdbStatus", QBRIDGE_FDB_STATUS), ("dot1dTpFdbPort", BRIDGE_FDB_PORT),
                           ("lldpRemChassisId", LLDP_CHASSIS_ID), ("lldpRemSysName", LLDP_SYS_NAME), ("lldpLocPortId", LLDP_LOCAL_PORT + (3,)),
                           ("vtpVlanState", VTP_VLAN_STATE), ("cdpCacheDeviceId", CDP_DEVICE_ID), ("cdpCacheAddress", CDP_ADDRESS)):
            step(name, lambda base=base: {"rows": len(agent.walk(base))})
        try:
            sw = Switch(agent, config.get("vlan_indexing") or "auto").read()
            switches.append(sw)
            entry["summary"] = {
                "ports": len(sw.ports), "learned_macs": len(sw.fdb), "fdb_source": sw.fdb_source, "own_macs": len(sw.macs),
                "lldp": sw.lldp_ok, "cdp": sw.cdp_ok, "cisco": sw.cisco, "vlans_read": sw.vlans_read, "neighbours": len(sw.neighbours), "macs_per_port_max": max(Counter(sw.fdb.values()).values(), default=0),
            }
        except Exception as exc:  # noqa: BLE001
            entry["error"] = _problem(exc)
    if switches:
        out = to_topology(switches, (config.get("root") or "").strip() or None)
        report["result"] = {
            "nodes": len(out["nodes"]), "nodes_with_parent": sum(1 for n in out["nodes"] if n["parent_mac"]),
            "clients": len(out["clients"]), "ports_named": sum(1 for c in out["clients"] if not c["port"].startswith("port ")),
        }
    return report
