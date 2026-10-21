"""SNMPv3 in the SNMP switch plugin: the two ciphers written out in pure Python (checked against the FIPS vectors and against the
`cryptography` package), and the plugin's v3 client against the simulated device of test_snmpv3 (and v2c still working next to it)."""

import importlib.util
import os
from pathlib import Path

import pytest

from tests import test_plugin_snmp as sim
from tests.test_snmpv3 import Device

plugin = sim.plugin


def test_aes_matches_the_fips_197_vector():
    key = bytes(range(16))
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert plugin.aes_encrypt_block(plugin._aes_key_schedule(key), block).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
    key256 = bytes(range(32))
    assert plugin.aes_encrypt_block(plugin._aes_key_schedule(key256), block).hex() == "8ea2b7ca516745bfeafc49904b496089"
    key192 = bytes(range(24))
    assert plugin.aes_encrypt_block(plugin._aes_key_schedule(key192), block).hex() == "dda97ca4864cdfe06eaf70a0ec0d7191"


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 31, 64, 100, 257])
def test_aes_cfb_matches_a_reference_implementation(size):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key, iv, data = os.urandom(16), os.urandom(16), os.urandom(size)
    expected = Cipher(algorithms.AES(key), modes.CFB(iv)).encryptor()
    reference = expected.update(data) + expected.finalize()
    assert plugin.aes_cfb(key, iv, data) == reference
    assert plugin.aes_cfb(key, iv, reference, decrypt=True) == data


def test_des_matches_the_classic_vector():
    subkeys = plugin._des_subkeys(bytes.fromhex("133457799bbcdff1"))
    assert plugin.des_block(subkeys, bytes.fromhex("0123456789abcdef")).hex() == "85e813540f0ab405"
    assert plugin.des_block(subkeys, bytes.fromhex("85e813540f0ab405"), decrypt=True).hex() == "0123456789abcdef"


@pytest.mark.parametrize("blocks", [1, 2, 5, 13])
def test_des_cbc_matches_a_reference_implementation(blocks):
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

    key, iv, data = os.urandom(8), os.urandom(8), os.urandom(8 * blocks)
    enc = Cipher(TripleDES(key * 3), modes.CBC(iv)).encryptor()
    reference = enc.update(data) + enc.finalize()
    assert plugin.des_cbc(key, iv, data) == reference
    assert plugin.des_cbc(key, iv, reference, decrypt=True) == data


# ---------------------------------------------------------------- the client against a simulated device
V3 = {"hosts": "10.4.0.1", "version": "3", "v3_user": "monitor", "v3_auth": "SHA", "v3_auth_password": "authpass1234",
      "v3_priv": "AES", "v3_priv_password": "privpass1234", "timeout": 1}


@pytest.fixture
def device(monkeypatch):
    m = sim.switch_mib("V3SW", "Some switch", "c0:00:00:00:04:01", {1001: "p1", 1002: "p2"}, [(sim.TV, 1001), (sim.CAM, 1002)])
    d = Device(m)
    monkeypatch.setattr(plugin, "SEND", d.handle)
    return d


def test_a_switch_is_read_over_snmpv3_with_authentication_and_encryption(device):
    out = plugin.fetch(V3)
    assert {c["mac"]: c["port"] for c in out["clients"]} == {sim.TV: "p1", sim.CAM: "p2"}
    assert out["nodes"][0]["name"] == "V3SW" and device.requests > 5


def test_a_wrong_password_is_an_auth_failure_so_netlens_stops_asking(device):
    with pytest.raises(plugin.AuthRefused) as exc:
        plugin.fetch({**V3, "v3_auth_password": "not-the-password"})
    assert exc.value.auth_failed is True and "authentication failed" in str(exc.value)


def test_v3_settings_are_checked():
    with pytest.raises(plugin.SnmpError):
        plugin.AgentV3("10.4.0.1", "", "SHA", "authpass1234")                       # no user
    with pytest.raises(plugin.SnmpError):
        plugin.AgentV3("10.4.0.1", "u", "SHA", "short")
    with pytest.raises(plugin.SnmpError):
        plugin.AgentV3("10.4.0.1", "u", "", "", "AES", "privpass1234")
    with pytest.raises(plugin.SnmpError):
        plugin.AgentV3("10.4.0.1", "u", "WHIRLPOOL", "authpass1234")


def test_a_clock_that_drifts_is_resynchronised(device):
    agent = plugin.make_agent("10.4.0.1", "", V3, 1)
    agent.get(plugin.SYS_NAME)
    device.drift = 5000
    assert plugin.SYS_NAME in agent.get(plugin.SYS_NAME)


def test_v3_vlan_reading_uses_the_context_vlan_n():
    agent = plugin.AgentV3("10.4.0.1", "u", "", "")                              # no authentication: the context is visible in the message
    agent._engine = (b"engine", 1, 0, 0.0)
    message, _ = agent.for_vlan(25)._message(plugin._tlv(plugin.GET, b"x"))
    assert b"vlan-25" in message and b"vlan-25" not in agent._message(plugin._tlv(plugin.GET, b"x"))[0]


def test_v2c_still_works_next_to_v3(monkeypatch):
    m = sim.switch_mib("OLD", "x", "c0:00:00:00:04:02", {1001: "p1"}, [(sim.TV, 1001)])
    monkeypatch.setattr(plugin, "SEND", lambda address, payload, timeout: m.handle(payload))
    out = plugin.fetch({"hosts": "10.4.0.2", "community": "public", "version": "2c"})
    assert [c["mac"] for c in out["clients"]] == [sim.TV]
    assert isinstance(plugin.make_agent("10.4.0.2", "public", {"version": "2c"}, 1), plugin.Agent) and not isinstance(plugin.make_agent("10.4.0.2", "public", {"version": "2c"}, 1), plugin.AgentV3)


def test_manifest_offers_v3_settings():
    import json
    from app.plugins.contract import validate_manifest

    manifest = validate_manifest(json.loads((Path(plugin.__file__).parent / "plugin.json").read_text()))
    keys = {f["key"] for f in manifest["config"]}
    assert {"v3_user", "v3_auth", "v3_auth_password", "v3_priv", "v3_priv_password"} <= keys


def test_a_device_that_cannot_decrypt_stays_silent_and_the_message_says_why(monkeypatch):
    def silent(address, payload, timeout):
        raise plugin.Timeout("x")

    monkeypatch.setattr(plugin, "SEND", silent)
    agent = plugin.make_agent("10.4.0.1", "", {**V3, "timeout": 1}, 1)
    agent._engine = (b"engine", 1, 0, 0.0)                    # discovery worked, as it does on a real device; only the real requests are dropped
    agent._keys(b"engine")
    with pytest.raises(plugin.Timeout, match="encryption password is wrong"):
        agent.get(plugin.SYS_NAME)
