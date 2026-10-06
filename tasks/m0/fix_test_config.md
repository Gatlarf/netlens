Fix ONE defect in tests/test_config.py and output the COMPLETE corrected file. Defect: test_load_settings_ranges_normalisation expects ('172.16.0.0/24',) for input 172.16.5.10/24, but the correct normalised network is 172.16.5.0/24. Change only that expectation. Keep everything else identical.

CURRENT FILE:
"""Tests for app.config."""

from pathlib import Path

import pytest

from app.config import ConfigError, Settings, is_scannable_range, load_settings


def _base_env(**overrides):
    env = {"NETLENS_TOKEN": "secret-token"}
    env.update(overrides)
    return env


def test_load_settings_defaults():
    settings = load_settings(_base_env())
    assert settings.token == "secret-token"
    assert settings.ranges == ()
    assert settings.quick_interval == 900
    assert settings.deep_interval == 86400
    assert settings.terminal_enabled is True
    assert settings.snmp_community is None
    assert settings.bind_host == "0.0.0.0"
    assert settings.bind_port == 8080
    assert settings.data_dir == Path("/data")


def test_load_settings_token_required():
    with pytest.raises(ConfigError) as exc:
        load_settings({})
    assert "NETLENS_TOKEN" in str(exc.value)


def test_load_settings_token_non_empty():
    with pytest.raises(ConfigError) as exc:
        load_settings({"NETLENS_TOKEN": ""})
    assert "NETLENS_TOKEN" in str(exc.value)


def test_config_error_does_not_leak_token():
    env = {"NETLENS_TOKEN": "supersecret", "NETLENS_BIND": "bad"}
    with pytest.raises(ConfigError) as exc:
        load_settings(env)
    assert "supersecret" not in str(exc.value)
    assert "NETLENS_BIND" in str(exc.value)


def test_load_settings_ranges_empty():
    settings = load_settings(_base_env(NETLENS_RANGES=""))
    assert settings.ranges == ()


def test_load_settings_ranges_single():
    settings = load_settings(_base_env(NETLENS_RANGES="192.168.1.5/24"))
    assert settings.ranges == ("192.168.1.0/24",)


def test_load_settings_ranges_multiple():
    settings = load_settings(_base_env(NETLENS_RANGES="192.168.1.5/24,10.0.0.0/20"))
    assert settings.ranges == ("192.168.1.0/24", "10.0.0.0/20")


def test_load_settings_ranges_normalisation():
    settings = load_settings(_base_env(NETLENS_RANGES="172.16.5.10/24"))
    assert settings.ranges == ("172.16.0.0/24",)


def test_load_settings_ranges_public_rejected():
    with pytest.raises(ConfigError) as exc:
        load_settings(_base_env(NETLENS_RANGES="8.8.8.0/24"))
    assert "NETLENS_RANGES" in str(exc.value)


def test_load_settings_ranges_prefix_too_small():
    with pytest.raises(ConfigError) as exc:
        load_settings(_base_env(NETLENS_RANGES="10.0.0.0/8"))
    assert "NETLENS_RANGES" in str(exc.value)


def test_load_settings_ranges_link_local_rejected():
    with pytest.raises(ConfigError) as exc:
        load_settings(_base_env(NETLENS_RANGES="169.254.0.0/16"))
    assert "NETLENS_RANGES" in str(exc.value)


def test_load_settings_ranges_invalid_cidr():
    with pytest.raises(ConfigError) as exc:
        load_settings(_base_env(NETLENS_RANGES="garbage"))
    assert "NETLENS_RANGES" in str(exc.value)


def test_load_settings_quick_interval_default():
    settings = load_settings(_base_env())
    assert settings.quick_interval == 900


def test_load_settings_quick_interval_custom():
    settings = load_settings(_base_env(NETLENS_QUICK_INTERVAL="120"))
    assert settings.quick_interval == 120


def test_load_settings_quick_interval_too_small():
    with pytest.raises(ConfigError) as exc:
        load_settings(_base_env(NETLENS_QUICK_INTERVAL="59"))
    assert "NETLENS_QUICK_INTERVAL" in str(exc.value)


def test_load_settings_quick_interval_non_int():
    with pytest.raises(ConfigError) as exc:
        load_settings(_base_env(NETLENS_QUICK_INTERVAL="abc"))
    assert "NETLENS_QUICK_INTERVAL" in str(exc.value)


def test_load_settings_deep_interval_default():
    settings = load_settings(_base_env())
    assert settings.deep_interval == 86400


def test_load_settings_deep_interval_custom():
    settings = load_settings(_base_env(NETLENS_DEEP_INTERVAL="3600"))
    assert settings.deep_interval == 3600


def test_load_settings_deep_interval_too_small():
    with pytest.raises(ConfigError) as exc:
        load_settings(_base_env(NETLENS_DEEP_INTERVAL="30"))
    assert "NETLENS_DEEP_INTERVAL" in str(exc.value)


def test_load_settings_terminal_enabled_default():
    settings = load_settings(_base_env())
    assert settings.terminal_enabled is True


def test_load_settings_terminal_enabled_on():
    settings = load_settings(_base_env(NETLENS_TERMINAL="on"))
    assert settings.terminal_enabled is True


def test_load_settings_terminal_enabled_off():
    settings = load_settings(_base_env(NETLENS_TERMINAL="off"))
    assert settings.terminal_enabled is False


def test_load_settings_terminal_enabled_case_insensitive():
    settings = load_settings(_base_env(NETLENS_TERMINAL="ON"))
    assert settings.terminal_enabled is True
    settings = load_settings(_base_env(NETLENS_TERMINAL="Off"))
    assert settings.terminal_enabled is False


def test_load_settings_terminal_enabled_invalid():
    with pytest.raises(ConfigError) as exc:
        load_settings(_base_env(NETLENS_TERMINAL="maybe"))
    assert "NETLENS_TERMINAL" in str(exc.value)


def test_load_settings_snmp_community_default():
    settings = load_settings(_base_env())
    assert settings.snmp_community is None


def test_load_settings_snmp_community_custom():
    settings = load_settings(_base_env(NETLENS_SNMP_COMMUNITY="public"))
    assert settings.snmp_community == "public"


def test_load_settings_bind_default():
    settings = load_settings(_base_env())
    assert settings.bind_host == "0.0.0.0"
    assert settings.bind_port == 8080


def test_load_settings_bind_custom():
    settings = load_settings(_base_env(NETLENS_BIND="127.0.0.1:9090"))
    assert settings.bind_host == "127.0.0.1"
    assert settings.bind_port == 9090


def test_load_settings_bind_port_too_low():
    with pytest.raises(ConfigError) as exc:
        load_settings(_base_env(NETLENS_BIND="127.0.0.1:0"))
    assert "NETLENS_BIND" in str(exc.value)


def test_load_settings_bind_port_too_high():
    with pytest.raises(ConfigError) as exc:
        load_settings(_base_env(NETLENS_BIND="127.0.0.1:65536"))
    assert "NETLENS_BIND" in str(exc.value)


def test_load_settings_bind_invalid_format():
    with pytest.raises(ConfigError) as exc:
        load_settings(_base_env(NETLENS_BIND="not-a-bind"))
    assert "NETLENS_BIND" in str(exc.value)


def test_load_settings_data_dir_default():
    settings = load_settings(_base_env())
    assert settings.data_dir == Path("/data")


def test_load_settings_data_dir_custom():
    settings = load_settings(_base_env(NETLENS_DATA_DIR="/tmp/netlens"))
    assert settings.data_dir == Path("/tmp/netlens")


def test_settings_is_dataclass():
    settings = load_settings(_base_env())
    assert isinstance(settings, Settings)


def test_config_error_is_exception():
    assert issubclass(ConfigError, Exception)


@pytest.mark.parametrize(
    "cidr, expected",
    [
        ("192.168.1.0/24", True),
        ("10.0.0.0/20", True),
        ("169.254.0.0/16", False),
        ("8.8.8.0/24", False),
        ("10.0.0.0/8", False),
        ("garbage", False),
        ("172.16.0.0/24", True),
        ("172.32.0.0/24", False),
    ],
)
def test_is_scannable_range(cidr, expected):
    assert is_scannable_range(cidr) is expected