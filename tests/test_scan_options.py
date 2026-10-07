import pytest
from app.scanner.options import (
    ScanOptions,
    PRESETS,
    normalize_ports,
    options_from_dict,
    options_to_dict,
    options_from_json,
    preset_dict,
    option_args,
    command_preview,
)


def test_option_args_default():
    opts = ScanOptions()
    assert option_args("quick", opts) == ["-T3", "--top-ports", "100"]
    assert option_args("deep", opts) == [
        "-T3",
        "-sV",
        "-O",
        "--osscan-guess",
        "--traceroute",
        "--top-ports",
        "1000",
    ]
    with pytest.raises(ValueError):
        option_args("unknown", opts)


def test_option_args_quick_variations():
    opts = ScanOptions(timing=4, quick_top_ports=50)
    assert option_args("quick", opts) == ["-T4", "--top-ports", "50"]

    opts = options_from_dict({"quick_ports": "22, 80,443"})
    assert option_args("quick", opts) == ["-T3", "-p", "22,80,443"]

    opts = options_from_dict({"quick_mode": "discovery"})
    assert option_args("quick", opts) == ["-T3", "-sn"]

    opts = options_from_dict({"skip_dns": True, "host_timeout": 90})
    args = option_args("quick", opts)
    assert args[-3:] == ["-n", "--host-timeout", "90s"]


def test_option_args_deep_variations():
    opts = options_from_dict({"deep_version": "light"})
    args = option_args("deep", opts)
    assert "-sV" in args
    idx = args.index("-sV")
    assert args[idx + 1] == "--version-light"

    opts = options_from_dict(
        {
            "deep_version": "off",
            "deep_os": False,
            "deep_traceroute": False,
            "deep_top_ports": 100,
            "timing": 4,
        }
    )
    assert option_args("deep", opts) == ["-T4", "--top-ports", "100"]

    opts = options_from_dict({"deep_ports": "1-1024,8080"})
    args = option_args("deep", opts)
    assert args == ["-T3", "-sV", "-O", "--osscan-guess", "--traceroute", "-p", "1-1024,8080"]


def test_normalize_ports_valid():
    assert normalize_ports("80") == "80"
    assert normalize_ports(" 22 , 80-90 ,443 ") == "22,80-90,443"
    assert normalize_ports("") == ""


@pytest.mark.parametrize(
    "spec,expected_msg",
    [
        ("22,,80", "empty item"),
        ("abc", "not a valid port"),
        ("0", "out of range"),
        ("70000", "out of range"),
        ("90-80", "start is after"),
        ("22;rm -rf /", "not a valid port"),
        ("1-2-3", "not a valid port"),
        (",".join(str(p) for p in range(1000, 1200)), "too long"),
    ],
)
def test_normalize_ports_invalid(spec, expected_msg):
    with pytest.raises(ValueError) as exc:
        normalize_ports(spec)
    assert expected_msg in str(exc.value)


def test_options_from_dict():
    base = ScanOptions()
    opts = options_from_dict({"timing": 4}, base)
    assert opts.timing == 4
    assert base.timing == 3

    opts = options_from_dict({"quick_top_ports": 50}, base)
    assert opts.quick_top_ports == 50
    assert opts.timing == 3

    with pytest.raises(ValueError) as exc:
        options_from_dict({"turbo": True})
    assert "unknown setting" in str(exc.value)


@pytest.mark.parametrize(
    "data,expected_msg",
    [
        ({"timing": 1}, "timing"),
        ({"timing": "4"}, "timing"),
        ({"timing": True}, "timing"),
        ({"quick_mode": "x"}, "quick_mode"),
        ({"deep_os": 1}, "deep_os"),
        ({"quick_top_ports": 0}, "quick_top_ports"),
        ({"deep_top_ports": 10001}, "deep_top_ports"),
        ({"deep_version": "fast"}, "deep_version"),
        ({"host_timeout": 5}, "host_timeout"),
        ({"quick_ports": "99999"}, "quick_ports"),
    ],
)
def test_options_from_dict_invalid(data, expected_msg):
    with pytest.raises(ValueError) as exc:
        options_from_dict(data)
    assert expected_msg in str(exc.value)


def test_options_from_dict_valid_host_timeout():
    for val in (0, 10, 86400):
        opts = options_from_dict({"host_timeout": val})
        assert opts.host_timeout == val


def test_options_to_dict_round_trip():
    opts = ScanOptions(timing=4, quick_top_ports=50, quick_ports="22,80")
    assert options_from_dict(options_to_dict(opts)) == opts


def test_options_from_json():
    for text in (None, "", "{broken", "[]", '{"timing": 99}'):
        assert options_from_json(text) == ScanOptions()

    opts = options_from_json('{"timing": 4}')
    assert opts.timing == 4


def test_presets():
    assert preset_dict("default") == options_to_dict(ScanOptions())

    fast = preset_dict("fast")
    assert fast["timing"] == 4
    assert fast["deep_version"] == "light"
    assert fast["deep_top_ports"] == 200
    assert fast["quick_top_ports"] == 100
    assert fast["deep_os"] is True

    fastest = preset_dict("fastest")
    assert fastest["skip_dns"] is True
    assert fastest["deep_os"] is False
    assert fastest["host_timeout"] == 120

    for name in PRESETS:
        opts = options_from_dict(preset_dict(name))
        assert isinstance(opts, ScanOptions)

    with pytest.raises(KeyError):
        preset_dict("nope")


def test_command_preview():
    opts = ScanOptions()
    assert command_preview("quick", opts) == "nmap -T3 --top-ports 100 -oX - <ranges>"