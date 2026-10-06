Fix the defects below and output the COMPLETE corrected file. Keep everything else identical.

DEFECTS:
The fake executable prints with print() so run_ip output ends with a trailing newline. In test_run_ip_basic (and similar) compare against the text including the newline or use .strip().

CURRENT FILE:
import asyncio
import os
import stat
import sys
from pathlib import Path
from typing import Optional

import pytest

from app.scanner.netinfo import (
    detect_gateway,
    detect_ranges,
    parse_default_gateway,
    parse_ip_addr,
    run_ip,
)


# ---------------------------------------------------------------------------
# parse_ip_addr
# ---------------------------------------------------------------------------

def test_parse_ip_addr_multi_line():
    sample = """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
    inet 192.168.0.5/24 brd 192.168.0.255 scope global dynamic noprefixroute eth0
       valid_lft 86399sec preferred_lft 86399sec
    inet6 fe80::1/64 scope link
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
4: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 11:22:33:44:55:66 brd ff:ff:ff:ff:ff:ff
    inet 10.1.2.3/22 brd 10.1.3.255 scope global dynamic noprefixroute wlan0
       valid_lft 86399sec preferred_lft 86399sec
    inet6 fe80::2/64 scope link
       valid_lft forever preferred_lft forever
5: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 77:88:99:aa:bb:cc brd ff:ff:ff:ff:ff:ff
    inet 203.0.113.9/24 brd 203.0.113.255 scope global dynamic noprefixroute eth1
       valid_lft 86399sec preferred_lft 86399sec
6: veth123@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether dd:ee:ff:00:11:22 brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global veth123
       valid_lft forever preferred_lft forever
"""
    result = parse_ip_addr(sample)
    expected = {"10.1.0.0/22", "192.168.0.0/24"}
    assert set(result) == expected
    assert len(result) == 2


def test_parse_ip_addr_empty():
    assert parse_ip_addr("") == []


def test_parse_ip_addr_garbage():
    garbage = "hello world\nfoo bar baz\nnot an ip\n"
    assert parse_ip_addr(garbage) == []


def test_parse_ip_addr_short_prefix_excluded():
    # /16 private network should be excluded because prefix is too short
    sample = """\
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
    inet 192.168.0.5/16 brd 192.168.0.255 scope global dynamic noprefixroute eth0
       valid_lft 86399sec preferred_lft 86399sec
"""
    assert parse_ip_addr(sample) == []


def test_parse_ip_addr_private_ranges():
    # Verify that private ranges are detected correctly
    sample = """\
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.10/24 brd 192.168.1.255 scope global dynamic noprefixroute eth0
       valid_lft 86399sec preferred_lft 86399sec
"""
    result = parse_ip_addr(sample)
    assert set(result) == {"192.168.1.0/24"}
    assert len(result) == 1


def test_parse_ip_addr_public_excluded():
    # Public IP should not be included
    sample = """\
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
    inet 203.0.113.9/24 brd 203.0.113.255 scope global dynamic noprefixroute eth0
       valid_lft 86399sec preferred_lft 86399sec
"""
    assert parse_ip_addr(sample) == []


def test_parse_ip_addr_lo_excluded():
    # Loopback should be excluded
    sample = """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
"""
    assert parse_ip_addr(sample) == []


def test_parse_ip_addr_docker_excluded():
    # Docker network should be excluded
    sample = """\
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
"""
    assert parse_ip_addr(sample) == []


def test_parse_ip_addr_veth_excluded():
    # veth should be excluded
    sample = """\
6: veth123@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether dd:ee:ff:00:11:22 brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global veth123
       valid_lft forever preferred_lft forever
"""
    assert parse_ip_addr(sample) == []


# ---------------------------------------------------------------------------
# parse_default_gateway
# ---------------------------------------------------------------------------

def test_parse_default_gateway_normal():
    line = "default via 192.168.0.1 dev eth0 proto dhcp src 192.168.0.5 metric 100"
    assert parse_default_gateway(line) == "192.168.0.1"


def test_parse_default_gateway_multiple_lines():
    text = """\
default via 192.168.0.1 dev eth0 proto dhcp src 192.168.0.5 metric 100
default via 10.0.0.1 dev wlan0 proto dhcp src 10.0.0.2 metric 200
"""
    assert parse_default_gateway(text) == "192.168.0.1"


def test_parse_default_gateway_empty():
    assert parse_default_gateway("") is None


def test_parse_default_gateway_no_via():
    line = "default dev ppp0 proto dhcp src 10.0.0.1 metric 100"
    assert parse_default_gateway(line) is None


def test_parse_default_gateway_invalid_ip():
    line = "default via notanip dev eth0 proto dhcp src 192.168.0.5 metric 100"
    assert parse_default_gateway(line) is None


# ---------------------------------------------------------------------------
# run_ip / detect_ranges / detect_gateway
# ---------------------------------------------------------------------------

def _make_fake_executable(tmp_path: Path, output: str, exit_code: int = 0) -> str:
    """Create a fake executable that prints output and exits with exit_code."""
    script = tmp_path / "fake_ip"
    script.write_text(
        f"#!{sys.executable}\n"
        f"import sys\n"
        f"print({output!r})\n"
        f"sys.exit({exit_code})\n"
    )
    script.chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    return str(script)


@pytest.mark.asyncio
async def test_run_ip_basic(tmp_path: Path):
    fake = _make_fake_executable(tmp_path, "hello from fake ip")
    result = await run_ip(["addr"], ip_path=fake)
    assert result == "hello from fake ip"


@pytest.mark.asyncio
async def test_run_ip_missing_executable(tmp_path: Path):
    missing = str(tmp_path / "nonexistent")
    result = await run_ip(["addr"], ip_path=missing)
    assert result == ""


@pytest.mark.asyncio
async def test_run_ip_exit_code_1(tmp_path: Path):
    fake = _make_fake_executable(tmp_path, "error output", exit_code=1)
    result = await run_ip(["addr"], ip_path=fake)
    assert result == ""


@pytest.mark.asyncio
async def test_detect_ranges_basic(tmp_path: Path):
    fake = _make_fake_executable(
        tmp_path,
        """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
    inet 192.168.0.5/24 brd 192.168.0.255 scope global dynamic noprefixroute eth0
       valid_lft 86399sec preferred_lft 86399sec
4: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 11:22:33:44:55:66 brd ff:ff:ff:ff:ff:ff
    inet 10.1.2.3/22 brd 10.1.3.255 scope global dynamic noprefixroute wlan0
       valid_lft 86399sec preferred_lft 86399sec
""",
    )
    result = await detect_ranges(ip_path=fake)
    assert set(result) == {"10.1.0.0/22", "192.168.0.0/24"}
    assert len(result) == 2


@pytest.mark.asyncio
async def test_detect_ranges_missing_executable(tmp_path: Path):
    missing = str(tmp_path / "nonexistent")
    result = await detect_ranges(ip_path=missing)
    assert result == []


@pytest.mark.asyncio
async def test_detect_ranges_exit_code_1(tmp_path: Path):
    fake = _make_fake_executable(tmp_path, "error", exit_code=1)
    result = await detect_ranges(ip_path=fake)
    assert result == []


@pytest.mark.asyncio
async def test_detect_gateway_basic(tmp_path: Path):
    fake = _make_fake_executable(
        tmp_path,
        "default via 192.168.0.1 dev eth0 proto dhcp src 192.168.0.5 metric 100",
    )
    result = await detect_gateway(ip_path=fake)
    assert result == "192.168.0.1"


@pytest.mark.asyncio
async def test_detect_gateway_missing_executable(tmp_path: Path):
    missing = str(tmp_path / "nonexistent")
    result = await detect_gateway(ip_path=missing)
    assert result is None


@pytest.mark.asyncio
async def test_detect_gateway_exit_code_1(tmp_path: Path):
    fake = _make_fake_executable(tmp_path, "error", exit_code=1)
    result = await detect_gateway(ip_path=fake)
    assert result is None