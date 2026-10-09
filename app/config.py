from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Settings:
    token: str
    ranges: tuple[str, ...]
    quick_interval: int
    deep_interval: int
    terminal_enabled: bool
    snmp_community: str | None
    bind_host: str
    bind_port: int
    data_dir: Path


def is_scannable_range(cidr: str) -> bool:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False

    if network.version != 4:
        return False

    if network.prefixlen < 20:
        return False

    private_networks = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("169.254.0.0/16"),
    ]

    for private in private_networks:
        if network.subnet_of(private):
            return True

    return False


def normalize_ranges(items) -> list[str]:
    """Validate and normalize user-supplied scan ranges (CIDR or single IPv4).

    Raises ValueError naming the first bad entry. Duplicates are dropped, order is kept.
    """
    result: list[str] = []
    for raw in items:
        raw = str(raw).strip()
        if not raw:
            continue
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            raise ValueError(f"invalid address or CIDR: {raw}")
        normalized = str(network)
        if not is_scannable_range(normalized):
            raise ValueError(
                f"not scannable: {raw} (private IPv4 ranges only, /20 or smaller)"
            )
        if normalized not in result:
            result.append(normalized)
    return result


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    if env is None:
        env = os.environ

    # Optional: a shared access token that always signs in as administrator (the way older installs work). Without it,
    # people sign in with a user name and password; the first one is created by the setup wizard.
    token = env.get("NETLENS_TOKEN", "").strip()

    ranges_str = env.get("NETLENS_RANGES", "")
    ranges: tuple[str, ...] = ()
    if ranges_str:
        raw_ranges = [r.strip() for r in ranges_str.split(",") if r.strip()]
        normalized: list[str] = []
        for raw in raw_ranges:
            try:
                network = ipaddress.ip_network(raw, strict=False)
            except ValueError:
                raise ConfigError(f"NETLENS_RANGES contains invalid CIDR: {raw}")
            if not is_scannable_range(str(network)):
                raise ConfigError(f"NETLENS_RANGES contains non-scannable range: {raw}")
            normalized.append(str(network))
        ranges = tuple(normalized)

    quick_interval_str = env.get("NETLENS_QUICK_INTERVAL", "900")
    try:
        quick_interval = int(quick_interval_str)
    except ValueError:
        raise ConfigError("NETLENS_QUICK_INTERVAL must be an integer")
    if quick_interval < 60:
        raise ConfigError("NETLENS_QUICK_INTERVAL must be >= 60")

    deep_interval_str = env.get("NETLENS_DEEP_INTERVAL", "86400")
    try:
        deep_interval = int(deep_interval_str)
    except ValueError:
        raise ConfigError("NETLENS_DEEP_INTERVAL must be an integer")
    if deep_interval < 60:
        raise ConfigError("NETLENS_DEEP_INTERVAL must be >= 60")

    terminal_str = env.get("NETLENS_TERMINAL", "on").strip().lower()
    if terminal_str == "on":
        terminal_enabled = True
    elif terminal_str == "off":
        terminal_enabled = False
    else:
        raise ConfigError("NETLENS_TERMINAL must be 'on' or 'off'")

    snmp_community = env.get("NETLENS_SNMP_COMMUNITY", "")
    snmp_community = snmp_community if snmp_community else None

    bind_str = env.get("NETLENS_BIND", "0.0.0.0:8080")
    if ":" not in bind_str:
        raise ConfigError("NETLENS_BIND must be in format host:port")
    host, port_str = bind_str.rsplit(":", 1)
    try:
        port = int(port_str)
    except ValueError:
        raise ConfigError("NETLENS_BIND port must be an integer")
    if not 1 <= port <= 65535:
        raise ConfigError("NETLENS_BIND port must be between 1 and 65535")

    data_dir = Path(env.get("NETLENS_DATA_DIR", "/data"))

    return Settings(
        token=token,
        ranges=ranges,
        quick_interval=quick_interval,
        deep_interval=deep_interval,
        terminal_enabled=terminal_enabled,
        snmp_community=snmp_community,
        bind_host=host,
        bind_port=port,
        data_dir=data_dir,
    )