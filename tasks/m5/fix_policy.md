Fix the defects below and output the COMPLETE corrected file. Keep everything else identical.

DEFECTS:
pick_port checks '(proto, port) not in open_ports' with proto being 'ssh'/'telnet', but open_ports holds (transport protocol, port) pairs like ('tcp', 22). The membership test must be ('tcp', port) in open_ports (only TCP counts; UDP entries are ignored).

CURRENT FILE:
from __future__ import annotations

import ipaddress
from typing import Iterable


def target_allowed(ip: str, ranges: Iterable[str]) -> bool:
    """Check if an IP address is allowed for scanning.

    Args:
        ip: IP address string.
        ranges: Iterable of CIDR strings representing allowed scan ranges.

    Returns:
        True if the IP is allowed, False otherwise.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    # Never allow loopback, unspecified, multicast, reserved, or public addresses
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_reserved:
        return False

    # If ranges are provided, check if IP is within any range
    if ranges:
        for cidr in ranges:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                if addr in network:
                    return True
            except ValueError:
                continue
        return False

    # If no ranges, allow private (RFC1918) or link-local addresses
    if addr.is_private or addr.is_link_local:
        return True

    return False


def pick_port(
    proto: str,
    requested: int | None,
    open_ports: list[tuple[str, int]],
) -> int:
    """Pick a port for SSH or Telnet connection.

    Args:
        proto: Protocol string, must be "ssh" or "telnet".
        requested: Requested port number, or None to use default.
        open_ports: List of (protocol, port) tuples for known open ports.

    Returns:
        The chosen port number.

    Raises:
        ValueError: If proto is invalid, requested port is out of range,
                    or the port is not open on the device.
    """
    if proto not in ("ssh", "telnet"):
        raise ValueError(f"Invalid protocol: {proto}")

    default_port = 22 if proto == "ssh" else 23

    if requested is None:
        port = default_port
    else:
        if not 1 <= requested <= 65535:
            raise ValueError("requested port must be 1-65535")
        port = requested

    # Check if the port is open on the device
    if (proto, port) not in open_ports:
        raise ValueError("port not open on this device")

    return port