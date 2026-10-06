"""Network interface detection utilities for Netlens."""

import asyncio
import ipaddress
from typing import Optional

from app.config import is_scannable_range


def parse_ip_addr(text: str) -> list[str]:
    """Parse output of `ip -o -f inet addr show`.

    Returns sorted unique list of scannable CIDR networks.
    """
    skip_prefixes = ("docker", "veth", "br-", "virbr", "tun", "tap", "wg")
    networks: set[str] = set()

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        # Interface name is the second whitespace field
        iface = parts[1]
        # Strip trailing ':' and any '@...' suffix
        iface = iface.rstrip(":")
        if "@" in iface:
            iface = iface.split("@")[0]

        # Skip loopback and virtual interfaces
        if iface == "lo":
            continue
        if any(iface.startswith(prefix) for prefix in skip_prefixes):
            continue

        # Find the CIDR after "inet"
        try:
            inet_idx = parts.index("inet")
        except ValueError:
            continue

        if inet_idx + 1 >= len(parts):
            continue

        cidr = parts[inet_idx + 1]

        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue

        if is_scannable_range(str(network)):
            networks.add(str(network))

    return sorted(networks)


def parse_default_gateway(text: str) -> Optional[str]:
    """Parse output of `ip -4 route show default`.

    Returns the gateway IP of the first default route, or None.
    """
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        if parts[0] != "default":
            continue

        # Gateway IP is the field after "via"
        try:
            via_idx = parts.index("via")
        except ValueError:
            continue

        if via_idx + 1 >= len(parts):
            continue

        gateway_str = parts[via_idx + 1]

        try:
            ipaddress.ip_address(gateway_str)
        except ValueError:
            continue

        return gateway_str

    return None


async def run_ip(args: list[str], ip_path: str = "ip", timeout: float = 5.0) -> str:
    """Run `ip` command and return stdout text.

    Returns empty string on FileNotFoundError, timeout, or non-zero exit.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            ip_path,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return ""

    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return ""

    if proc.returncode != 0:
        return ""

    return stdout.decode("utf-8", errors="replace")


async def detect_ranges(ip_path: str = "ip") -> list[str]:
    """Detect scannable network ranges from local interfaces."""
    text = await run_ip(["-o", "-f", "inet", "addr", "show"], ip_path)
    return parse_ip_addr(text)


async def detect_gateway(ip_path: str = "ip") -> Optional[str]:
    """Detect default gateway from routing table."""
    text = await run_ip(["-4", "route", "show", "default"], ip_path)
    return parse_default_gateway(text)