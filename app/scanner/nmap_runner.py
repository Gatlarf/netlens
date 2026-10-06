"""Nmap runner for Netlens scanner."""

from __future__ import annotations

import asyncio
import ipaddress
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.config import is_scannable_range


class ScanError(RuntimeError):
    """Raised when an nmap scan fails."""


def build_args(kind: str, targets: list[str], timing: int = 3) -> list[str]:
    """Build nmap argument list (without executable name).

    Args:
        kind: "quick" or "deep".
        targets: List of target strings (CIDR ranges or private IPv4 addresses).
        timing: Nmap timing template (0-5).

    Returns:
        List of nmap arguments.

    Raises:
        ValueError: If kind is invalid, timing is out of range, or a target is invalid.
    """
    if timing < 0 or timing > 5:
        raise ValueError(f"timing must be 0-5, got {timing}")

    if kind == "quick":
        args = ["-T" + str(timing), "--top-ports", "100", "-oX", "-"]
    elif kind == "deep":
        args = [
            "-T" + str(timing),
            "-sV",
            "-O",
            "--osscan-guess",
            "--top-ports",
            "1000",
            "-oX",
            "-",
        ]
    else:
        raise ValueError(f"invalid kind: {kind!r}")

    for target in targets:
        if not _is_valid_target(target):
            raise ValueError(f"invalid target: {target}")
        args.append(target)

    return args


def _is_valid_target(target: str) -> bool:
    """Check if a target is a valid scannable range or private IPv4 address."""
    try:
        from app.config import is_scannable_range

        if is_scannable_range(target):
            return True
    except ImportError:
        pass

    # Check if it's a single private IPv4 address
    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        return False

    if addr.version != 4:
        return False

    if addr.is_private or addr.is_link_local:
        return True

    return False


async def run_nmap(
    kind: str,
    targets: list[str],
    *,
    nmap_path: str = "nmap",
    timing: int = 3,
    timeout: float = 3600.0,
) -> str:
    """Run nmap and return stdout as UTF-8 string.

    Args:
        kind: "quick" or "deep".
        targets: List of target strings.
        nmap_path: Path to nmap executable.
        timing: Nmap timing template (0-5).
        timeout: Timeout in seconds.

    Returns:
        stdout decoded as UTF-8.

    Raises:
        ScanError: If nmap fails, times out, or is not found.
    """
    args = build_args(kind, targets, timing)

    try:
        process = await asyncio.create_subprocess_exec(
            nmap_path,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        raise ScanError("nmap not found")

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        process.kill()
        raise ScanError("nmap timed out")

    if process.returncode != 0:
        stderr_text = stderr.decode("utf-8", errors="replace")
        last_500 = stderr_text[-500:]
        raise ScanError(f"nmap exited with code {process.returncode}: {last_500}")

    return stdout.decode("utf-8", errors="replace")