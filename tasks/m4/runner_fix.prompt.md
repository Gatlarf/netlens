INTERFACES OF EXISTING CODE (use these exact names; do not invent attributes, columns or functions that are not listed):

## Database schema (app/db.py, SQLite, connections use row_factory=sqlite3.Row)
CREATE TABLE schema_version (
            version INTEGER
        )
CREATE TABLE devices (
            id INTEGER PRIMARY KEY,
            mac TEXT UNIQUE,
            primary_ip TEXT,
            hostname TEXT,
            vendor TEXT,
            os_name TEXT,
            os_confidence INTEGER,
            device_type TEXT,
            type_override TEXT,
            custom_name TEXT,
            notes TEXT,
            tags TEXT,
            online INTEGER NOT NULL DEFAULT 1,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            pos_x REAL,
            pos_y REAL,
            raw_xml TEXT
        )
CREATE TABLE device_ips (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            ip TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(device_id, ip)
        )
CREATE TABLE device_names (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(device_id, name, source)
        )
CREATE TABLE ports (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            proto TEXT NOT NULL,
            port INTEGER NOT NULL,
            state TEXT NOT NULL,
            service TEXT,
            product TEXT,
            version TEXT,
            updated TEXT NOT NULL,
            UNIQUE(device_id, proto, port)
        )
CREATE TABLE scans (
            id INTEGER PRIMARY KEY,
            kind TEXT NOT NULL,
            status TEXT NOT NULL,
            started TEXT NOT NULL,
            finished TEXT,
            hosts_found INTEGER NOT NULL DEFAULT 0,
            error TEXT
        )
CREATE TABLE events (
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            kind TEXT NOT NULL,
            detail TEXT
        )
CREATE TABLE relations (
            id INTEGER PRIMARY KEY,
            src_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            dst_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 1.0,
            manual INTEGER NOT NULL DEFAULT 0,
            UNIQUE(src_id, dst_id, kind)
        )
CREATE TABLE settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
CREATE TABLE host_keys (
            device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
            fingerprint TEXT NOT NULL,
            first_seen TEXT NOT NULL
        )

TASK:
In app/scanner/nmap_runner.py (output the COMPLETE file; current file below) the "deep" argument list must include "--traceroute" immediately after "--osscan-guess": ["-T<timing>", "-sV", "-O", "--osscan-guess", "--traceroute", "--top-ports", "1000", "-oX", "-"] (targets appended last as before). Nothing else changes.

CURRENT FILE:
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