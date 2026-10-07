"""Nmap runner for Netlens scanner."""

from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.config import is_scannable_range


class ScanError(RuntimeError):
    """Raised when an nmap scan fails."""


def build_args(kind: str, targets: list[str], timing: int = 3, stats_every: str | None = None) -> list[str]:
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
            "--traceroute",
            "--top-ports",
            "1000",
            "-oX",
            "-",
        ]
    else:
        raise ValueError(f"invalid kind: {kind!r}")

    if stats_every:
        # periodic <taskprogress> elements in the XML stream (used for live progress)
        args[0:0] = ["--stats-every", stats_every]

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


_TASK_PROGRESS_RE = re.compile(r'<taskprogress task="([^"]*)"[^>]*?percent="([0-9.]+)"')
_TASK_BEGIN_RE = re.compile(r'<taskbegin task="([^"]*)"')
_HOST_RE = re.compile(r"<host[ >]")


def _scan_progress(text: str, state: dict) -> dict | None:
    """Update `state` from nmap's XML stream seen so far; return a progress dict if something changed."""
    events = [(m.start(), m.group(1), 0.0) for m in _TASK_BEGIN_RE.finditer(text, state["pos"])]
    events += [(m.start(), m.group(1), min(100.0, float(m.group(2)))) for m in _TASK_PROGRESS_RE.finditer(text, state["pos"])]
    changed = False
    for _, task, percent in sorted(events):  # apply in stream order
        state.update(task=task, percent=percent)
        changed = True
    hosts = len(_HOST_RE.findall(text))
    if hosts != state["hosts"]:
        state["hosts"] = hosts
        changed = True
    # leave a small overlap so a tag split across two chunks is still found next time
    state["pos"] = max(state["pos"], len(text) - 200)
    if not changed:
        return None
    return {"task": state["task"], "percent": state["percent"], "hosts_found": state["hosts"]}


async def run_nmap(
    kind: str,
    targets: list[str],
    *,
    nmap_path: str = "nmap",
    timing: int = 3,
    timeout: float = 3600.0,
    progress=None,
) -> str:
    """Run nmap and return stdout as UTF-8 string.

    Args:
        kind: "quick" or "deep".
        targets: List of target strings.
        nmap_path: Path to nmap executable.
        timing: Nmap timing template (0-5).
        timeout: Timeout in seconds.
        progress: Optional callable receiving {"task", "percent", "hosts_found"} while nmap runs.

    Returns:
        stdout decoded as UTF-8.

    Raises:
        ScanError: If nmap fails, times out, or is not found.
    """
    args = build_args(kind, targets, timing, stats_every="2s" if progress else None)

    try:
        process = await asyncio.create_subprocess_exec(
            nmap_path,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        raise ScanError("nmap not found")
    except OSError as exc:
        raise ScanError(f"cannot execute nmap: {exc}")

    async def read_stdout() -> bytes:
        chunks: list[bytes] = []
        text = ""
        state = {"pos": 0, "task": "", "percent": None, "hosts": 0}
        while True:
            chunk = await process.stdout.read(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if progress is not None:
                text += chunk.decode("utf-8", errors="replace")
                update = _scan_progress(text, state)
                if update is not None:
                    try:
                        progress(update)
                    except Exception:  # a broken progress callback must never break the scan
                        pass
        return b"".join(chunks)

    async def run() -> tuple[bytes, bytes]:
        stdout, stderr = await asyncio.gather(read_stdout(), process.stderr.read())
        await process.wait()
        return stdout, stderr

    try:
        stdout, stderr = await asyncio.wait_for(run(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        raise ScanError("nmap timed out")

    if process.returncode != 0:
        stderr_text = stderr.decode("utf-8", errors="replace")
        last_500 = stderr_text[-500:]
        raise ScanError(f"nmap exited with code {process.returncode}: {last_500}")

    return stdout.decode("utf-8", errors="replace")
