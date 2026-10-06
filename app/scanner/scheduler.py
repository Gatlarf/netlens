"""
app/scanner/scheduler.py

Async scheduler loop that periodically triggers quick and deep scans via ScanManager.
"""

import asyncio
import logging
import time
from typing import Optional

from app.scanner.orchestrator import ScanBusy, ScanManager


def due_kind(
    now: float,
    started_at: float,
    last_quick: Optional[float],
    last_deep: Optional[float],
    quick_interval: float,
    deep_interval: float,
) -> Optional[str]:
    """
    Determine which scan kind is due at time `now`.

    Returns "quick", "deep", or None.
    """
    # If neither quick nor deep has ever run, do a quick scan immediately.
    if last_quick is None and last_deep is None:
        return "quick"

    # Check if deep scan is due.
    deep_due = False
    if last_deep is not None:
        deep_due = (now - last_deep) >= deep_interval
    elif last_deep is None:
        # Deep scan is due if at least 600 seconds have passed since start.
        deep_due = (now - started_at) >= 600

    if deep_due:
        return "deep"

    # Check if quick scan is due.
    if last_quick is not None and (now - last_quick) >= quick_interval:
        return "quick"

    return None


async def scheduler_loop(
    manager: ScanManager,
    quick_interval: float,
    deep_interval: float,
    *,
    poll: float = 15.0,
    clock: callable = time.monotonic,
    sleep: callable = asyncio.sleep,
) -> None:
    """
    Run an async loop that periodically triggers quick and deep scans.

    Parameters:
        manager: ScanManager instance.
        quick_interval: Seconds between quick scans.
        deep_interval: Seconds between deep scans.
        poll: Seconds to sleep between iterations.
        clock: Callable returning current time (monotonic).
        sleep: Async sleep function.
    """
    logger = logging.getLogger(__name__)

    started_at = clock()
    last_quick: Optional[float] = None
    last_deep: Optional[float] = None

    while True:
        now = clock()
        kind = due_kind(now, started_at, last_quick, last_deep, quick_interval, deep_interval)

        if kind is not None and not manager.is_running():
            try:
                await manager.start(kind)
            except ScanBusy:
                pass
            except Exception:
                logger.exception("Scheduler failed to start scan")
                # Continue to next iteration
                await sleep(poll)
                continue

            # Update last scan times on success
            if kind == "deep":
                last_deep = now
                last_quick = now  # A deep scan also counts as a quick scan
            else:
                last_quick = now

        await sleep(poll)