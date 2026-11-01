"""The program watches itself: when it can no longer open files (a leak of descriptors) or its database, the health check says so and, after two minutes, the
process ends so the container restarts it. A server that is "up" but answers every request with an error is worse than one that restarts."""

from __future__ import annotations

import asyncio
import logging
import os
import resource
import time
from pathlib import Path

log = logging.getLogger(__name__)

WANT_FILES = 65536          # the limit for open files we ask for (the container's default of 1024 is reached by a long-running scanner)
FULL = 0.9                  # open files / limit from which the program counts as unwell
EVERY = 30                  # seconds between two checks
STRIKES = 4                 # consecutive bad checks (two minutes) before the process ends


def raise_file_limit() -> int:
    """Raise the soft limit for open files to what the hard limit allows (up to WANT_FILES); returns the limit now in force."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = WANT_FILES if hard == resource.RLIM_INFINITY else min(hard, WANT_FILES)
    if soft != resource.RLIM_INFINITY and soft < target:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
            return target
        except (ValueError, OSError):
            pass
    return soft


def open_files() -> tuple[int, int]:
    """(descriptors open now, the limit)."""
    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    try:
        return len(os.listdir("/proc/self/fd")), soft
    except OSError:
        return 0, soft


def problem(db_path: str | Path) -> str | None:
    """A sentence when the program is unwell, None when it is fine. Cheap: it runs in every health check."""
    used, limit = open_files()
    if limit != resource.RLIM_INFINITY and limit > 0 and used >= limit * FULL:
        return f"almost out of file descriptors ({used} of {limit} in use)"
    try:
        from app.db import connect

        conn = connect(db_path)
        try:
            conn.execute("SELECT 1 FROM settings LIMIT 1").fetchone()
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001 - any failure to read the database counts
        return f"the database cannot be opened ({exc.__class__.__name__}: {exc})"
    return None


def describe_files() -> str:
    """What the open descriptors are (files by name, sockets, pipes), most common first: the first thing to know when they leak."""
    import re
    from collections import Counter

    kinds: Counter = Counter()
    for name in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink(f"/proc/self/fd/{name}")
        except OSError:
            continue
        kinds[re.sub(r"\d+", "N", target)] += 1
    return ", ".join(f"{count} x {kind}" for kind, count in kinds.most_common(8))


async def loop(db_path: str | Path, *, die=None, every: float = EVERY, strikes: int = STRIKES) -> None:
    """Check every `every` seconds; after `strikes` bad checks in a row, call `die` (the process ends, the container's restart policy brings it back)."""
    die = die or (lambda: os._exit(70))
    bad = 0
    said = 0.0
    while True:
        await asyncio.sleep(every)
        used, limit = open_files()
        if limit and limit != resource.RLIM_INFINITY and used >= limit * 0.5 and time.monotonic() - said > 600:       # a leak shows long before it hurts
            said = time.monotonic()
            log.warning("watchdog: %d of %d file descriptors in use: %s", used, limit, await asyncio.to_thread(describe_files))
        found = await asyncio.to_thread(problem, db_path)
        if found is None:
            if bad:
                log.warning("watchdog: the problem is gone")
            bad = 0
            continue
        bad += 1
        log.error("watchdog: %s (%d of %d)", found, bad, strikes)
        if bad >= strikes:
            log.critical("watchdog: still unwell after %d checks; ending the process so that it restarts", bad)
            die()
            return
