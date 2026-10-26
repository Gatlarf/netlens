"""Process hardening that costs nothing."""

from __future__ import annotations

import ctypes
import logging
import sys

log = logging.getLogger(__name__)
PR_SET_DUMPABLE = 4


def protect_process() -> bool:
    """Make this process non-dumpable. Its /proc/<pid> files (environment, memory, file descriptors) then belong to root, so a process of the same user (a plugin that runs in this
    container) cannot read the encryption key or the tokens from them, and cannot attach a debugger. Returns True when it was set."""
    if not sys.platform.startswith("linux"):
        return False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl failed")
    except (OSError, AttributeError) as exc:
        log.warning("could not make the process non-dumpable: %s", exc)
        return False
    return True
