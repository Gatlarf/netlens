"""Netlens' own log (Scans & events → System log): what the application itself says, kept in a small rotating file in the data folder.

The container log (`docker logs`) shows the same lines but is gone when the container is re-created, and is out of reach for many people (a
Synology, Portainer). Here the errors and warnings of the application are kept across restarts (3 files of 2 MB) and can be read, searched and
downloaded in the browser. Requests are not logged here (that is the audit log); passwords and tokens never reach a log line.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import re
import time
from pathlib import Path
from typing import Any

FILE_NAME = "netlens.log"
MAX_BYTES, BACKUPS = 2 * 1024 * 1024, 2
STAMP = "%Y-%m-%dT%H:%M:%SZ"
LEVELS = {"debug": 10, "info": 20, "warning": 30, "error": 40}
LINE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ) (DEBUG|INFO|WARNING|ERROR|CRITICAL) ([^ :]+): (.*)$")
_HANDLER_ATTR = "_netlens_syslog"


class _Formatter(logging.Formatter):
    converter = time.gmtime

    def format(self, record: logging.LogRecord) -> str:
        record.message = record.getMessage()
        text = f"{time.strftime(STAMP, self.converter(record.created))} {record.levelname} {record.name}: {record.message}"
        if record.exc_info:
            text += "\n" + self.formatException(record.exc_info)
        return text


def log_dir(data_dir: Path | str) -> Path:
    return Path(data_dir) / "logs"


def setup(data_dir: Path | str, level: str | None = None) -> Path | None:
    """Send the application's log lines to a rotating file as well as to the container log. Safe to call twice. Returns the file, or None if it cannot be written."""
    root = logging.getLogger()
    chosen = LEVELS.get((level or os.environ.get("NETLENS_LOG_LEVEL", "info")).strip().lower(), 20)
    root.setLevel(min(chosen, root.level or chosen))
    if not any(getattr(h, _HANDLER_ATTR, False) for h in root.handlers):
        stream = logging.StreamHandler()                       # the container log gets the application's lines too, in the same shape
        stream.setFormatter(_Formatter())
        stream.setLevel(chosen)
        setattr(stream, _HANDLER_ATTR, True)
        root.addHandler(stream)
    path = log_dir(data_dir) / FILE_NAME
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not any(isinstance(h, logging.handlers.RotatingFileHandler) and getattr(h, _HANDLER_ATTR, False) for h in root.handlers):
            handler = logging.handlers.RotatingFileHandler(path, maxBytes=MAX_BYTES, backupCount=BACKUPS, encoding="utf-8")
            handler.setFormatter(_Formatter())
            handler.setLevel(chosen)
            setattr(handler, _HANDLER_ATTR, True)
            root.addHandler(handler)
    except OSError:
        return None
    for noisy in ("httpx", "httpcore", "asyncio", "watchfiles"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    return path


def _files(data_dir: Path | str) -> list[Path]:
    base = log_dir(data_dir) / FILE_NAME
    return [p for p in [base] + [Path(f"{base}.{i}") for i in range(1, BACKUPS + 1)] if p.exists()]       # newest first


def entries(data_dir: Path | str, level: str = "info", query: str = "", limit: int = 300) -> dict[str, Any]:
    """The log entries (newest first) at or above `level` that contain `query`. A traceback belongs to the line above it."""
    floor = LEVELS.get(level.lower(), 20)
    needle = query.strip().lower()
    out: list[dict] = []
    total = 0
    for path in _files(data_dir):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        chunk: list[dict] = []
        for line in lines:
            m = LINE.match(line)
            if m:
                chunk.append({"ts": m.group(1), "level": m.group(2).lower(), "logger": m.group(3), "message": m.group(4)})
            elif chunk:
                chunk[-1]["message"] += "\n" + line
        for e in reversed(chunk):
            total += 1
            if LEVELS.get(e["level"], 50) >= floor and (not needle or needle in (e["message"] + " " + e["logger"]).lower()):
                out.append(e)
        if len(out) >= limit:
            break
    return {"entries": out[:limit], "path": str(log_dir(data_dir) / FILE_NAME), "bytes": sum(p.stat().st_size for p in _files(data_dir)), "files": len(_files(data_dir))}


def download(data_dir: Path | str) -> str:
    """All kept lines, oldest first, as text."""
    parts = []
    for path in reversed(_files(data_dir)):
        try:
            parts.append(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return "".join(parts)
