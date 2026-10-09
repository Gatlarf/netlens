"""Scheduled backups: a consistent copy of the database in <data>/backups, the newest N kept.

Settings: `backup.schedule` = {"enabled", "every_hours", "keep"}, `backup.last` = result of the latest run.
The files hold saved credentials, so the folder and the files are private (0700 / 0600).
"""

import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.backup import BackupError, create_backup, validate_backup
from app.db import add_event, get_setting, set_setting

log = logging.getLogger(__name__)

SCHEDULE_KEY = "backup.schedule"
LAST_KEY = "backup.last"
EVERY_HOURS = (6, 12, 24, 72, 168)
DEFAULT = {"enabled": False, "every_hours": 24, "keep": 7}
NAME_RE = re.compile(r"^netlens-\d{8}-\d{6}\.db$")


def backup_dir(db_path: "str | os.PathLike") -> Path:
    return Path(db_path).resolve().parent / "backups"


def clean_schedule(raw: dict) -> dict:
    """Validated schedule; raises ValueError with a message for the user."""
    every = raw.get("every_hours", DEFAULT["every_hours"])
    keep = raw.get("keep", DEFAULT["keep"])
    if every not in EVERY_HOURS:
        raise ValueError("choose one of the offered intervals")
    if not isinstance(keep, int) or isinstance(keep, bool) or not 1 <= keep <= 60:
        raise ValueError("keep between 1 and 60 backups")
    return {"enabled": bool(raw.get("enabled", False)), "every_hours": every, "keep": keep}


def get_schedule(conn) -> dict:
    try:
        return clean_schedule({**DEFAULT, **json.loads(get_setting(conn, SCHEDULE_KEY) or "{}")})
    except (ValueError, TypeError):
        return dict(DEFAULT)


def set_schedule(conn, raw: dict) -> dict:
    schedule = clean_schedule({**get_schedule(conn), **raw})
    set_setting(conn, SCHEDULE_KEY, json.dumps(schedule))
    return schedule


def get_last(conn) -> dict | None:
    try:
        value = json.loads(get_setting(conn, LAST_KEY) or "null")
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def list_backups(db_path) -> list[dict]:
    folder = backup_dir(db_path)
    if not folder.is_dir():
        return []
    items = []
    for path in folder.iterdir():
        if NAME_RE.match(path.name) and path.is_file():
            stat = path.stat()
            items.append({"name": path.name, "size": stat.st_size, "created": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()})
    return sorted(items, key=lambda i: i["name"], reverse=True)


def backup_path(db_path, name: str) -> Path | None:
    """The file for a listed backup name (never a path the caller made up)."""
    if not NAME_RE.match(name or ""):
        return None
    path = backup_dir(db_path) / name
    return path if path.is_file() else None


def prune(db_path, keep: int) -> None:
    for item in list_backups(db_path)[keep:]:
        try:
            (backup_dir(db_path) / item["name"]).unlink()
        except OSError:
            log.warning("could not remove old backup %s", item["name"])


def run_backup(conn, db_path, now: datetime | None = None) -> dict:
    """Make a backup now, remember the outcome and raise a `backup_failed` event on failure."""
    now = now or datetime.now(timezone.utc)
    folder = backup_dir(db_path)
    name = "netlens-" + now.strftime("%Y%m%d-%H%M%S") + ".db"
    target = folder / name
    result = {"at": now.isoformat(), "ok": True, "name": name, "error": None}
    try:
        folder.mkdir(mode=0o700, exist_ok=True)
        os.chmod(folder, 0o700)
        create_backup(db_path, target)
        os.chmod(target, 0o600)
        validate_backup(target)
        prune(db_path, get_schedule(conn)["keep"])
    except (BackupError, OSError) as exc:
        result.update(ok=False, name=None, error=str(exc)[:300])
        try:
            target.unlink()
        except OSError:
            pass
    set_setting(conn, LAST_KEY, json.dumps(result))
    if not result["ok"]:
        add_event(conn, "backup_failed", result["error"])
    return result


def is_due(conn, now: datetime | None = None) -> bool:
    schedule = get_schedule(conn)
    if not schedule["enabled"]:
        return False
    now = now or datetime.now(timezone.utc)
    last = get_last(conn)
    if not last:
        return True
    try:
        at = datetime.fromisoformat(last["at"])
    except (KeyError, ValueError):
        return True
    # a failed run is tried again after an hour, a good one after the interval
    wait = timedelta(hours=schedule["every_hours"]) - timedelta(minutes=5) if last.get("ok") else timedelta(hours=1)
    return now - at >= wait


def run_if_due(conn, db_path) -> dict | None:
    return run_backup(conn, db_path) if is_due(conn) else None
