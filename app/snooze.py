"""Acknowledge and snooze: "I know, do not tell me again for a while".

A snooze is about one subject: a device being offline (`device:<id>`), a service check (`service:<id>`), a health reading
(`metric:<device id>:<metric>:<label>`, which also covers the disk forecast of that disk) or a remote site (`site:<id>`).
While it lasts, the events about that subject are still recorded but tagged "Snoozed" and left out of the notifications, and the
dashboard moves the item to a "Snoozed" list. A snooze ends by itself when the problem is over (the recovery event clears it),
or when its time is up: if the problem is still there, it is announced once more.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone

from app.db import get_setting, set_setting

KEY = "snoozes"
TAG = "Snoozed"
STAMP = "%Y-%m-%dT%H:%M:%SZ"
SUBJECT_RE = re.compile(r"^(device:\d{1,9}|service:\d{1,9}|site:\d{1,9}|metric:\d{1,9}:[a-z_]{1,32}:[^\n\r\t]{0,60})$")
RESOLVES = {"device_online", "service_up", "metric_ok", "probe_online"}
MIN_MINUTES, MAX_MINUTES = 5, 60 * 24 * 30
MAX_NOTE = 200


def _now(now: datetime | None) -> datetime:
    return now or datetime.now(timezone.utc)


def _load(conn: sqlite3.Connection) -> list[dict]:
    try:
        data = json.loads(get_setting(conn, KEY) or "[]")
    except ValueError:
        return []
    return [e for e in data if isinstance(e, dict) and e.get("key") and e.get("until")] if isinstance(data, list) else []


def _save(conn: sqlite3.Connection, entries: list[dict]) -> None:
    set_setting(conn, KEY, json.dumps(entries))
    conn.commit()


def _until(entry: dict) -> datetime | None:
    try:
        return datetime.strptime(entry["until"], STAMP).replace(tzinfo=timezone.utc)
    except (ValueError, KeyError, TypeError):
        return None


def active(conn: sqlite3.Connection, now: datetime | None = None) -> dict[str, dict]:
    """subject -> the snooze, for the ones that have not ended."""
    now = _now(now)
    out = {}
    for e in _load(conn):
        until = _until(e)
        if until and until > now:
            out[e["key"]] = e
    return out


def snooze(conn: sqlite3.Connection, subject: str, minutes: int, by: str = "", note: str = "", now: datetime | None = None) -> dict:
    if not isinstance(subject, str) or not SUBJECT_RE.match(subject):
        raise ValueError("that cannot be snoozed")
    if isinstance(minutes, bool) or not isinstance(minutes, int) or not MIN_MINUTES <= minutes <= MAX_MINUTES:
        raise ValueError(f"snooze for between {MIN_MINUTES} minutes and 30 days")
    now = _now(now)
    entry = {"key": subject, "until": (now + timedelta(minutes=minutes)).strftime(STAMP), "by": str(by)[:40], "note": str(note or "")[:MAX_NOTE],
             "created": now.strftime(STAMP)}
    entries = [e for e in _load(conn) if e["key"] != subject and (_until(e) or now) > now]
    entries.append(entry)
    _save(conn, entries[-500:])
    return entry


def clear(conn: sqlite3.Connection, subject: str) -> bool:
    entries = _load(conn)
    kept = [e for e in entries if e["key"] != subject]
    if len(kept) != len(entries):
        _save(conn, kept)
        return True
    return False


def tag(conn: sqlite3.Connection, kind: str, subject: str | None, now: str | None = None) -> str | None:
    """Used by add_event: the tag of an event about a snoozed subject. A recovery ends the snooze (and is held back itself)."""
    if not subject:
        return None
    when = datetime.strptime(now, STAMP).replace(tzinfo=timezone.utc) if now else None
    if subject not in active(conn, when):
        return None
    if kind in RESOLVES:
        clear(conn, subject)
    return TAG


def expire(conn: sqlite3.Connection, now: datetime | None = None) -> list[str]:
    """Remove the snoozes that ended; for a problem that is still there raise one ordinary event. Returns the event kinds raised."""
    from app.db import add_event

    now = _now(now)
    entries = _load(conn)
    ended = [e for e in entries if (_until(e) or now) <= now]
    if not ended:
        return []
    _save(conn, [e for e in entries if e not in ended])
    raised: list[str] = []
    stamp = now.strftime(STAMP)
    for e in ended:
        kind, _, rest = e["key"].partition(":")
        if kind == "device":
            row = conn.execute("SELECT id, online, COALESCE(custom_name, hostname, primary_ip) AS n FROM devices WHERE id = ?", (int(rest),)).fetchone()
            if row and not row["online"]:
                add_event(conn, "device_offline", f"{row['n']} is still offline (the snooze ended)", device_id=row["id"], now=stamp, subject=None)
                raised.append("device_offline")
        elif kind == "service":
            row = conn.execute("SELECT name, device_id, last_up FROM service_checks WHERE id = ?", (int(rest),)).fetchone()
            if row and row["last_up"] == 0:
                add_event(conn, "service_down", f"{row['name']} is still down (the snooze ended)", device_id=row["device_id"], now=stamp, subject=None)
                raised.append("service_down")
        elif kind == "site":
            row = conn.execute("SELECT name, offline_notified FROM probes WHERE id = ?", (int(rest),)).fetchone()
            if row and row["offline_notified"]:
                add_event(conn, "probe_offline", f"{row['name']} is still not reporting (the snooze ended)", now=stamp, subject=None)
                raised.append("probe_offline")
        elif kind == "metric":
            device_id, metric, label = rest.split(":", 2)
            row = conn.execute(
                "SELECT s.level, s.value, COALESCE(d.custom_name, d.hostname, d.primary_ip) AS n FROM metric_state s JOIN host_monitors m ON m.id = s.monitor_id "
                "JOIN devices d ON d.id = m.device_id WHERE m.device_id = ? AND s.metric = ? AND s.label = ?", (int(device_id), metric, label)).fetchone()
            if row and row["level"] != "ok":
                ev = "metric_critical" if row["level"] == "critical" else "metric_warning"
                where = f" on {label}" if label else ""
                add_event(conn, ev, f"{row['n']}: {metric.replace('_', ' ')}{where} is still {row['value']:g} (the snooze ended)", device_id=int(device_id), now=stamp, subject=None)
                raised.append(ev)
    return raised
