"""Escalation (a paid feature): an alert that nobody acknowledges is sent on, to other channels, after a while.

A policy has levels: "after 15 minutes tell these channels, after 45 minutes those". It looks at the serious events (the kinds that break through quiet
hours, or the ones you choose). An event stops escalating when somebody acknowledges it or when it has resolved itself (the matching recovery event
arrived). Who is on call is whoever is behind the channels of a level: use a channel per person or per team (e-mail, ntfy, Telegram ...).
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from app import licence
from app.db import get_setting, set_setting

log = logging.getLogger(__name__)
KEY = "escalation.policy"
STAMP = "%Y-%m-%dT%H:%M:%SZ"
LOOKBACK = timedelta(hours=24)


class PolicyError(ValueError):
    pass


def default_kinds() -> list[str]:
    from app.notify.channels import CRITICAL

    return sorted(CRITICAL)


def get_policy(conn: sqlite3.Connection) -> dict[str, Any]:
    try:
        doc = json.loads(get_setting(conn, KEY) or "{}")
    except ValueError:
        doc = {}
    levels = doc.get("levels") if isinstance(doc.get("levels"), list) else []
    return {"enabled": bool(doc.get("enabled")), "kinds": doc.get("kinds") if isinstance(doc.get("kinds"), list) and doc["kinds"] else default_kinds(),
            "levels": [{"after_min": int(l["after_min"]), "channels": [str(c) for c in l.get("channels", [])]} for l in levels if isinstance(l, dict) and str(l.get("after_min", "")).isdigit()]
            or [{"after_min": 15, "channels": []}]}


def save_policy(conn: sqlite3.Connection, data: dict) -> dict[str, Any]:
    from app.notify.channels import EVENT_LABELS, load_channels

    known = {str(c.get("id")) for c in load_channels(conn)}
    kinds = data.get("kinds") or default_kinds()
    if not isinstance(kinds, list) or any(k not in EVENT_LABELS for k in kinds):
        raise PolicyError("choose events from the list")
    levels = []
    for i, level in enumerate(data.get("levels") or []):
        after = level.get("after_min")
        if not isinstance(after, int) or isinstance(after, bool) or not 1 <= after <= 1440:
            raise PolicyError(f"level {i + 1}: the time is between 1 and 1440 minutes")
        channels = [str(c) for c in level.get("channels") or []]
        if any(c not in known for c in channels):
            raise PolicyError(f"level {i + 1}: choose channels that exist (Settings → Alert channels)")
        levels.append({"after_min": after, "channels": channels})
    if not levels:
        raise PolicyError("add at least one level")
    if [l["after_min"] for l in levels] != sorted({l["after_min"] for l in levels}):
        raise PolicyError("the levels must have increasing times")
    if len(levels) > 4:
        raise PolicyError("at most four levels")
    set_setting(conn, KEY, json.dumps({"enabled": bool(data.get("enabled")), "kinds": kinds, "levels": levels}))
    return get_policy(conn)


def _resolved(conn: sqlite3.Connection, event: sqlite3.Row) -> bool:
    from app.remediation import RECOVERY

    good = RECOVERY.get(event["kind"])
    if not good or event["device_id"] is None:
        return False
    return bool(conn.execute("SELECT 1 FROM events WHERE kind = ? AND device_id = ? AND id > ? LIMIT 1", (good, event["device_id"], event["id"])).fetchone())


def open_items(conn: sqlite3.Connection, now: datetime | None = None) -> list[dict]:
    """The serious events that are neither acknowledged nor resolved, with the level they reached."""
    now = now or datetime.now(timezone.utc)
    policy = get_policy(conn)
    since = (now - LOOKBACK).strftime(STAMP)
    marks = ",".join("?" for _ in policy["kinds"])
    out = []
    for e in conn.execute(f"SELECT e.*, COALESCE(d.custom_name, d.hostname, d.primary_ip) AS name, d.primary_ip AS ip, d.mac, d.vendor, d.trusted FROM events e LEFT JOIN devices d ON d.id = e.device_id "
                          f"WHERE e.ts >= ? AND e.kind IN ({marks}) AND (e.maintenance IS NULL OR e.maintenance = '') ORDER BY e.id", (since, *policy["kinds"])):
        state = conn.execute("SELECT * FROM escalation_state WHERE event_id = ?", (e["id"],)).fetchone()
        if (state and state["acked_at"]) or _resolved(conn, e):
            continue
        out.append({"id": e["id"], "ts": e["ts"], "kind": e["kind"], "detail": e["detail"], "device": e["name"], "device_id": e["device_id"], "level": state["level"] if state else 0, "event": dict(e)})
    return out


def acknowledge(conn: sqlite3.Connection, event_id: int, who: str, now: datetime | None = None) -> None:
    if not conn.execute("SELECT 1 FROM events WHERE id = ?", (event_id,)).fetchone():
        raise PolicyError("that event does not exist")
    stamp = (now or datetime.now(timezone.utc)).strftime(STAMP)
    conn.execute("INSERT INTO escalation_state (event_id, level, acked_by, acked_at) VALUES (?, 0, ?, ?) ON CONFLICT(event_id) DO UPDATE SET acked_by = excluded.acked_by, acked_at = excluded.acked_at", (event_id, who, stamp))
    conn.commit()


def due(conn: sqlite3.Connection, now: datetime | None = None) -> list[tuple[dict, int, list[str]]]:
    """[(item, new level, channel ids)] for what has to be escalated now."""
    now = now or datetime.now(timezone.utc)
    policy = get_policy(conn)
    if not policy["enabled"] or not licence.allows(conn, "oncall", now):
        return []
    out = []
    for item in open_items(conn, now):
        age = now - datetime.strptime(item["ts"], STAMP).replace(tzinfo=timezone.utc)
        reached = item["level"]
        for index, level in enumerate(policy["levels"], 1):
            if index > reached and age >= timedelta(minutes=level["after_min"]):
                out.append((item, index, level["channels"]))
                reached = index
    return out


async def process(db_path: str, *, now: datetime | None = None, poster=None, mailer=None) -> int:
    from app.db import connect
    from app.notify import channels as ch

    now = now or datetime.now(timezone.utc)
    sent = 0
    conn = connect(db_path)
    try:
        by_id = {str(c.get("id")): c for c in ch.load_channels(conn)}
        for item, level, ids in due(conn, now):
            title = f"ESCALATION {level}: {ch.build_digest([item['event']])[0]}"
            body = f"Nobody has acknowledged this for {int((now - datetime.strptime(item['ts'], STAMP).replace(tzinfo=timezone.utc)).total_seconds() // 60)} minutes.\n\n{item['detail'] or item['kind']}"
            for cid in ids:
                channel = by_id.get(cid)
                if channel is None or not channel.get("enabled", True):
                    continue
                try:
                    await asyncio.to_thread(ch.send_channel, channel, title, body, [item["event"]], **({"poster": poster} if poster else {}), **({"mailer": mailer} if mailer else {}))
                    sent += 1
                except ch.ChannelError as exc:
                    log.warning("escalation through %s failed: %s", channel.get("name"), exc)
            conn.execute("INSERT INTO escalation_state (event_id, level, sent_at) VALUES (?, ?, ?) ON CONFLICT(event_id) DO UPDATE SET level = excluded.level, sent_at = excluded.sent_at",
                         (item["id"], level, now.strftime(STAMP)))
            conn.commit()
    finally:
        conn.close()
    return sent


async def loop(db_path: str) -> None:
    await asyncio.sleep(40)
    while True:
        try:
            await process(db_path)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - escalation must never stop the monitoring
            log.exception("escalation round failed")
        await asyncio.sleep(30)
