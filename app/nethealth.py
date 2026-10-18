"""Alerts from the network health checks (IPv4 and IPv6), run in the background.

Every half hour the two checks run. A problem is announced only when it is still there on the next run (one blip of the internet is not an
alert), as `net_critical` for a problem and `net_warning` for something to look at; when it has gone, `net_ok` says so. The state is kept per
finding, so a problem that stays is announced once, and a warning that becomes a problem is announced again.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from typing import Any, Callable

from app.db import add_event, get_setting, set_setting, utcnow

log = logging.getLogger(__name__)
STATE_KEY = "nethealth.state"
LABEL = {"v4": "IPv4", "v6": "IPv6"}
KINDS = {"bad": "net_critical", "warn": "net_warning"}
INTERVAL_S = 1800
CONFIRM_RUNS = 2


def _load(conn: sqlite3.Connection) -> dict[str, dict[str, dict]]:
    try:
        doc = json.loads(get_setting(conn, STATE_KEY) or "{}")
    except ValueError:
        doc = {}
    return {fam: (doc.get(fam) if isinstance(doc.get(fam), dict) else {}) for fam in LABEL}


def update(conn: sqlite3.Connection, family: str, result: dict[str, Any], now: str | None = None) -> list[str]:
    """Take one health result into account; returns the kinds of the events it raised."""
    now = now or utcnow()
    state = _load(conn)
    mine = state[family]
    raised: list[str] = []
    seen: set[str] = set()
    for f in result.get("findings", []):
        if f["level"] not in KINDS:
            continue
        seen.add(f["key"])
        cur = mine.get(f["key"]) or {"runs": 0, "alerted": None}
        cur.update({"runs": cur["runs"] + 1, "level": f["level"], "title": f["title"], "text": f["text"], "ts": now})
        rank = {"warn": 1, "bad": 2}
        if cur["runs"] >= CONFIRM_RUNS and rank[f["level"]] > rank.get(cur["alerted"], 0):
            add_event(conn, KINDS[f["level"]], f"{LABEL[family]}: {f['title']}. {f['text']}"[:600], now=now)
            cur["alerted"] = f["level"]
            raised.append(KINDS[f["level"]])
        mine[f["key"]] = cur
    for key in list(mine):
        if key in seen:
            continue
        if mine[key].get("alerted"):
            add_event(conn, "net_ok", f"{LABEL[family]}: {mine[key]['title']} is no longer a problem.", now=now)
            raised.append("net_ok")
        del mine[key]
    set_setting(conn, STATE_KEY, json.dumps(state))
    conn.commit()
    return raised


def attention(conn: sqlite3.Connection) -> list[dict[str, str]]:
    """The announced problems, for the dashboard: [{level, text}]."""
    items = []
    for fam, entries in _load(conn).items():
        for e in entries.values():
            if e.get("alerted"):
                items.append({"level": "bad" if e["level"] == "bad" else "warn", "text": f"{LABEL[fam]}: {e['title']}"})
    return sorted(items, key=lambda i: i["level"] != "bad")


async def round_once(db_path: str, ranges: Callable[[], list[str]]) -> None:
    from app import ipv4health, ipv6health
    from app.db import connect

    conn = connect(db_path)
    try:
        update(conn, "v4", await ipv4health.run(conn, ranges()))
        update(conn, "v6", await ipv6health.run(conn))
    finally:
        conn.close()


async def loop(db_path: str, ranges: Callable[[], list[str]]) -> None:
    await asyncio.sleep(120)
    while True:
        try:
            await round_once(db_path, ranges)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - the checks must never disturb the monitoring
            log.exception("network health round failed")
        await asyncio.sleep(INTERVAL_S)
