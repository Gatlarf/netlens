"""Anomalies: a reading that is unusual for this device at this time of day (a paid feature, see app/insights.py).

No fixed limit: every series is compared with its own past. For each watched series Netlens takes the last two weeks, keeps the
readings of the same kind of hour (the same hour of day, weekday or weekend) and compares the last quarter of an hour with their
median. The spread is the median absolute deviation, so one bad night does not make a bad night normal. A reading is an anomaly
when it is far outside that spread and also clearly different in absolute terms (a quiet device that goes from 1 to 4 percent is not).
It has to last two rounds, and one series is announced at most once every six hours.
This is statistics, no language model.
"""

from __future__ import annotations

import json
import logging
import statistics
import time
from typing import Any

from app import tsdb
from app.db import add_event, get_setting, set_setting, utcnow

log = logging.getLogger(__name__)

HISTORY = 14 * 86400
MIN_HISTORY = 5 * 86400
NOW_SPAN = 20 * 60
MIN_SAMPLES = 8
SIGMAS = 5.0
COOLDOWN = 6 * 3600
STATE_KEY = "anomaly.state"
# (entity, metric, label) -> what a deviation has to be at least, in the unit of the metric, and a readable name
WATCHED = {
    ("device", "cpu_pct"): ("Processor busy", 25.0), ("device", "mem_pct"): ("Memory in use", 15.0),
    ("device", "rtt_ms"): ("Response time", 40.0), ("service", "response_ms"): ("Service response time", 150.0),
}


def _hour_class(ts: float) -> tuple[int, bool]:
    t = time.gmtime(ts)
    return t.tm_hour, t.tm_wday >= 5


def judge(points: list[list[float]], current: float, now: float, min_delta: float) -> dict[str, Any] | None:
    """How unusual `current` is against `points` ([t, avg, ...], oldest first). None when there is not enough history to say."""
    if len(points) < MIN_SAMPLES * 2 or points[-1][0] - points[0][0] < MIN_HISTORY:
        return None
    hour, weekend = _hour_class(now)
    same = [p[1] for p in points if _hour_class(p[0]) == (hour, weekend) and p[1] is not None]
    if len(same) < MIN_SAMPLES:
        same = [p[1] for p in points if _hour_class(p[0])[0] == hour and p[1] is not None]      # every day of the week
    if len(same) < MIN_SAMPLES:
        return None
    median = statistics.median(same)
    mad = statistics.median(abs(x - median) for x in same) * 1.4826
    spread = max(mad, min_delta / SIGMAS / 2)
    deviation = current - median
    score = deviation / spread
    return {"median": round(median, 2), "current": round(current, 2), "score": round(score, 1), "unusual": deviation >= min_delta and score >= SIGMAS}


def scan(conn, now: float | None = None) -> list[dict[str, Any]]:
    """Every watched series with a verdict; only the unusual ones are listed (the most unusual first)."""
    now = now if now is not None else time.time()
    store = tsdb.for_conn(conn)
    if store is None:
        return []
    names = {r["id"]: r["custom_name"] or r["hostname"] or r["primary_ip"] or f"device {r['id']}" for r in conn.execute("SELECT id, custom_name, hostname, primary_ip FROM devices")}
    online = {r["id"] for r in conn.execute("SELECT id FROM devices WHERE online = 1")}
    snames = {r["id"]: (r["name"], r["device_id"]) for r in conn.execute("SELECT id, name, device_id FROM service_checks WHERE enabled = 1")}
    out = []
    for entity, ids in (("device", online), ("service", set(snames))):
        for entity_id in ids:
            for s in store.metrics_of(entity, entity_id):
                spec = WATCHED.get((entity, s["metric"]))
                if spec is None or s["last"] is None or s["last_ts"] is None or now - s["last_ts"] > 3600:
                    continue
                recent = store.query(entity, entity_id, s["metric"], s["label"], span=NOW_SPAN, end=int(now), points=10)["points"]
                if not recent:
                    continue
                current = sum(p[1] for p in recent) / len(recent)
                past = store.query(entity, entity_id, s["metric"], s["label"], span=HISTORY, end=int(now) - 3600, points=600)["points"]
                verdict = judge(past, current, now, spec[1])
                if verdict and verdict["unusual"]:
                    device_id = entity_id if entity == "device" else snames[entity_id][1]
                    what = names.get(entity_id) if entity == "device" else snames[entity_id][0]
                    out.append({"entity": entity, "entity_id": entity_id, "device_id": device_id, "metric": s["metric"], "label": s["label"], "title": spec[0], "unit": s["unit"], "name": what, **verdict})
    out.sort(key=lambda a: -a["score"])
    return out


def _unit(a: dict) -> str:
    return "%" if a["unit"] == "%" or a["metric"].endswith("_pct") else " ms" if a["unit"] == "ms" else ""


def describe(a: dict) -> str:
    unit = _unit(a)
    return f"{a['title']} of {a['name']} is {a['current']:g}{unit}, unusual for this time of day (normally about {a['median']:g}{unit})"


def check(conn, now: float | None = None) -> list[str]:
    """Raise an `anomaly` event for a series that was unusual in two rounds in a row. Returns the texts raised."""
    from app import insights

    if not insights.allowed(conn):
        return []
    now = now if now is not None else time.time()
    try:
        state = json.loads(get_setting(conn, STATE_KEY) or "{}")
    except ValueError:
        state = {}
    new: dict[str, dict] = {}
    raised = []
    for a in scan(conn, now):
        key = f"{a['entity']}:{a['entity_id']}:{a['metric']}:{a['label']}"
        before = state.get(key, {})
        entry = {"streak": before.get("streak", 0) + 1, "announced": before.get("announced", 0)}
        if entry["streak"] >= 2 and now - entry["announced"] >= COOLDOWN:
            text = describe(a)
            add_event(conn, "anomaly", text, device_id=a["device_id"], now=utcnow(), subject=f"anomaly:{key}")
            entry["announced"] = now
            raised.append(text)
        new[key] = entry
    for key, entry in state.items():                      # back to normal: remember when it was announced, so a flicker is not announced again at once
        if key not in new and now - entry.get("announced", 0) < COOLDOWN:
            new[key] = {"streak": 0, "announced": entry["announced"]}
    set_setting(conn, STATE_KEY, json.dumps(new))
    return raised


async def loop(db_path: str) -> None:
    import asyncio

    from app.db import connect

    await asyncio.sleep(120)
    while True:
        try:
            conn = connect(db_path)
            try:
                if await asyncio.to_thread(check, conn):
                    from app.notify.channels import process_channels

                    await process_channels(db_path)
            finally:
                conn.close()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - detection must never stop the monitoring
            log.exception("anomaly detection round failed")
        await asyncio.sleep(15 * 60)
