"""The health score: one number from 0 to 100 for the network, one for the cameras, and one for each device that counts.

What counts (only devices that are marked always-on, or that someone marked critical):
  gear      routers, switches and access points           weight 1.0
  hosts     servers, NAS, virtual machines, critical ones  weight 0.5 (a virtual machine counts half of a switch)
  containers all containers together                       weight 0.25 (less than one virtual machine)
The importance somebody gave a device multiplies its weight: critical x3, normal x1, low x0 (a low device never counts).
Cameras never lower the network score: they have a score of their own.

A device scores from what is measured about it (a part that is not measured is left out, never counted as zero):
  uptime       the share of checks that were answered in 7 days, less a few points for every time it went up and down in the last day (one outage is free)
  loss         the share of checks that were answered in the last 24 hours
  latency      the average answer time of the last 24 hours (a good answer is under 30 ms, nothing is left at 300 ms)
  temperature  the newest reading (fine below 55 °C, half at 80 °C, nothing at 100 °C)
A device that is offline right now cannot score more than 30.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from app import checkstats
from app.stats import _ago, _flaps

GEAR = {"router", "switch", "ap"}
HOSTS = {"server", "nas", "vm"}
WEIGHT = {"gear": 1.0, "hosts": 0.5, "containers": 0.25}
TIER = {"critical": 3.0, "normal": 1.0, "low": 0.0}
PARTS = {"uptime": 40, "loss": 20, "latency": 20, "temperature": 20}          # how much each reading counts in one device's score
OFFLINE_CAP = 30
MIN_CHECKS = 3                                                              # fewer checks than this say nothing yet
FLAP_POINTS = 4                                                             # points off the uptime part for every up/down change in the last day beyond the two of one single outage


def _clip(value: float) -> float:
    return max(0.0, min(100.0, value))


def latency_score(ms: float) -> float:
    return _clip(100 - (ms - 30) * 100 / 270)


def temperature_score(c: float) -> float:
    if c <= 55:
        return 100.0
    if c <= 80:
        return 100 - (c - 55) * 50 / 25
    if c <= 90:
        return 50 - (c - 80) * 30 / 10
    return _clip(20 - (c - 90) * 2)


def group_of(kind: str, tier: str, always_on: bool) -> str | None:
    """Which group a device belongs to for the score, or None when it does not count."""
    if kind == "camera":
        return "cameras" if always_on or tier == "critical" else None
    if not (always_on or tier == "critical"):
        return None
    if kind in GEAR:
        return "gear"
    if kind in HOSTS or tier == "critical":
        return "hosts"
    return None


def device_score(parts: dict[str, float | None], online: bool) -> tuple[float | None, str | None]:
    """The score of one device from its parts, and the name of the part that costs the most (None when nothing is measured yet)."""
    have = {k: v for k, v in parts.items() if v is not None}
    if not have:
        return None, None
    total = sum(PARTS[k] for k in have)
    score = sum(PARTS[k] * v for k, v in have.items()) / total
    if not online:
        score = min(score, OFFLINE_CAP)
    worst = max(have, key=lambda k: PARTS[k] * (100 - have[k]) / total)
    return round(score, 1), (worst if have[worst] < 100 else None)


def _reason(part: str | None, online: bool, parts: dict, extra: dict) -> str:
    if not online:
        return "is not answering"
    if part == "temperature" and extra.get("temp") is not None:
        return f"runs hot ({extra['temp']:.0f} °C)"
    if part == "uptime":
        return f"went up and down {extra['flaps']} times in a day" if extra.get("flaps") else f"was reachable {extra['uptime']:.1f}% of the time this week"
    if part == "loss":
        return f"missed {100 - extra['day']:.0f}% of its checks today"
    if part == "latency" and extra.get("ms") is not None:
        return f"answers slowly ({extra['ms']:.0f} ms)"
    return "is below its best"


def _entry(d: dict, group: str, tier: str, week: dict, day: dict, flaps: dict, readings: dict[int, dict]) -> dict | None:
    """The score of one device (None while nothing is known about it). `group` is where the device counts: "gear", "hosts", "cameras", or "other" for a device that is not in the network score."""
    w_ups, w_n = (week.get(d["id"]) or (0, 0))[:2]
    d_ups, d_n, rtt_sum, rtt_n = (day.get(d["id"]) or (0, 0, 0, 0))[:4]
    parts: dict[str, float | None] = {"uptime": None, "loss": None, "latency": None, "temperature": None}
    extra: dict[str, Any] = {"flaps": flaps.get(d["id"], 0)}
    if w_n >= MIN_CHECKS:
        extra["uptime"] = 100 * w_ups / w_n
        parts["uptime"] = _clip(extra["uptime"] - FLAP_POINTS * max(0, extra["flaps"] - 2))
    if d_n >= MIN_CHECKS:
        extra["day"] = 100 * d_ups / d_n
        parts["loss"] = extra["day"]
    if rtt_n and rtt_n >= MIN_CHECKS:
        extra["ms"] = rtt_sum / rtt_n
        parts["latency"] = latency_score(extra["ms"])
    if group != "cameras":
        temp = (readings.get(d["id"]) or {}).get("temp")
        if temp is not None:
            extra["temp"] = temp
            parts["temperature"] = temperature_score(temp)
    else:
        parts["latency"] = None                                                 # a camera is judged on being there, not on how fast it answers
    score, worst = device_score(parts, bool(d["online"]))
    if score is None and not d["online"]:
        score, worst = float(OFFLINE_CAP), "uptime"
    if score is None:
        return None
    return {"id": d["id"], "name": d["name"], "group": group, "tier": tier, "score": score, "parts": parts, "weight": WEIGHT.get(group, 1.0) * TIER[tier],
            "reason": _reason(worst, bool(d["online"]), parts, extra), "online": bool(d["online"])}


def compute(conn: sqlite3.Connection, now: str, devices: list[dict], readings: dict[int, dict], container_numbers: dict) -> dict[str, Any]:
    """The score block of the summary: {score, label, parts, why, costs, cameras, devices: {id: score}}. `devices` is the summary's device list."""
    tiers = {r["id"]: (r["tier"] or "normal", bool(r["always_on"])) for r in conn.execute("SELECT id, tier, always_on FROM devices")}
    week = checkstats.totals(conn, _ago(now, days=7))
    day = checkstats.totals(conn, _ago(now, hours=24))
    flaps = _flaps(conn, _ago(now, hours=24))

    entries: list[dict] = []
    for d in devices:
        tier, always_on = tiers.get(d["id"], ("normal", False))
        group = group_of(d["type"], tier, always_on)
        if group is None:
            continue
        entry = _entry(d, group, tier, week, day, flaps, readings)
        if entry is not None:
            entries.append(entry)

    cameras = [e for e in entries if e["group"] == "cameras"]
    counted = [e for e in entries if e["group"] != "cameras" and e["weight"] > 0]

    boxes = container_numbers.get("running") or 0
    sick = (container_numbers.get("unhealthy") or 0) + (container_numbers.get("restarting") or 0)
    host = next((x.get("host_device_id") for x in container_numbers.get("problems") or [] if x.get("host_device_id")), None)
    container_score = None if not boxes else round(_clip(100 * (1 - sick / boxes)), 1)
    total_weight = sum(e["weight"] for e in counted) + (WEIGHT["containers"] if container_score is not None else 0)
    score = None
    costs: list[dict] = []
    if total_weight > 0:
        lost = {e["id"]: e["weight"] * (100 - e["score"]) / total_weight for e in counted}
        score = round(100 - sum(lost.values()) - ((WEIGHT["containers"] * (100 - container_score) / total_weight) if container_score is not None else 0))
        for e in counted:
            if lost[e["id"]] >= 0.5:
                costs.append({"device_id": e["id"], "name": e["name"], "points": round(lost[e["id"]]), "reason": e["reason"]})
        if container_score is not None and container_score < 100:
            costs.append({"device_id": None, "name": "Containers", "points": round(WEIGHT["containers"] * (100 - container_score) / total_weight),
                          "reason": f"{sick} of {boxes} are unhealthy or restarting",
                          "href": (f"#/device/{host}/network/virtualization" if host else "#/devices")})
        costs = sorted((c for c in costs if c["points"] >= 1), key=lambda c: -c["points"])[:5]

    def spread(part: str) -> float | None:
        rows = [(e["weight"], e["parts"][part]) for e in counted if e["parts"].get(part) is not None]
        total = sum(w for w, _ in rows)
        return round(sum(w * v for w, v in rows) / total) if total else None

    cam_rows = [e for e in cameras if e["tier"] != "low"]
    cam_total = sum(TIER[e["tier"]] for e in cam_rows)
    cam_score = round(sum(TIER[e["tier"]] * e["score"] for e in cam_rows) / cam_total) if cam_total else None
    label = None if score is None else "good" if score >= 80 else "fair" if score >= 50 else "poor"
    why = None
    if score is not None and costs:
        why = f"Held back by {costs[0]['name']}: it {costs[0]['reason']}." if costs[0]["device_id"] is not None else f"Held back by containers: {costs[0]['reason']}."
    return {
        "score": score, "label": label, "why": why, "costs": costs,
        "parts": {"latency": spread("latency"), "loss": spread("loss"), "uptime": spread("uptime"), "temperature": spread("temperature"),
                  "containers": container_score},
        "counted": {"gear": sum(1 for e in counted if e["group"] == "gear"), "hosts": sum(1 for e in counted if e["group"] == "hosts"), "containers": boxes},
        "cameras": {"score": cam_score, "total": len(cameras), "online": sum(1 for e in cameras if e["online"]),
                    "weakest": [{"device_id": e["id"], "name": e["name"], "score": round(e["score"])} for e in sorted(cameras, key=lambda e: e["score"])[:3] if round(e["score"]) < 100]},
        "devices": {e["id"]: round(e["score"]) for e in entries},
    }


# ----------------------------------------------------------------------------- the score over time
KEEP_DAYS = 400


def remember(conn: sqlite3.Connection, now: str, block: dict[str, Any]) -> None:
    """Keep today's score (the newest reading of the day). Written only when it changes, so a page that asks all day costs one read."""
    if block.get("score") is None:
        return
    day = now[:10]
    cameras = (block.get("cameras") or {}).get("score")
    row = conn.execute("SELECT score, cameras FROM score_history WHERE day = ?", (day,)).fetchone()
    if row is not None and row["score"] == block["score"] and row["cameras"] == cameras:
        return
    conn.execute("INSERT INTO score_history (day, score, cameras, updated) VALUES (?, ?, ?, ?) ON CONFLICT(day) DO UPDATE SET score = excluded.score, cameras = excluded.cameras, updated = excluded.updated",
                 (day, block["score"], cameras, now))
    if row is None:                                       # a new day: drop what is too old (once a day)
        from datetime import datetime, timedelta

        old = (datetime.strptime(day, "%Y-%m-%d") - timedelta(days=KEEP_DAYS)).strftime("%Y-%m-%d")
        conn.execute("DELETE FROM score_history WHERE day < ?", (old,))
    conn.commit()


def history(conn: sqlite3.Connection, since_day: str, until_day: str | None = None) -> list[dict[str, Any]]:
    """[{day, score, cameras}] from `since_day` (inclusive), oldest first."""
    if until_day:
        rows = conn.execute("SELECT day, score, cameras FROM score_history WHERE day >= ? AND day <= ? ORDER BY day", (since_day, until_day))
    else:
        rows = conn.execute("SELECT day, score, cameras FROM score_history WHERE day >= ? ORDER BY day", (since_day,))
    return [dict(r) for r in rows]


def trend(conn: sqlite3.Connection, now: str, score: int | None) -> dict[str, Any] | None:
    """How the score moved: against the last day before today that has a reading ({"delta": +2, "since": "2026-11-16"}), None while there is no earlier day."""
    if score is None:
        return None
    row = conn.execute("SELECT day, score FROM score_history WHERE day < ? ORDER BY day DESC LIMIT 1", (now[:10],)).fetchone()
    if row is None:
        return None
    return {"delta": score - row["score"], "since": row["day"], "was": row["score"]}


# ----------------------------------------------------------------------------- one device
def label_of(score: float | None) -> str | None:
    return None if score is None else "good" if score >= 80 else "fair" if score >= 50 else "poor"


def for_device(conn: sqlite3.Connection, now: str, device_id: int) -> dict[str, Any] | None:
    """The score of one device for its page: {score, label, reason, counted, parts}, or None when the device does not exist or nothing is known about it yet.
    `counted` says whether the device is part of the network score (always-on or critical devices); the score itself is worked out the same way for every device."""
    from app import tsdb
    from app.hostmetrics import service as hm
    from app.stats import TYPE

    row = conn.execute("SELECT d.id, COALESCE(d.custom_name, d.hostname, d.primary_ip) AS name, d.online, d.tier, d.always_on, " + TYPE + " AS type FROM devices d WHERE d.id = ?", (device_id,)).fetchone()
    if row is None:
        return None
    tier, always_on = row["tier"] or "normal", bool(row["always_on"])
    group = group_of(row["type"], tier, always_on)
    store = tsdb.for_conn(conn)
    readings: dict[int, dict] = {}
    if store is not None:
        known = store.metrics_of_many("device", [device_id]).get(device_id, [])
        readings[device_id] = hm.latest_readings(store, device_id, known)
    d = {"id": device_id, "name": row["name"] or str(device_id), "type": row["type"], "online": bool(row["online"])}
    entry = _entry(d, group or ("cameras" if row["type"] == "camera" else "other"), tier, checkstats.totals(conn, _ago(now, days=7)), checkstats.totals(conn, _ago(now, hours=24)),
                   _flaps(conn, _ago(now, hours=24)), readings)
    if entry is None:
        return None
    score = round(entry["score"])
    return {"score": score, "label": label_of(score), "reason": entry["reason"] if score < 100 else None, "counted": group is not None and entry["weight"] > 0,
            "parts": {k: (None if v is None else round(v)) for k, v in entry["parts"].items()}}
