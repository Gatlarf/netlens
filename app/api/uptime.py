from typing import Literal

from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.api.devices import get_conn
from app.api.stats import _cached
from app.auth import devices_in_scope, scope_of
from app.db import connect
from app.uptime import RANGES, core_choices, device_uptime, set_core, uptime_overview

router = APIRouter(prefix="/api", tags=["uptime"])


@router.get("/uptime/latest")
def get_uptime_latest(request: Request, conn=Depends(get_conn)) -> list[dict]:
    """The response time right now of every device that answered a check in the last half hour (the average of its last three checks), for views that move
    with it, such as the radar of the HUD. {id, rtt_ms, up, ts}; a device whose latest check failed has up false and no rtt_ms."""
    from datetime import datetime, timedelta, timezone

    since = (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    latest: dict[int, list] = {}
    for r in conn.execute("SELECT device_id, ts, up, rtt_ms FROM checks WHERE ts >= ? ORDER BY ts", (since,)):
        latest.setdefault(r["device_id"], []).append(r)
    scope = scope_of(request)
    allowed = devices_in_scope(conn, scope) if scope is not None else None
    out = []
    for device_id, rows in latest.items():
        if allowed is not None and device_id not in allowed:
            continue
        last = rows[-1]
        times = [r["rtt_ms"] for r in rows[-3:] if r["up"] and r["rtt_ms"] is not None]
        out.append({"id": device_id, "up": bool(last["up"]), "rtt_ms": round(sum(times) / len(times), 2) if last["up"] and times else None, "ts": last["ts"]})
    return out


@router.get("/devices/{device_id}/calendar")
def get_device_calendar(device_id: int, days: int = Query(365, ge=7, le=400), conn=Depends(get_conn)) -> dict:
    """Availability of a device per day (a calendar heatmap), with outages per day and its firmware and OS changes as marks. {from, to, days: [{d, pct, outages}], marks: [{d, kind, text}]}"""
    from app import visuals

    out = visuals.calendar(conn, device_id, days)
    if out is None:
        raise HTTPException(status_code=404, detail="device not found")
    return out


@router.get("/uptime/replay")
def get_uptime_replay(request: Request, hours: int = Query(24, ge=1, le=168), conn=Depends(get_conn)) -> dict:
    """What the HUD time machine replays: for every device with checks in the last `hours`, its state at the start of the window (`initial`) and every
    change after that. Only changes are returned, not the checks, so a week of a big network stays small. `markers` are the things that changed in the same period (a port opened, an update, a container stopped) for the amber ticks. {from, to, changes: [{id, ts, up, initial}], markers: [{ts, id, kind, text}]}"""
    from app.db import ago, utcnow

    since = ago(hours=hours)
    scope = scope_of(request)
    allowed = devices_in_scope(conn, scope) if scope is not None else None
    changes = []
    for r in conn.execute(
        "WITH s AS (SELECT device_id, ts, up, LAG(up) OVER (PARTITION BY device_id ORDER BY ts, id) AS prev FROM checks WHERE ts >= ?) "
        "SELECT device_id, ts, up, prev FROM s WHERE prev IS NULL OR prev != up ORDER BY ts",
        (since,),
    ):
        if allowed is not None and r["device_id"] not in allowed:
            continue
        first = r["prev"] is None
        changes.append({"id": r["device_id"], "ts": since if first else r["ts"], "up": bool(r["up"]), "initial": first})
    from app import causes

    marks = ",".join("?" * len(causes.CHANGES))
    markers = []
    for r in conn.execute(f"SELECT ts, device_id, kind, detail FROM events WHERE ts >= ? AND kind IN ({marks}) AND device_id IS NOT NULL AND maintenance IS NULL ORDER BY id DESC LIMIT 400", (since, *causes.CHANGES)):
        if allowed is None or r["device_id"] in allowed:
            markers.append({"ts": r["ts"], "id": r["device_id"], "kind": r["kind"], "text": (r["detail"] or r["kind"].replace("_", " "))[:140]})
    markers.reverse()
    return {"from": since, "to": utcnow(), "changes": changes, "markers": markers}


@router.get("/uptime")
def get_uptime_overview(request: Request, bars: int = Query(60, ge=1, le=240), range: Literal["6h", "24h", "7d", "30d"] | None = None) -> list[dict]:
    """Per-device heartbeat bars and 24h/7d/30d uptime, like Uptime Kuma's dashboard. With `range` each bar is a slice of that period with its
    time and response time (what the page uses); without it the bars are the last checks as 1/0."""
    def build():
        conn = connect(request.app.state.db_path)
        try:
            return uptime_overview(conn, bars=bars, days=RANGES[range] if range else None)
        finally:
            conn.close()

    result = _cached(request, ("uptime", request.app.state.db_path, range, bars), build)
    scope = scope_of(request)
    if scope is not None:                      # a customer view: only the devices of its groups
        conn = connect(request.app.state.db_path)
        try:
            allowed = devices_in_scope(conn, scope)
        finally:
            conn.close()
        result = [r for r in result if r.get("id") in allowed]
    return result


@router.get("/devices/{device_id}/uptime")
def get_device_uptime(
    device_id: int,
    limit: int = Query(60, ge=1, le=500),
    range: Literal["6h", "24h", "7d", "30d"] | None = None,
    conn=Depends(get_conn),
) -> dict:
    if conn.execute("SELECT 1 FROM devices WHERE id = ?", (device_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="device not found")
    return device_uptime(conn, device_id, limit=limit, days=RANGES[range] if range else None)


@router.get("/uptime/core")
def get_core(conn=Depends(get_conn)) -> dict:
    """Every device with whether it is marked always-on, plus Netlens's suggestions."""
    return {"devices": core_choices(conn)}


class CoreBody(BaseModel):
    device_ids: list[int] = Field(max_length=5000)


@router.put("/uptime/core")
def put_core(body: CoreBody, request: Request, conn=Depends(get_conn)) -> dict:
    """Mark exactly these devices as always-on (an administrator; viewers are refused by the role filter)."""
    count = set_core(conn, body.device_ids)
    request.app.state.__dict__.get("stats_cache", {}).clear()      # the pages show the new choice at once
    return {"count": count}
