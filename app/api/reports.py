"""Reports: the monthly availability report and the weekly summary."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from app import reports
from app.api.devices import get_conn

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _month(conn, month: str | None) -> str:
    return month or datetime.now(timezone.utc).strftime("%Y-%m")


def _report(conn, month, scope, services, group, only_outages, target, hours=None, ignore_maintenance=None):
    month = _month(conn, month)
    try:
        start, end = reports.month_bounds(month)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if scope not in reports.SCOPES:
        raise HTTPException(status_code=422, detail=f"scope must be one of {', '.join(reports.SCOPES)}")
    saved = reports.get_settings(conn)
    hours = saved["hours"] if hours is None else hours
    if hours not in reports.HOURS:
        raise HTTPException(status_code=422, detail=f"hours must be one of {', '.join(reports.HOURS)}")
    ignore = saved["ignore_maintenance"] if ignore_maintenance is None else ignore_maintenance
    out = reports.availability(conn, start, end, scope=scope, with_services=services, group_id=group, only_outages=only_outages, target=target, hours=hours, business=saved,
                               ignore_maintenance=ignore)
    out["month"] = month
    out["business"] = {k: saved[k] for k in ("business_days", "business_start", "business_end")}
    return out


@router.get("/availability")
def availability(month: str | None = Query(None), scope: str = Query("all"), services: bool = Query(True), group: int | None = Query(None),
                 only_outages: bool = Query(False), target: float | None = Query(None, ge=0, le=100), hours: str | None = Query(None),
                 ignore_maintenance: bool | None = Query(None), conn=Depends(get_conn)) -> dict:
    """Availability of the devices and services in one calendar month (default: this one). `scope=core`: only the always-on devices; `services=false`: no service
    checks; `group`: one device group; `only_outages`: list only what had an outage; `target`: an availability goal in percent (rows below it are flagged);
    `hours=business`: count only the business hours; `ignore_maintenance=true`: leave out the time of planned maintenance windows (both default to the saved report settings)."""
    out = _report(conn, month, scope, services, group, only_outages, target, hours, ignore_maintenance)
    out["months"] = reports.months_available(conn)
    out["groups"] = [{"id": r["id"], "name": r["name"]} for r in conn.execute("SELECT id, name FROM device_groups ORDER BY name COLLATE NOCASE")]
    return out


@router.get("/availability.csv")
def availability_csv(month: str | None = Query(None), scope: str = Query("all"), services: bool = Query(True), group: int | None = Query(None),
                     only_outages: bool = Query(False), target: float | None = Query(None, ge=0, le=100), hours: str | None = Query(None),
                     ignore_maintenance: bool | None = Query(None), conn=Depends(get_conn)) -> PlainTextResponse:
    out = _report(conn, month, scope, services, group, only_outages, target, hours, ignore_maintenance)
    return PlainTextResponse(reports.availability_csv(out), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="netlens-availability-{out["month"]}.csv"'})


@router.get("/weekly")
def weekly(conn=Depends(get_conn)) -> dict:
    """The weekly summary as it would be sent now, and the schedule."""
    data = reports.weekly(conn)
    title, text = reports.weekly_text(data)
    return {"title": title, "text": text, "data": data, "settings": reports.get_settings(conn), "days": reports.DAYS}


class SettingsBody(BaseModel):
    enabled: bool | None = None
    day: int | None = None
    hour: int | None = None
    scope: str | None = None            # "all" or "core" (only the always-on devices)
    services: bool | None = None
    new_devices: bool | None = None
    health: bool | None = None
    disks: bool | None = None
    sites: bool | None = None
    max_items: int | None = None        # how many outages, disks ... the text lists
    ignore_maintenance: bool | None = None
    hours: str | None = None            # "all" or "business"
    business_days: list[int] | None = None
    business_start: int | None = None
    business_end: int | None = None
    monthly: bool | None = None         # e-mail the report of the last month
    monthly_day: int | None = None
    monthly_hour: int | None = None
    monthly_target: float | None = None


@router.put("/weekly/settings")
def put_settings(body: SettingsBody, conn=Depends(get_conn)) -> dict:
    try:
        return {"settings": reports.save_settings(conn, body.model_dump(exclude_unset=True))}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/monthly")
def monthly(conn=Depends(get_conn)) -> dict:
    """The monthly report of the last full month as it would be sent now, and the settings."""
    data = reports.monthly(conn)
    title, text = reports.monthly_text(data)
    return {"title": title, "text": text, "data": data, "settings": reports.get_settings(conn)}


@router.post("/monthly/send")
async def send_monthly_now(request: Request) -> dict:
    """Send the monthly report now to the channels that ticked "Monthly report" (to try it out)."""
    result = await reports.send_monthly(request.app.state.db_path, force=True)
    if not result.get("channels"):
        raise HTTPException(status_code=409, detail='no notification channel has "Monthly report" ticked; tick it under Settings → Notifications')
    return result


@router.post("/weekly/send")
async def send_now(request: Request) -> dict:
    """Send the weekly report now to the channels that ticked "Weekly report" (to try it out)."""
    result = await reports.send_weekly(request.app.state.db_path, force=True)
    if not result.get("channels"):
        raise HTTPException(status_code=409, detail='no notification channel has "Weekly report" ticked; tick it under Settings → Notifications')
    return result
