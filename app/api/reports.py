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


@router.get("/availability")
def availability(month: str | None = Query(None), conn=Depends(get_conn)) -> dict:
    """Availability of every device and service in one calendar month (default: this one)."""
    month = _month(conn, month)
    try:
        start, end = reports.month_bounds(month)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    out = reports.availability(conn, start, end)
    out["month"] = month
    out["months"] = reports.months_available(conn)
    return out


@router.get("/availability.csv")
def availability_csv(month: str | None = Query(None), conn=Depends(get_conn)) -> PlainTextResponse:
    month = _month(conn, month)
    try:
        start, end = reports.month_bounds(month)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    body = reports.availability_csv(reports.availability(conn, start, end))
    return PlainTextResponse(body, media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="netlens-availability-{month}.csv"'})


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


@router.put("/weekly/settings")
def put_settings(body: SettingsBody, conn=Depends(get_conn)) -> dict:
    try:
        return {"settings": reports.save_settings(conn, body.model_dump(exclude_unset=True))}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/weekly/send")
async def send_now(request: Request) -> dict:
    """Send the weekly report now to the channels that ticked "Weekly report" (to try it out)."""
    result = await reports.send_weekly(request.app.state.db_path, force=True)
    if not result.get("channels"):
        raise HTTPException(status_code=409, detail='no notification channel has "Weekly report" ticked; tick it under Settings → Notifications')
    return result
