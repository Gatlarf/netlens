"""The switch for application statistics, and the applications one device used (see app/usagecfg.py). Administrators only."""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from app import usagecat, usagecfg
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["statistics"])


class UsageBody(BaseModel):
    enabled: bool


@router.get("/usage")
def state(conn=Depends(get_conn)) -> dict:
    return {"enabled": usagecfg.enabled(conn), "stored_rows": usagecfg.stored_rows(conn), **usagecat.overview(conn)}


@router.put("/usage")
def change(body: UsageBody, request: Request, conn=Depends(get_conn)) -> dict:
    removed = usagecfg.set_enabled(conn, body.enabled)
    request.app.state.__dict__.setdefault("stats_cache", {}).clear()
    return {"enabled": body.enabled, "removed_rows": removed}


@router.get("/devices/{device_id}/applications")
def device_applications(device_id: int, days: int = Query(7, ge=1, le=90), conn=Depends(get_conn)) -> dict:
    """What one device used over the last `days` days: traffic per application (when the router can say so), and per day."""
    if conn.execute("SELECT 1 FROM devices WHERE id = ?", (device_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="device not found")
    if not usagecfg.enabled(conn):
        return {"enabled": False, "available": False}
    last = conn.execute("SELECT MAX(day) FROM client_usage WHERE device_id = ?", (device_id,)).fetchone()[0]
    if last is None:
        return {"enabled": True, "available": False}
    first = (datetime.strptime(last, "%Y-%m-%d") - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    per_day = conn.execute(
        "SELECT day, SUM(rx_bytes) AS rx, SUM(tx_bytes) AS tx FROM client_usage WHERE device_id = ? AND day >= ? GROUP BY day ORDER BY day", (device_id, first)).fetchall()
    apps = conn.execute(
        "SELECT name, SUM(rx_bytes) AS rx, SUM(tx_bytes) AS tx FROM client_app_usage WHERE device_id = ? AND day >= ? GROUP BY name "
        "ORDER BY SUM(rx_bytes) + SUM(tx_bytes) DESC LIMIT 25", (device_id, first)).fetchall()
    listed = conn.execute("SELECT COALESCE(SUM(rx_bytes + tx_bytes), 0) FROM client_app_usage WHERE device_id = ? AND day >= ?", (device_id, first)).fetchone()[0]
    every = conn.execute("SELECT name, SUM(rx_bytes) AS rx, SUM(tx_bytes) AS tx FROM client_app_usage WHERE device_id = ? AND day >= ? GROUP BY name", (device_id, first)).fetchall()
    policy = usagecat.Policy(conn)
    return {
        "detail": policy.detail, "categories": usagecat.categorise(conn, every, policy)[:25],
        "enabled": True, "available": True, "from": first, "to": last, "days": len(per_day),
        "rx": sum(r["rx"] for r in per_day), "tx": sum(r["tx"] for r in per_day),
        "per_day": [{"day": r["day"], "rx": r["rx"], "tx": r["tx"]} for r in per_day],
        "applications": [{"name": r["name"], "rx": r["rx"], "tx": r["tx"], "share": round(100 * (r["rx"] + r["tx"]) / listed, 1) if listed else 0} for r in apps],
    }


class DetailBody(BaseModel):
    detail: str


class RedirectBody(BaseModel):
    label: str


class RuleBody(BaseModel):
    pattern: str
    category: str


def _done(request: Request, conn, call) -> dict:
    try:
        changed = call()
    except ValueError as err:
        raise HTTPException(status_code=422, detail=str(err))
    request.app.state.__dict__.setdefault("stats_cache", {}).clear()
    return {"rewritten_rows": changed, **usagecat.overview(conn)}


@router.put("/usage/detail")
def set_detail(body: DetailBody, request: Request, conn=Depends(get_conn)) -> dict:
    """Names with their category, or categories only (which rewrites what is stored into categories: it cannot be undone)."""
    return _done(request, conn, lambda: usagecat.set_detail(conn, body.detail))


@router.put("/usage/redirects/{category}")
def set_redirect(category: str, body: RedirectBody, request: Request, conn=Depends(get_conn)) -> dict:
    """Show a whole category under another label (\"Others\"). What is stored for it is rewritten to the label: it cannot be undone."""
    return _done(request, conn, lambda: usagecat.set_redirect(conn, category, body.label))


@router.delete("/usage/redirects/{category}")
def delete_redirect(category: str, request: Request, conn=Depends(get_conn)) -> dict:
    return _done(request, conn, lambda: usagecat.clear_redirect(conn, category))


@router.post("/usage/rules")
def add_rule(body: RuleBody, request: Request, conn=Depends(get_conn)) -> dict:
    return _done(request, conn, lambda: usagecat.add_rule(conn, body.pattern, body.category))


@router.delete("/usage/rules/{rule_id}")
def delete_rule(rule_id: int, request: Request, conn=Depends(get_conn)) -> dict:
    return _done(request, conn, lambda: 0 if usagecat.delete_rule(conn, rule_id) else (_ for _ in ()).throw(ValueError("no such rule")))
