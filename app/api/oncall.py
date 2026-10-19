"""The on-call schedule (see app/oncall.py)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from app import licence, oncall
from app.api.devices import get_conn
from app.notify.channels import load_channels

router = APIRouter(prefix="/api", tags=["oncall"])


def _doc(conn) -> dict[str, Any]:
    policy = oncall.get_policy(conn)
    return {"allowed": licence.allows(conn, "oncall"), "policy": policy, "now": oncall.on_call(conn, policy=policy), "upcoming": oncall.timeline(conn),
            "channels": [{"id": str(c.get("id")), "name": c.get("name") or c.get("type")} for c in load_channels(conn)]}


@router.get("/oncall")
def get_oncall(conn=Depends(get_conn)) -> dict[str, Any]:
    """The on-call schedule, who is on call now and the shifts of the coming week."""
    return _doc(conn)


@router.put("/oncall")
def put_oncall(body: dict, conn=Depends(get_conn)) -> dict[str, Any]:
    """Save the on-call schedule."""
    if not licence.allows(conn, "oncall"):
        raise HTTPException(status_code=402, detail="on-call schedules need a licence or the free trial (Settings → Licence)")
    try:
        oncall.save_policy(conn, body)
    except oncall.OnCallError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _doc(conn)
