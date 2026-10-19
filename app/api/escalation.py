"""The escalation policy and the alerts that nobody has acknowledged yet (see app/escalation.py)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app import escalation, licence, oncall
from app.api.devices import get_conn
from app.notify.channels import EVENT_LABELS, load_channels

router = APIRouter(prefix="/api", tags=["escalation"])


def _doc(conn) -> dict[str, Any]:
    items = [{k: v for k, v in i.items() if k != "event"} for i in escalation.open_items(conn)]
    return {"allowed": licence.allows(conn, "oncall"), "policy": escalation.get_policy(conn), "open": items,
            "channels": ([{"id": oncall.TOKEN, "name": "Whoever is on call (see On-call schedule)"}] if licence.allows(conn, "schedules") else []) + [{"id": str(c.get("id")), "name": c.get("name") or c.get("type")} for c in load_channels(conn)], "kinds": [{"id": k, "label": EVENT_LABELS[k]} for k in escalation.default_kinds() if k in EVENT_LABELS]
            + [{"id": k, "label": v} for k, v in EVENT_LABELS.items() if k not in escalation.default_kinds() and not k.startswith("report_")]}


@router.get("/escalation")
def get_escalation(conn=Depends(get_conn)) -> dict[str, Any]:
    return _doc(conn)


@router.put("/escalation")
def put_escalation(body: dict, conn=Depends(get_conn)) -> dict[str, Any]:
    if not licence.allows(conn, "oncall"):
        raise HTTPException(status_code=402, detail="escalation needs a licence or the free trial (Settings → Licence)")
    try:
        escalation.save_policy(conn, body)
    except escalation.PolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _doc(conn)


class Nothing(BaseModel):
    pass


@router.post("/escalation/{event_id}/ack")
def ack(event_id: int, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    user = getattr(getattr(request, "state", None), "user", None)
    try:
        escalation.acknowledge(conn, event_id, getattr(user, "username", "an administrator"))
    except escalation.PolicyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return _doc(conn)
