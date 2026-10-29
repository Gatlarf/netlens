"""Four-eyes approval (app/approvals.py): ask, list, decide, cancel. Administrators only; the person who asks can never decide their own request."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app import approvals, audit, secpolicy
from app.api.devices import get_conn
from app.auth import client_ip, identify, require_admin

router = APIRouter(prefix="/api", tags=["approvals"])


class AskBody(BaseModel):
    action: str
    target: str = ""
    reason: str


class DecideBody(BaseModel):
    approve: bool
    comment: str = ""


def _me(request: Request):
    require_admin(request)
    principal = identify(request)
    if not approvals.person(principal):
        raise HTTPException(status_code=400, detail="approvals are for people signed in with a user account: the access token and API tokens cannot ask or decide")
    return principal


def _fail(exc: approvals.ApprovalError, status: int = 422) -> HTTPException:
    return HTTPException(status_code=404 if str(exc).startswith("no such") else status, detail=str(exc))


@router.get("/approvals")
def list_approvals(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    principal = _me(request)
    pol = secpolicy.get(conn)
    return {**approvals.listing(conn, principal), "policy": {"actions": pol["four_eyes"], "minutes": pol["four_eyes_minutes"]}, "actions": approvals.ACTIONS}


@router.post("/approvals", status_code=201)
def ask(body: AskBody, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    principal = _me(request)
    label = ""
    if body.action in ("terminal", "remote"):
        if not body.target.isdigit():
            raise HTTPException(status_code=422, detail="name the device")
        device = conn.execute("SELECT COALESCE(custom_name, hostname, primary_ip) AS name FROM devices WHERE id = ?", (int(body.target),)).fetchone()
        if device is None:
            raise HTTPException(status_code=404, detail="no such device")
        label = device["name"]
    elif body.action == "restore":
        label = "the backup " + (body.target[:60] or "uploaded")
    try:
        made = approvals.request(conn, principal, body.action, body.target, label, body.reason)
    except approvals.ApprovalError as exc:
        raise _fail(exc) from None
    audit.record_by(conn, principal, client_ip(request), "POST", request.url.path, 201, f"Asked for approval to {approvals.ACTIONS[body.action].lower()}{' ' + label if label else ''}: {made['reason']}")
    return made


@router.get("/approvals/{approval_id}")
def one(approval_id: int, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    _me(request)
    try:
        return approvals.get(conn, approval_id)
    except approvals.ApprovalError as exc:
        raise _fail(exc) from None


@router.post("/approvals/{approval_id}/decide")
def decide(approval_id: int, body: DecideBody, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    principal = _me(request)
    try:
        done = approvals.decide(conn, principal, approval_id, body.approve, body.comment, secpolicy.get(conn)["four_eyes_minutes"])
    except approvals.ApprovalError as exc:
        raise _fail(exc, 409 if "already" in str(exc) or "just now" in str(exc) else 403 if "your own" in str(exc) else 422) from None
    audit.record_by(conn, principal, client_ip(request), "POST", request.url.path, 200,
                    f"{'Approved' if body.approve else 'Denied'} the request of {done['requester']} to {approvals.ACTIONS[done['action']].lower()}{' ' + done['label'] if done['label'] else ''}")
    return done


@router.post("/approvals/{approval_id}/cancel")
def cancel(approval_id: int, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    principal = _me(request)
    try:
        return approvals.cancel(conn, principal, approval_id)
    except approvals.ApprovalError as exc:
        raise _fail(exc) from None
