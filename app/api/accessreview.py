"""Access review and evidence pack (app/accessreview.py). Administrators, and users whose custom role grants "access review" (reading only)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from app import accessreview, audit, licence, roles
from app.api.devices import get_conn
from app.auth import client_ip, identify, require_admin

router = APIRouter(prefix="/api", tags=["access-review"])


class CompleteBody(BaseModel):
    comment: str = ""


def _reader(request: Request, conn) -> None:
    if not roles.has(request, "access_review"):
        raise HTTPException(status_code=403, detail="this needs an administrator, or a role with access to the access review")
    if not licence.allows(conn, "privileged"):
        raise HTTPException(status_code=402, detail="the access review and the evidence pack are part of the Enterprise edition (or the free trial)")


@router.get("/access-review")
def get_report(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    _reader(request, conn)
    return accessreview.report(conn)


@router.get("/access-review.csv")
def get_csv(request: Request, conn=Depends(get_conn)) -> PlainTextResponse:
    _reader(request, conn)
    return PlainTextResponse(accessreview.csv_text(accessreview.report(conn)), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="netlens-access-review.csv"'})


@router.post("/access-review/pack")
def make_pack(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    _reader(request, conn)
    doc = accessreview.pack(conn)
    audit.record_by(conn, identify(request), client_ip(request), "POST", request.url.path, 200,
                    f"Made a signed access review pack: {doc['report']['totals']['accounts']} accounts, {len(doc['report']['findings'])} findings; sha256 {doc['sha256'][:24]}…")
    return doc


@router.post("/access-review/verify")
def verify_pack(body: dict, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    _reader(request, conn)
    return accessreview.verify(conn, body)


@router.post("/access-review/complete")
def complete_review(body: CompleteBody, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    _reader(request, conn)
    principal = identify(request)
    done = accessreview.complete(conn, getattr(principal, "username", ""), body.comment)
    audit.record_by(conn, principal, client_ip(request), "POST", request.url.path, 200, f"Completed the access review{': ' + done['comment'] if done['comment'] else ''}")
    return done
