"""The credential store (see app/credstore.py). Administrators only. A secret is accepted here and never returned."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from app import audit, credstore
from app.api.devices import get_conn
from app.auth import client_ip, identify, require_admin

router = APIRouter(prefix="/api", tags=["credentials"])


def _user(request: Request) -> str:
    principal = getattr(request.state, "user", None) or identify(request)
    return getattr(principal, "username", "") or ""


def _note(request: Request, conn, method: str, action: str) -> None:
    audit.record_by(conn, getattr(request.state, "user", None) or identify(request), client_ip(request), method, request.url.path, 200, action)


@router.get("/credentials")
def list_credentials(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    return {"credentials": credstore.listing(conn, _user(request)), "kinds": {k: list(v) for k, v in credstore.KINDS.items()}}


@router.post("/credentials")
def create_credential(body: dict, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    try:
        made = credstore.create(conn, _user(request), body.get("name", ""), str(body.get("kind") or "login"), body, shared=bool(body.get("shared")))
    except credstore.CredentialError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    _note(request, conn, "POST", f"Stored the login \"{made['name']}\" ({made['kind']}) in the credential store" + (", shared" if made["shared"] else ""))
    return made


@router.put("/credentials/{cred_id}")
def update_credential(cred_id: str, body: dict, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    try:
        made = credstore.update(conn, _user(request), cred_id, body, True)
    except credstore.CredentialError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    changed = sorted(k for k in body if k in ("name", "username", "domain", "shared") or (k in credstore.SECRET_FIELDS and body[k]))
    _note(request, conn, "PUT", f"Changed the login \"{made['name']}\" in the credential store: " + (", ".join(changed) or "nothing") + " (secrets are never written to the log)")
    return made


@router.delete("/credentials/{cred_id}")
def delete_credential(cred_id: str, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    try:
        gone = credstore.delete(conn, _user(request), cred_id, True)
    except credstore.CredentialError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    _note(request, conn, "DELETE", f"Deleted the login \"{gone['name']}\" from the credential store")
    return {"deleted": True}
