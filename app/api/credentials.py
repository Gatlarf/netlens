"""The credential store (see app/credstore.py). Administrators only. A secret is accepted here and never returned."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app import audit, credstore, licence, pam
from app.api.devices import get_conn
from app.auth import client_ip, identify, require_admin
from app.terminal.access import ensure_allowed

router = APIRouter(prefix="/api", tags=["credentials"])


def _user(request: Request) -> str:
    principal = getattr(request.state, "user", None) or identify(request)
    return getattr(principal, "username", "") or ""


def _note(request: Request, conn, method: str, action: str) -> None:
    audit.record_by(conn, getattr(request.state, "user", None) or identify(request), client_ip(request), method, request.url.path, 200, action)


@router.get("/credentials")
def list_credentials(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    return {"credentials": credstore.listing(conn, _user(request)), "kinds": {k: list(v) for k, v in credstore.KINDS.items()},
            "pam": {"allowed": licence.allows(conn, "privileged"), "providers": pam.providers()}}


def _need_pam(conn, what: str = "using your privileged-access system (PAM) for logins") -> None:
    if not licence.allows(conn, "privileged"):
        raise HTTPException(status_code=402, detail=f"{what} is part of the Enterprise edition (or the free trial)")


@router.post("/credentials", dependencies=[Depends(ensure_allowed)])
def create_credential(body: dict, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    if str(body.get("kind") or "login") == "pam":
        _need_pam(conn)
    if body.get("route_mode"):
        _need_pam(conn, "routing a login through a bastion or a PAM session proxy")
    try:
        made = credstore.create(conn, _user(request), body.get("name", ""), str(body.get("kind") or "login"), body, shared=bool(body.get("shared")))
    except credstore.CredentialError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    _note(request, conn, "POST", f"Stored the login \"{made['name']}\" ({made['kind']}) in the credential store" + (", shared" if made["shared"] else ""))
    return made


@router.put("/credentials/{cred_id}", dependencies=[Depends(ensure_allowed)])
def update_credential(cred_id: str, body: dict, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    current = credstore.peek(conn, _user(request), cred_id)
    if current and current.get("kind") == "pam":
        _need_pam(conn)
    if body.get("route_mode"):
        _need_pam(conn, "routing a login through a bastion or a PAM session proxy")
    try:
        made = credstore.update(conn, _user(request), cred_id, body, True)
    except credstore.CredentialError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    changed = sorted(k for k in body if k in ("name", "username", "domain", "shared", "path", "mount", "url", "provider", "reason_required") or (k in credstore.SECRET_FIELDS and body[k]))
    pam.forget(cred_id)
    _note(request, conn, "PUT", f"Changed the login \"{made['name']}\" in the credential store: " + (", ".join(changed) or "nothing") + " (secrets are never written to the log)")
    return made


class TestBody(BaseModel):
    reason: str = ""


@router.post("/credentials/{cred_id}/test", dependencies=[Depends(ensure_allowed)])
async def test_credential(cred_id: str, request: Request, body: TestBody | None = None, conn=Depends(get_conn)) -> dict[str, Any]:
    """Ask the PAM for this login once, to see that it works. Says which fields came back, never their values. Every try is in the audit log like any other check-out."""
    require_admin(request)
    entry = credstore.peek(conn, _user(request), cred_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="no such login")
    if entry.get("kind") != "pam":
        raise HTTPException(status_code=422, detail="only a login in your PAM system can be tried this way")
    try:
        found = await credstore.resolve_async(conn, _user(request), cred_id, "test from the settings page", (body.reason if body else ""), "")
    except credstore.CredentialError as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": True, "message": "the PAM system handed out the login", "fields": sorted(k for k in ("username", "password", "private_key", "passphrase", "domain") if found.get(k))}


@router.delete("/credentials/{cred_id}", dependencies=[Depends(ensure_allowed)])
def delete_credential(cred_id: str, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    try:
        gone = credstore.delete(conn, _user(request), cred_id, True)
    except credstore.CredentialError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    _note(request, conn, "DELETE", f"Deleted the login \"{gone['name']}\" from the credential store")
    return {"deleted": True}
