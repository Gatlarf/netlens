"""Hosts: the overview and the bulk set-up / removal of monitoring (see app/hosts.py). Administrators only."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from app import audit, hosts
from app.hostmetrics import service as hm
from app.api.devices import get_conn
from app.auth import client_ip, identify, require_admin
from app.terminal.access import ensure_allowed

router = APIRouter(prefix="/api", tags=["hosts"])


@router.get("/hosts")
def list_hosts(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    return {"hosts": hosts.overview(conn), "levels": list(hosts.LEVELS), "settings": {"allow_plain_winrm": hm.plain_winrm_allowed(conn)}}


@router.put("/hosts/settings", dependencies=[Depends(ensure_allowed)])
def put_settings(body: dict, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    if "allow_plain_winrm" in body:
        on = hm.set_plain_winrm(conn, bool(body["allow_plain_winrm"]))
        audit.record_by(conn, getattr(request.state, "user", None) or identify(request), client_ip(request), "PUT", request.url.path, 200,
                        "Allowed WinRM over plain http (port 5985; the Windows password then crosses the network unencrypted)" if on else "Switched WinRM over plain http off")
    return {"settings": {"allow_plain_winrm": hm.plain_winrm_allowed(conn)}}


@router.post("/hosts/apply", dependencies=[Depends(ensure_allowed)])
async def apply_hosts(body: dict, request: Request) -> dict[str, Any]:
    require_admin(request)
    ids = [i for i in (body.get("device_ids") or []) if isinstance(i, int) and not isinstance(i, bool)]
    if not ids or len(ids) > 100:
        raise HTTPException(status_code=422, detail="choose between 1 and 100 hosts")
    level = str(body.get("level") or "")
    if level not in hosts.LEVELS:
        raise HTTPException(status_code=422, detail="level must be one of: " + ", ".join(hosts.LEVELS))
    opts = {k: body.get(k) for k in ("method", "credential_id", "admin_credential_id", "admin_username", "admin_password", "admin_private_key", "enable_sshd", "allow_from", "reason")}
    who = getattr(request.state, "user", None) or identify(request)
    results = await hosts.apply(request.app.state.db_path, ids, level, opts, who, client_ip(request))
    return {"results": results, "done": sum(1 for r in results if r["ok"]), "failed": sum(1 for r in results if not r["ok"])}
