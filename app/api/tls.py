"""Built-in HTTPS (app/tls.py): status, a self-signed certificate, your own certificate and key, and the restart that applies a change. Administrators only, from where
the terminal may be used (the local network by default); every change needs step-up when that is on."""

from __future__ import annotations

import os
import signal
import threading
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app import audit, tls
from app.api.devices import get_conn
from app.auth import client_ip, identify, require_admin
from app.terminal.access import ensure_allowed

router = APIRouter(prefix="/api", tags=["tls"])


class SelfSigned(BaseModel):
    names: list[str]
    days: int = 825


class Upload(BaseModel):
    certificate: str
    key: str


def _state(request: Request) -> dict[str, Any]:
    running = bool(getattr(request.app.state, "tls_running", False))
    data = tls.info(request.app.state.settings.data_dir, running)
    return {**data, "page_is_https": request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https",
            "restart_needed": data.get("configured", False) != running, "env_managed": data.get("source") == "environment"}


def _note(request: Request, conn, text: str) -> None:
    audit.record_by(conn, identify(request), client_ip(request), request.method, request.url.path, 200, text)


@router.get("/tls")
def tls_status(request: Request) -> dict[str, Any]:
    require_admin(request)
    return _state(request)


@router.post("/tls/self-signed", dependencies=[Depends(ensure_allowed)])
def tls_self_signed(body: SelfSigned, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    if os.environ.get("NETLENS_TLS_CERT", "").strip():
        raise HTTPException(status_code=409, detail="the certificate is set by NETLENS_TLS_CERT in the container's environment: change it there")
    try:
        tls.make_self_signed(request.app.state.settings.data_dir, body.names, body.days)
    except tls.TlsError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    _note(request, conn, f"Made a self-signed HTTPS certificate for {', '.join(n.strip() for n in body.names)[:120]}")
    return _state(request)


@router.post("/tls/upload", dependencies=[Depends(ensure_allowed)])
def tls_upload(body: Upload, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    if os.environ.get("NETLENS_TLS_CERT", "").strip():
        raise HTTPException(status_code=409, detail="the certificate is set by NETLENS_TLS_CERT in the container's environment: change it there")
    try:
        data = tls.install(request.app.state.settings.data_dir, body.certificate, body.key)
    except tls.TlsError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    _note(request, conn, f"Installed an HTTPS certificate ({data.get('subject', '')[:100]}; the key is never shown)")
    return _state(request)


@router.delete("/tls", dependencies=[Depends(ensure_allowed)])
def tls_remove(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    require_admin(request)
    if os.environ.get("NETLENS_TLS_CERT", "").strip():
        raise HTTPException(status_code=409, detail="the certificate is set by NETLENS_TLS_CERT in the container's environment: change it there")
    tls.remove(request.app.state.settings.data_dir)
    _note(request, conn, "Removed the HTTPS certificate (Netlens serves plain http after the next restart)")
    return _state(request)


@router.post("/tls/restart", dependencies=[Depends(ensure_allowed)])
def tls_restart(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    """Stop Netlens so that the container's restart policy starts it again with the new certificate. Without a restart policy it stays stopped: the page says so."""
    require_admin(request)
    _note(request, conn, "Restarted Netlens to apply the HTTPS setting")
    threading.Timer(1.0, lambda: os.kill(os.getpid(), signal.SIGTERM)).start()
    return {"restarting": True}
