"""The unauthenticated side of share links: the page itself and its data. Nothing else here is public."""

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from app import shares
from app.auth import LoginLimiter, client_ip
from app.db import connect

router = APIRouter(tags=["share"])
PAGE = Path(__file__).resolve().parent.parent / "static" / "share.html"
HEADERS = {"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow", "Referrer-Policy": "no-referrer"}
KEY_HEADER = "x-share-key"


class Pin(BaseModel):
    pin: str


def _guard(request: Request) -> None:
    """Guessing tokens is hopeless, but keep a scanner from hammering the endpoint."""
    limiter: LoginLimiter = request.app.state.share_limiter
    host = client_ip(request)
    if not limiter.allowed(host):
        raise HTTPException(status_code=429, detail="too many attempts")


def _missing(request: Request):
    request.app.state.share_limiter.record_failure(client_ip(request))
    raise HTTPException(status_code=404, detail="this link does not exist or has expired")


@router.get("/share/{token}")
def share_page(request: Request, token: str) -> FileResponse:
    _guard(request)
    conn = connect(request.app.state.db_path)
    try:
        live = shares.find(conn, token, count=False) is not None  # the data request counts the visit
    finally:
        conn.close()
    if not live:
        _missing(request)
    return FileResponse(PAGE, headers=HEADERS)


@router.get("/share-api/{token}")
def share_data(request: Request, token: str) -> JSONResponse:
    _guard(request)
    conn = connect(request.app.state.db_path)
    try:
        link = shares.find(conn, token, count=False)
        if link is None:
            _missing(request)
        if not shares.allowed(link, request.headers.get(KEY_HEADER)):
            return JSONResponse(shares.locked_page(link), status_code=401, headers=HEADERS)   # the page then asks for the PIN
        shares.find(conn, token)  # counts the visit
        return JSONResponse(shares.public_data(conn, link), headers=HEADERS)
    finally:
        conn.close()


@router.post("/share-api/{token}/unlock")
def share_unlock(request: Request, token: str, body: Pin) -> JSONResponse:
    _guard(request)
    conn = connect(request.app.state.db_path)
    try:
        link = shares.find(conn, token, count=False)
        if link is None:
            _missing(request)
        pins: LoginLimiter = request.app.state.share_pin_limiter
        host = client_ip(request)
        if not pins.allowed(host):
            raise HTTPException(status_code=429, detail="too many wrong PINs, try again in a few minutes")
        key = shares.unlock(link, body.pin)
        if key is None:
            pins.record_failure(host)
            raise HTTPException(status_code=403, detail="that PIN is not right")
        return JSONResponse({"key": key}, headers=HEADERS)
    finally:
        conn.close()
