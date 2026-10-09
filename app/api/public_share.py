"""The unauthenticated side of share links: the page itself and its data. Nothing else here is public."""

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

from app import shares
from app.auth import LoginLimiter
from app.db import connect

router = APIRouter(tags=["share"])
PAGE = Path(__file__).resolve().parent.parent / "static" / "share.html"
HEADERS = {"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow", "Referrer-Policy": "no-referrer"}


def _guard(request: Request) -> None:
    """Guessing tokens is hopeless, but keep a scanner from hammering the endpoint."""
    limiter: LoginLimiter = request.app.state.share_limiter
    host = request.client.host if request.client else "unknown"
    if not limiter.allowed(host):
        raise HTTPException(status_code=429, detail="too many attempts")


@router.get("/share/{token}")
def share_page(request: Request, token: str) -> FileResponse:
    _guard(request)
    conn = connect(request.app.state.db_path)
    try:
        live = shares.find(conn, token, count=False) is not None  # the data request counts the visit
    finally:
        conn.close()
    if not live:
        request.app.state.share_limiter.record_failure(request.client.host if request.client else "unknown")
        raise HTTPException(status_code=404, detail="this link does not exist or has expired")
    return FileResponse(PAGE, headers=HEADERS)


@router.get("/share-api/{token}")
def share_data(request: Request, token: str) -> JSONResponse:
    _guard(request)
    conn = connect(request.app.state.db_path)
    try:
        link = shares.find(conn, token)
        if link is None:
            request.app.state.share_limiter.record_failure(request.client.host if request.client else "unknown")
            raise HTTPException(status_code=404, detail="this link does not exist or has expired")
        return JSONResponse(shares.public_data(conn, link), headers=HEADERS)
    finally:
        conn.close()
