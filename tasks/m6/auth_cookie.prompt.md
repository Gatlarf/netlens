INTERFACES OF EXISTING CODE (use these exact names; do not invent attributes, columns or functions that are not listed):

## Database schema (app/db.py, SQLite, connections use row_factory=sqlite3.Row)
CREATE TABLE schema_version (
            version INTEGER
        )
CREATE TABLE devices (
            id INTEGER PRIMARY KEY,
            mac TEXT UNIQUE,
            primary_ip TEXT,
            hostname TEXT,
            vendor TEXT,
            os_name TEXT,
            os_confidence INTEGER,
            device_type TEXT,
            type_override TEXT,
            custom_name TEXT,
            notes TEXT,
            tags TEXT,
            online INTEGER NOT NULL DEFAULT 1,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            pos_x REAL,
            pos_y REAL,
            raw_xml TEXT
        )
CREATE TABLE device_ips (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            ip TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(device_id, ip)
        )
CREATE TABLE device_names (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(device_id, name, source)
        )
CREATE TABLE ports (
            id INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            proto TEXT NOT NULL,
            port INTEGER NOT NULL,
            state TEXT NOT NULL,
            service TEXT,
            product TEXT,
            version TEXT,
            updated TEXT NOT NULL,
            UNIQUE(device_id, proto, port)
        )
CREATE TABLE scans (
            id INTEGER PRIMARY KEY,
            kind TEXT NOT NULL,
            status TEXT NOT NULL,
            started TEXT NOT NULL,
            finished TEXT,
            hosts_found INTEGER NOT NULL DEFAULT 0,
            error TEXT
        )
CREATE TABLE events (
            id INTEGER PRIMARY KEY,
            ts TEXT NOT NULL,
            device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            kind TEXT NOT NULL,
            detail TEXT
        )
CREATE TABLE relations (
            id INTEGER PRIMARY KEY,
            src_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            dst_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 1.0,
            manual INTEGER NOT NULL DEFAULT 0,
            UNIQUE(src_id, dst_id, kind)
        )
CREATE TABLE settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
CREATE TABLE host_keys (
            device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
            fingerprint TEXT NOT NULL,
            first_seen TEXT NOT NULL
        )

## app/api/auth.py
11:class LoginBody(BaseModel):
12:    token: str
19:async def login(request: Request, body: LoginBody) -> JSONResponse:
21:    limiter: LoginLimiter = request.app.state.login_limiter
49:async def logout(request: Request) -> JSONResponse:
56:async def session(request: Request) -> JSONResponse:

TASK:
Modify app/api/auth.py (output the COMPLETE file; current file below). Keep ALL behaviour. Change: the session cookie set by POST /login must also carry secure=True when the connection is HTTPS: request.url.scheme == "https" or the header x-forwarded-proto (first comma-separated value, lowercased, stripped) equals "https". Plain HTTP keeps secure=False (the UI must keep working on a LAN without TLS). Apply the same condition to the delete_cookie call in POST /logout (secure=<same flag>).
CURRENT FILE:
import hmac
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.auth import COOKIE_NAME, is_authorized, session_value, LoginLimiter


class LoginBody(BaseModel):
    token: str


router = APIRouter(prefix="/api", tags=["auth"])


@router.post("/login")
async def login(request: Request, body: LoginBody) -> JSONResponse:
    settings = request.app.state.settings
    limiter: LoginLimiter = request.app.state.login_limiter

    key = request.client.host if request.client else "unknown"

    if not limiter.allowed(key):
        from fastapi import HTTPException
        raise HTTPException(status_code=429, detail="too many attempts")

    if not hmac.compare_digest(body.token.encode(), settings.token.encode()):
        limiter.record_failure(key)
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="invalid token")

    limiter.reset(key)

    response = JSONResponse({"ok": True})
    response.set_cookie(
        COOKIE_NAME,
        session_value(settings.token),
        httponly=True,
        samesite="strict",
        path="/",
        max_age=30 * 24 * 3600,
    )
    return response


@router.post("/logout")
async def logout(request: Request) -> JSONResponse:
    response = JSONResponse({"ok": True})
    response.delete_cookie(COOKIE_NAME, path="/")
    return response


@router.get("/session")
async def session(request: Request) -> JSONResponse:
    settings = request.app.state.settings
    authenticated = is_authorized(
        settings.token,
        request.cookies.get(COOKIE_NAME),
        request.headers.get("authorization"),
    )
    return JSONResponse({"authenticated": authenticated})