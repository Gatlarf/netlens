"""First-run setup: create the first administrator and confirm the scan ranges.

Open to anyone on the network until the first user exists (and only on installs without NETLENS_TOKEN: with a token the
owner already has administrator access and creates users under Settings). After that these routes answer 409 / 404.
"""

import json

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app import users
from app.api.auth import _session_cookie
from app.api.config import RANGES_KEY, apply_overrides, normalize_ranges
from app.db import connect, set_setting
from app.scanner.orchestrator import ScanBusy

router = APIRouter(prefix="/api", tags=["setup"])


def setup_required(request: Request, conn) -> bool:
    return not request.app.state.settings.token and not users.has_users(conn)


class SetupBody(BaseModel):
    username: str
    password: str
    ranges: list[str] | None = None  # None or empty: keep auto-detect
    start_scan: bool = True


@router.get("/setup")
async def get_setup(request: Request) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        if not setup_required(request, conn):
            raise HTTPException(status_code=404, detail="setup is already done")
    finally:
        conn.close()
    try:
        detected = await request.app.state.scan_manager.ranges_provider()
    except Exception:  # noqa: BLE001 - detection is only a suggestion
        detected = []
    return {"required": True, "detected_ranges": list(detected or []), "min_password": users.MIN_PASSWORD}


@router.post("/setup")
async def do_setup(request: Request, body: SetupBody) -> JSONResponse:
    app = request.app
    conn = connect(app.state.db_path)
    try:
        if not setup_required(request, conn):
            raise HTTPException(status_code=409, detail="setup is already done")
        try:
            ranges = normalize_ranges(body.ranges or [])
            username, password = users.check_username(body.username), users.check_password(body.password)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        if users.create_first_admin(conn, username, password) is None:
            raise HTTPException(status_code=409, detail="setup is already done")
        if ranges:
            set_setting(conn, RANGES_KEY, json.dumps(ranges))
        cookie = users.login(conn, username, password)
    finally:
        conn.close()
    apply_overrides(app)
    started = False
    if body.start_scan:
        try:
            await app.state.scan_manager.start("quick")
            started = True
        except ScanBusy:
            pass
    response = JSONResponse({"ok": True, "scan_started": started})
    _session_cookie(response, request, cookie)
    return response
