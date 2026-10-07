import asyncio
import os
import tempfile
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask

from app.api import config as config_api
from app.backup import BackupError, create_backup, restore_backup, validate_backup
from app.db import connect

MAX_UPLOAD = 256 * 1024 * 1024

router = APIRouter(prefix="/api", tags=["backup"])


@router.get("/backup")
async def download_backup(request: Request) -> FileResponse:
    """Download a consistent snapshot of the whole database (includes saved SMTP/Proxmox credentials)."""
    fd, tmp = tempfile.mkstemp(prefix="netlens-backup-", suffix=".db")
    os.close(fd)
    try:
        await asyncio.to_thread(create_backup, request.app.state.db_path, tmp)
    except BackupError as exc:
        os.unlink(tmp)
        raise HTTPException(status_code=500, detail=str(exc))
    name = "netlens-backup-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + ".db"
    return FileResponse(
        tmp,
        media_type="application/octet-stream",
        filename=name,
        background=BackgroundTask(os.unlink, tmp),
    )


@router.post("/restore")
async def upload_restore(request: Request) -> dict:
    """Replace the database content with an uploaded backup (raw request body)."""
    app = request.app
    if app.state.scan_manager.is_running():
        raise HTTPException(status_code=409, detail="a scan is running; wait for it to finish and try again")

    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_UPLOAD:
        raise HTTPException(status_code=413, detail="backup file is too large")
    data = await request.body()
    if not data:
        raise HTTPException(status_code=422, detail="the file is empty")
    if len(data) > MAX_UPLOAD:
        raise HTTPException(status_code=413, detail="backup file is too large")

    db_path = str(app.state.db_path)
    fd, tmp = tempfile.mkstemp(prefix="netlens-restore-", suffix=".db", dir=os.path.dirname(os.path.abspath(db_path)))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        try:
            version = await asyncio.to_thread(validate_backup, tmp)
            await asyncio.to_thread(restore_backup, db_path, tmp)
        except BackupError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

    config_api.apply_overrides(app)  # the restored settings (ranges, intervals, ...) take effect now
    conn = connect(db_path)
    try:
        devices = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    finally:
        conn.close()
    return {"ok": True, "backup_schema_version": version, "devices": devices}
