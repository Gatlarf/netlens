import asyncio
import os
import tempfile

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app import backup_schedule as bs
from app.api import config as config_api
from app.backup import BackupError, restore_backup, validate_backup
from app.db import connect

router = APIRouter(prefix="/api", tags=["backup"])


class ScheduleBody(BaseModel):
    enabled: bool | None = None
    every_hours: int | None = None
    keep: int | None = Field(default=None)


def _view(request: Request, conn) -> dict:
    db_path = request.app.state.db_path
    return {
        "schedule": bs.get_schedule(conn),
        "intervals": list(bs.EVERY_HOURS),
        "last": bs.get_last(conn),
        "backups": bs.list_backups(db_path),
    }


@router.get("/backups")
def get_backups(request: Request) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        return _view(request, conn)
    finally:
        conn.close()


@router.put("/backups/schedule")
def put_schedule(request: Request, body: ScheduleBody) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        try:
            bs.set_schedule(conn, body.model_dump(exclude_none=True))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        return _view(request, conn)
    finally:
        conn.close()


@router.post("/backups/run")
async def run_now(request: Request) -> dict:
    db_path = request.app.state.db_path

    def work() -> dict:
        conn = connect(db_path)
        try:
            result = bs.run_backup(conn, db_path, data_dir=request.app.state.settings.data_dir)
            return {**_view(request, conn), "result": result}
        finally:
            conn.close()

    data = await asyncio.to_thread(work)
    if not data["result"]["ok"]:
        raise HTTPException(status_code=500, detail=data["result"]["error"])
    return data


@router.get("/backups/{name}")
def download(request: Request, name: str) -> FileResponse:
    path = bs.backup_path(request.app.state.db_path, name)
    if path is None:
        raise HTTPException(status_code=404, detail="no such backup")
    return FileResponse(path, media_type="application/octet-stream", filename=name)


@router.delete("/backups/{name}")
def delete(request: Request, name: str) -> dict:
    path = bs.backup_path(request.app.state.db_path, name)
    if path is None:
        raise HTTPException(status_code=404, detail="no such backup")
    path.unlink()
    conn = connect(request.app.state.db_path)
    try:
        return _view(request, conn)
    finally:
        conn.close()


def _four_eyes(request: Request, target: str) -> None:
    from app import approvals, secpolicy
    from app.auth import identify

    conn = connect(str(request.app.state.db_path))
    try:
        approvals.require(conn, getattr(request.state, "user", None) or identify(request), secpolicy.get(conn), "restore", target[:80])
    except approvals.ApprovalError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from None
    finally:
        conn.close()


@router.post("/backups/{name}/restore")
async def restore(request: Request, name: str) -> dict:
    app = request.app
    _four_eyes(request, name)
    path = bs.backup_path(app.state.db_path, name)
    if path is None:
        raise HTTPException(status_code=404, detail="no such backup")
    if app.state.scan_manager.is_running():
        raise HTTPException(status_code=409, detail="a scan is running; wait for it to finish and try again")
    db_path = str(app.state.db_path)
    try:
        version = await asyncio.to_thread(validate_backup, path)
        restored = await asyncio.to_thread(restore_backup, db_path, path, app.state.settings.data_dir)
    except BackupError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    config_api.apply_overrides(app)
    conn = connect(db_path)
    try:
        devices = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    finally:
        conn.close()
    return {"ok": True, "backup_schema_version": version, "devices": devices, **restored}
