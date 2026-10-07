from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlite3 import Connection

from app.api.devices import get_conn
from app.scanner.orchestrator import ScanBusy
from app.scanner.scans import average_duration, elapsed_seconds, list_scans, running_scan

router = APIRouter(prefix="/api", tags=["scans"])


class ScanBody(BaseModel):
    kind: Literal["quick", "deep"] = "quick"


@router.get("/scans")
def get_scans(
    request: Request,
    limit: int = 50,
    conn: Connection = Depends(get_conn),
) -> list[dict[str, Any]]:
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 200")
    return list_scans(conn, limit)


@router.get("/scans/current")
def get_current_scan(
    request: Request,
    conn: Connection = Depends(get_conn),
) -> dict[str, Any]:
    scan = running_scan(conn)
    progress = request.app.state.scan_manager.progress if scan is not None else None
    body: dict[str, Any] = {"running": scan is not None, "scan": scan, "progress": progress}
    if scan is not None:
        average, samples = average_duration(conn, scan["kind"])
        body["elapsed_seconds"] = elapsed_seconds(scan["started"])
        body["average_seconds"] = average  # mean of recent finished scans of the same kind, None if no history
        body["average_samples"] = samples
    return body


@router.post("/scans", status_code=202)
async def create_scan(
    request: Request,
    body: ScanBody = ScanBody(),
    conn: Connection = Depends(get_conn),
) -> dict[str, Any]:
    scan_manager = request.app.state.scan_manager
    try:
        scan_id = await scan_manager.start(body.kind)
    except ScanBusy:
        raise HTTPException(status_code=409, detail="scan already running")
    return {"id": scan_id}