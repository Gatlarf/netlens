from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app import dashboard
from app.api.stats import _cached, _passive
from app.api.devices import get_conn
from app.db import connect
from app.scanner.scans import running_scan
from app.stats import summary

router = APIRouter(prefix="/api", tags=["dashboard"])


@router.get("/dashboard")
def get_dashboard(request: Request) -> dict:
    """The start page: the summary plus what needs attention, the latest events and a few small series."""
    db_path = request.app.state.db_path

    def build():
        conn = connect(db_path)
        try:
            s = summary(conn, scan_running=running_scan(conn) is not None, data_dir=request.app.state.settings.data_dir, passive=_passive(request))
            return dashboard.build(conn, s)
        finally:
            conn.close()

    return _cached(request, ("dashboard", db_path), build)


class LayoutBody(BaseModel):
    order: list[str]


@router.get("/dashboard/layout")
def get_layout(request: Request, conn=Depends(get_conn)) -> dict:
    """The cards this user chose, in order (null while the user still has the default)."""
    return {"order": dashboard.get_layout(conn, request.state.user)}


@router.put("/dashboard/layout")
def put_layout(body: LayoutBody, request: Request, conn=Depends(get_conn)) -> dict:
    try:
        return {"order": dashboard.set_layout(conn, request.state.user, body.order)}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.delete("/dashboard/layout")
def delete_layout(request: Request, conn=Depends(get_conn)) -> dict:
    dashboard.reset_layout(conn, request.state.user)
    return {"order": None}
