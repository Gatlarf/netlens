from fastapi import APIRouter, Request

from app import dashboard
from app.api.stats import _cached, _passive
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
