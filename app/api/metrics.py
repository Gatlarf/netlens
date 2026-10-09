from fastapi import APIRouter, Request, Response

from app.db import connect
from app.metrics import render_metrics
from app.scanner.scans import running_scan

router = APIRouter(tags=["metrics"])


@router.get("/metrics")
def metrics(request: Request) -> Response:
    """Prometheus scrape endpoint. Needs the same token as the API (Prometheus: `authorization: credentials: <token>`)."""
    conn = connect(request.app.state.db_path)
    try:
        text = render_metrics(conn, scan_running=running_scan(conn) is not None, data_dir=request.app.state.settings.data_dir)
    finally:
        conn.close()
    return Response(text, media_type="text/plain; version=0.0.4; charset=utf-8")
