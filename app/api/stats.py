import time

from fastapi import APIRouter, HTTPException, Query, Request

from app.db import connect
from app.scanner.scans import running_scan
from app.stats import RANGES, compute_stats, summary

router = APIRouter(prefix="/api", tags=["stats"])
CACHE_SECONDS = 30  # the page and Home Assistant both poll; computing is cheap but not free


def _cached(request: Request, key: tuple, build):
    cache = request.app.state.__dict__.setdefault("stats_cache", {})
    hit = cache.get(key)
    now = time.monotonic()
    if hit and now - hit[0] < CACHE_SECONDS:
        return hit[1]
    value = build()
    cache[key] = (now, value)
    return value


@router.get("/stats")
def get_stats(request: Request, range: str = Query("7d")) -> dict:
    """Everything for the Statistics page. `range` is 24h, 7d, 30d or 90d (the window of the history groups)."""
    if range not in RANGES:
        raise HTTPException(status_code=422, detail=f"range must be one of {', '.join(RANGES)}")
    db_path = request.app.state.db_path

    def build():
        conn = connect(db_path)
        try:
            return compute_stats(conn, range, db_path=db_path)
        finally:
            conn.close()

    return _cached(request, ("stats", db_path, range), build)


@router.get("/stats/summary")
def get_summary(request: Request) -> dict:
    """Small, versioned document for Home Assistant and other integrations (see `api` in the answer)."""
    db_path = request.app.state.db_path

    def build():
        conn = connect(db_path)
        try:
            return summary(conn, scan_running=running_scan(conn) is not None)
        finally:
            conn.close()

    return _cached(request, ("summary", db_path), build)
