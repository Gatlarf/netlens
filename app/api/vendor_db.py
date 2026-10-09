import asyncio
import logging

from fastapi import APIRouter, HTTPException, Request

from app.db import connect, get_setting, set_setting, utcnow
from app.scanner import vendor as vendor_db
from app.scanner.store import refresh_identification

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["vendor-db"])

REFRESHED_KEY = "vendor.refreshed"
ERROR_KEY = "vendor.error"
REFRESH_DAYS = 30


def status(conn) -> dict:
    return {**vendor_db.info(), "refreshed": get_setting(conn, REFRESHED_KEY), "error": get_setting(conn, ERROR_KEY) or None}


def refresh_now(conn, data_dir) -> dict:
    """Download the newest registry from IEEE, then fill in vendors and re-classify. Remembers the outcome; raises on failure."""
    try:
        entries = vendor_db.refresh(data_dir)
    except (OSError, ValueError) as exc:
        set_setting(conn, ERROR_KEY, f"{utcnow()} {exc}"[:300])
        raise
    set_setting(conn, REFRESHED_KEY, utcnow())
    set_setting(conn, ERROR_KEY, "")
    return {"entries": entries, **refresh_identification(conn)}


def due(conn, now: str | None = None) -> bool:
    """Once a month; a failed attempt is tried again after a day."""
    from datetime import datetime, timedelta, timezone

    def parse(text):
        return datetime.strptime(text[:20], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

    current = parse(now) if now else datetime.now(timezone.utc)
    error = get_setting(conn, ERROR_KEY)
    if error:
        try:
            return current - parse(error) >= timedelta(days=1)
        except ValueError:
            return True
    refreshed = get_setting(conn, REFRESHED_KEY)
    if not refreshed:
        return True
    try:
        return current - parse(refreshed) >= timedelta(days=REFRESH_DAYS)
    except ValueError:
        return True


@router.get("/vendor-db")
def get_vendor_db(request: Request) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        return status(conn)
    finally:
        conn.close()


@router.post("/vendor-db/refresh")
async def refresh_vendor_db(request: Request) -> dict:
    """Download the newest vendor registry from IEEE now."""
    data_dir = request.app.state.settings.data_dir

    def work() -> dict:
        conn = connect(request.app.state.db_path)
        try:
            result = refresh_now(conn, data_dir)
            return {**status(conn), "result": result}
        finally:
            conn.close()

    try:
        return await asyncio.to_thread(work)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=f"could not download the registry: {exc}")
