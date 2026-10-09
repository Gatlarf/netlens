import asyncio

from fastapi import APIRouter, Request
from pydantic import BaseModel

from app import updates
from app.db import connect

router = APIRouter(prefix="/api", tags=["update"])


def _getter(request: Request):
    return getattr(request.app.state, "update_getter", updates.http_get)


def _check(request: Request, force: bool) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        return updates.check(conn, force=force, getter=_getter(request))
    finally:
        conn.close()


@router.get("/update")
async def get_update(request: Request, refresh: bool = False) -> dict:
    """Is a newer Netlens available? Answers from a one-day cache unless `refresh` is set."""
    return await asyncio.to_thread(_check, request, refresh)


class UpdateSettings(BaseModel):
    enabled: bool


@router.put("/update")
def put_update(request: Request, body: UpdateSettings) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        updates.set_enabled(conn, body.enabled)
        return updates.status(conn)
    finally:
        conn.close()
