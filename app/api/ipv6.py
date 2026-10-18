"""The optional IPv6 discovery (see app/scanner/ipv6.py)."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.devices import get_conn
from app.db import get_setting, set_setting
from app.scanner import ipv6

router = APIRouter(prefix="/api", tags=["ipv6"])


class Body(BaseModel):
    enabled: bool | None = None
    show: bool | None = None


def _doc(conn) -> dict[str, Any]:
    status = {}
    try:
        status = json.loads(get_setting(conn, "ipv6.status") or "{}")
    except ValueError:
        pass
    return {"enabled": ipv6.enabled(conn), "show": ipv6.showing(conn), "status": status, "addresses": conn.execute("SELECT COUNT(*) FROM device_ipv6").fetchone()[0],
            "devices": conn.execute("SELECT COUNT(DISTINCT device_id) FROM device_ipv6").fetchone()[0]}


@router.get("/ipv6")
def get_ipv6(conn=Depends(get_conn)) -> dict[str, Any]:
    return _doc(conn)


@router.put("/ipv6")
def put_ipv6(body: Body, conn=Depends(get_conn)) -> dict[str, Any]:
    if body.enabled is not None:
        set_setting(conn, ipv6.SETTING, "1" if body.enabled else "0")
    if body.show is not None:
        set_setting(conn, ipv6.SHOW_SETTING, "1" if body.show else "0")
    return _doc(conn)


@router.post("/ipv6/discover")
async def discover(conn=Depends(get_conn)) -> dict[str, Any]:
    """Look for IPv6 addresses now (without a scan)."""
    from app.db import utcnow

    entries = await ipv6.collect()
    result = ipv6.apply(conn, entries)
    ipv6.set_status(conn, {"ts": utcnow(), "seen": len(entries), **result})
    return _doc(conn)


@router.get("/ipv6/health")
def get_health(conn=Depends(get_conn)) -> dict[str, Any]:
    """The last IPv6 health result (null before the first run)."""
    from app import ipv6health

    return {"result": ipv6health.last(conn), "discovery": ipv6.enabled(conn)}


@router.post("/ipv6/health/run")
async def run_health(conn=Depends(get_conn)) -> dict[str, Any]:
    """Look at the IPv6 side of the network now."""
    from app import ipv6health

    return {"result": await ipv6health.run(conn), "discovery": ipv6.enabled(conn)}
