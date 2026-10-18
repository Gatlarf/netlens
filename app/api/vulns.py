"""What the vulnerability plugins report (see app/vulns.py). A paid feature: without a licence the page explains that, and nothing is listed."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app import licence, vulns
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["vulnerabilities"])


@router.get("/vulns")
def get_vulns(device_id: int | None = None, severity: str | None = None, q: str = "", limit: int = 500, conn=Depends(get_conn)) -> dict[str, Any]:
    allowed = licence.allows(conn, "vulnerabilities")
    if not allowed:
        return {"allowed": False, "summary": None, "servers": [], "top": [], "findings": []}
    return {"allowed": True, "summary": vulns.summary(conn), "servers": vulns.servers(conn), "top": vulns.top_devices(conn),
            "findings": vulns.findings(conn, device_id, severity, q, max(1, min(limit, 2000)))}
