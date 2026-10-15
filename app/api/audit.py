"""The audit log (administrators only, see app/audit.py)."""

from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse

from app import audit
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["audit"])


@router.get("/audit")
def list_audit(limit: int = Query(100, ge=1, le=1000), before: int | None = None, user: str = "", q: str = "", conn=Depends(get_conn)) -> dict:
    rows = audit.entries(conn, limit, before, user.strip(), q.strip())
    users = [r["user"] for r in conn.execute("SELECT DISTINCT user FROM audit_log WHERE user != '' ORDER BY user LIMIT 100")]
    return {"entries": rows, "users": users, "more": len(rows) == limit}


@router.get("/audit.csv")
def audit_csv(conn=Depends(get_conn)) -> PlainTextResponse:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["time (UTC)", "user", "role", "address", "what", "method", "path", "status"])
    for r in audit.entries(conn, 1000):
        cells = [r["ts"], r["user"], r["role"], r["ip"], r["action"], r["method"], r["path"], r["status"]]
        writer.writerow([("'" + c if isinstance(c, str) and c[:1] in "=+-@" else c) for c in cells])
    return PlainTextResponse(out.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="netlens-audit-log.csv"'})
