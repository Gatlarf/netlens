from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.api.devices import get_conn
from app.db import utcnow
from app.services import CheckError, describe, record_result, run_check, validate_check
from app.stats import _ago

router = APIRouter(prefix="/api", tags=["services"])


class CheckBody(BaseModel):
    device_id: int | None = None
    name: str | None = None
    kind: str | None = None
    host: str | None = None
    port: int | None = None
    path: str | None = None
    expect: str | None = None
    interval_s: int | None = None
    timeout_s: int | None = None
    enabled: bool | None = None


def _row(conn, check_id: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM service_checks WHERE id = ?", (check_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="check not found")
    return dict(row)


def _present(conn, c: dict[str, Any]) -> dict[str, Any]:
    day = conn.execute("SELECT SUM(up) AS u, COUNT(*) AS n FROM service_results WHERE check_id = ? AND ts >= ?", (c["id"], _ago(utcnow(), hours=24))).fetchone()
    dev = conn.execute("SELECT COALESCE(custom_name, hostname, primary_ip) AS n FROM devices WHERE id = ?", (c["device_id"],)).fetchone() if c["device_id"] else None
    return {
        "id": c["id"], "device_id": c["device_id"], "device_name": dev["n"] if dev else None, "name": c["name"], "kind": c["kind"],
        "host": c["host"], "port": c["port"], "path": c["path"], "expect": c["expect"], "interval_s": c["interval_s"],
        "timeout_s": c["timeout_s"], "enabled": bool(c["enabled"]), "target": describe(c),
        "state": None if c["last_up"] is None else ("up" if c["last_up"] else "down"),
        "last_ts": c["last_ts"], "last_ms": c["last_ms"], "last_detail": c["last_detail"], "since": c["since"],
        "uptime_24h": round(day["u"] / day["n"] * 100, 2) if day["n"] else None,
    }


@router.get("/service-checks")
def list_checks(device_id: int | None = None, conn=Depends(get_conn)) -> list[dict]:
    rows = conn.execute("SELECT * FROM service_checks" + (" WHERE device_id = ?" if device_id is not None else "") + " ORDER BY name COLLATE NOCASE, id", (device_id,) if device_id is not None else ()).fetchall()
    return [_present(conn, dict(r)) for r in rows]


def _check_device(conn, device_id: int | None) -> None:
    if device_id is not None and conn.execute("SELECT 1 FROM devices WHERE id = ?", (device_id,)).fetchone() is None:
        raise HTTPException(status_code=422, detail="that device does not exist")


@router.post("/service-checks", status_code=201)
def create_check(body: CheckBody, conn=Depends(get_conn)) -> dict:
    try:
        data = validate_check(body.model_dump(exclude_none=True))
    except CheckError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    _check_device(conn, body.device_id)
    count = conn.execute("SELECT COUNT(*) FROM service_checks").fetchone()[0]
    if count >= 200:
        raise HTTPException(status_code=422, detail="at most 200 checks")
    cur = conn.execute(
        "INSERT INTO service_checks (device_id, name, kind, host, port, path, expect, interval_s, timeout_s, enabled, created) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (body.device_id, data["name"], data["kind"], data["host"], data["port"], data["path"], data["expect"], data["interval_s"], data["timeout_s"], data["enabled"], utcnow()),
    )
    conn.commit()
    return _present(conn, _row(conn, cur.lastrowid))


@router.patch("/service-checks/{check_id}")
def update_check(check_id: int, body: CheckBody, conn=Depends(get_conn)) -> dict:
    current = _row(conn, check_id)
    merged = {**{k: current[k] for k in ("name", "kind", "host", "port", "path", "expect", "interval_s", "timeout_s")}, "enabled": bool(current["enabled"])}
    merged.update(body.model_dump(exclude_none=True, exclude={"device_id"}))
    try:
        data = validate_check(merged)
    except CheckError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    device_id = body.device_id if "device_id" in body.model_fields_set else current["device_id"]
    _check_device(conn, device_id)
    # a changed target starts a new history: the old state says nothing about the new one
    changed_target = any(data[k] != current[k] for k in ("kind", "host", "port", "path", "expect"))
    conn.execute(
        "UPDATE service_checks SET device_id=?, name=?, kind=?, host=?, port=?, path=?, expect=?, interval_s=?, timeout_s=?, enabled=? "
        + (", last_ts=NULL, last_up=NULL, last_ms=NULL, last_detail=NULL, since=NULL " if changed_target else " ")
        + "WHERE id=?",
        (device_id, data["name"], data["kind"], data["host"], data["port"], data["path"], data["expect"], data["interval_s"], data["timeout_s"], data["enabled"], check_id),
    )
    if changed_target:
        conn.execute("DELETE FROM service_results WHERE check_id = ?", (check_id,))
    conn.commit()
    return _present(conn, _row(conn, check_id))


@router.delete("/service-checks/{check_id}")
def delete_check(check_id: int, conn=Depends(get_conn)) -> dict:
    _row(conn, check_id)
    conn.execute("DELETE FROM service_checks WHERE id = ?", (check_id,))
    conn.commit()
    return {"removed": check_id}


@router.post("/service-checks/{check_id}/run")
async def run_now(check_id: int, conn=Depends(get_conn)) -> dict:
    """Run a check now and record the result (the answer shows what happened)."""
    check = _row(conn, check_id)
    result = await run_check(check)
    record_result(conn, _row(conn, check_id), result)
    return {"up": result.up, "ms": result.ms, "detail": result.detail, "check": _present(conn, _row(conn, check_id))}


@router.get("/service-checks/{check_id}/results")
def results(check_id: int, limit: int = Query(90, ge=1, le=1000), conn=Depends(get_conn)) -> list[dict]:
    _row(conn, check_id)
    rows = conn.execute("SELECT ts, up, ms, detail FROM service_results WHERE check_id = ? ORDER BY id DESC LIMIT ?", (check_id, limit)).fetchall()
    return [{"ts": r["ts"], "up": bool(r["up"]), "ms": r["ms"], "detail": r["detail"]} for r in reversed(rows)]
