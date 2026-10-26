"""Host monitors: ask a device for its health (SNMP or SSH), and the limits that raise alerts."""

from __future__ import annotations

import json
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app import credstore, tsdb
from app.auth import identify
from app.api.devices import get_conn
from app.hostmetrics import service as hm
from app.hostmetrics.snmp import GROUP_TITLES

router = APIRouter(prefix="/api", tags=["monitors"])


class MonitorBody(BaseModel):
    method: str | None = None
    address: str | None = None
    port: int | None = None
    interval_s: int | None = None
    community: str | None = None
    version: str | None = None
    username: str | None = None
    password: str | None = None
    auth_proto: str | None = None
    auth_password: str | None = None
    priv_proto: str | None = None
    priv_password: str | None = None
    platform: str | None = None
    auth: str | None = None
    verify_tls: bool | None = None
    private_key: str | None = None
    passphrase: str | None = None
    clear_password: bool | None = None
    credential_id: str | None = None
    alerts: bool | None = None
    enabled: bool | None = None


def _device(conn, device_id: int):
    row = conn.execute("SELECT id, primary_ip, hostname, custom_name FROM devices WHERE id = ?", (device_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="device not found")
    return row


def _may_use(request: Request, conn, data: dict[str, Any]) -> None:
    """Binding a monitor to a stored login is allowed to whoever may see that login (the owner, or an administrator for a shared one)."""
    cred_id = data.get("credential_id")
    if not cred_id:
        return
    principal = getattr(request.state, "user", None) or identify(request)
    if credstore.peek(conn, getattr(principal, "username", "") or "", str(cred_id)) is None:
        raise HTTPException(status_code=422, detail="no such stored login")


def _data(body: MonitorBody) -> dict[str, Any]:
    return body.model_dump(exclude_unset=True)


@router.get("/devices/{device_id}/monitor")
def get_monitor(device_id: int, conn=Depends(get_conn)) -> dict:
    device = _device(conn, device_id)
    row = hm.get_monitor(conn, device_id)
    return {"monitor": ({**hm.public(conn, row), "managed": row["source"] == "central"} if row else None), "default_address": device["primary_ip"], "groups": GROUP_TITLES,
            "state": _state(conn, row["id"]) if row else []}


def _state(conn, monitor_id: int) -> list[dict]:
    return [{"metric": r["metric"], "label": r["label"], "level": r["level"], "since": r["since"], "value": r["value"]}
            for r in conn.execute("SELECT * FROM metric_state WHERE monitor_id = ? ORDER BY metric, label", (monitor_id,))]


@router.post("/devices/{device_id}/monitor/test")
async def test_monitor(device_id: int, body: MonitorBody, request: Request, conn=Depends(get_conn)) -> dict:
    """Try the readings with what is in the form (or what is stored, for the secrets left empty). Nothing is saved."""
    device = _device(conn, device_id)
    row = hm.get_monitor(conn, device_id)
    data = _data(body)
    data.setdefault("address", (row["address"] if row else None) or device["primary_ip"])
    current = None
    if row is not None and data.get("method") in (None, row["method"]):
        current = {"method": row["method"], "address": row["address"], "port": row["port"], "interval_s": row["interval_s"],
                   "alerts": bool(row["alerts"]), "enabled": bool(row["enabled"]), "secret": hm.raw_secret(conn, row)}
    _may_use(request, conn, data)
    try:
        d = hm.validate(data, current)
    except hm.MonitorError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    d["secret"] = hm.resolve_secret(conn, d["method"], d["secret"])
    if d["secret"].get("credential_id") and not d["secret"].get("username"):
        raise HTTPException(status_code=422, detail="the stored login is gone: pick another one")
    known = None
    if d["method"] == "ssh":
        from app.terminal.hostkeys import get_fingerprint

        known = get_fingerprint(conn, device_id)
    state: dict = {}
    try:
        points, found, fingerprint = await hm.read(d["method"], d["address"], d["port"], d["secret"], None, state, known)
        if d["method"] in ("snmp",) or (d["method"] in ("ssh", "winrm") and "network" in found):
            # traffic and processor need two rounds: take a second reading a moment later so the test shows real numbers
            import asyncio

            await asyncio.sleep(2)
            points, found, fingerprint = await hm.read(d["method"], d["address"], d["port"], d["secret"], None, state, known)
    except hm.MonitorError as exc:
        return {"ok": False, "error": str(exc), "found": [], "values": []}
    values = [{"metric": m, "label": label, "value": v, "unit": u} for m, label, v, u in points]
    return {"ok": True, "error": None, "found": found, "found_titles": [GROUP_TITLES.get(g, g) for g in found], "values": values[:60],
            "fingerprint": fingerprint, "new_host_key": bool(fingerprint) and known is None and d["method"] == "ssh"}


@router.put("/devices/{device_id}/monitor")
async def put_monitor(device_id: int, body: MonitorBody, request: Request, conn=Depends(get_conn)) -> dict:
    device = _device(conn, device_id)
    existing = hm.get_monitor(conn, device_id)
    if existing is not None and existing["source"] == "central":
        raise HTTPException(status_code=409, detail="this monitor is managed by the central Netlens and cannot be changed here")
    data = _data(body)
    data.setdefault("address", device["primary_ip"])
    _may_use(request, conn, data)
    try:
        saved = hm.save_monitor(conn, device_id, data)
    except hm.MonitorError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"monitor": saved}


@router.post("/devices/{device_id}/monitor/run")
async def run_now(device_id: int, request_conn=Depends(get_conn)) -> dict:
    """Read now (the answer says what happened) instead of waiting for the next round."""
    conn = request_conn
    _device(conn, device_id)
    row = hm.get_monitor(conn, device_id)
    if row is None:
        raise HTTPException(status_code=404, detail="this device has no monitor")
    db_path = tsdb.db_file(conn)
    result = await hm.run_monitor(db_path, row["id"])
    # the traffic counters need a second reading to turn into a rate
    return {**result, "monitor": hm.public(conn, hm.get_monitor(conn, device_id))}


@router.delete("/devices/{device_id}/monitor")
def delete_monitor(device_id: int, conn=Depends(get_conn)) -> dict:
    _device(conn, device_id)
    row = hm.get_monitor(conn, device_id)
    if row is None:
        raise HTTPException(status_code=404, detail="this device has no monitor")
    if row["source"] == "central":
        raise HTTPException(status_code=409, detail="this monitor is managed by the central Netlens and cannot be removed here")
    conn.execute("DELETE FROM metric_state WHERE monitor_id = ?", (row["id"],))
    conn.execute("DELETE FROM host_monitors WHERE id = ?", (row["id"],))
    conn.commit()
    hm._STATES.pop(row["id"], None)
    return {"removed": device_id}


# ----------------------------------------------------------------------------- overview and limits
_latest = hm.latest_readings


@router.get("/monitors")
def overview(conn=Depends(get_conn)) -> dict:
    """Every monitored device with its newest readings and the readings that are past a limit."""
    store = tsdb.for_conn(conn)
    levels: dict[int, str] = {}
    for p in hm.problems(conn):
        cur = levels.get(p["device_id"], "ok")
        levels[p["device_id"]] = "critical" if "critical" in (cur, p["level"]) else "warning"
    out = []
    rows = conn.execute(
        "SELECT m.*, COALESCE(d.custom_name, d.hostname, d.primary_ip) AS name, d.primary_ip AS ip, d.online AS online, COALESCE(d.type_override, d.device_type) AS type "
        "FROM host_monitors m JOIN devices d ON d.id = m.device_id ORDER BY LOWER(COALESCE(d.custom_name, d.hostname, d.primary_ip))").fetchall()
    known = store.metrics_of_many("device", [r["device_id"] for r in rows]) if store is not None else {}
    saved = hm.all_overrides(conn)
    for row in rows:
        out.append({
            "device_id": row["device_id"], "name": row["name"], "ip": row["ip"], "type": row["type"], "online": bool(row["online"]),
            "method": row["method"], "enabled": bool(row["enabled"]), "alerts": bool(row["alerts"]), "last_ts": row["last_ts"],
            "last_ok": None if row["last_ok"] is None else bool(row["last_ok"]), "last_error": row["last_error"],
            "level": levels.get(row["device_id"], "ok"), "latest": _latest(store, row["device_id"], known.get(row["device_id"], [])),
            "limits": hm.rules(conn, row["device_id"]) if hm.device_overrides(conn, row["device_id"], saved) else None,
        })
    from app import storage

    return {"monitors": out, "problems": hm.problems(conn), "storage_problems": storage.problems(conn)}


class LimitsBody(BaseModel):
    rules: dict[str, dict[str, Any]]


@router.get("/devices/{device_id}/limits")
def get_device_limits(device_id: int, conn=Depends(get_conn)) -> dict:
    """The limits that apply to this device, and which of them were set for it alone."""
    _device(conn, device_id)
    return {"rules": hm.rules(conn, device_id), "general": hm.rules(conn), "overrides": hm.device_overrides(conn, device_id)}


@router.put("/devices/{device_id}/limits")
def put_device_limits(device_id: int, body: LimitsBody, conn=Depends(get_conn)) -> dict:
    _device(conn, device_id)
    try:
        hm.save_device_limits(conn, device_id, body.rules)
    except hm.MonitorError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"rules": hm.rules(conn, device_id), "general": hm.rules(conn), "overrides": hm.device_overrides(conn, device_id)}


@router.get("/forecast")
def get_forecast(conn=Depends(get_conn)) -> dict:
    """Monitored disks with their growth trend and the day they run full, the ones that fill soonest first."""
    from app import forecast

    return {"items": forecast.forecasts(conn), "alert_days": forecast.alert_days(conn)}


@router.get("/monitoring/limits")
def get_limits(conn=Depends(get_conn)) -> dict:
    return {"rules": hm.rules(conn)}


@router.put("/monitoring/limits")
def put_limits(body: LimitsBody, conn=Depends(get_conn)) -> dict:
    try:
        return {"rules": hm.save_rules(conn, body.rules)}
    except hm.MonitorError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
