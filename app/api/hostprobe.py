"""Host probes (see app/hostprobe): what uses the storage of a host, snapshots over time, and how a host is locked down for it. Administrators only."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from app import audit
from app.api.devices import get_conn
from app.auth import client_ip, require_admin
from app.hostmetrics import service as hm
from app.hostprobe import credentials, scripts, service

router = APIRouter(prefix="/api", tags=["hostprobe"])


def _admin(request: Request) -> None:
    require_admin(request)


def _who(request: Request):
    return getattr(request.state, "user", None)


def _note(request: Request, conn, method: str, action: str) -> None:
    """An explicit audit line (the generic one for this request is switched off in app/audit.py: this one knows more)."""
    audit.record_by(conn, _who(request), client_ip(request), method, request.url.path, 200, action)


@router.get("/hostprobe/settings")
def get_settings(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    _admin(request)
    return service.public_settings(conn)


@router.put("/hostprobe/settings")
def put_settings(body: dict, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    _admin(request)
    try:
        out = service.save_settings(conn, body)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    changed = sorted([f"{name}.{k}" for name, v in (body.get("providers") or {}).items() if isinstance(v, dict) for k in v] + [k for k in ("names_to_llm", "keep_days") if k in body])
    _note(request, conn, "PUT", "Changed the host probe settings: " + (", ".join(changed) or "nothing") + " (secret values are never written to the log)")
    return out


@router.post("/hostprobe/ca")
def create_ca(request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    """Create the certificate authority, or replace it (hosts then need the new public key)."""
    _admin(request)
    had = credentials.ca_public(conn)
    pub = credentials.ca_create(conn)
    _note(request, conn, "POST", ("Replaced" if had else "Created") + f" the Netlens SSH certificate authority (public key {_fingerprint(pub)})"
          + ("; hosts that trusted the old key refuse new certificates" if had else ""))
    return {"ca_public_key": pub}


@router.get("/hostprobe/setup")
def get_setup(request: Request, platform: str = "linux", user: str = "netlens-ro", public_key: str | None = None, conn=Depends(get_conn)) -> dict[str, Any]:
    """The files and lines that lock a host down to the probe: for a key (give its public part) and for certificates from the Netlens CA."""
    _admin(request)
    if platform not in ("linux", "windows"):
        raise HTTPException(status_code=422, detail="platform must be linux or windows")
    if not user.replace("-", "").replace("_", "").isalnum() or len(user) > 32:
        raise HTTPException(status_code=422, detail="the user name may only hold letters, digits, - and _")
    ca = credentials.ca_public(conn)
    audit.record_read(conn, _who(request), client_ip(request), request.url.path, f"Viewed the files that prepare a {platform} host for the storage probe (account {user})")
    make = scripts.linux_setup if platform == "linux" else scripts.windows_setup
    return {"platform": platform, "user": user, "has_ca": bool(ca), "files": make(user, public_key, ca)}


def _fingerprint(public_key: str) -> str:
    import asyncssh

    try:
        return asyncssh.import_public_key(public_key).get_fingerprint("sha256")
    except (asyncssh.Error, ValueError):
        return "?"


def _device(conn, device_id: int):
    row = conn.execute("SELECT id, COALESCE(custom_name, hostname, primary_ip) AS name FROM devices WHERE id = ?", (device_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="device not found")
    return row


def _view(conn, device_id: int) -> dict[str, Any]:
    monitor = hm.get_monitor(conn, device_id)
    snaps = service.snapshots(conn, device_id, 30)
    last = service.latest_ok(conn, device_id)
    growth = None
    if last:
        prev = service.latest_ok(conn, device_id, before=_earlier(last["taken"]))
        if prev and prev["id"] != last["id"]:
            from app.hostprobe import parse

            growth = {"from": prev["taken"], "to": last["taken"], **parse.compare(prev["data"], last["data"], min_bytes=50 * 1024 ** 2)}
    return {"script_version": scripts.SCRIPT_VERSION, "config": service.device_config(conn, device_id), "monitor": monitor["method"] if monitor else None, "snapshots": snaps,
            "latest": {"taken": last["taken"], "mode": last["mode"], "data": last["data"]} if last else None, "growth_since_previous": growth,
            "last_error": next((s["error"] for s in snaps[:1] if not s["ok"]), None)}


def _earlier(stamp: str) -> str:
    from datetime import datetime, timedelta, timezone

    return (datetime.strptime(stamp, service.STAMP).replace(tzinfo=timezone.utc) - timedelta(seconds=1)).strftime(service.STAMP)


@router.get("/devices/{device_id}/hostprobe")
def get_device(device_id: int, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    _admin(request)
    row = _device(conn, device_id)
    view = _view(conn, device_id)
    if view["latest"]:
        audit.record_read(conn, _who(request), client_ip(request), request.url.path, f"Viewed the storage inspection of {row['name']} (folder and file names)")
    return view


@router.put("/devices/{device_id}/hostprobe")
def put_device(device_id: int, body: dict, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    _admin(request)
    _device(conn, device_id)
    try:
        service.save_settings(conn, {"devices": {str(device_id): {k: body[k] for k in ("enabled", "interval_h", "provider", "username") if k in body}}})
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _view(conn, device_id)


@router.post("/devices/{device_id}/hostprobe/run")
async def run_now(device_id: int, request: Request) -> dict[str, Any]:
    """Take a snapshot now (it can take a minute on a big disk)."""
    _admin(request)
    from app.db import connect

    db = connect(request.app.state.db_path)
    try:
        _device(db, device_id)
    finally:
        db.close()
    result = await service.run_one(request.app.state.db_path, device_id, actor=(_who(request), client_ip(request)))
    db = connect(request.app.state.db_path)
    try:
        return {"ok": result["ok"], "error": result["error"], **_view(db, device_id)}
    finally:
        db.close()
