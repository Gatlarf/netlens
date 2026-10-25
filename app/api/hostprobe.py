"""Host probes (see app/hostprobe): what uses the storage of a host, snapshots over time, and how a host is locked down for it. Administrators only."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from app import audit
from app.api.devices import get_conn
from app.auth import client_ip, require_admin
from app.hostmetrics import service as hm
from app.hostprobe import credentials, diagnose as engineer, scripts, service

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
    from app.hostprobe import parse as _parse

    hidden = [{**u, "text": _parse.describe_unaccounted(u)} for u in _parse.unaccounted(last["data"])] if last else []
    probes = {}
    for name in scripts.PROBES:
        snaps = service.snapshots(conn, device_id, 1, probe=name)
        good = service.latest_ok(conn, device_id, probe=name)
        probes[name] = {"title": scripts.TITLES[name], "taken": good["taken"] if good else None, "mode": good["mode"] if good else None,
                        "error": snaps[0]["error"] if snaps and not snaps[0]["ok"] else None, "last_try": snaps[0]["taken"] if snaps else None}
    diagnosis = engineer.diagnose(conn, device_id) if any(p["taken"] for p in probes.values()) else None
    return {"probes": probes, "diagnosis": diagnosis, "hidden": hidden, "script_version": scripts.SCRIPT_VERSION, "config": service.device_config(conn, device_id), "monitor": monitor["method"] if monitor else None, "snapshots": snaps,
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
        service.save_settings(conn, {"devices": {str(device_id): {k: body[k] for k in ("enabled", "interval_h", "provider", "username", "probes") if k in body}}})
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _view(conn, device_id)


@router.get("/devices/{device_id}/hostprobe/{probe}")
def get_probe(device_id: int, probe: str, request: Request, conn=Depends(get_conn)) -> dict[str, Any]:
    """The newest answer of one probe (with the findings that come from it), and the few before it."""
    _admin(request)
    row = _device(conn, device_id)
    if probe not in scripts.PROBES:
        raise HTTPException(status_code=404, detail="no such probe")
    last = service.latest_ok(conn, device_id, probe=probe)
    audit.record_read(conn, _who(request), client_ip(request), request.url.path, f"Viewed the '{probe}' probe results of {row['name']}")
    findings = []
    if last and probe != "storage":
        from app.hostprobe import analyze

        findings = [{k: e[k] for k in ("level", "weight", "text")} for e in analyze.analyze(probe, last["data"], {"onset": None}) if not any(t.startswith("ok:") for t in e["tags"])]
    return {"probe": probe, "title": scripts.TITLES[probe], "latest": last, "findings": findings, "history": service.snapshots(conn, device_id, 20, probe=probe)}


@router.post("/devices/{device_id}/hostprobe/run")
async def run_now(device_id: int, request: Request, probe: str = "storage") -> dict[str, Any]:
    """Take a snapshot now (it can take a minute on a big disk)."""
    _admin(request)
    from app.db import connect

    if probe not in scripts.PROBES:
        raise HTTPException(status_code=422, detail="probe must be one of: " + ", ".join(scripts.PROBES))
    db = connect(request.app.state.db_path)
    try:
        _device(db, device_id)
    finally:
        db.close()
    result = await service.run_one(request.app.state.db_path, device_id, actor=(_who(request), client_ip(request)), probe=probe)
    db = connect(request.app.state.db_path)
    try:
        return {"ok": result["ok"], "error": result["error"], **_view(db, device_id)}
    finally:
        db.close()


_LAST_LIVE: dict[int, float] = {}


@router.post("/devices/{device_id}/hostprobe/diagnose")
async def diagnose_now(device_id: int, body: dict, request: Request) -> dict[str, Any]:
    """The digital engineer: find the cause of a symptom ("the server is slow", "why did it restart?") with the read-only probes it calls for.
    live=true looks first (each look is in the audit log; at most one live diagnosis per host a minute); otherwise it uses the snapshots there are."""
    import time

    from app.db import connect

    _admin(request)
    symptom = str(body.get("symptom") or "")[:200]
    live = bool(body.get("live"))
    db = connect(request.app.state.db_path)
    try:
        row = _device(db, device_id)
        if live:
            if time.time() - _LAST_LIVE.get(device_id, 0) < 60:
                raise HTTPException(status_code=429, detail="this host was looked at less than a minute ago: wait a moment, or use the snapshots (live off)")
            _LAST_LIVE[device_id] = time.time()
        plan = engineer.plan(symptom)
        _note(request, db, "POST", f"Asked the digital engineer about {row['name']}: \"{symptom or 'what is wrong?'}\" ({'looked live at ' + ', '.join(plan) if live else 'from the snapshots'})")
    finally:
        db.close()
    if live:
        return await engineer.diagnose_live(request.app.state.db_path, device_id, symptom, actor=(_who(request), client_ip(request)))
    db = connect(request.app.state.db_path)
    try:
        return engineer.diagnose(db, device_id, symptom)
    finally:
        db.close()
