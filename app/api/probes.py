"""Remote sites: the list and details for the web interface, and the endpoint a probe pushes its report to."""

from __future__ import annotations

import json
import zlib
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app import probes as probes_mod
from app.api.devices import get_conn
from app.auth import LoginLimiter, client_ip
from app.db import connect

router = APIRouter(prefix="/api", tags=["remote-sites"])
push_router = APIRouter(tags=["remote-sites"])
MAX_BODY = 12 * 1024 * 1024


class NameBody(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    customer: str | None = None


def _row(conn, probe_id: int):
    row = conn.execute("SELECT * FROM probes WHERE id = ?", (probe_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="remote site not found")
    return row


@router.get("/probes")
def list_probes(conn=Depends(get_conn)) -> list[dict]:
    return [probes_mod.present(conn, r) for r in conn.execute("SELECT * FROM probes ORDER BY name COLLATE NOCASE")]


@router.get("/probes-search")
def search_remote_devices(q: str = "", conn=Depends(get_conn)) -> list[dict]:
    """Devices of the remote sites that match a search text (name, address, MAC or vendor), for the search box. Frozen sites are left out."""
    q = q.strip().lower()[:60]
    if len(q) < 2:
        return []
    like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    locked = probes_mod.locked_ids(conn)
    rows = conn.execute("SELECT d.id, d.probe_id, d.name, d.ip, d.vendor, p.name AS site FROM remote_devices d JOIN probes p ON p.id = d.probe_id "
                        "WHERE lower(d.name || ' ' || COALESCE(d.ip, '') || ' ' || COALESCE(d.mac, '') || ' ' || COALESCE(d.vendor, '')) LIKE ? ESCAPE '\\' ORDER BY d.name COLLATE NOCASE LIMIT 30", (like,)).fetchall()
    return [{"id": r["id"], "probe_id": r["probe_id"], "name": r["name"], "ip": r["ip"], "vendor": r["vendor"], "site": r["site"]} for r in rows if r["probe_id"] not in locked][:10]


@router.post("/probes", status_code=201)
def create_probe(body: NameBody, conn=Depends(get_conn)) -> dict:
    try:
        probe, token = probes_mod.create(conn, body.name or "")
    except probes_mod.LicenceLimit as exc:
        raise HTTPException(status_code=402, detail=str(exc))
    except probes_mod.ProbeError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"probe": probe, "token": token}


@router.get("/probes/{probe_id}")
def probe_detail(probe_id: int, conn=Depends(get_conn)) -> dict[str, Any]:
    row = _row(conn, probe_id)
    summary = json.loads(row["summary"] or "{}")
    devices = [{"id": r["id"], "key": r["key"], "name": r["name"], "ip": r["ip"], "mac": r["mac"], "vendor": r["vendor"], "type": r["type"], "os": r["os"],
                "online": bool(r["online"]), "always_on": bool(r["always_on"]), "ports": json.loads(r["ports"] or "[]"), "first_seen": r["first_seen"], "last_seen": r["last_seen"]}
               for r in conn.execute("SELECT * FROM remote_devices WHERE probe_id = ? ORDER BY online ASC, name COLLATE NOCASE", (probe_id,))]
    services = [{"id": r["id"], "key": r["key"], "name": r["name"], "kind": r["kind"], "target": r["target"], "state": r["state"], "ms": r["ms"],
                 "detail": r["detail"], "since": r["since"], "checked": r["checked"]}
                for r in conn.execute("SELECT * FROM remote_services WHERE probe_id = ? ORDER BY name COLLATE NOCASE", (probe_id,))]
    from app import snooze

    snoozed = snooze.active(conn).get(f"site:{probe_id}")
    return {"probe": probes_mod.present(conn, row), "devices": devices, "services": services, "problems": summary.get("problems") or [],
            "monitors": summary.get("monitors") or [], "scan": summary.get("scan"),
            "config_state": {"accepts": bool(summary.get("accepts_config")), "site_rev": summary.get("config_rev") or 0},
            "events": probes_mod.site_events(conn, probe_id), "pending_commands": probes_mod.pending_commands(conn, probe_id),
            "snoozed_until": snoozed["until"] if snoozed else None, "snooze": f"site:{probe_id}"}


class CommandBody(BaseModel):
    command: str


@router.post("/probes/{probe_id}/command", status_code=202)
def send_command(probe_id: int, body: CommandBody, conn=Depends(get_conn)) -> dict[str, Any]:
    """Ask the remote site to do something (for now: scan its network). It is handed over with the site's next report."""
    _row(conn, probe_id)
    try:
        return {"pending": probes_mod.queue_command(conn, probe_id, body.command)}
    except probes_mod.ProbeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.patch("/probes/{probe_id}")
def update_probe(probe_id: int, body: NameBody, conn=Depends(get_conn)) -> dict:
    row = _row(conn, probe_id)
    if body.name is not None:
        try:
            name = probes_mod.clean_name(body.name)
        except probes_mod.ProbeError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        if conn.execute("SELECT 1 FROM probes WHERE name = ? COLLATE NOCASE AND id != ?", (name, probe_id)).fetchone():
            raise HTTPException(status_code=422, detail="there is already a remote site with that name")
        conn.execute("UPDATE probes SET name = ? WHERE id = ?", (name, probe_id))
    if body.customer is not None:
        customer = " ".join(body.customer.split())
        if len(customer) > 60:
            raise HTTPException(status_code=422, detail="the customer name is too long (60 characters at most)")
        conn.execute("UPDATE probes SET customer = ? WHERE id = ?", (customer, probe_id))
    if body.enabled is not None:
        conn.execute("UPDATE probes SET enabled = ? WHERE id = ?", (int(body.enabled), probe_id))
    conn.commit()
    return probes_mod.present(conn, _row(conn, row["id"]))


@router.post("/probes/{probe_id}/token")
def new_token(probe_id: int, conn=Depends(get_conn)) -> dict:
    """A new token; the old one stops working at once."""
    _row(conn, probe_id)
    return {"token": probes_mod.rotate_token(conn, probe_id)}


class ConfigBody(BaseModel):
    services: list[dict] = []
    monitors: list[dict] = []


@router.get("/probes/{probe_id}/config")
def get_config(probe_id: int, conn=Depends(get_conn)) -> dict[str, Any]:
    from app import probe_config

    _row(conn, probe_id)
    return probe_config.public(probe_config.load(conn, probe_id))


@router.put("/probes/{probe_id}/config")
def put_config(probe_id: int, body: ConfigBody, conn=Depends(get_conn)) -> dict[str, Any]:
    from app import probe_config

    _row(conn, probe_id)
    try:
        cfg = probe_config.save(conn, probe_id, body.model_dump())
    except probe_config.ConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return probe_config.public(cfg)


@router.delete("/probes/{probe_id}")
def delete_probe(probe_id: int, conn=Depends(get_conn)) -> dict:
    _row(conn, probe_id)
    probes_mod.delete(conn, probe_id)
    return {"removed": probe_id}


# ----------------------------------------------------------------------------- the report of a probe
@push_router.post("/api/probe/push")
async def push(request: Request) -> dict:
    limiter: LoginLimiter = request.app.state.share_limiter
    host = client_ip(request)
    if not limiter.allowed(host):
        raise HTTPException(status_code=429, detail="too many attempts")
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY:
        raise HTTPException(status_code=413, detail="the report is too large")
    body = await request.body()            # read it before answering, so a refusal does not cut the connection off in the sender's face
    conn = connect(request.app.state.db_path)
    try:
        probe = probes_mod.find_by_token(conn, token) if token else None
        if probe is None or not probe["enabled"]:
            limiter.record_failure(host)
            raise HTTPException(status_code=401, detail="this token is not valid (the remote site may have been removed or its token replaced)")
        if probe["id"] in probes_mod.locked_ids(conn):
            raise HTTPException(status_code=402, detail="the central Netlens has no licence for this many remote sites: this site is frozen until a licence key is added there")
        if len(body) > MAX_BODY:
            raise HTTPException(status_code=413, detail="the report is too large")
        if request.headers.get("content-encoding", "").lower() == "gzip":
            try:
                inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
                body = inflater.decompress(body, MAX_BODY * 4)
                if inflater.unconsumed_tail:             # more than the limit: a decompression bomb, not a report
                    raise HTTPException(status_code=413, detail="the report is too large")
            except zlib.error:
                raise HTTPException(status_code=400, detail="the report is not valid gzip")
        try:
            payload = json.loads(body)
        except ValueError:
            raise HTTPException(status_code=400, detail="the report is not valid JSON")
        try:
            result = probes_mod.ingest(conn, probe, payload, remote_ip=host)
        except probes_mod.ProbeError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        if isinstance(payload, dict):
            from app import probe_config

            config = probe_config.for_probe(conn, probe["id"], payload)
            if config is not None:
                result["config"] = config
            if payload.get("accepts_config"):
                commands = probes_mod.take_commands(conn, probe["id"])
                if commands:
                    result["commands"] = commands
    finally:
        conn.close()
    # the events this report raised should reach the channels now, not at the next scan
    if result.get("events") or result.get("ok"):
        from app.notify.channels import process_channels

        await process_channels(request.app.state.db_path)
    return result
