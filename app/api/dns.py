"""DNS registration: settings, the preview of what Netlens would change, and applying what the administrator approves."""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.db import connect, utcnow
from app.dns import service as dns
from app.plugins.contract import ContractError, validate_output
from app.plugins.runner import PluginRunError
from app.plugins.service import PluginService, _key, _load_json, get_state, get_status

router = APIRouter(prefix="/api", tags=["dns"])


def _service(request: Request) -> PluginService:
    return PluginService(request.app.state.db_path, request.app.state.settings.data_dir, getattr(request.app.state, "plugin_runner", None))


def _dns_plugins(service: PluginService, conn):
    return [p for p in service.plugins().values() if p.manifest and p.manifest["kind"] == "dns"]


def _active(service: PluginService, conn, values: dict):
    plugins = _dns_plugins(service, conn)
    if values["plugin"]:
        chosen = next((p for p in plugins if p.id == values["plugin"]), None)
        if chosen:
            return chosen
    return next((p for p in plugins if get_state(conn, p)["enabled"]), None)


def _view(service: PluginService, conn) -> dict:
    values = dns.get_settings(conn)
    plugins = _dns_plugins(service, conn)
    active = _active(service, conn, values)
    out = {
        "settings": values,
        "plugins": [{"id": p.id, "name": p.name, "enabled": get_state(conn, p)["enabled"], "version": p.manifest["version"]} for p in plugins],
        "plugin": active.id if active else None,
        "snapshot": None,
        "status": None,
        "plan": None,
        "marker": dns.MARKER,
        "needs_setup": not values["networks"].strip(),
    }
    if active is None:
        return out
    out["status"] = get_status(conn, active.id)
    data = _load_json(conn, _key(active.id, "data"))
    if isinstance(data, dict) and "zones" in data:
        out["snapshot"] = {"zones": len(data["zones"]), "records": len(data["records"]), "managed": sum(1 for r in data["records"] if r["managed"]),
                           "server": data.get("server"), "writable": [z["name"] for z in data["zones"] if z["writable"]]}
        if not out["needs_setup"]:
            try:
                out["plan"] = dns.make_plan(conn, active.id, validate_output("dns", data))
                labels = {r["id"]: r["n"] for r in conn.execute("SELECT id, COALESCE(custom_name, hostname, primary_ip) AS n FROM devices")}
                for item in out["plan"]["items"]:
                    item["device"] = labels.get(item["device_id"]) or item.get("device")
            except (ValueError, ContractError) as exc:
                out["plan_error"] = str(exc)
    return out


@router.get("/dns")
def get_dns(request: Request) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        return _view(_service(request), conn)
    finally:
        conn.close()


class SettingsBody(BaseModel):
    plugin: str | None = None
    networks: str | None = Field(default=None, max_length=2000)
    grace_hours: float | None = None
    only_known: bool | None = None
    skip_windows: bool | None = None
    template: str | None = None
    max_offline_days: int | None = None
    remove: bool | None = None
    auto_apply: bool | None = None
    register_containers: bool | None = None
    max_changes: int | None = None


@router.put("/dns/settings")
def put_settings(body: SettingsBody, request: Request) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        try:
            dns.save_settings(conn, body.model_dump(exclude_unset=True, exclude_none=True))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        return _view(_service(request), conn)
    finally:
        conn.close()


@router.post("/dns/refresh")
async def refresh(request: Request) -> dict:
    """Read the DNS server(s) now and show the new preview."""
    service = _service(request)
    conn = connect(request.app.state.db_path)
    try:
        active = _active(service, conn, dns.get_settings(conn))
        if active is None:
            raise HTTPException(status_code=409, detail="no DNS plugin is turned on: install one under Settings → Integrations → Browse plugins")
    finally:
        conn.close()
    result = await service.sync(active.id)
    if "error" in result:
        raise HTTPException(status_code=502, detail=result["error"])
    conn = connect(request.app.state.db_path)
    try:
        return _view(service, conn)
    finally:
        conn.close()


class ApplyBody(BaseModel):
    ids: list[str] | None = None      # change ids to apply; none = every planned change


@router.post("/dns/apply")
async def apply(body: ApplyBody, request: Request) -> dict:
    service = _service(request)
    conn = connect(request.app.state.db_path)
    try:
        values = dns.get_settings(conn)
        active = _active(service, conn, values)
        if active is None:
            raise HTTPException(status_code=409, detail="no DNS plugin is turned on")
        data = _load_json(conn, _key(active.id, "data"))
        if not isinstance(data, dict) or "zones" not in data:
            raise HTTPException(status_code=409, detail="read the DNS server first (Refresh)")
        plan = dns.make_plan(conn, active.id, validate_output("dns", data))
        try:
            changes = dns.select_changes(plan, body.ids, int(values["max_changes"]))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
    finally:
        conn.close()
    if not changes:
        raise HTTPException(status_code=422, detail="nothing to apply")
    try:
        results = await service.apply_dns(active, changes)
    except (PluginRunError, ContractError) as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    conn = connect(request.app.state.db_path)
    try:
        counts = dns.record_results(conn, active.id, changes, results)
    finally:
        conn.close()
    await service.sync(active.id)            # read back what the server has now
    conn = connect(request.app.state.db_path)
    try:
        view = _view(service, conn)
    finally:
        conn.close()
    return {"results": results, "counts": counts, **view}
