import asyncio
import json

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.db import connect, get_setting
from app.integrations.proxmox_client import ProxmoxClient, ProxmoxError
from app.integrations.proxmox_config import (
    ProxmoxConfig,
    is_configured,
    load_config,
    normalize_url,
    public_dict,
    save_config,
)
from app.integrations.proxmox_sync import STATUS_KEY, apply_proxmox_relations, sync_now

router = APIRouter(prefix="/api", tags=["proxmox"])


def _payload(conn) -> dict:
    status = None
    raw = get_setting(conn, STATUS_KEY)
    if raw:
        try:
            status = json.loads(raw)
        except ValueError:
            pass
    return {**public_dict(load_config(conn)), "status": status}


class ProxmoxBody(BaseModel):
    """Only the fields sent are changed. Secrets left out (or null) keep their saved value."""

    enabled: bool | None = None
    url: str | None = Field(default=None, max_length=300)
    verify_tls: bool | None = None
    username: str | None = Field(default=None, max_length=200)
    password: str | None = Field(default=None, max_length=500)
    token_id: str | None = Field(default=None, max_length=200)
    token_secret: str | None = Field(default=None, max_length=500)


def _merge(cfg: ProxmoxConfig, body: ProxmoxBody) -> ProxmoxConfig:
    fields = body.model_fields_set
    if "url" in fields and body.url is not None:
        try:
            cfg.url = normalize_url(body.url)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
    for name in ("enabled", "verify_tls"):
        if name in fields and getattr(body, name) is not None:
            setattr(cfg, name, getattr(body, name))
    for name in ("username", "token_id"):
        if name in fields and getattr(body, name) is not None:
            setattr(cfg, name, getattr(body, name).strip())
    for name in ("password", "token_secret"):
        value = getattr(body, name)
        if value:  # empty/missing keeps the saved secret; use the Clear buttons in the UI to wipe via ""+flag if ever needed
            setattr(cfg, name, value)
    return cfg


@router.get("/proxmox")
def get_proxmox(request: Request) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        return _payload(conn)
    finally:
        conn.close()


@router.put("/proxmox")
async def put_proxmox(request: Request, body: ProxmoxBody) -> dict:
    db_path = request.app.state.db_path
    conn = connect(db_path)
    try:
        cfg = _merge(load_config(conn), body)
        if cfg.enabled and not is_configured(cfg):
            raise HTTPException(
                status_code=422,
                detail="to enable the connector set the URL and either an API token or a username and password",
            )
        save_config(conn, cfg)
        if not cfg.enabled:
            # Edges created by the connector disappear with it; stored guests stay for when it is re-enabled.
            conn.execute("DELETE FROM relations WHERE source = 'proxmox' AND manual = 0")
            conn.commit()
        result = _payload(conn)
    finally:
        conn.close()
    if cfg.enabled:
        await sync_now(db_path, client_factory=getattr(request.app.state, "proxmox_factory", ProxmoxClient))
        conn = connect(db_path)
        try:
            result = _payload(conn)
        finally:
            conn.close()
    return result


@router.post("/proxmox/test")
async def test_proxmox(request: Request, body: ProxmoxBody) -> dict:
    """Try the connection with the values in the form (secrets fall back to the saved ones). Saves nothing."""
    conn = connect(request.app.state.db_path)
    try:
        cfg = _merge(load_config(conn), body)
    finally:
        conn.close()
    if not is_configured(cfg):
        raise HTTPException(status_code=422, detail="enter the URL and either an API token or a username and password")
    factory = getattr(request.app.state, "proxmox_factory", ProxmoxClient)

    def run():
        client = factory(cfg)
        version = client.version()
        inv = client.inventory()
        return version, inv

    try:
        version, inv = await asyncio.to_thread(run)
    except ProxmoxError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {"ok": True, "version": version, "nodes": len(inv["nodes"]), "guests": len(inv["guests"])}


@router.post("/proxmox/sync")
async def sync_proxmox(request: Request) -> dict:
    result = await sync_now(
        request.app.state.db_path, client_factory=getattr(request.app.state, "proxmox_factory", ProxmoxClient)
    )
    if "error" in result:
        raise HTTPException(status_code=502, detail=result["error"])
    return result
