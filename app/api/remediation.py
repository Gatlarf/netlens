"""Auto-remediation and the digital engineer (paid features, see app/remediation.py and app/engineer.py)."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app import engineer, licence, openrouter, providers, remediation
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["remediation"])


def _allowed(conn) -> None:
    if not licence.allows(conn, "remediation"):
        raise HTTPException(status_code=402, detail="auto-remediation needs a licence or the free trial (Settings → Licence)")


def _overview(conn) -> dict[str, Any]:
    devices = [{"id": r["id"], "name": r["custom_name"] or r["hostname"] or r["primary_ip"]} for r in conn.execute("SELECT id, custom_name, hostname, primary_ip FROM devices ORDER BY 2 COLLATE NOCASE")]
    from app.notify.channels import EVENT_LABELS

    return {"allowed": licence.allows(conn, "remediation"), "paused": remediation.paused(conn), "rules": remediation.list_rules(conn), "runs": remediation.recent_runs(conn),
            "kinds": [{"id": k, "label": EVENT_LABELS[k]} for k in remediation.trigger_kinds()], "devices": devices, "actions": list(remediation.ACTIONS), "modes": list(remediation.MODES),
            "engineer": {**engineer.settings(conn), "allowed": licence.allows(conn, "engineer")}, "summary": remediation.summary(conn)}


@router.get("/remediation")
def get_remediation(conn=Depends(get_conn)) -> dict[str, Any]:
    return _overview(conn)


@router.post("/remediation/rules", status_code=201)
def create_rule(body: dict, conn=Depends(get_conn)) -> dict:
    _allowed(conn)
    try:
        return remediation.save_rule(conn, body)
    except remediation.RuleError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.put("/remediation/rules/{rule_id}")
def update_rule(rule_id: int, body: dict, conn=Depends(get_conn)) -> dict:
    _allowed(conn)
    try:
        return remediation.save_rule(conn, body, rule_id)
    except remediation.RuleError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.delete("/remediation/rules/{rule_id}")
def delete_rule(rule_id: int, conn=Depends(get_conn)) -> dict:
    remediation.delete_rule(conn, rule_id)
    return {"removed": rule_id}


class RunBody(BaseModel):
    device_id: int | None = None


@router.post("/remediation/rules/{rule_id}/run")
async def run_rule_now(rule_id: int, body: RunBody, request: Request, conn=Depends(get_conn)) -> dict:
    """Try a rule on a device now (it is recorded like any run; the cooldown and limits do not apply to a test)."""
    _allowed(conn)
    rule = remediation.get_rule(conn, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="that rule does not exist")
    device_id = body.device_id if body.device_id is not None else rule["device_id"]
    if device_id is None:
        raise HTTPException(status_code=422, detail="choose the device to try it on")
    from app.db import utcnow

    run_id = remediation._new_run(conn, rule, {"id": None, "kind": "test", "detail": "started by " + _who(request), "device_id": device_id}, "pending", utcnow(), device_id=device_id)
    return await asyncio.to_thread(remediation.execute, conn, run_id)


def _who(request: Request) -> str:
    user = getattr(request.state, "user", None)
    return getattr(user, "username", "an administrator")


class Decision(BaseModel):
    approve: bool


@router.post("/remediation/runs/{run_id}/decide")
async def decide_run(run_id: int, body: Decision, request: Request, conn=Depends(get_conn)) -> dict:
    try:
        return await asyncio.to_thread(remediation.decide, conn, run_id, body.approve, _who(request))
    except remediation.RuleError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.post("/remediation/runs/{run_id}/ask")
async def ask_engineer(run_id: int, conn=Depends(get_conn)) -> dict:
    if not licence.allows(conn, "engineer"):
        raise HTTPException(status_code=402, detail="the digital engineer needs a licence or the free trial (Settings → Licence)")
    if not engineer.settings(conn)["enabled"]:
        raise HTTPException(status_code=422, detail="switch the language model on first (Settings → AI)")
    try:
        answer = await asyncio.to_thread(engineer.advise, conn, run_id)
    except (engineer.EngineerError, remediation.RuleError) as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return answer or {}


class Pause(BaseModel):
    paused: bool


@router.put("/remediation/paused")
def pause(body: Pause, conn=Depends(get_conn)) -> dict:
    remediation.set_paused(conn, body.paused)
    return {"paused": body.paused}


class EngineerBody(BaseModel):
    enabled: bool | None = None
    url: str | None = None
    model: str | None = None
    api_key: str | None = None
    clear_key: bool | None = None
    redact: bool | None = None


@router.get("/engineer")
def get_engineer(conn=Depends(get_conn)) -> dict:
    return {**engineer.settings(conn), "allowed": licence.allows(conn, "engineer")}


@router.put("/engineer")
def put_engineer(body: EngineerBody, conn=Depends(get_conn)) -> dict:
    try:
        return {**engineer.save_settings(conn, body.model_dump(exclude_none=True)), "allowed": licence.allows(conn, "engineer")}
    except engineer.EngineerError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/engineer/test")
async def test_engineer(conn=Depends(get_conn)) -> dict:
    try:
        text = await asyncio.to_thread(engineer.chat, conn, [{"role": "user", "content": "Reply with the single word: ready"}], 40.0)
    except engineer.EngineerError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {"ok": True, "answer": text[:200]}


class OpenRouterPick(BaseModel):
    model: str
    api_key: str | None = None


def _engineer_allowed(conn) -> None:
    if not licence.allows(conn, "engineer"):
        raise HTTPException(status_code=402, detail="the digital engineer needs a licence or the free trial (Settings → Licence)")


def _key(conn, body: OpenRouterPick) -> str | None:
    from app.db import get_setting

    return (body.api_key or "").strip() or get_setting(conn, "engineer.api_key")


@router.get("/engineer/openrouter")
async def get_openrouter(refresh: bool = False, conn=Depends(get_conn)) -> dict:
    """The free models OpenRouter offers right now (live), with the result of any exam on this installation, and the state of the chosen model."""
    try:
        models = await asyncio.to_thread(openrouter.free_models, conn, None, refresh)
        error = None
    except openrouter.OpenRouterError as exc:
        models, error = [], str(exc)
    state = openrouter.watch_state(conn)
    return {"models": models, "error": error, "watch": state, "watch_message": openrouter.message(state["model"], state["state"]) if state and state["state"] != "ok" else None}


@router.post("/engineer/openrouter/test")
async def test_openrouter(body: OpenRouterPick, conn=Depends(get_conn)) -> dict:
    _engineer_allowed(conn)
    try:
        return await asyncio.to_thread(openrouter.run_test, conn, body.model, _key(conn, body))
    except openrouter.OpenRouterError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/engineer/openrouter/use")
async def use_openrouter(body: OpenRouterPick, conn=Depends(get_conn)) -> dict:
    _engineer_allowed(conn)
    try:
        return {**await asyncio.to_thread(openrouter.use, conn, body.model, (body.api_key or "").strip() or None), "allowed": True}
    except (openrouter.OpenRouterError, engineer.EngineerError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))


class ModelsBody(BaseModel):
    url: str
    api_key: str | None = None


@router.get("/engineer/providers")
def get_providers(conn=Depends(get_conn)) -> dict:
    """The providers to choose from, with their addresses, and the one in use."""
    return {"providers": providers.public(), "current": engineer.settings(conn)["provider"]}


@router.post("/engineer/models")
async def list_provider_models(body: ModelsBody, conn=Depends(get_conn)) -> dict:
    """The models a provider offers this key. The saved key is used only for the provider it was saved for, never for another address."""
    from app.db import get_setting

    key = (body.api_key or "").strip()
    if not key and providers.host_of(body.url) == providers.host_of(get_setting(conn, "engineer.url") or ""):
        key = get_setting(conn, "engineer.api_key") or ""
    try:
        return {"models": await asyncio.to_thread(providers.list_models, body.url, key or None), "provider": providers.detect(body.url)}
    except providers.ProviderError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
