"""Insights (a paid feature, see app/insights.py): questions, incidents, unusual readings, predictions, unknown devices, post-mortems."""

from __future__ import annotations

import asyncio
import time
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app import anomaly, ask, forecast, identify, incidents, insights, modelcheck, postmortem, reportsummary
from app import engineer
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["insights"])
_CACHE: dict[str, tuple[float, Any]] = {}


def _allowed(conn) -> None:
    if not insights.allowed(conn):
        raise HTTPException(status_code=402, detail="Insights need a licence or the free trial (Settings → Licence)")


def _cached(conn, key: str, make, ttl: float = 90.0):
    from app import tsdb

    full = tsdb.db_file(conn) + key
    hit = _CACHE.get(full)
    if hit and time.monotonic() - hit[0] < ttl:
        return hit[1]
    value = make()
    _CACHE[full] = (time.monotonic(), value)
    return value


def _overview(conn) -> dict[str, Any]:
    state = {**insights.status(conn), "report_summary": reportsummary.enabled(conn) if insights.allowed(conn) else False}
    out: dict[str, Any] = {"status": state, "presets": [{"id": p["id"], "text": p["text"]} for p in ask.PRESETS]}
    if not state["allowed"]:
        return out
    out["incidents"] = [{k: i[k] for k in ("id", "start", "end", "title", "summary", "devices", "device_count", "resolved", "ongoing")} for i in incidents.incidents(conn, 7)[:30]]
    out["anomalies"] = _cached(conn, "anomalies", lambda: [{**a, "text": anomaly.describe(a)} for a in anomaly.scan(conn)[:30]])
    out["predictions"] = {"disks": [f for f in forecast.cached(conn) if f["days_to_full"] is not None][:20], "memory": forecast.memory_trends(conn)[:20]}
    out["unknown_devices"] = identify.unknown_devices(conn, 50)
    return out


@router.get("/insights")
def get_insights(conn=Depends(get_conn)) -> dict[str, Any]:
    return _overview(conn)


class Question(BaseModel):
    question: str = Field(max_length=500)
    mode: Literal["auto", "rules", "model"] = "auto"


@router.post("/insights/ask")
async def ask_question(body: Question, conn=Depends(get_conn)) -> dict:
    _allowed(conn)
    return await asyncio.to_thread(lambda: ask.answer(conn, body.question, mode=body.mode))


@router.post("/insights/incidents/{incident_id}/words")
async def incident_words(incident_id: int, conn=Depends(get_conn)) -> dict:
    """The incident in the language model's words (the plain summary stays when there is no model)."""
    _allowed(conn)
    found = next((i for i in incidents.incidents(conn, 30) if i["id"] == incident_id), None)
    if found is None:
        raise HTTPException(status_code=404, detail="that incident is no longer in the list")
    text = await asyncio.to_thread(incidents.narrate, conn, found)
    return {"text": text or found["summary"], "source": "model" if text else "rules"}


@router.get("/insights/identify/{device_id}")
async def identify_device(device_id: int, conn=Depends(get_conn)) -> dict:
    _allowed(conn)
    out = await asyncio.to_thread(identify.suggest, conn, device_id)
    if out is None:
        raise HTTPException(status_code=404, detail="no such device")
    return out


@router.get("/insights/postmortem/{run_id}")
async def get_postmortem(run_id: int, words: bool = False, conn=Depends(get_conn)) -> dict:
    _allowed(conn)
    out = await asyncio.to_thread(postmortem.postmortem, conn, run_id)
    if out is None:
        raise HTTPException(status_code=404, detail="no such run")
    if words:
        text = await asyncio.to_thread(postmortem.narrate, conn, out)
        out["words"] = text
    return out


class SettingsBody(BaseModel):
    llm: bool | None = None
    report_summary: bool | None = None


@router.put("/insights/settings")
def put_settings(body: SettingsBody, conn=Depends(get_conn)) -> dict:
    _allowed(conn)
    if body.llm is not None:
        insights.set_llm_wanted(conn, body.llm)
    if body.report_summary is not None:
        reportsummary.set_enabled(conn, body.report_summary)
    return _overview(conn)["status"]


@router.post("/insights/model-check")
async def model_check(conn=Depends(get_conn)) -> dict:
    """Five small exams that show whether the connected language model is reliable enough (takes a minute with a slow model)."""
    _allowed(conn)
    if not insights.llm_ready(conn) and not engineer.settings(conn)["url"]:
        raise HTTPException(status_code=409, detail="connect a language model first (Settings → Digital engineer)")
    return await asyncio.to_thread(modelcheck.run, conn)
