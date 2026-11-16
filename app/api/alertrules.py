"""Alert rules (app/alertrules.py): which events are recorded but not sent. Administrators only."""
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app import alertrules, groups as groups_mod
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["alert rules"])


class PreviewBody(BaseModel):
    rule: dict[str, Any]
    days: int = 7


class EnabledBody(BaseModel):
    enabled: bool


def _kinds() -> list[dict]:
    from app import incidents
    from app.notify.channels import CRITICAL, EVENT_LABELS

    recovers = incidents.RECOVERS
    return [{"kind": k, "label": label, "problem": k in incidents.PROBLEMS, "recovery_of": recovers.get(k), "critical": k in CRITICAL}
            for k, label in EVENT_LABELS.items() if k not in alertrules.NEVER_MUTED]


@router.get("/alert-rules")
def list_rules(conn=Depends(get_conn)) -> dict:
    counts = alertrules.muted_counts(conn)
    return {"rules": [{**r, "muted_7d": counts.get(r["name"], 0)} for r in alertrules.load(conn)], "kinds": _kinds(),
            "groups": [{"id": g["id"], "name": g["name"]} for g in groups_mod.list_groups(conn)], "types": list(alertrules.TYPES), "max_rules": alertrules.MAX_RULES}


@router.post("/alert-rules", status_code=201)
def create_rule(body: dict[str, Any], conn=Depends(get_conn)) -> dict:
    body = {k: v for k, v in body.items() if k != "id"}
    try:
        return alertrules.upsert(conn, body)
    except alertrules.RuleError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.put("/alert-rules/{rule_id}")
def change_rule(rule_id: str, body: dict[str, Any], conn=Depends(get_conn)) -> dict:
    if not any(r["id"] == rule_id for r in alertrules.load(conn)):
        raise HTTPException(status_code=404, detail="no such rule")
    try:
        return alertrules.upsert(conn, {**body, "id": rule_id})
    except alertrules.RuleError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.put("/alert-rules/{rule_id}/enabled")
def switch_rule(rule_id: str, body: EnabledBody, conn=Depends(get_conn)) -> dict:
    rule = alertrules.set_enabled(conn, rule_id, body.enabled)
    if rule is None:
        raise HTTPException(status_code=404, detail="no such rule")
    return rule


@router.delete("/alert-rules/{rule_id}", status_code=204)
def delete_rule(rule_id: str, conn=Depends(get_conn)) -> None:
    if not alertrules.remove(conn, rule_id):
        raise HTTPException(status_code=404, detail="no such rule")


@router.post("/alert-rules/preview")
def preview_rule(body: PreviewBody, conn=Depends(get_conn)) -> dict:
    """What this rule would have done to the last days of events (it changes nothing)."""
    try:
        return alertrules.preview(conn, body.rule, body.days)
    except alertrules.RuleError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
