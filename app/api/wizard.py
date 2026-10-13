"""Progress of the getting-started wizard (one state for the whole installation, administrators only).

`status` is "new" (nobody has opened it yet: installs from before the wizard, or a token install), "pending" (a fresh install that
has not finished it), "dismissed" (the nudge on the dashboard was closed) or "done". The demo always reports "done".
"""

import json

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.api.devices import get_conn
from app.db import get_setting, set_setting

router = APIRouter(prefix="/api", tags=["wizard"])

KEY = "wizard.state"
STATUSES = ("new", "pending", "dismissed", "done")
STEPS = 9


def read_state(conn) -> dict:
    try:
        raw = json.loads(get_setting(conn, KEY) or "{}")
    except ValueError:
        raw = {}
    status = raw.get("status") if raw.get("status") in STATUSES else "new"
    step = raw.get("step") if isinstance(raw.get("step"), int) and 0 <= raw["step"] < STEPS else 0
    return {"status": status, "step": step, "steps": STEPS}


def write_state(conn, status: str, step: int = 0) -> dict:
    set_setting(conn, KEY, json.dumps({"status": status, "step": step}))
    return read_state(conn)


class WizardBody(BaseModel):
    status: str | None = None
    step: int | None = None


@router.get("/wizard")
def get_wizard(request: Request, conn=Depends(get_conn)) -> dict:
    if request.app.state.settings.demo:
        return {"status": "done", "step": 0, "steps": STEPS}
    return read_state(conn)


@router.put("/wizard")
def put_wizard(body: WizardBody, conn=Depends(get_conn)) -> dict:
    current = read_state(conn)
    status = body.status if body.status is not None else current["status"]
    if status not in STATUSES:
        raise HTTPException(status_code=422, detail="unknown status")
    step = body.step if body.step is not None else current["step"]
    if not 0 <= step < STEPS:
        raise HTTPException(status_code=422, detail="unknown step")
    return write_state(conn, status, step)
