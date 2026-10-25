from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app import dashboard
from app.auth import require_admin
from app.api.stats import _cached, _passive
from app.api.devices import get_conn
from app.db import connect
from app.scanner.scans import running_scan
from app.stats import summary

router = APIRouter(prefix="/api", tags=["dashboard"])


def _plugin_cards(request: Request, conn) -> list[dict]:
    from app import plugin_cards
    from app.plugins.service import PluginService, get_state, get_status

    service = PluginService(request.app.state.db_path, request.app.state.settings.data_dir, getattr(request.app.state, "plugin_runner", None))
    out: list[dict] = []
    for plugin in service.plugins().values():
        if plugin.manifest and get_state(conn, plugin)["enabled"]:
            out += plugin_cards.resolve(conn, plugin.manifest, get_status(conn, plugin.id))
    return out


@router.get("/dashboard")
def get_dashboard(request: Request) -> dict:
    """The start page: the summary plus what needs attention, the latest events and a few small series."""
    db_path = request.app.state.db_path

    def build():
        conn = connect(db_path)
        try:
            s = summary(conn, scan_running=running_scan(conn) is not None, data_dir=request.app.state.settings.data_dir, passive=_passive(request))
            doc = dashboard.build(conn, s)
            doc["plugin_cards"] = _plugin_cards(request, conn)
            return doc
        finally:
            conn.close()

    doc = dict(_cached(request, ("dashboard", db_path), build))
    # what someone acknowledged moves to its own list, so it stops counting as "needs attention" (not cached: it changes at once)
    from app import snooze

    conn = connect(db_path)
    try:
        asleep = snooze.active(conn)
    finally:
        conn.close()
    if asleep:
        keep, held = [], []
        for item in doc["attention"]:
            entry = asleep.get(item.get("snooze"))
            if entry:
                held.append({**item, "until": entry["until"], "by": entry.get("by"), "note": entry.get("note")})
            else:
                keep.append(item)
        doc["attention"], doc["snoozed"] = keep, held
    else:
        doc["snoozed"] = []
    return doc


class LayoutBody(BaseModel):
    order: list[str]
    custom: list[dict] = []
    sizes: dict[str, str] = {}


@router.get("/dashboard/layout")
def get_layout(request: Request, conn=Depends(get_conn)) -> dict:
    """The cards this user chose, in order (null while the user still has the default)."""
    return dashboard.get_layout(conn, request.state.user) or {"order": None, "custom": [], "sizes": {}}


@router.put("/dashboard/layout")
def put_layout(body: LayoutBody, request: Request, conn=Depends(get_conn)) -> dict:
    try:
        return dashboard.set_layout(conn, request.state.user, body.order, body.custom, body.sizes)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.delete("/dashboard/layout")
def delete_layout(request: Request, conn=Depends(get_conn)) -> dict:
    dashboard.reset_layout(conn, request.state.user)
    return {"order": None, "custom": [], "sizes": {}}


class SharedBody(BaseModel):
    cards: list[dict] = []


@router.get("/dashboard/shared")
def get_shared(conn=Depends(get_conn)) -> dict:
    """Cards an administrator made available to everybody (they are added from the card pool)."""
    return {"cards": dashboard.get_shared(conn)}


@router.put("/dashboard/shared")
def put_shared(body: SharedBody, request: Request, conn=Depends(get_conn)) -> dict:
    require_admin(request)
    try:
        return {"cards": dashboard.set_shared(conn, body.cards)}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/dashboard/default")
def get_default(conn=Depends(get_conn)) -> dict:
    """The dashboard an administrator set for everybody (null while there is none)."""
    return dashboard.get_default(conn) or {"order": None, "custom": [], "sizes": {}}


@router.put("/dashboard/default")
def put_default(body: LayoutBody, request: Request, conn=Depends(get_conn)) -> dict:
    require_admin(request)
    try:
        return dashboard.set_default(conn, body.order, body.custom, body.sizes)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.delete("/dashboard/default")
def delete_default(request: Request, conn=Depends(get_conn)) -> dict:
    require_admin(request)
    dashboard.reset_default(conn)
    return {"order": None, "custom": [], "sizes": {}}
