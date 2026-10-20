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
            from app import vault

            unreadable = vault.status(conn)["unreadable"]
            if unreadable:       # a restore on another machine without the key: the passwords have to be entered again, or the key put back
                doc["attention"].insert(0, {"level": "bad", "text": f"{unreadable} stored password setting(s) cannot be read: the encryption key is missing or different",
                                            "href": "#/settings/backup"})
            from app.hostmetrics import service as host_monitors

            for p in host_monitors.problems(conn)[:8]:      # a disk filling up, a hot server, a UPS on battery
                where = f" on {p['label']}" if p["label"] else ""
                value = f"{p['value']:.0f}{p['unit']}" if p["unit"] else f"{p['value']:g}"
                text = f"{p['device']}: {p['title'].lower()}{where} is {value}"
                if p["metric"] == "storage_status":
                    text = f"{p['device']}: {p['label'] or 'storage'} is {'degraded or needs attention' if p['level'] == 'warning' else 'failed'}"
                if p["metric"] == "service_stopped":
                    text = f"{p['device']}: the service {p['label']} has stopped with an error"
                doc["attention"].append({"level": "bad" if p["level"] == "critical" else "warn",
                                         "text": text, "href": f"#/device/{p['device_id']}", "snooze": p["snooze"]})
            from app import probes as probes_mod

            for row in conn.execute("SELECT * FROM probes WHERE enabled = 1 ORDER BY LOWER(name)"):
                site = probes_mod.present(conn, row)
                href = f"#/remote-sites?id={site['id']}"
                if site["locked"]:
                    doc["attention"].append({"level": "warn", "text": f"{site['name']} is frozen: the licence takes in fewer remote sites", "href": "#/settings/licence", "snooze": None})
                    continue
                if site["state"] == "silent":
                    doc["attention"].append({"level": "bad", "text": f"{site['name']} has stopped reporting", "href": href, "snooze": f"site:{site['id']}"})
                    continue
                bk = site.get("backups") or {}
                if bk.get("failed") or bk.get("late"):
                    doc["attention"].append({"level": "bad" if bk.get("failed") else "warn", "text": f"{site['name']}: {bk.get('failed', 0)} backup(s) failed, {bk.get('late', 0)} late", "href": "#/backups", "snooze": None})
                down = site["devices"]["core_down"]
                if down:
                    doc["attention"].append({"level": "bad", "text": f"{site['name']}: {down} always-on device{'s' if down != 1 else ''} offline", "href": href})
                if site["services"]["down"]:
                    doc["attention"].append({"level": "bad", "text": f"{site['name']}: {site['services']['down']} service check{'s' if site['services']['down'] != 1 else ''} down", "href": href})
                if site["problems"]["count"]:
                    doc["attention"].append({"level": "bad" if site["problems"]["critical"] else "warn",
                                             "text": f"{site['name']}: {site['problems']['count']} health problem{'s' if site['problems']['count'] != 1 else ''}", "href": href})
            doc["attention"].sort(key=lambda i: {"bad": 0, "warn": 1}.get(i["level"], 2))
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


@router.get("/dashboard/layout")
def get_layout(request: Request, conn=Depends(get_conn)) -> dict:
    """The cards this user chose, in order (null while the user still has the default)."""
    return dashboard.get_layout(conn, request.state.user) or {"order": None, "custom": []}


@router.put("/dashboard/layout")
def put_layout(body: LayoutBody, request: Request, conn=Depends(get_conn)) -> dict:
    try:
        return dashboard.set_layout(conn, request.state.user, body.order, body.custom)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.delete("/dashboard/layout")
def delete_layout(request: Request, conn=Depends(get_conn)) -> dict:
    dashboard.reset_layout(conn, request.state.user)
    return {"order": None, "custom": []}


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
    return dashboard.get_default(conn) or {"order": None, "custom": []}


@router.put("/dashboard/default")
def put_default(body: LayoutBody, request: Request, conn=Depends(get_conn)) -> dict:
    require_admin(request)
    try:
        return dashboard.set_default(conn, body.order, body.custom)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.delete("/dashboard/default")
def delete_default(request: Request, conn=Depends(get_conn)) -> dict:
    require_admin(request)
    dashboard.reset_default(conn)
    return {"order": None, "custom": []}
