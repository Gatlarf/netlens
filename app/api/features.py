"""Which optional parts of Netlens are in use, so the menu only shows pages that have something to show.
A page that comes from plugins (backups, storage, smart home, vulnerabilities, DNS) is listed only while a plugin of its kind is installed and switched on, or a plugin that is
switched on has reported data for it (a NAS plugin reports storage). Data left behind by a plugin that was removed does not bring the page back. The demo has no real
plugins, so there the data counts."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.api.devices import get_conn
from app.plugins.service import PluginService

router = APIRouter(prefix="/api", tags=["features"])

# page -> (plugin kind that switches it on, table that holds what plugins reported for it). A NAS plugin (kind "hypervisor") also reports storage, so the page
# is on when a plugin of the kind is on OR a plugin that is on has reported rows for it. Rows left by a plugin that was removed or switched off do not count.
FEATURES = {
    "backups": ("backup", "backup_servers"),
    "storage": ("storage", "storage_systems"),
    "smarthome": ("inventory", "inventory_servers"),
    "vulnerabilities": ("vulnerability", "vuln_servers"),
    "dns": ("dns", None),
    "remote_sites": (None, "probes"),
}


@router.get("/features")
def get_features(request: Request, conn=Depends(get_conn)) -> dict:
    service = PluginService(request.app.state.db_path, request.app.state.settings.data_dir, getattr(request.app.state, "plugin_runner", None))
    from app.plugins.service import get_state

    kinds: set[str] = set()
    on: list[str] = []
    for plugin_id, plugin in service.plugins().items():
        if plugin.manifest and get_state(conn, plugin).get("enabled"):
            kinds.add(plugin.manifest["kind"])
            on.append(plugin_id)
    demo = bool(getattr(request.app.state.settings, "demo", False))
    out = {}
    for name, (kind, table) in FEATURES.items():
        if kind is None:                                      # not from plugins: there are remote sites or not
            out[name] = bool(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])       # noqa: S608 - a fixed table name
        elif kind in kinds:
            out[name] = True
        elif table and (on or demo):
            where, args = ("", ()) if demo else (f" WHERE plugin_id IN ({','.join('?' * len(on))})", tuple(on))
            out[name] = bool(conn.execute(f"SELECT COUNT(*) FROM {table}{where}", args).fetchone()[0])          # noqa: S608 - fixed table names, bound values
        else:
            out[name] = False
    return out
