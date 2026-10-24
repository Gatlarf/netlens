"""Which optional parts of Netlens are in use, so the menu only shows pages that have something to show."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.api.devices import get_conn
from app.plugins.service import PluginService

router = APIRouter(prefix="/api", tags=["features"])

# page -> (plugin kind that switches it on, a statement that is true when data exists already)
FEATURES = {
    "backups": ("backup", "SELECT COUNT(*) FROM backup_servers"),
    "storage": ("storage", "SELECT COUNT(*) FROM storage_systems"),
    "smarthome": ("inventory", "SELECT COUNT(*) FROM inventory_servers"),
    "vulnerabilities": ("vulnerability", "SELECT COUNT(*) FROM vuln_servers"),
    "dns": ("dns", "SELECT 0"),
    "remote_sites": (None, "SELECT COUNT(*) FROM probes"),
}


@router.get("/features")
def get_features(request: Request, conn=Depends(get_conn)) -> dict:
    service = PluginService(request.app.state.db_path, request.app.state.settings.data_dir, getattr(request.app.state, "plugin_runner", None))
    from app.plugins.service import get_state

    kinds: set[str] = set()
    for plugin in service.plugins().values():
        if plugin.manifest and get_state(conn, plugin).get("enabled"):
            kinds.add(plugin.manifest["kind"])
    out = {}
    for name, (kind, sql) in FEATURES.items():
        out[name] = (kind in kinds) or bool(conn.execute(sql).fetchone()[0])
    return out
