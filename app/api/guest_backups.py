"""What a backup plugin (Proxmox Backup Server ...) reports, tied to the guests: servers, stores, what is backed up, problems, guests without a backup."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app import guestbackups
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["backups"])


@router.get("/guest-backups")
def get_guest_backups(conn=Depends(get_conn)) -> dict:
    doc = guestbackups.overview(conn)
    doc["sites"] = sites(conn)
    return doc


def sites(conn) -> list[dict]:
    """The backups of the remote sites that report some (the roll-up of all locations)."""
    import json

    from app import probes

    frozen = probes.locked_ids(conn)
    out = []
    for row in conn.execute("SELECT id, name, enabled, last_seen, summary FROM probes WHERE enabled = 1 ORDER BY LOWER(name)"):
        if row["id"] in frozen:
            continue
        backups = json.loads(row["summary"] or "{}").get("backups") or {}
        if backups.get("configured"):
            out.append({"id": row["id"], "name": row["name"], "last_seen": row["last_seen"], **backups})
    return out
