"""What a backup plugin (Proxmox Backup Server ...) reports, tied to the guests: servers, stores, what is backed up, problems, guests without a backup."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app import guestbackups
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["backups"])


@router.get("/guest-backups")
def get_guest_backups(conn=Depends(get_conn)) -> dict:
    return guestbackups.overview(conn)
