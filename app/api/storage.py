"""What a storage plugin (NetApp, Dell, Pure, Ceph ...) reports: systems, pools, volumes with their clients, disks and alerts."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app import storage
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["storage"])


@router.get("/storage")
def get_storage(conn=Depends(get_conn)) -> dict:
    return storage.overview(conn)
