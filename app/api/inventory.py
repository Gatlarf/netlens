"""What smart-home hubs (Home Assistant ...) report: devices with their area, protocol, battery and availability."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app import inventory
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["inventory"])


@router.get("/inventory")
def get_inventory(conn=Depends(get_conn)) -> dict:
    return inventory.overview(conn)
