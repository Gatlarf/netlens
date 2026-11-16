"""Wi-Fi channels of an access point and the internet connections of a gateway, for the device page."""
from fastapi import APIRouter, Depends, HTTPException

from app import airspace, uplinks
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["airspace"])


def _exists(conn, device_id: int) -> None:
    if conn.execute("SELECT 1 FROM devices WHERE id = ?", (device_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="device not found")


@router.get("/devices/{device_id}/wifi-channels")
def wifi_channels(device_id: int, conn=Depends(get_conn)) -> dict:
    """The radios of this access point (channel, width, clients, airtime in use), the networks it hears and a quieter channel when there is one."""
    _exists(conn, device_id)
    return airspace.for_device(conn, device_id)


@router.get("/devices/{device_id}/uplinks")
def device_uplinks(device_id: int, conn=Depends(get_conn)) -> dict:
    """The internet connections of this gateway: state, which one carries the traffic, and how the load is shared."""
    _exists(conn, device_id)
    return uplinks.for_device(conn, device_id)
