from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.devices import get_conn
from app.db import utcnow
from app.stats import _ago

router = APIRouter(prefix="/api", tags=["wifi"])

QUALITY = ((-55, "excellent"), (-65, "good"), (-75, "fair"), (-127, "weak"))


def signal_quality(rssi: int | None) -> str | None:
    if rssi is None:
        return None
    return next(label for limit, label in QUALITY if rssi >= limit)


@router.get("/devices/{device_id}/wifi")
def device_wifi(device_id: int, hours: int = Query(24, ge=1, le=336), conn=Depends(get_conn)) -> dict:
    """Signal history of a Wi-Fi client (from the router plugin), its current node and its last moves between nodes."""
    if conn.execute("SELECT 1 FROM devices WHERE id = ?", (device_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="device not found")
    rows = conn.execute(
        "SELECT ts, node, band, rssi, tx_mbps, rx_mbps FROM wifi_samples WHERE device_id = ? AND ts >= ? ORDER BY id",
        (device_id, _ago(utcnow(), hours=hours)),
    ).fetchall()
    samples = [dict(r) for r in rows]
    last = conn.execute("SELECT ts, node, band, rssi, tx_mbps, rx_mbps FROM wifi_samples WHERE device_id = ? ORDER BY id DESC LIMIT 1", (device_id,)).fetchone()
    roams = [dict(r) for r in conn.execute("SELECT ts, detail FROM events WHERE device_id = ? AND kind = 'wifi_roamed' ORDER BY id DESC LIMIT 10", (device_id,))]
    current = None
    if last is not None:
        current = {**dict(last), "quality": signal_quality(last["rssi"])}
    return {"current": current, "samples": samples, "roams": roams}
