from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.devices import get_conn
from app.db import utcnow
from app.stats import _ago

router = APIRouter(prefix="/api", tags=["switch ports"])

COUNTERS = ("tx_packets", "rx_packets", "tx_errors", "rx_errors")


def _seconds(a: str, b: str) -> float:
    from datetime import datetime

    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return (datetime.strptime(b, fmt) - datetime.strptime(a, fmt)).total_seconds()


def _increase(samples: list, key: str) -> int | None:
    """Growth of a counter over the samples; a counter that went back (the switch restarted) starts again from its new value."""
    total, last = 0, None
    for s in samples:
        value = s[key]
        if value is None:
            continue
        if last is not None:
            total += value - last if value >= last else value
        last = value
    return total if last is not None else None


@router.get("/devices/{device_id}/switch-ports")
def device_switch_ports(device_id: int, hours: int = Query(24, ge=1, le=336), conn=Depends(get_conn)) -> dict:
    """The ports of a switch (from a switch plugin): link state, speed, packets per second now and errors in the last hours."""
    if conn.execute("SELECT 1 FROM devices WHERE id = ?", (device_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="device not found")
    ports = [dict(r) for r in conn.execute("SELECT * FROM switch_ports WHERE device_id = ? ORDER BY port", (device_id,))]
    if not ports:
        return {"ports": [], "hours": hours}
    since = _ago(utcnow(), hours=hours)
    samples: dict[int, list] = {}
    for r in conn.execute("SELECT port, ts, up, tx_packets, rx_packets, tx_errors, rx_errors FROM switch_port_samples WHERE device_id = ? AND ts >= ? ORDER BY port, id", (device_id, since)):
        samples.setdefault(r["port"], []).append(r)
    for port in ports:
        rows = samples.get(port["port"], [])
        rate = {"tx_pps": None, "rx_pps": None}
        if len(rows) >= 2:
            span = _seconds(rows[-2]["ts"], rows[-1]["ts"])
            for src, dst in (("tx_packets", "tx_pps"), ("rx_packets", "rx_pps")):
                a, b = rows[-2][src], rows[-1][src]
                if span > 0 and a is not None and b is not None and b >= a:
                    rate[dst] = round((b - a) / span, 1)
        port.update(rate)
        port["tx_errors_window"] = _increase(rows, "tx_errors")
        port["rx_errors_window"] = _increase(rows, "rx_errors")
        port["tx_packets_window"] = _increase(rows, "tx_packets")
        port["rx_packets_window"] = _increase(rows, "rx_packets")
        port["flaps"] = sum(1 for a, b in zip(rows, rows[1:]) if a["up"] != b["up"])
    return {"ports": ports, "hours": hours}
