from pydantic import BaseModel

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.api.devices import get_conn
from app import portmap
from app.db import utcnow
from app.hierarchy import ancestors, device_name, load_hierarchy, would_loop
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


@router.get("/devices/{device_id}/port-map")
def device_port_map(device_id: int, conn=Depends(get_conn)) -> dict:
    """Which device sits behind which port of this switch (links from a plugin and links set by hand), and where the switch itself is connected."""
    if conn.execute("SELECT 1 FROM devices WHERE id = ?", (device_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="device not found")
    return portmap.for_switch(conn, device_id)


class ConnectionBody(BaseModel):
    node_device_id: int            # the switch (or access point) this device hangs on
    port: str | None = None        # its port, a number or the name the switch gives it; may be empty when only the switch is known
    replace: bool = False          # the switch now sits below this device: turn that around (one answer to the question a 409 asks)
    keep_parent: bool = False      # ... or only record the port and leave the tree as it is (the other answer)


@router.put("/devices/{device_id}/connection")
def set_connection(device_id: int, body: ConnectionBody, request: Request, conn=Depends(get_conn)) -> dict:
    """Say by hand which switch (and port) a device is connected to. A plugin never overwrites this; the device sits below the switch."""
    devs, hierarchy = load_hierarchy(conn)
    if device_id not in devs:
        raise HTTPException(status_code=404, detail="device not found")
    if body.node_device_id == device_id:
        raise HTTPException(status_code=422, detail="a device cannot be connected to itself")
    if body.node_device_id not in devs:
        raise HTTPException(status_code=422, detail="switch not found")
    if would_loop(hierarchy, device_id, body.node_device_id) and not body.keep_parent:
        # the switch sits below this device now (a parent you set, or one that was found): connecting the device to the switch turns that around
        chain = [body.node_device_id]
        for up in ancestors(hierarchy, body.node_device_id):
            chain.append(up)
            if up == device_id:
                break
        fix = [(c, p) for c, p in zip(chain, chain[1:]) if devs[c]["parent_mode"] == "device" and devs[c]["parent_device_id"] == p]
        if not body.replace:
            sw, dev = device_name(devs[body.node_device_id]), device_name(devs[device_id])
            text = (f"{sw} sits below {dev} in the network tree now ({hierarchy[body.node_device_id].reason.lower()}). "
                    f"You can only record that {dev} is plugged into this port and leave the tree as it is, or turn it around: {dev} will sit below {sw}")
            if fix:
                text += " and the parent you set for " + ", ".join(device_name(devs[c]) for c, _ in fix) + " is removed (it becomes automatic)"
            raise HTTPException(status_code=409, detail=text + ".")
        for c, p in fix:
            portmap.clear_manual(conn, c)
            conn.execute("UPDATE devices SET parent_mode = 'auto', parent_device_id = NULL WHERE id = ? AND parent_mode = 'device' AND parent_device_id = ?", (c, p))
        conn.commit()
    portmap.set_manual(conn, device_id, body.node_device_id, body.port, utcnow(), set_parent=not body.keep_parent)
    request.app.state.__dict__.get("stats_cache", {}).clear()
    return {"device_id": device_id, "node_device_id": body.node_device_id, "port": (body.port or "").strip()[:60] or None}


@router.delete("/devices/{device_id}/connection")
def clear_connection(device_id: int, request: Request, conn=Depends(get_conn)) -> dict:
    """Forget a connection set by hand (a connection a plugin reports stays)."""
    removed = portmap.clear_manual(conn, device_id)
    request.app.state.__dict__.get("stats_cache", {}).clear()
    return {"removed": removed}


@router.get("/devices/{device_id}/firewall")
def device_firewall(device_id: int, conn=Depends(get_conn)) -> dict:
    """What a firewall plugin reports about this device: version, high availability, VPN tunnels and licences (days left worked out now)."""
    import json
    from datetime import date

    row = conn.execute("SELECT data, updated, plugin_id FROM firewall_state WHERE device_id = ?", (device_id,)).fetchone()
    if row is None:
        return {"firewall": None}
    data = json.loads(row["data"])
    data.pop("warned", None)
    today = date.fromisoformat(utcnow()[:10])
    for lic in data.get("licences") or []:
        lic["days_left"] = (date.fromisoformat(lic["expires"]) - today).days if lic.get("expires") else None
    return {"firewall": data, "updated": row["updated"], "plugin": row["plugin_id"]}
