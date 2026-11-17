"""Demo data for the newer cards: the Wi-Fi channels of the mesh nodes, the internet connections of the router (multi-WAN), the history of the network health
score, the alert rules and the customer report templates. Nothing here is real, and nothing is sent anywhere (the report templates have no schedule)."""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta

from app.demo import network as net


def _node(key: str, **extra) -> dict:
    spec = net.BY_KEY[key]
    return {"name": spec.custom or spec.name, "macs": [net.mac(spec)], "ip": f"{net.SUBNET}.{spec.octet}", **extra}


def _neighbour(n: int, ssid: str, band: str, channel: int, signal: int, width: int = 20, security: str = "WPA2") -> dict:
    return {"bssid": f"a2:5c:7e:00:{n:02x}:{channel:02x}", "ssid": ssid, "band": band, "channel": channel, "signal_dbm": signal, "width_mhz": width, "security": security}


def topology_data() -> dict:
    """What the ASUS mesh reports about the air around it, and what the router reports about its internet connections."""
    crowd24 = [_neighbour(1, "Telenet-4F2A", "2.4 GHz", 6, -52), _neighbour(2, "Telenet-91BC", "2.4 GHz", 6, -61), _neighbour(3, "Ziggo-7731", "2.4 GHz", 6, -66),
               _neighbour(4, "Proximus-Home", "2.4 GHz", 7, -70), _neighbour(5, "TP-Link_E2A0", "2.4 GHz", 6, -74), _neighbour(6, "VOO-A1B3", "2.4 GHz", 11, -80, security="WPA3")]
    crowd5 = [_neighbour(10, "Telenet-4F2A-5G", "5 GHz", 36, -64, 80), _neighbour(11, "Ziggo-7731-5G", "5 GHz", 36, -71, 80), _neighbour(12, "Proximus-Home-5G", "5 GHz", 44, -77, 40)]
    radios = lambda ch24, ch5, c24, c5, u24, u5, ssid: [  # noqa: E731
        {"name": "wl0", "band": "2.4 GHz", "channel": ch24, "width_mhz": 20, "clients": c24, "utilization_pct": u24, "noise_dbm": -90, "ssid": ssid},
        {"name": "wl1", "band": "5 GHz", "channel": ch5, "width_mhz": 80, "clients": c5, "utilization_pct": u5, "noise_dbm": -94, "ssid": ssid}]
    return {"nodes": [
        _node("n_base", wifi={"radios": radios(6, 36, 7, 12, 61, 28, "Home"), "neighbours": crowd24 + crowd5, "scanned": True}),
        _node("n_attic", wifi={"radios": radios(6, 100, 5, 6, 48, 14, "Home"), "neighbours": crowd24[:4] + crowd5[:1], "scanned": True}),
        _node("n_guest", wifi={"radios": radios(1, 149, 3, 5, 22, 9, "Home"), "neighbours": crowd24[3:] + crowd5[2:], "scanned": True}),
        _node("n_garage", wifi={"radios": radios(11, 44, 4, 3, 34, 11, "Home"), "neighbours": crowd24[4:] + crowd5[1:2], "scanned": True}),
        _node("gw", uplinks={"mode": "failover", "connections": [
            {"name": "Fibre", "interface": "eth0", "up": True, "active": True, "ip": "84.195.22.118", "gateway": "84.195.16.1", "weight": None, "priority": 1, "latency_ms": 9.4, "loss_pct": 0.0},
            {"name": "Backup 4G", "interface": "usb0", "up": True, "active": False, "ip": "100.72.18.4", "gateway": "100.72.18.1", "weight": None, "priority": 2, "latency_ms": 48.0, "loss_pct": 0.5}]}),
    ]}


def apply(conn, now: datetime) -> None:
    from app import airspace, uplinks
    from app.plugins.contract import validate_output

    data = validate_output("topology", topology_data())
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    airspace.record(conn, "asus", data, stamp)
    uplinks.record(conn, "asus", data, stamp)


def seed(conn, ids: dict, now: datetime) -> None:
    from app import alertrules, reporttemplates

    apply(conn, now)
    # the score of the last month: mostly good, a bad patch when the garage mesh node was flaky, slowly getting better
    rng = random.Random(1117)
    for back in range(30, 0, -1):
        day = (now - timedelta(days=back)).strftime("%Y-%m-%d")
        score = max(40, min(99, round(88 + 4 * (30 - back) / 30 - (22 if 14 <= back <= 17 else 0) + rng.randint(-3, 3))))
        cameras = max(40, min(100, score + rng.randint(-6, 4)))
        conn.execute("INSERT INTO score_history (day, score, cameras, updated) VALUES (?, ?, ?, ?) ON CONFLICT(day) DO UPDATE SET score = excluded.score, cameras = excluded.cameras, updated = excluded.updated", (day, score, cameras, day + "T23:00:00Z"))
    conn.commit()
    group = {r["name"]: r["id"] for r in conn.execute("SELECT id, name FROM device_groups")}
    switch = ids.get("sw_garden")
    for rule in (
        {"name": "Quiet nights for the cameras", "type": "mute", "kinds": ["device_offline", "device_online"], "scope": {"type": "group", "ids": [group["Cameras"]]} if "Cameras" in group else {"type": "type", "value": "camera"},
         "when": {"days": [0, 1, 2, 3, 4, 5, 6], "from": "23:00", "to": "06:00"}, "recoveries": True, "note": "Wi-Fi cameras drop out at night when the neighbours' networks are busy."},
        {"name": "Stop flapping alerts", "type": "repeat", "kinds": ["device_offline"], "scope": {"type": "all"}, "count": 3, "minutes": 10, "per": "device", "note": "After three offline messages in ten minutes, one message says the rest are held back."},
        *([{"name": "Behind the garden switch", "type": "while_down", "kinds": ["device_offline", "service_down"], "scope": {"type": "below", "device_id": switch}, "device_id": switch, "note": "No alerts for the garden devices while the switch itself is down."}] if switch else []),
    ):
        alertrules.upsert(conn, rule)
    # the rules did not exist while the history was made: mark the night-time messages of the cameras as the first rule would have held them back
    tag = "Rule: Quiet nights for the cameras"
    for row in conn.execute("SELECT e.id, e.ts FROM events e JOIN devices d ON d.id = e.device_id WHERE e.kind IN ('device_offline', 'device_online') AND d.device_type = 'camera' AND e.maintenance IS NULL").fetchall():
        hour = int(row["ts"][11:13])
        if hour >= 23 or hour < 6:
            conn.execute("UPDATE events SET maintenance = ? WHERE id = ?", (tag, row["id"]))
    for tpl in (
        {"name": "Monthly report for the family", "title": "The home network, last month", "subtitle": "Prepared by Netlens", "prepared_for": "The family", "accent": "#0f766e", "period": "month",
         "sections": ["summary", "availability", "incidents", "changes", "capacity", "network", "devices"], "schedule": {"frequency": "off"}, "footer": "Made with Netlens"},
        {"name": "Weekly cameras and Wi-Fi", "title": "Cameras and Wi-Fi", "accent": "#2563eb", "period": "7d", "sections": ["summary", "availability", "network", "health"],
         "scope": {"type": "group", "ids": [group["Cameras"]]} if "Cameras" in group else {"type": "all"}, "schedule": {"frequency": "off"}},
    ):
        reporttemplates.upsert(conn, tpl)
    conn.commit()
