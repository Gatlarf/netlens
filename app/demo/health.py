"""Health readings for the demo: a few devices that are "monitored" with believable processor, memory, disk, traffic and
temperature curves, one disk that is filling up and a printer that is nearly out of toner, so the Health page has a story."""

from __future__ import annotations

import json
import math
from datetime import datetime, timedelta, timezone

from app import tsdb, vault
from app.db import utcnow
from app.demo.network import BY_KEY, ip

GB = 1024 ** 3
TB = 1024 ** 4

# key -> (method, groups, character)
MONITORS = {
    "gw": ("snmp", ["uptime", "cpu", "memory", "network", "temperature"], "router"),
    "sw_rack": ("snmp", ["uptime", "cpu", "memory", "network", "temperature"], "switch"),
    "sw_office": ("snmp", ["uptime", "cpu", "memory", "network"], "switch"),
    "pve": ("ssh", ["uptime", "cpu", "memory", "disk", "network", "temperature"], "hypervisor"),
    "nas": ("snmp", ["uptime", "cpu", "memory", "disk", "network", "temperature"], "nas"),
    "pbs": ("ssh", ["uptime", "cpu", "memory", "disk", "network"], "backup"),
    "rpi_docker": ("ssh", ["uptime", "cpu", "memory", "disk", "network", "temperature"], "pi"),
    "hv": ("snmp", ["uptime", "cpu", "memory", "disk", "network"], "windows"),
    "printer": ("snmp", ["uptime", "supplies"], "printer"),
}


def _noise(t: float, salt: int) -> float:
    """A repeatable wobble between -1 and 1."""
    return (((int(t) // 30) * 2654435761 + salt * 40503) % 2000) / 1000.0 - 1.0


def _day(t: float) -> float:
    """0..1: quiet at night, busy in the afternoon."""
    hour = (t % 86400) / 3600.0
    return 0.5 + 0.5 * math.sin((hour - 9) / 24 * 2 * math.pi)


def readings(key: str, t: float, now: float) -> list[tuple]:
    """(metric, label, value, unit) of one demo device at time t."""
    kind = MONITORS[key][2]
    salt = BY_KEY[key].octet
    day = _day(t)
    age_days = (now - t) / 86400.0
    out: list[tuple] = []
    base_cpu = {"router": 9, "switch": 4, "hypervisor": 22, "nas": 11, "backup": 6, "pi": 14, "windows": 18, "printer": 0}[kind]
    if kind != "printer":
        cpu = base_cpu + day * base_cpu * 0.9 + _noise(t, salt) * base_cpu * 0.25
        if kind == "backup" and 1.0 <= (t % 86400) / 3600.0 <= 3.0:       # the nightly backup
            cpu += 55
        out.append(("cpu_pct", "", max(1.0, min(100.0, cpu)), "%"))
        mem_base = {"router": 41, "switch": 28, "hypervisor": 71, "nas": 63, "backup": 38, "pi": 47, "windows": 66}[kind]
        out.append(("mem_pct", "", min(97.0, mem_base + _noise(t // 600, salt + 3) * 2.5 + day * 3), "%"))
        out.append(("uptime_s", "", 0.0, "s"))              # set by _uptime_fix
        rate = {"router": 40e6, "switch": 25e6, "hypervisor": 18e6, "nas": 30e6, "backup": 3e6, "pi": 1.2e6, "windows": 6e6}[kind]
        down = rate * (0.15 + day) * (1 + _noise(t, salt + 5) * 0.3)
        up = down * {"router": 0.25, "nas": 0.5, "backup": 6.0}.get(kind, 0.35)
        if kind == "backup" and 1.0 <= (t % 86400) / 3600.0 <= 3.0:
            down *= 40
        out.append(("net_rx_bps", "eth0" if kind != "router" else "WAN", max(1e3, down), "bps"))
        out.append(("net_tx_bps", "eth0" if kind != "router" else "WAN", max(1e3, up), "bps"))
    if kind in ("router", "switch", "hypervisor", "nas", "pi"):
        temp = {"router": 52, "switch": 41, "hypervisor": 58, "nas": 44, "pi": 51}[kind] + day * 5 + _noise(t, salt + 7) * 1.2
        out.append(("temp_c", "CPU" if kind != "nas" else "Disk 1", temp, "\u00b0C"))
    if kind == "hypervisor":
        out.append(("disk_pct", "/", 38.0 + (1 - age_days / 40) * 3, "%"))
        out.append(("disk_free_b", "/", 0.62 * 480 * GB, "B"))
    if kind == "nas":
        pct = 74.0 + (1 - min(age_days, 60) / 60) * 14 + (_noise(t // 86400, salt) * 0.2)        # 14 points in 60 days: now 88 %
        out.append(("disk_pct", "/mnt/tank", pct, "%"))
        out.append(("disk_free_b", "/mnt/tank", (100 - pct) / 100 * 12 * TB, "B"))
        out.append(("disk_pct", "/mnt/backup", 52.0 + (1 - min(age_days, 60) / 60) * 4, "%"))
        out.append(("disk_free_b", "/mnt/backup", 0.44 * 8 * TB, "B"))
    if kind == "backup":
        pct = 61.0 + (1 - min(age_days, 30) / 30) * 27             # growing about a point a day: 88 % now
        out.append(("disk_pct", "/mnt/datastore", pct, "%"))
        out.append(("disk_free_b", "/mnt/datastore", (100 - pct) / 100 * 4 * TB, "B"))
    if kind == "pi":
        out.append(("disk_pct", "/", 27.0 + _noise(t // 86400, salt) * 0.3, "%"))
        out.append(("disk_free_b", "/", 0.73 * 58 * GB, "B"))
    if kind == "windows":
        out.append(("disk_pct", "C:\\", 58.0 + (1 - min(age_days, 30) / 30) * 2, "%"))
        out.append(("disk_free_b", "C:\\", 0.42 * 475 * GB, "B"))
    if kind == "printer":
        out.append(("uptime_s", "", 0.0, "s"))
        out.append(("supply_pct", "Black toner", max(7.0, 44.0 - (60 - min(age_days, 60)) * 0.62), "%"))
        out.append(("supply_pct", "Cyan toner", 71.0, "%"))
        out.append(("supply_pct", "Drum unit", 63.0, "%"))
    return out


def _uptime_fix(points: list[tuple], t: float, key: str, now: float) -> list[tuple]:
    """Uptime counts up from the last restart, 37 days before now (the printer 9 days)."""
    out = []
    for metric, label, value, unit in points:
        if metric == "uptime_s":
            start = now - (9 if MONITORS[key][2] == "printer" else 37) * 86400
            value = max(0.0, t - start)
        out.append((metric, label, value, unit))
    return out


def seed(conn, ids: dict[str, int], now: datetime, days: int = 14) -> None:
    """Monitors for the demo devices, two weeks of readings and the levels they are at now."""
    store = tsdb.for_conn(conn)
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    end = now.timestamp()
    for key, (method, groups, _kind) in MONITORS.items():
        device_id = ids.get(key)
        if device_id is None:
            continue
        secret = {"community": "public", "version": "2c"} if method == "snmp" else {"username": "monitor", "password": "demo-password"}
        conn.execute(
            "INSERT OR REPLACE INTO host_monitors (device_id, method, address, port, credential, interval_s, groups, alerts, enabled, last_ts, last_ok, since, created) "
            "VALUES (?,?,?,?,?,?,?,?,1,?,1,?,?)",
            (device_id, method, ip(BY_KEY[key]), 161 if method == "snmp" else 22, vault.encrypt(conn, json.dumps(secret)), 60, json.dumps(groups), 1, stamp,
             (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ"), stamp))
        monitor_id = conn.execute("SELECT id FROM host_monitors WHERE device_id = ?", (device_id,)).fetchone()[0]
        for metric, label, value, _unit in _uptime_fix(readings(key, end, end), end, key, end):
            level = "ok"
            since = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
            if metric == "disk_pct" and value >= 85:
                level, since = "warning", (now - timedelta(days=3, hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ")
            if metric == "supply_pct" and label == "Black toner" and value <= 15:
                level, since = "warning", (now - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
            if metric in ("disk_pct", "cpu_pct", "mem_pct", "temp_c", "supply_pct", "battery_pct"):
                conn.execute("INSERT OR REPLACE INTO metric_state (monitor_id, metric, label, level, since, value) VALUES (?,?,?,?,?,?)", (monitor_id, metric, label, level, since, value))
    if store is not None:
        rows = []
        step = 300
        t = end - days * 86400
        while t <= end:
            for key in MONITORS:
                device_id = ids.get(key)
                if device_id is None:
                    continue
                for metric, label, value, unit in _uptime_fix(readings(key, t, end), t, key, end):
                    rows.append((int(t), "device", device_id, metric, value, label, unit))
            t += step
        store.record_bulk(rows)
        store.rollup(int(end) + 1)
        store.prune(int(end))
    conn.commit()


def tick(conn, ids: dict[str, int], now: datetime) -> None:
    """One more reading for every demo monitor (the demo loop calls this every round)."""
    store = tsdb.for_conn(conn)
    if store is None:
        return
    t = now.timestamp()
    rows = []
    for key in MONITORS:
        device_id = ids.get(key)
        if device_id is None:
            continue
        for metric, label, value, unit in _uptime_fix(readings(key, t, t), t, key, t):
            rows.append((int(t), "device", device_id, metric, value, label, unit))
    store.record_bulk(rows)
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute("UPDATE host_monitors SET last_ts = ?, last_ok = 1", (stamp,))
    conn.commit()
