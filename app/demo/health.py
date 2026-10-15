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
        if kind != "switch":                     # a switch reports its ports instead
            out.append(("net_rx_bps", "eth0" if kind != "router" else "WAN", max(1e3, down), "bps"))
            out.append(("net_tx_bps", "eth0" if kind != "router" else "WAN", max(1e3, up), "bps"))
    if kind in ("router", "switch", "hypervisor", "nas", "pi"):
        temp = {"router": 52, "switch": 41, "hypervisor": 58, "nas": 44, "pi": 51}[kind] + day * 5 + _noise(t, salt + 7) * 1.2
        out.append(("temp_c", "CPU" if kind != "nas" else "Disk 1", temp, "\u00b0C"))
    if kind == "switch":
        # a few ports: some in use, one with a flaky cable (errors), the uplink the busiest, two without a link
        ports = [("Gi1/0/1", 0.62, 0.0), ("Gi1/0/2", 0.18, 0.0), ("Gi1/0/3", 0.07, 2.4), ("Gi1/0/4", 0.03, 0.0), ("Gi1/0/5", 0.0, 0.0), ("Gi1/0/6", 0.0, 0.0),
                 ("Gi1/0/10", 0.11, 0.0), ("Gi1/0/11", 0.0, 0.0)]
        for i, (name, load, errors) in enumerate(ports):
            if load == 0.0 and name != "Gi1/0/11":
                out.append(("if_up", name, 0.0, "state"))
                continue
            out.append(("if_up", name, 1.0, "state"))
            frac = min(0.97, max(0.001, load * (0.35 + day) + _noise(t // 120, salt + 20 + i) * 0.02)) if load else 0.002
            out.append(("net_rx_bps", name, frac * 1e9 * 0.8, "bps"))
            out.append(("net_tx_bps", name, frac * 1e9 * 0.4, "bps"))
            out.append(("if_util_pct", name, frac * 80, "%"))
            if errors:
                out.append(("if_err_ps", name, max(0.0, errors * (0.5 + abs(_noise(t // 300, salt + 40)))), "/s"))
    if kind == "hypervisor":
        out.append(("disk_pct", "/", 38.0 + (1 - age_days / 40) * 3, "%"))
        out.append(("disk_free_b", "/", 0.62 * 480 * GB, "B"))
    if kind == "nas":
        pct = 74.0 + (1 - min(age_days, 60) / 60) * 14 + (_noise(t // 86400, salt) * 0.2)        # 14 points in 60 days: now 88 %
        out.append(("disk_pct", "/mnt/tank", pct, "%"))
        out.append(("disk_free_b", "/mnt/tank", (100 - pct) / 100 * 12 * TB, "B"))
        out.append(("storage_status", "tank", 0.0, "state"))
        out.append(("disk_pct", "/mnt/backup", 52.0 + (1 - min(age_days, 60) / 60) * 4, "%"))
        out.append(("disk_free_b", "/mnt/backup", 0.44 * 8 * TB, "B"))
    if kind == "backup":
        pct = 61.0 + (1 - min(age_days, 30) / 30) * 27             # growing about a point a day: 88 % now
        out.append(("storage_status", "md0", 1.0 if age_days < 2 else 0.0, "state"))        # a disk of the mirror dropped out two days ago
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
            if metric == "storage_status" and value >= 1:
                level, since = ("critical" if value >= 2 else "warning"), (now - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
            if metric in ("disk_pct", "cpu_pct", "mem_pct", "temp_c", "supply_pct", "battery_pct", "storage_status"):
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


# ----------------------------------------------------------------------------- a remote site
SITE_NAME = "Branch office"
SITE_DEVICES = [
    # key, name, ip, vendor, type, always_on, ports, online
    ("c8:3a:35:00:00:01", "gateway-branch", "10.20.0.1", "MikroTik", "router", True, [80, 443, 8291], True),
    ("c8:3a:35:00:00:02", "switch-branch", "10.20.0.2", "TP-Link", "switch", True, [80], True),
    ("00:11:32:00:00:03", "nas-branch", "10.20.0.10", "Synology", "nas", True, [445, 5000, 5001], True),
    ("18:db:f2:00:00:04", "reception-pc", "10.20.0.21", "Dell", "pc", False, [135, 445], True),
    ("18:db:f2:00:00:05", "accounting-pc", "10.20.0.22", "Dell", "pc", False, [135, 445], True),
    ("98:fa:9b:00:00:06", "manager-laptop", "10.20.0.23", "Lenovo", "pc", False, [], False),
    ("00:1b:a9:00:00:07", "printer-branch", "10.20.0.30", "Brother Industries", "printer", False, [80, 631, 9100], True),
    ("ec:71:db:00:00:08", "cam-entrance", "10.20.0.40", "Reolink", "camera", True, [80, 554], True),
    ("b0:95:75:00:00:09", "plug-coffee", "10.20.0.50", "TP-Link Tapo", "iot", False, [80], True),
]
SITE_SERVICES = [("svc:1", "Branch router web", "http", "http://10.20.0.1/", "up", 9.0), ("svc:2", "File server SMB", "tcp", "10.20.0.10:445", "up", 3.2),
                 ("svc:3", "Printer queue", "tcp", "10.20.0.30:9100", "up", 6.5), ("svc:4", "Certificate of the VPN", "cert", "certificate of vpn.branch.example:443", "up", 40.0)]


def seed_remote(conn, now: datetime, days: int = 7) -> None:
    from app.db import add_event

    token = vault.encrypt(conn, "demo")[-24:]
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    summary = {
        "problems": [{"device_key": "00:11:32:00:00:03", "device": "nas-branch", "metric": "disk_pct", "label": "/volume1", "level": "warning", "value": 87.0, "title": "Disk full", "unit": "%",
                      "since": (now - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")}],
        "monitors": [{"device_key": "00:11:32:00:00:03", "device": "nas-branch", "method": "snmp", "ok": True, "error": None, "level": "warning",
                      "latest": {"cpu": 12.0, "mem": 58.0, "disk": 87.0, "temp": 44.0}, "disk_label": "/volume1"}],
        "scan": {"finished": stamp, "running": False, "hosts": 8}, "counts": {"devices": len(SITE_DEVICES), "services": len(SITE_SERVICES), "samples": 0},
    }
    cur = conn.execute("INSERT INTO probes (name, token_hash, created, last_seen, last_ip, version, interval_s, snapshot_ts, summary) VALUES (?,?,?,?,?,?,?,?,?)",
                       (SITE_NAME, "demo-" + token, (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"), stamp, "203.0.113.45", "0.4.0", 60, stamp, json.dumps(summary)))
    probe_id = cur.lastrowid
    dev_ids = {}
    for key, name, ip_, vendor, kind, always_on, ports, online in SITE_DEVICES:
        c = conn.execute("INSERT INTO remote_devices (probe_id, key, mac, ip, name, vendor, type, online, always_on, ports, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                         (probe_id, key, key, ip_, name, vendor, kind, int(online), int(always_on), json.dumps(ports), (now - timedelta(days=25)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                          stamp if online else (now - timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%SZ")))
        dev_ids[key] = c.lastrowid
    svc_ids = {}
    for key, name, kind, target, state, ms in SITE_SERVICES:
        c = conn.execute("INSERT INTO remote_services (probe_id, key, name, kind, target, state, ms, detail, since, checked) VALUES (?,?,?,?,?,?,?,?,?,?)",
                         (probe_id, key, name, kind, target, state, ms, "valid for 40 more days" if kind == "cert" else "answered", (now - timedelta(days=9)).strftime("%Y-%m-%dT%H:%M:%SZ"), stamp))
        svc_ids[key] = c.lastrowid
    for when, kind, text in ((now - timedelta(hours=5), "remote_offline", f"{SITE_NAME}: manager-laptop (10.20.0.23) went offline"),
                             (now - timedelta(days=2), "remote_metric_warning", f"{SITE_NAME}: nas-branch: disk full on /volume1 is 87% (limit 85%)"),
                             (now - timedelta(days=4, hours=3), "remote_service_down", f"{SITE_NAME}: Printer queue (10.20.0.30:9100) is down: timed out"),
                             (now - timedelta(days=4, hours=2), "remote_service_up", f"{SITE_NAME}: Printer queue (10.20.0.30:9100) is up")):
        conn.execute("INSERT INTO events (ts, device_id, kind, detail) VALUES (?, NULL, ?, ?)", (when.strftime("%Y-%m-%dT%H:%M:%SZ"), kind, text))
    store = tsdb.for_conn(conn)
    if store is not None:
        rows = []
        end = now.timestamp()
        t = end - days * 86400
        while t <= end:
            day = _day(t)
            for key, ident in dev_ids.items():
                spec = next(d for d in SITE_DEVICES if d[0] == key)
                online = spec[7] or t < end - 5 * 3600
                rows.append((int(t), "remote", ident, "up", 1.0 if online else 0.0, "", "state"))
                if online:
                    rows.append((int(t), "remote", ident, "rtt_ms", 1.5 + _noise(t, ident) * 0.6 + (day * 2 if spec[4] == "iot" else 0), "", "ms"))
            nas = dev_ids["00:11:32:00:00:03"]
            rows.append((int(t), "remote", nas, "cpu_pct", 9 + day * 8 + _noise(t, 3) * 2, "", "%"))
            rows.append((int(t), "remote", nas, "mem_pct", 55 + day * 4, "", "%"))
            rows.append((int(t), "remote", nas, "disk_pct", 80 + (t - (end - days * 86400)) / (days * 86400) * 7, "/volume1", "%"))
            for key, ident in svc_ids.items():
                rows.append((int(t), "remote_service", ident, "up", 1.0, "", "state"))
                rows.append((int(t), "remote_service", ident, "response_ms", 5 + _noise(t, ident) * 2 + day * 3, "", "ms"))
            t += 600
        store.record_bulk(rows)
        store.rollup(int(end) + 1)
    conn.commit()


def tick_remote(conn, now: datetime) -> None:
    """The remote site keeps reporting in the demo."""
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute("UPDATE probes SET last_seen = ?, snapshot_ts = ? WHERE name = ?", (stamp, stamp, SITE_NAME))
    conn.execute("UPDATE remote_devices SET last_seen = ? WHERE online = 1 AND probe_id IN (SELECT id FROM probes WHERE name = ?)", (stamp, SITE_NAME))
    conn.execute("UPDATE remote_services SET checked = ? WHERE probe_id IN (SELECT id FROM probes WHERE name = ?)", (stamp, SITE_NAME))
    conn.commit()
