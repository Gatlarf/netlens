"""Measure how Netlens behaves on a big network.

    python tools/bench.py --devices 2000 [--days 7] [--json out.json]

Builds a made-up network in a temporary folder (devices with ports and names, a hierarchy, groups, event history, an uptime history of one check per device
every 5 minutes, health readings for one device in twenty), then times the pages and API calls a person waits for, and the work a scan does. Everything happens
in this process (no network), so the numbers are what the server spends, not what a browser would add.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

VENDORS = ["Ubiquiti", "TP-Link", "Apple", "Samsung", "Intel", "Raspberry Pi", "Synology", "Dell", "HP", "Espressif", "Sonos", "Google"]
TYPES = ["router", "switch", "server", "phone", "laptop", "printer", "camera", "iot", "nas", "tv"]
STAMP = "%Y-%m-%dT%H:%M:%SZ"


def build(data_dir: Path, devices: int, days: int, seed: int = 7) -> dict:
    from app.db import connect, init_db
    from app.scanner.nmap_parser import ScanHost, ScanPort
    from app.scanner.store import save_scan_results

    rnd = random.Random(seed)
    db_path = data_dir / "netlens.db"
    conn = connect(db_path)
    init_db(conn)
    now = datetime.now(timezone.utc)
    hosts = []
    for i in range(devices):
        n = i + 1
        ip = f"10.{(n // 62500) % 250}.{(n // 250) % 250}.{n % 250 + 1}"
        mac = "02:%02x:%02x:%02x:%02x:%02x" % ((n >> 32) & 255, (n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255)
        ports = [ScanPort("tcp", p, "open", s, None, None, None) for p, s in rnd.sample([(22, "ssh"), (80, "http"), (443, "https"), (445, "microsoft-ds"), (8080, "http-proxy"), (53, "domain"), (631, "ipp"), (1883, "mqtt")], rnd.choice([0, 0, 1, 2, 3, 5]))]
        name = f"host-{n:05d}.lan" if rnd.random() < 0.7 else None
        hosts.append(ScanHost(ip=ip, mac=mac, vendor=rnd.choice(VENDORS), hostnames=[(name, "dns")] if name else [], ports=ports, os_name=rnd.choice(["Linux 5.x", "Windows 10", None, "Apple iOS"]),
                              os_accuracy=90, os_type=rnd.choice(TYPES), ttl=64, via="arp", rtt_ms=rnd.random() * 20))
    t = time.perf_counter()
    save_scan_results(conn, hosts, "deep", now=(now - timedelta(days=days)).strftime(STAMP))
    first_scan = time.perf_counter() - t
    t = time.perf_counter()
    save_scan_results(conn, hosts, "quick", now=now.strftime(STAMP))
    rescan = time.perf_counter() - t

    ids = [r[0] for r in conn.execute("SELECT id FROM devices ORDER BY id")]
    # hierarchy: a switch per 20 devices, the switches hang off two routers
    switches = ids[:max(1, devices // 20)]
    rel = []
    for k, d in enumerate(ids):
        if d in switches:
            rel.append((d, ids[k % 2 if k > 1 else 0], "uplink", "bench"))
        else:
            rel.append((d, switches[k % len(switches)], "uplink", "bench"))
    conn.executemany("INSERT OR IGNORE INTO relations (src_id, dst_id, kind, source) VALUES (?, ?, ?, ?)", [r for r in rel if r[0] != r[1]])
    for name in ("Home", "Office", "Lab", "Guests", "Cameras", "Servers", "Printers", "IoT"):
        conn.execute("INSERT INTO device_groups (name, color) VALUES (?, '#2563eb')", (name,))
    gids = [r[0] for r in conn.execute("SELECT id FROM device_groups")]
    conn.executemany("UPDATE devices SET group_id = ? WHERE id = ?", [(rnd.choice(gids), d) for d in ids if rnd.random() < 0.8])
    # event history: about five per device over the period
    kinds = ["device_offline", "device_online", "port_opened", "ip_changed", "device_new"]
    events = [((now - timedelta(minutes=rnd.randint(1, days * 1440))).strftime(STAMP), d, rnd.choice(kinds), "bench") for d in ids for _ in range(5)]
    conn.executemany("INSERT INTO events (ts, device_id, kind, detail) VALUES (?, ?, ?, ?)", events)
    # uptime history: one check per device every 5 minutes
    t = time.perf_counter()
    start = now - timedelta(days=days)
    steps = days * 288
    for chunk in range(0, steps, 288):
        rows = []
        for s in range(chunk, min(steps, chunk + 288)):
            ts = (start + timedelta(minutes=5 * s)).strftime(STAMP)
            rows.extend((d, ts, 0 if rnd.random() < 0.01 else 1, 1.0 + rnd.random() * 5) for d in ids)
        conn.executemany("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (?, ?, ?, ?)", rows)
        conn.commit()
    history = time.perf_counter() - t
    # health readings (the graphs) for one device in twenty
    from app import tsdb

    store = tsdb.for_conn(conn)
    monitored = ids[::20]
    for d in monitored:
        conn.execute("INSERT INTO host_monitors (device_id, method, address, port, credential, interval_s, groups, alerts, enabled, created) VALUES (?,?,?,?,?,?,?,?,?,?)",
                     (d, "snmp", "10.0.0.1", 161, "", 60, "[]", 1, 1, now.strftime(STAMP)))
    conn.commit()
    t = time.perf_counter()
    points = []
    for s in range(0, steps, 12):                                   # one reading an hour keeps the build quick; the store rolls it up like any other
        ts = int((start + timedelta(minutes=5 * s)).timestamp())
        for d in monitored:
            points += [("device", d, "cpu_pct", rnd.random() * 60, "", "%"), ("device", d, "mem_pct", 40 + rnd.random() * 30, "", "%"), ("device", d, "net_rx_bps", rnd.random() * 1e8, "eth0", "bps")]
        store.record(points, ts=ts)
        points = []
    tsdb_build = time.perf_counter() - t
    conn.close()
    size = sum(f.stat().st_size for f in data_dir.glob("*.db"))
    return {"first_scan_s": first_scan, "rescan_s": rescan, "history_build_s": history, "tsdb_build_s": tsdb_build, "db_mb": size / 1e6, "devices": len(ids), "check_rows": len(ids) * steps}


def time_calls(data_dir: Path, rounds: int) -> list[dict]:
    from fastapi.testclient import TestClient

    from app.config import load_settings
    from app.main import create_app

    from app import checkstats
    from app.db import connect

    warm = connect(data_dir / "netlens.db")
    t = time.perf_counter()
    folded = checkstats.backfill(warm)                  # what the first start after an update does in the background
    warm.close()
    started = time.perf_counter()
    app = create_app(load_settings({"NETLENS_TOKEN": "bench", "NETLENS_DATA_DIR": str(data_dir)}), db_path=data_dir / "netlens.db")
    out = []
    auth = {"Authorization": "Bearer bench"}
    with TestClient(app) as client:
        startup = time.perf_counter() - started
        out.append({"call": "start the application", "cold_ms": startup * 1000, "ms": startup * 1000, "kb": 0})
        if folded:
            out.append({"call": f"(one time: hourly roll-up of {folded:,} checks)", "cold_ms": (started - t) * 1000, "ms": (started - t) * 1000, "kb": 0})
        calls = [("Device list", "/api/devices"), ("Device search", "/api/devices?q=host-0042"), ("Map", "/api/map"), ("Hierarchy", "/api/hierarchy"), ("Dashboard", "/api/dashboard"),
                 ("Uptime page (24 h)", "/api/uptime?range=24h"), ("Uptime page (30 days)", "/api/uptime?range=30d"), ("Statistics (7 days)", "/api/stats?range=7d"), ("Summary", "/api/stats/summary"),
                 ("Events (latest 100)", "/api/events"), ("Prometheus metrics", "/metrics"), ("Availability report", "/api/reports/availability"), ("Weekly report", "/api/reports/weekly"),
                 ("Export devices (JSON)", "/api/export/devices.json"), ("Changes", "/api/changes")]
        for label, path in calls:
            times, size, status = [], 0, 0
            for i in range(rounds):
                t = time.perf_counter()
                r = client.get(path, headers=auth)
                times.append((time.perf_counter() - t) * 1000)
                size, status = len(r.content), r.status_code
            out.append({"call": label, "path": path, "status": status, "cold_ms": times[0], "ms": statistics.median(times[1:]) if len(times) > 1 else times[0], "kb": size / 1024})
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--devices", type=int, default=500)
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--rounds", type=int, default=4)
    ap.add_argument("--json")
    ap.add_argument("--keep", help="reuse this folder instead of a temporary one")
    a = ap.parse_args()
    folder = Path(a.keep) if a.keep else Path(tempfile.mkdtemp(prefix="netlens-bench-"))
    folder.mkdir(parents=True, exist_ok=True)
    if not (folder / "netlens.db").exists():
        built = build(folder, a.devices, a.days)
    else:
        built = {"devices": a.devices}
    print(f"built: {json.dumps({k: round(v, 2) if isinstance(v, float) else v for k, v in built.items()})}")
    calls = time_calls(folder, a.rounds)
    print(f"{'call':32} {'first ms':>9} {'repeat ms':>10} {'size kB':>9}   (first = nothing cached yet; repeat = answered from the 15 s cache where there is one)")
    for c in calls:
        print(f"{c['call']:32} {c.get('cold_ms', c['ms']):9.0f} {c['ms']:10.0f} {c['kb']:9.0f}" + ("" if c.get("status", 200) == 200 else f"   HTTP {c['status']}"))
    if a.json:
        Path(a.json).write_text(json.dumps({"devices": a.devices, "days": a.days, "built": built, "calls": calls}, indent=1))


if __name__ == "__main__":
    main()
