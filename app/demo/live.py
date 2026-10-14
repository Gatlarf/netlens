"""The demo's heartbeat: every few minutes it "scans" the made-up network, so the pages keep moving.

It adds a check result per device and per service check, sometimes takes a device (or a switch with everything behind it) offline for
ten to twenty minutes and brings it back, and starts the data over once an hour or once a day (NETLENS_DEMO_RESET).
Nothing here touches the network.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.db import add_event, connect, get_setting, set_setting
from app.demo import network as net
from app.demo.network import BY_KEY, DEVICES, chain, ip
from app.demo.seed import SERVICE_CHECKS, STAMP, fmt, seed

log = logging.getLogger(__name__)
TICK_SECONDS = 300
KEEP_DAYS = 30
FRAGILE = [s.key for s in DEVICES if s.profile in ("normal", "flaky") and s.type not in ("router",)]
INFRA = ["sw_garden", "n_garage"]


class Sim:
    def __init__(self, seed_value: int | None = None) -> None:
        self.rng = random.Random(seed_value)
        self.down: dict[str, datetime] = {}      # device key -> when it comes back
        self.last_prune = datetime.min.replace(tzinfo=timezone.utc)


def _scheduled_up(spec: net.Spec, now: datetime) -> bool:
    """The part of a device's behaviour that follows the clock (phones in the evening, the backup server at night, a stopped VM)."""
    if spec.profile == "off":
        return False
    if spec.profile == "nightly":
        return not (now.hour == 2 and now.minute >= 30 or now.hour == 3 and now.minute < 30)
    if spec.profile == "evening":
        start = 9.5 if now.weekday() >= 5 else 17.5
        hour = now.hour + now.minute / 60
        return start <= hour < 23.25
    return True


def reset_due(conn, mode: str, now: datetime) -> bool:
    if mode == "off":
        return False
    try:
        seeded = datetime.strptime(get_setting(conn, "demo.seeded") or "", STAMP).replace(tzinfo=timezone.utc)
    except ValueError:
        return True
    return seeded.strftime("%Y%m%d%H" if mode == "hourly" else "%Y%m%d") != now.strftime("%Y%m%d%H" if mode == "hourly" else "%Y%m%d")


def tick(conn, sim: Sim, now: datetime) -> None:
    """One round: decide who is up, record it, and raise the events for every change."""
    rng = sim.rng
    for key, back in list(sim.down.items()):
        if now >= back:
            del sim.down[key]
    if rng.random() < 0.10:
        key = rng.choice(FRAGILE)
        sim.down.setdefault(key, now + timedelta(minutes=rng.choice((10, 15, 20))))
    if rng.random() < 0.025:
        sim.down.setdefault(rng.choice(INFRA), now + timedelta(minutes=rng.choice((15, 20))))
    ids = {r["hostname"]: r["id"] for r in conn.execute("SELECT id, hostname FROM devices")}
    stamp = fmt(now)
    state = {s.key: _scheduled_up(s, now) and not any(k in sim.down for k in chain(s.key)) for s in DEVICES}
    before = {r["id"]: bool(r["online"]) for r in conn.execute("SELECT id, online FROM devices")}
    for s in DEVICES:
        device_id = ids.get(s.name)
        if device_id is None:
            continue
        up = state[s.key]
        base = {"router": 0.6, "switch": 0.8, "camera": 3.0, "server": 0.4, "nas": 0.4, "vm": 0.5}.get(s.type, 4.0 if s.medium == "wifi" else 1.0)
        conn.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (?, ?, ?, ?)", (device_id, stamp, 1 if up else 0, round(base * rng.uniform(0.7, 1.9), 2) if up else None))
        if up:
            conn.execute("UPDATE devices SET online = 1, last_seen = ? WHERE id = ?", (stamp, device_id))
            conn.execute("UPDATE device_ips SET last_seen = ? WHERE device_id = ?", (stamp, device_id))
        else:
            conn.execute("UPDATE devices SET online = 0 WHERE id = ?", (device_id,))
    conn.commit()
    from app import tsdb

    series = tsdb.for_conn(conn)
    if series is not None:
        points = []
        for row in conn.execute("SELECT device_id, up, rtt_ms FROM checks WHERE ts = ?", (stamp,)):
            points.append(("device", row["device_id"], "up", row["up"], "", "state"))
            if row["rtt_ms"] is not None:
                points.append(("device", row["device_id"], "rtt_ms", row["rtt_ms"], "", "ms"))
        series.record(points, ts=int(now.timestamp()))
    for s in DEVICES:
        device_id = ids.get(s.name)
        if device_id is not None and before.get(device_id) != state[s.key]:
            if state[s.key]:
                add_event(conn, "device_online", None, device_id=device_id, now=stamp)
            else:
                add_event(conn, "device_offline", ip(s), device_id=device_id, now=stamp)
    online = sum(state.values())
    conn.execute("INSERT INTO scans (kind, status, started, finished, hosts_found) VALUES ('quick', 'done', ?, ?, ?)", (stamp, fmt(now + timedelta(seconds=rng.randint(14, 24))), online))
    # service checks follow their device
    for name, kind, key, host, port, path, expect, interval, base in SERVICE_CHECKS:
        row = conn.execute("SELECT id, last_up FROM service_checks WHERE name = ?", (name,)).fetchone()
        if row is None:
            continue
        up = state[key]
        ms = round(base * rng.uniform(0.6, 1.8), 1) if up else None
        conn.execute("INSERT INTO service_results (check_id, ts, up, ms, detail) VALUES (?, ?, ?, ?, ?)", (row["id"], stamp, 1 if up else 0, ms, "answered" if up else "timed out"))
        if row["last_up"] != (1 if up else 0):
            conn.execute("UPDATE service_checks SET since = ? WHERE id = ?", (stamp, row["id"]))
            add_event(conn, "service_up" if up else "service_down", f"{name} ({kind} {host}:{port}) is {'up again' if up else 'down: timed out'}", device_id=ids.get(BY_KEY[key].name), now=stamp)
        conn.execute("UPDATE service_checks SET last_ts = ?, last_up = ?, last_ms = ?, last_detail = ? WHERE id = ?", (stamp, 1 if up else 0, ms, "answered" if up else "timed out", row["id"]))
        if series is not None:
            series.record([("service", row["id"], "up", 1 if up else 0, "", "state")] + ([("service", row["id"], "response_ms", ms, "", "ms")] if ms is not None else []), ts=int(now.timestamp()))
    # wifi clients roam now and then
    for s in DEVICES:
        if s.medium == "wifi" and s.link == "asus" and state[s.key] and ids.get(s.name):
            conn.execute("INSERT INTO wifi_samples (device_id, ts, node, band, rssi, tx_mbps, rx_mbps) VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (ids[s.name], stamp, BY_KEY[s.parent].name.replace("mesh-", "").title(), s.band, rng.randint(-78, -45), round(rng.uniform(30, 280), 1), round(rng.uniform(1, 60), 1)))
    # the scheduled internet speed test, every six hours
    last = conn.execute("SELECT ts FROM speedtests WHERE kind = 'internet' ORDER BY id DESC LIMIT 1").fetchone()
    if last is None or (now - datetime.strptime(last["ts"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)) >= timedelta(hours=6):
        conn.execute("INSERT INTO speedtests (ts, kind, target, down_mbps, up_mbps, latency_ms, jitter_ms, ok, detail) VALUES (?, 'internet', 'Cloudflare', ?, ?, ?, ?, 1, ?)",
                     (stamp, round(rng.gauss(485, 25), 1), round(rng.gauss(48, 2.5), 1), round(rng.gauss(10, 1.5), 1), round(abs(rng.gauss(1.8, 0.7)), 2),
                      json.dumps({"server": "Brussels", "server_code": "BRU", "isp": "Example Telecom", "country": "BE"})))
    # what the plugins "reported" a moment ago
    for plugin in ("proxmox", "asus", "docker", "truenas", "hyperv", "npm", "snmp", "technitium"):
        raw = get_setting(conn, f"plugin.{plugin}.status")
        if raw:
            status = json.loads(raw)
            status["ts"] = stamp
            set_setting(conn, f"plugin.{plugin}.status", json.dumps(status))
    conn.execute("UPDATE hypervisor_guests SET updated = ?", (stamp,))
    conn.execute("UPDATE proxy_sites SET updated = ?", (stamp,))
    conn.execute("UPDATE ports SET updated = ?", (stamp,))
    today = stamp[:10]
    events_today = conn.execute("SELECT COUNT(*) FROM events WHERE ts >= ?", (today,)).fetchone()[0]
    scans_today = conn.execute("SELECT COUNT(*) FROM scans WHERE started >= ?", (today,)).fetchone()[0]
    ports = conn.execute("SELECT COUNT(*) FROM ports").fetchone()[0]
    conn.execute("INSERT INTO stats_daily (day, devices, online, new_devices, open_ports, events, scans) VALUES (?, ?, ?, 0, ?, ?, ?) "
                 "ON CONFLICT(day) DO UPDATE SET devices = excluded.devices, online = excluded.online, open_ports = excluded.open_ports, events = excluded.events, scans = excluded.scans",
                 (today, len(DEVICES), online, ports, events_today, scans_today))
    if now - sim.last_prune > timedelta(hours=6):
        sim.last_prune = now
        cutoff = fmt(now - timedelta(days=KEEP_DAYS))
        for table, column in (("checks", "ts"), ("service_results", "ts"), ("wifi_samples", "ts"), ("scans", "started"), ("events", "ts")):
            conn.execute(f"DELETE FROM {table} WHERE {column} < ?", (cutoff,))
    conn.commit()


def step(db_path: str, data_dir: Path, mode: str, sim: Sim, now: datetime | None = None) -> None:
    now = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    conn = connect(db_path)
    try:
        if reset_due(conn, mode, now):
            seed(conn, data_dir, now)
            sim.down.clear()
            log.info("demo data started over")
        else:
            tick(conn, sim, now)
            from app import tsdb

            series = tsdb.for_conn(conn)
            if series is not None:
                series.maintain()
    finally:
        conn.close()


async def demo_loop(db_path: str, data_dir: Path, mode: str) -> None:
    sim = Sim()
    while True:
        await asyncio.sleep(TICK_SECONDS)
        try:
            await asyncio.to_thread(step, db_path, data_dir, mode, sim)
        except Exception:  # noqa: BLE001 - the demo keeps running whatever one round does
            log.exception("demo round failed")
