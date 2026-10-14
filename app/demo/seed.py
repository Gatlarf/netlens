"""Fills an empty Netlens database with the made-up network of the demo, including a month of believable history.

`seed(conn, data_dir, now)` wipes everything except the accounts and writes: devices with names, addresses, ports and groups; the
hierarchy; DNS registration (a fake Technitium); virtual machines and containers; reverse-proxy sites with certificates; service
checks; the installed plugins; and 30 days of uptime, events, scans and statistics with outages that make sense (a flaky plug, a
nightly backup server, a switch that takes its cameras down with it, one power cut).
"""

from __future__ import annotations

import json
import random
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.db import get_setting, set_setting
from app.demo import network as net
from app.demo.network import ALWAYS_ON, BY_KEY, DEVICES, DOMAIN, GROUPS, REVERSE_ZONE, chain, ip, mac

STAMP = "%Y-%m-%dT%H:%M:%SZ"
HISTORY_DAYS = 30
STEP = timedelta(minutes=30)
KEEP = ("schema_version", "users", "sessions", "api_tokens")
DEMO_USER, DEMO_PASSWORD = "demo", "netlens-demo"
PLUGIN_DIR = Path(__file__).resolve().parent / "plugins"


def fmt(moment: datetime) -> str:
    return moment.strftime(STAMP)


# ----------------------------------------------------------------------------- outages
def _outages(rng: random.Random, spec: net.Spec, start: datetime, end: datetime) -> list[tuple[datetime, datetime]]:
    """When the device itself is off, as (from, until) pairs. Parents, power cuts and the like are added on top."""
    out: list[tuple[datetime, datetime]] = []
    days = (end - start).days
    p = spec.profile
    if p == "off":
        return [(start - timedelta(days=1), end + timedelta(days=1))]
    if p == "solid":
        return out
    if p == "normal":
        for _ in range(rng.randint(0, 2)):
            at = start + timedelta(minutes=rng.randint(0, days * 1440 - 200))
            out.append((at, at + timedelta(minutes=rng.choice((30, 30, 60, 90, 150)))))
    elif p == "flaky":
        at = start + timedelta(hours=rng.randint(2, 30))
        while at < end:
            out.append((at, at + timedelta(minutes=rng.choice((30, 30, 60, 60, 90, 180)))))
            at += timedelta(hours=rng.randint(20, 90))
    elif p == "nightly":
        day = start.replace(hour=2, minute=30, second=0, microsecond=0)
        while day < end:
            out.append((day, day + timedelta(minutes=60)))
            day += timedelta(days=1)
    elif p == "evening":
        day = start.replace(hour=0, minute=0, second=0, microsecond=0)
        while day < end:
            weekend = day.weekday() >= 5
            on_from, on_to = (9, 23) if weekend else (17, 23)
            out.append((day, day + timedelta(hours=on_from, minutes=rng.randint(0, 90))))
            out.append((day + timedelta(hours=on_to, minutes=rng.randint(0, 40)), day + timedelta(days=1)))
            day += timedelta(days=1)
    return out


def _timeline(rng: random.Random, now: datetime) -> tuple[list[datetime], dict[str, list[bool]], list[tuple[str, datetime, datetime]]]:
    """Sample times and, per device, whether it was up at each of them. Also the events worth telling about."""
    start = (now - timedelta(days=HISTORY_DAYS)).replace(minute=0, second=0, microsecond=0)
    times = []
    t = start
    while t <= now:
        times.append(t)
        t += STEP
    own = {s.key: _outages(rng, s, start, now) for s in DEVICES}
    # a switch in the garden that fails twice, taking the cameras behind it along
    for days_ago, hours in ((17, 3), (4, 2)):
        at = (now - timedelta(days=days_ago)).replace(hour=14, minute=0, second=0, microsecond=0)
        own["sw_garden"].append((at, at + timedelta(hours=hours)))
    # a power cut: everything goes dark for 50 minutes nine days ago, and the servers need a while longer
    cut = (now - timedelta(days=9)).replace(hour=19, minute=30, second=0, microsecond=0)
    for s in DEVICES:
        if s.profile != "off":
            own[s.key].append((cut, cut + timedelta(minutes=60 if s.type not in ("server", "nas", "vm") else 90)))
    # the router gets a firmware update at night, once
    fw = (now - timedelta(days=12)).replace(hour=3, minute=0, second=0, microsecond=0)
    own["gw"].append((fw, fw + timedelta(minutes=30)))

    def down(key: str, at: datetime) -> bool:
        return any(a <= at < b for a, b in own[key])

    up: dict[str, list[bool]] = {}
    for s in DEVICES:
        path = [k for k in chain(s.key)]
        # a device is also gone when a switch/router/host it depends on is; wireless "evening" devices only follow their own schedule
        up[s.key] = [not any(down(k, t) for k in path) for t in times]
    return times, up, [(k, a, b) for k, spans in own.items() for a, b in spans]


# ----------------------------------------------------------------------------- the pieces
def _wipe(conn) -> None:
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")]
    for table in tables:
        if table not in KEEP:
            conn.execute(f'DELETE FROM "{table}"')
    conn.commit()


def _ensure_user(conn) -> None:
    from app import users

    if not conn.execute("SELECT 1 FROM users WHERE username = ?", (DEMO_USER,)).fetchone():
        # the demo account is an administrator (so every page shows) but the demo guard switches every change off
        users.create_user(conn, DEMO_USER, DEMO_PASSWORD, "admin")


def _devices(conn, now: datetime, up_now: dict[str, bool], rng: random.Random) -> dict[str, int]:
    group_ids = {}
    for name, color in GROUPS:
        group_ids[name] = conn.execute("INSERT INTO device_groups (name, color) VALUES (?, ?)", (name, color)).lastrowid
    ids: dict[str, int] = {}
    first = fmt(now - timedelta(days=HISTORY_DAYS))
    for s in DEVICES:
        recent = s.key in ("ph_ben", "tv_kids", "cam_attic", "p1")                         # joined the network lately
        first_seen = fmt(now - timedelta(days=rng.randint(2, 9))) if recent else first
        last_seen = fmt(now) if up_now[s.key] else fmt(now - timedelta(minutes=rng.randint(40, 600)))
        cur = conn.execute(
            """INSERT INTO devices (mac, primary_ip, hostname, vendor, os_name, os_confidence, device_type, custom_name, notes, online, first_seen, last_seen,
                                    notify_offline, parent_mode, trusted, hints, os_type, group_id, dns_mode, always_on)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'auto', ?, '[]', ?, ?, 'auto', ?)""",
            (mac(s), ip(s), s.name, s.vendor, s.os, rng.choice((92, 95, 98, 100)), s.type, s.custom or None, s.notes or None, 1 if up_now[s.key] else 0,
             first_seen, last_seen, 0 if s.profile in ("evening", "off") else 1, 1 if s.known else 0,
             "general purpose" if s.type in ("server", "pc", "nas") else "specialized", group_ids.get(s.group),
             1 if s.key in ALWAYS_ON else 0),
        )
        ids[s.key] = cur.lastrowid
        conn.execute("INSERT INTO device_ips (device_id, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)", (cur.lastrowid, ip(s), first_seen, last_seen))
        conn.execute("INSERT INTO device_names (device_id, name, source, first_seen, last_seen) VALUES (?, ?, 'ptr', ?, ?)", (cur.lastrowid, f"{s.name}.{DOMAIN}", first_seen, last_seen))
        conn.execute("INSERT INTO device_names (device_id, name, source, first_seen, last_seen) VALUES (?, ?, 'mdns', ?, ?)", (cur.lastrowid, s.name, first_seen, last_seen))
        for port, service, product in s.ports:
            conn.execute("INSERT INTO ports (device_id, proto, port, state, service, product, version, updated) VALUES (?, 'tcp', ?, 'open', ?, ?, NULL, ?)",
                         (cur.lastrowid, port, service, product or None, fmt(now)))
    return ids


def _relations(conn, ids: dict[str, int]) -> None:
    gw = ids["gw"]
    for s in DEVICES:
        if s.key == "gw":
            continue
        conn.execute("INSERT INTO relations (src_id, dst_id, kind, source, confidence, manual) VALUES (?, ?, 'gateway', 'scan', 1.0, 0)", (ids[s.key], gw))
        if s.parent and s.link in ("asus", "snmp"):
            conn.execute("INSERT INTO relations (src_id, dst_id, kind, source, confidence, manual) VALUES (?, ?, 'uplink', ?, 1.0, 0)", (ids[s.key], ids[s.parent], f"plugin:{s.link}"))
        elif s.parent and s.link in ("proxmox", "hyperv"):
            conn.execute("INSERT INTO relations (src_id, dst_id, kind, source, confidence, manual) VALUES (?, ?, 'host-of', ?, 1.0, 0)", (ids[s.key], ids[s.parent], f"plugin:{s.link}"))
        elif s.parent:
            conn.execute("INSERT INTO relations (src_id, dst_id, kind, source, confidence, manual) VALUES (?, ?, 'route', 'traceroute', 0.8, 0)", (ids[s.key], ids[s.parent]))


def _history(conn, ids, times, up, rng, now) -> list[tuple[str, int, str, str | None]]:
    """Uptime checks, scans and the up/down events; returns the events as (ts, device id, kind, detail)."""
    events: list[tuple[str, int, str, str | None]] = []
    rows = []
    for s in DEVICES:
        base = {"router": 0.6, "switch": 0.8, "camera": 3.0, "server": 0.4, "nas": 0.4, "vm": 0.5}.get(s.type, 4.0 if s.medium == "wifi" else 1.0)
        series = up[s.key]
        for i, t in enumerate(times):
            rtt = round(base * rng.uniform(0.7, 1.9) + (rng.random() < 0.03) * rng.uniform(5, 30), 2) if series[i] else None
            rows.append((ids[s.key], fmt(t), 1 if series[i] else 0, rtt))
            if i and series[i] != series[i - 1]:
                events.append((fmt(t), ids[s.key], "device_online" if series[i] else "device_offline", None if series[i] else ip(s)))
    conn.executemany("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (?, ?, ?, ?)", rows)
    scans = []
    for i, t in enumerate(times):
        online = sum(1 for s in DEVICES if up[s.key][i])
        deep = t.hour == 3 and t.minute == 0
        scans.append(("deep" if deep else "quick", "done", fmt(t), fmt(t + timedelta(seconds=rng.randint(70, 140) if deep else rng.randint(14, 24))), online))
    conn.executemany("INSERT INTO scans (kind, status, started, finished, hosts_found) VALUES (?, ?, ?, ?, ?)", scans)
    return events


def _other_events(ids, now, rng) -> list[tuple[str, int | None, str, str | None]]:
    out: list[tuple[str, int | None, str, str | None]] = []

    def at(days, hour=10, minute=0):
        return fmt((now - timedelta(days=days)).replace(hour=hour, minute=minute, second=rng.randint(0, 59), microsecond=0))

    for s in DEVICES:
        if s.key in ("ph_ben", "tv_kids", "cam_attic", "p1"):
            out.append((at(rng.randint(2, 9), rng.randint(8, 20), rng.randint(0, 59)), ids[s.key], "device_new", f"{ip(s)} {s.vendor}"))
    out += [
        (at(20, 8), ids["ph_anna"], "ip_changed", "192.168.42.201 -> 192.168.42.127"), (at(11, 21), ids["pc_guest"], "ip_changed", "192.168.42.188 -> 192.168.42.122"),
        (at(6, 7), ids["tab_k"], "ip_changed", "192.168.42.230 -> 192.168.42.125"), (at(15, 12), ids["pve"], "os_changed", "Linux 6.5 (Proxmox VE) -> Linux 6.8 (Proxmox VE)"),
        (at(8, 4), ids["rpi_docker"], "os_changed", "Linux 6.1 (Debian 12) -> Linux 6.6 (Debian 12)"), (at(12, 3, 31), ids["gw"], "os_changed", "Linux 5.4.0 -> Linux 5.4.1"),
        (at(13, 15), ids["media"], "port_opened", "tcp/8096 (http, Jellyfin) opened"), (at(5, 9), ids["docker1"], "port_opened", "tcp/8222 (http, Vaultwarden) opened"),
        (at(3, 16), ids["lab"], "port_unexpected", "tcp/5900 (vnc) opened on a device that had no open ports of this kind"), (at(10, 14), ids["printer"], "port_closed", "tcp/515 (printer) closed"),
        (at(2, 18), ids["ph_ben"], "wifi_roamed", "mesh-attic -> mesh-basement (5 GHz)"), (at(2, 7), ids["tab_k"], "wifi_roamed", "mesh-basement -> mesh-guestroom (2.4 GHz)"),
        (at(1, 19), ids["ph_anna"], "wifi_roamed", "mesh-basement -> mesh-guestroom (5 GHz)"), (at(7, 20), ids["pc_ben"], "wifi_roamed", "mesh-basement -> mesh-attic (5 GHz)"),
        (at(9, 19, 31), None, "service_down", "Home Assistant (http://192.168.42.70:8123/) is down: timed out"), (at(9, 20, 12), None, "service_up", "Home Assistant (http://192.168.42.70:8123/) is up again"),
        (at(4, 14, 5), None, "service_down", "Garden switch (tcp 192.168.42.12:80) is down: connection refused"), (at(4, 16, 3), None, "service_up", "Garden switch (tcp 192.168.42.12:80) is up again"),
        (at(2, 5, 11), None, "service_down", "Public site (https://www.example.net/) is down: HTTP 502"), (at(2, 5, 20), None, "service_up", "Public site (https://www.example.net/) is up again"),
        (at(1, 11), ids["rpi_docker"], "container_restarting", "esphome on rpi-docker keeps restarting (7 restarts)"),
        (at(3, 2, 14), ids["docker1"], "container_stopped", "watchtower on docker-lxc1 stopped (exit code 0)"),
        (at(5, 8), ids["pve"], "guest_update_available", "An update is available for the virtual machine media-vm on pve-nuc (jellyfin 10.9.11)"),
        (at(1, 6), None, "cert_expiring", "The certificate cloud.example.net expires in 6 days (used by cloud.example.net)"),
        (at(2, 9), None, "dns_registered", "Registered 4 names in DNS (3 added, 1 updated)"),
        (at(6, 3, 12), None, "login_failed", "5 wrong passwords in 60 seconds from 203.0.113.45"),
        (at(14, 6), None, "dhcp_rogue", "A new DHCP server answered: 192.168.42.99 (not one of the known servers)"),
    ]
    return out


def _stats(conn, ids, times, up, events, now) -> None:
    by_day: dict[str, int] = {}
    for ts, *_ in events:
        by_day[ts[:10]] = by_day.get(ts[:10], 0) + 1
    ports = conn.execute("SELECT COUNT(*) FROM ports").fetchone()[0]
    scans: dict[str, int] = {}
    for t in times:
        scans[fmt(t)[:10]] = scans.get(fmt(t)[:10], 0) + 1
    last_of_day: dict[str, int] = {}
    for i, t in enumerate(times):
        last_of_day[fmt(t)[:10]] = i
    for day, i in last_of_day.items():
        online = sum(1 for s in DEVICES if up[s.key][i])
        conn.execute("INSERT INTO stats_daily (day, devices, online, new_devices, open_ports, events, scans) VALUES (?, ?, ?, 0, ?, ?, ?)",
                     (day, len(DEVICES), online, ports, by_day.get(day, 0), scans.get(day, 0)))


# ----------------------------------------------------------------------------- services, plugins, DNS, proxies
SERVICE_CHECKS = [
    # name, kind, device key, host, port, path, expect, interval, base ms
    ("DNS server 1 - external lookup", "dns", "dns1", f"{net.SUBNET}.74", 53, "example.org", "", 60, 18),
    ("DNS server 2 - external lookup", "dns", "rpi_dns", f"{net.SUBNET}.54", 53, "example.org", "", 60, 24),
    ("Router admin", "http", "gw", f"{net.SUBNET}.1", 80, "/", "", 120, 35),
    ("Home Assistant", "http", "ha", f"{net.SUBNET}.70", 8123, "/", "", 60, 90),
    ("NAS web interface", "http", "nas", f"{net.SUBNET}.31", 443, "/", "", 120, 60),
    ("Proxmox VE", "http", "pve", f"{net.SUBNET}.30", 8006, "/", "", 120, 70),
    ("Nginx Proxy Manager", "http", "proxy", f"{net.SUBNET}.73", 81, "/", "", 120, 45),
    ("Jellyfin", "http", "media", f"{net.SUBNET}.75", 8096, "/health", "Healthy", 120, 40),
    ("Office printer (IPP)", "tcp", "printer", f"{net.SUBNET}.130", 631, "", "", 300, 12),
    ("Front door camera stream", "tcp", "cam_front", f"{net.SUBNET}.100", 554, "", "", 120, 8),
    ("Garden switch", "tcp", "sw_garden", f"{net.SUBNET}.12", 80, "", "", 120, 9),
    ("Backup server", "http", "pbs", f"{net.SUBNET}.32", 8007, "/", "", 300, 55),
    ("Technitium DNS admin", "http", "dns1", f"{net.SUBNET}.74", 5380, "/", "", 120, 30),
    ("Public site (www.example.net)", "http", "web1", "www.example.net", 443, "/", "", 60, 140),
    ("Kitchen plug page", "http", "plug", f"{net.SUBNET}.150", 80, "/", "", 300, 150),
]


def _services(conn, ids, times, up, rng, now) -> list[int]:
    check_ids = []
    spikes = {"Public site (www.example.net)": (now - timedelta(days=2)).replace(hour=5, minute=0, second=0, microsecond=0)}
    for name, kind, key, host, port, path, expect, interval, base in SERVICE_CHECKS:
        cur = conn.execute(
            """INSERT INTO service_checks (device_id, name, kind, host, port, path, expect, interval_s, timeout_s, enabled, created)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 5, 1, ?)""", (ids[key], name, kind, host, port, path, expect, interval, fmt(now - timedelta(days=HISTORY_DAYS))))
        check_ids.append(cur.lastrowid)
        rows, last = [], None
        spike = spikes.get(name)
        for i, t in enumerate(times):
            ok = up[key][i] and not (spike and spike <= t < spike + timedelta(minutes=30))
            ms = round(base * rng.uniform(0.6, 1.8) * (6 if rng.random() < 0.02 else 1), 1) if ok else None
            detail = "answered" if ok else ("timed out" if kind != "http" or key != "web1" else "HTTP 502")
            rows.append((cur.lastrowid, fmt(t), 1 if ok else 0, ms, detail))
            last = (fmt(t), 1 if ok else 0, ms, detail)
        conn.executemany("INSERT INTO service_results (check_id, ts, up, ms, detail) VALUES (?, ?, ?, ?, ?)", rows)
        since = fmt(times[-1])
        for j in range(len(rows) - 1, 0, -1):
            if rows[j][2] != rows[j - 1][2]:
                since = rows[j][1]
                break
        else:
            since = rows[0][1]
        conn.execute("UPDATE service_checks SET last_ts = ?, last_up = ?, last_ms = ?, last_detail = ?, since = ? WHERE id = ?", (*last, since, cur.lastrowid))
    return check_ids


def _install_plugins(conn, data_dir: Path, ids, now) -> None:
    """Switch on the plugins the demo pretends to use. The external ones are copied stand-ins (manifest only)."""
    from app.plugins.contract import default_config
    from app.plugins.registry import _read_plugin

    ts = fmt(now)

    def state(plugin_id: str, path: Path, overrides: dict, status: dict, source: str = "index", version: str | None = None) -> None:
        plugin = _read_plugin(path, path.parent.name == "builtin")
        config = default_config(plugin.manifest)
        config.update({k: v for k, v in overrides.items() if k in config})
        set_setting(conn, f"plugin.{plugin_id}", json.dumps({"enabled": True, "config": config}))
        set_setting(conn, f"plugin.{plugin_id}.status", json.dumps({"ts": ts, "ok": True, **status}))
        if path.parent.name != "builtin":
            set_setting(conn, f"plugin.{plugin_id}.install", json.dumps({"source": source, "version": plugin.manifest["version"], "sha256": "0" * 64, "level": None, "installed": fmt(now - timedelta(days=21))}))

    dest = data_dir / "plugins"
    for plugin_id in ("docker", "hyperv", "npm", "snmp", "technitium", "truenas"):
        target = dest / plugin_id
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(PLUGIN_DIR / plugin_id, target)
    builtin = Path(__file__).resolve().parent.parent / "plugins" / "builtin"
    state("proxmox", builtin / "proxmox", {"servers": [{"id": "s1", "host": f"https://{net.SUBNET}.30:8006", "token_id": "netlens@pve!demo", "token_secret": "demo-secret", "username": "", "password": ""}], "verify_tls": False},
          {"hosts": 1, "hosts_matched": 1, "guests": 7, "guests_matched": 7, "links": 7})
    state("asus", builtin / "asus", {"url": f"https://{net.SUBNET}.1:8443", "username": "netlens", "password": "demo-password", "verify_tls": False}, {"nodes": 4, "clients": 17, "links": 17, "samples": 10, "roams": 4})
    state("docker", dest / "docker", {"servers": [{"id": "s1", "host": f"http://{net.SUBNET}.33:2375", "lan": ""}, {"id": "s2", "host": f"http://{net.SUBNET}.71:2375", "lan": ""}], "check_image_updates": True},
          {"hosts": 2, "hosts_matched": 2, "guests": 22, "guests_matched": 0, "links": 0})
    state("truenas", dest / "truenas", {"servers": [{"id": "s1", "host": f"https://{net.SUBNET}.31", "api_key": "demo-key"}]}, {"hosts": 1, "hosts_matched": 1, "guests": 3, "guests_matched": 0, "links": 0})
    state("hyperv", dest / "hyperv", {"servers": [{"id": "s1", "host": f"{net.SUBNET}.41", "username": "netlens", "password": "demo-password", "lan": ""}]}, {"hosts": 1, "hosts_matched": 1, "guests": 1, "guests_matched": 1, "links": 1})
    state("npm", dest / "npm", {"servers": [{"id": "s1", "host": f"http://{net.SUBNET}.73:81", "email": "netlens@home.example.net", "password": "demo-password", "lan": ""}], "create_checks": False},
          {"proxies": 1, "sites": 12, "sites_matched": 12, "certificates": 4, "expiring": 1, "checks": 0, "alerts": 1, "warnings": 0})
    state("snmp", dest / "snmp", {"servers": [{"id": "s1", "host": f"{net.SUBNET}.10", "community": "public"}, {"id": "s2", "host": f"{net.SUBNET}.11", "community": "public"}, {"id": "s3", "host": f"{net.SUBNET}.12", "community": "public"}]},
          {"switches": 3, "hosts": 3, "links": 6})
    state("technitium", dest / "technitium", {"servers": [{"id": "s1", "host": f"http://{net.SUBNET}.74:5380", "token": "demo-token"}]}, {"zones": 2, "records": 0, "managed": 0, "planned": 0, "conflicts": 0})


def _guests(conn, ids, now) -> None:
    ts = fmt(now)
    started = fmt(now - timedelta(days=19, hours=3))

    def guest(plugin, gid, name, kind, host_name, status, device=None, host=None, macs=(), ips=(), **details):
        conn.execute(
            """INSERT INTO hypervisor_guests (plugin_id, guest_id, name, kind, host_name, status, macs, ips, device_id, host_device_id, updated, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (plugin, gid, name, kind, host_name, status, json.dumps(list(macs)), json.dumps(list(ips)), ids.get(device), ids.get(host), ts, json.dumps(details)))

    for gid, key, kind, cpus, mem, disk, os_, status in (
        ("100", "ha", "qemu", 2, 4096, 32, "l26", "running"), ("101", "docker1", "lxc", 4, 8192, 120, "debian", "running"), ("102", "web1", "lxc", 1, 1024, 16, "debian", "running"),
        ("103", "proxy", "lxc", 1, 1024, 8, "debian", "running"), ("104", "dns1", "lxc", 1, 512, 8, "debian", "running"), ("105", "media", "qemu", 4, 6144, 64, "l26", "running"),
        ("106", "testvm", "qemu", 2, 2048, 20, "l26", "stopped")):
        s = BY_KEY[key]
        extra = {"update_available": True, "version": "10.9.11"} if key == "media" else {}
        guest("proxmox", gid, s.name, kind, "pve-nuc", status, key, "pve", [mac(s)], [ip(s)], started=started if status == "running" else None, os=os_, cpus=cpus, memory_mb=mem, disk_gb=disk, autostart=key != "testvm", **extra)
    s = BY_KEY["hvlab"]
    guest("hyperv", "6f1c9a3e-0000-4000-8000-00000000a001", s.name, "vm", "forge-hv", "running", "hvlab", "hv", [mac(s)], [ip(s)], started=started, cpus=2, memory_mb=4096, disk_gb=80, autostart=True)
    # containers: (host key, name, image, status, health, restarts, update available, published ports)
    containers = [
        ("rpi_docker", "mosquitto", "eclipse-mosquitto:2", "running", None, 0, False, [(1883, 1883)]), ("rpi_docker", "zigbee2mqtt", "koenkk/zigbee2mqtt:1.40", "running", None, 0, True, [(8080, 8081)]),
        ("rpi_docker", "esphome", "esphome/esphome:2024.9", "restarting", "unhealthy", 7, False, [(6052, 6052)]), ("rpi_docker", "node-red", "nodered/node-red:3.1", "running", "healthy", 0, False, [(1880, 1880)]),
        ("rpi_docker", "watchtower", "containrrr/watchtower:1.7", "exited", None, 0, False, []), ("rpi_docker", "portainer-agent", "portainer/agent:2.21", "running", None, 0, True, [(9001, 9001)]),
        ("docker1", "grafana", "grafana/grafana:11.2", "running", "healthy", 0, False, [(3000, 3000)]), ("docker1", "prometheus", "prom/prometheus:v2.54", "running", "healthy", 0, False, [(9090, 9090)]),
        ("docker1", "loki", "grafana/loki:3.1", "running", None, 0, False, [(3100, 3100)]), ("docker1", "vaultwarden", "vaultwarden/server:1.32", "running", "healthy", 0, True, [(80, 8222)]),
        ("docker1", "uptime-kuma", "louislam/uptime-kuma:1", "running", "healthy", 0, False, [(3001, 3001)]), ("docker1", "paperless", "paperlessngx/paperless-ngx:2.12", "running", "healthy", 1, False, [(8000, 8000)]),
        ("docker1", "immich-server", "ghcr.io/immich-app/immich-server:v1.116", "running", "healthy", 0, True, [(2283, 2283)]), ("docker1", "immich-db", "tensorchord/pgvecto-rs:pg14", "running", "healthy", 0, False, []),
        ("docker1", "homepage", "ghcr.io/gethomepage/homepage:v0.9", "running", None, 0, False, [(3000, 3002)]), ("docker1", "netlens", "ghcr.io/gatlarf/netlens:latest", "running", "healthy", 0, False, [(8080, 8080)]),
        ("docker1", "whoami", "traefik/whoami:v1.10", "running", None, 0, False, [(80, 8088)]), ("docker1", "dozzle", "amir20/dozzle:v8", "running", None, 0, False, [(8080, 8888)]),
        ("docker1", "ntfy", "binwiederhier/ntfy:v2", "running", "healthy", 0, False, [(80, 8089)]), ("docker1", "changedetection", "dgtlmoon/changedetection.io:0.47", "running", None, 0, True, [(5000, 5000)]),
        ("docker1", "frigate", "ghcr.io/blakeblackshear/frigate:0.14", "running", "healthy", 0, False, [(5000, 5001)]), ("docker1", "mealie", "hkotel/mealie:v1.12", "running", "healthy", 0, False, [(9000, 9925)]),
    ]
    for host_key, name, image, status, health, restarts, update, ports in containers:
        host = BY_KEY[host_key]
        details = {"image": image, "image_created": fmt(now - timedelta(days=40)), "health": health, "restarts": restarts, "started": started if status != "exited" else None,
                   "network_driver": "bridge", "update_available": update, "image_checked": True, "restarting": status == "restarting", "ports": [{"container_port": c, "host_port": h, "proto": "tcp", "bind": "0.0.0.0"} for c, h in ports]}
        details = {k: v for k, v in details.items() if v not in (None, "")}
        guest("docker", f"{ip(host)}:2375/{name}", name, "container", host.name, status, None, host_key, [], [], **details)
    for gid, name, status in (("instance:jellyfin", "jellyfin", "running"), ("instance:nextcloud", "nextcloud", "running"), ("instance:syncthing", "syncthing", "stopped")):
        guest("truenas", gid, name, "app", "truenas", status, None, "nas", [], [], started=started if status == "running" else None)


def _proxy(conn, ids, now) -> None:
    ts = fmt(now)
    cert = lambda days: fmt(now + timedelta(days=days))                                    # noqa: E731
    sites = [  # id, domains, scheme, target key, port, guest id, cert (name, expires in days), extra
        ("1", ["ha.example.net"], "http", "ha", 8123, "100", ("ha.example.net", 54), {"websockets": True}),
        ("2", ["media.example.net"], "http", "media", 8096, "105", ("media.example.net", 54), {"websockets": True}),
        ("3", ["cloud.example.net"], "https", "nas", 443, None, ("cloud.example.net", 6), {}),
        ("4", ["vault.example.net"], "http", "docker1", 8222, "101", ("vault.example.net", 71), {}),
        ("5", ["grafana.example.net"], "http", "docker1", 3000, "101", ("grafana.example.net", 71), {"access_list": "family"}),
        ("6", ["status.example.net"], "http", "docker1", 3001, "101", ("status.example.net", 71), {}),
        ("7", ["photos.example.net"], "http", "docker1", 2283, "101", ("photos.example.net", 71), {"websockets": True}),
        ("8", ["paper.example.net"], "http", "docker1", 8000, "101", ("paper.example.net", 71), {"access_list": "family"}),
        ("9", ["www.example.net", "example.net"], "https", "web1", 443, "102", ("example.net", 33), {}),
        ("10", ["blog.example.net"], "http", "web1", 80, "102", ("blog.example.net", 33), {}),
        ("11", ["old.example.net"], "http", "testvm", 8080, "106", None, {}),
    ]
    proxy = ids["proxy"]
    for sid, domains, scheme, key, port, gid, cert_info, extra in sites:
        s = BY_KEY[key]
        enabled = 0 if sid == "11" else 1
        details = {"ssl": bool(cert_info), "ssl_forced": bool(cert_info), "certificate_id": sid if cert_info else None, **extra}
        if cert_info:
            details.update({"cert_name": cert_info[0], "cert_provider": "letsencrypt", "cert_expires": cert(cert_info[1])})
        details = {k: v for k, v in details.items() if v not in (None, "", False)}
        plugin = "truenas" if key == "nas" else "proxmox"
        conn.execute(
            """INSERT INTO proxy_sites (plugin_id, site_id, proxy_id, proxy_name, proxy_device_id, type, domains, enabled, scheme, forward_host, forward_port,
                                        target_device_id, target_plugin_id, target_guest_id, target_name, target_how, details, updated)
               VALUES ('npm', ?, ?, 'proxy-lxc', ?, 'proxy', ?, ?, ?, ?, ?, ?, ?, ?, ?, 'own address', ?, ?)""",
            (f"proxy-{sid}", f"{net.SUBNET}.73:81", proxy, json.dumps(domains), enabled, scheme, ip(s), port, ids[key], plugin if gid else None, gid, s.name, json.dumps(details), ts))
    conn.execute("INSERT INTO proxy_sites (plugin_id, site_id, proxy_id, proxy_name, proxy_device_id, type, domains, enabled, scheme, forward_host, forward_port, details, updated) "
                 "VALUES ('npm', 'redirect-12', ?, 'proxy-lxc', ?, 'redirect', ?, 1, 'http', 'www.example.net', 443, ?, ?)",
                 (f"{net.SUBNET}.73:81", proxy, json.dumps(["shop.example.net"]), json.dumps({"redirect_to": "https://www.example.net/shop"}), ts))


def _dns(conn, ids, now) -> None:
    ts = fmt(now)
    zone = DOMAIN
    set_setting(conn, "dns.settings", json.dumps({
        "plugin": "technitium", "networks": f"{net.SUBNET}.0/24 = {zone}", "grace_hours": 2, "only_known": True, "skip_windows": True, "template": "{type}-{vendor}-{mac4}",
        "max_offline_days": 7, "remove": False, "register_containers": False, "register_sites": False, "auto_apply": False, "max_changes": 25}))
    set_setting(conn, "domain_suffix", zone)
    records = []
    for s in DEVICES:
        if not s.known or s.windows and s.key in ("pc_anna", "hv", "hvlab") or s.profile == "off":
            continue
        records.append((s.key, s.name))
    snapshot_records = []
    for key, name in records:
        s = BY_KEY[key]
        fq = f"{name}.{zone}"
        snapshot_records.append({"zone": zone, "name": fq, "type": "A", "value": ip(s), "ttl": 3600, "managed": True, "comment": "managed by Netlens"})
        snapshot_records.append({"zone": REVERSE_ZONE, "name": f"{s.octet}.{REVERSE_ZONE}", "type": "PTR", "value": fq, "ttl": 3600, "managed": True, "comment": "managed by Netlens"})
        for rtype, rname, value in (("A", fq, ip(s)), ("PTR", f"{s.octet}.{REVERSE_ZONE}", fq)):
            conn.execute("INSERT INTO dns_records (plugin_id, zone, name, type, value, device_id, created) VALUES ('technitium', ?, ?, ?, ?, ?, ?)",
                         (zone if rtype == "A" else REVERSE_ZONE, rname, rtype, value, ids[key], fmt(now - timedelta(days=20))))
    # Windows machines register themselves: Netlens leaves their records alone
    for key in ("pc_anna", "hv"):
        s = BY_KEY[key]
        snapshot_records.append({"zone": zone, "name": f"{s.name}.{zone}", "type": "A", "value": ip(s), "ttl": 1200, "managed": False, "comment": ""})
    snapshot_records.append({"zone": zone, "name": f"nas.{zone}", "type": "CNAME", "value": f"truenas.{zone}", "ttl": 3600, "managed": False, "comment": ""})
    snapshot = {"zones": [{"name": zone, "kind": "forward", "writable": True}, {"name": REVERSE_ZONE, "kind": "reverse", "writable": True}], "records": snapshot_records, "server": f"dns-lxc1 ({net.SUBNET}.74)"}
    set_setting(conn, "plugin.technitium.data", json.dumps(snapshot))
    managed = sum(1 for r in snapshot_records if r["managed"])
    set_setting(conn, "plugin.technitium.status", json.dumps({"ts": ts, "ok": True, "zones": 2, "records": len(snapshot_records), "managed": managed, "planned": 0, "conflicts": 0}))


def _wifi(conn, ids, times, up, rng) -> None:
    nodes = {"n_base": "Basement", "n_attic": "Attic", "n_guest": "Guest Room", "n_garage": "Garage"}
    ts = fmt(times[-1])
    for s in DEVICES:
        if s.link not in ("asus", "snmp") or not s.parent:
            continue
        node_spec = BY_KEY[s.parent]
        if s.link == "asus":
            conn.execute("INSERT INTO client_links (device_id, plugin_id, node_mac, node_name, port, medium, updated) VALUES (?, 'asus', ?, ?, NULL, ?, ?)",
                         (ids[s.key], mac(node_spec), nodes.get(s.parent, node_spec.name), s.medium, ts))
        if s.medium == "wifi" and s.link == "asus":
            rows = []
            for i, t in enumerate(times[-336:]):                       # a week
                if up[s.key][len(times) - 336 + i] and i % 2 == 0:
                    rows.append((ids[s.key], fmt(t), nodes.get(s.parent), s.band, rng.randint(-78, -45), round(rng.uniform(30, 280), 1), round(rng.uniform(1, 60), 1)))
            conn.executemany("INSERT INTO wifi_samples (device_id, ts, node, band, rssi, tx_mbps, rx_mbps) VALUES (?, ?, ?, ?, ?, ?, ?)", rows)


def _speedtests(conn, now: datetime, rng: random.Random) -> None:
    """A month of scheduled internet tests (a slow patch on day 12), a few iperf3 runs and browser tests."""
    rows = []
    for i in range(HISTORY_DAYS * 4):
        when = now - timedelta(hours=6 * i)
        slow = 11.5 <= (now - when).total_seconds() / 86400 <= 12.5
        evening = when.hour in (18, 20)
        down = rng.gauss(180 if slow else 455 if evening else 495, 22)
        up = rng.gauss(46 if slow else 48, 2.5)
        latency = rng.gauss(14 if slow else 10, 1.5)
        jitter = abs(rng.gauss(1.8, 0.7))
        ok = i != 41                                              # one test that could not reach the server
        rows.append((fmt(when), "internet", "Cloudflare", round(down, 1) if ok else None, round(up, 1) if ok else None, round(latency, 1) if ok else None, round(jitter, 2) if ok else None,
                     1 if ok else 0, None if ok else "Could not reach the test server. Is the internet connection up?", json.dumps({"server": "Brussels", "server_code": "BRU", "isp": "Example Telecom", "country": "BE"}) if ok else "{}"))
    runs = [("pc_anna", "iperf-in", 931, 936), ("pve", "iperf-in", 941, 940), ("nas", "iperf-in", 938, 939), ("pc_anna", "iperf-in", 929, 935), ("pve", "iperf-in", 940, 941)]
    for n, (key, kind, up, down) in enumerate(runs):
        when = now - timedelta(days=1 + n * 5, hours=n)
        rows.append((fmt(when), kind, ip(BY_KEY[key]), round(down + rng.uniform(-6, 4), 1), round(up + rng.uniform(-6, 4), 1), None, None, 1, None, json.dumps({"streams": 4, "seconds": 10, "retransmits": rng.randint(0, 12)})))
    for n, (target, up, down) in enumerate((("192.168.42.31:5201", 912, 931), ("192.168.42.30:5201", 927, 934))):
        rows.append((fmt(now - timedelta(days=3 + n * 9)), "iperf-out", target, down, up, None, None, 1, None, json.dumps({"streams": 4, "seconds": 10, "direction": "both"})))
    for n, (label, down, up, lat) in enumerate((("Wi-Fi, kitchen tablet", 312.4, 188.9, 6.2), ("Wi-Fi, Anna's phone", 402.7, 251.3, 5.1), ("Wired, desk-anna", 934.5, 921.0, 1.1))):
        rows.append((fmt(now - timedelta(days=2 + n * 4, hours=3)), "browser", f"{net.SUBNET}.{120 + n}", down, up, lat, round(rng.uniform(0.3, 1.8), 2), 1, None, json.dumps({"label": label})))
    conn.executemany("INSERT INTO speedtests (ts, kind, target, down_mbps, up_mbps, latency_ms, jitter_ms, ok, error, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", sorted(rows))


def seed(conn, data_dir: Path, now: datetime | None = None) -> dict:
    now = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    rng = random.Random(20261012)
    _wipe(conn)
    _ensure_user(conn)
    times, up, _spans = _timeline(rng, now)
    up_now = {k: v[-1] for k, v in up.items()}
    ids = _devices(conn, now, up_now, rng)
    _relations(conn, ids)
    events = _history(conn, ids, times, up, rng, now)
    extra = _other_events(ids, now, rng)
    all_events = sorted([(ts, did, kind, detail) for ts, did, kind, detail in events] + extra, key=lambda e: e[0])
    conn.executemany("INSERT INTO events (ts, device_id, kind, detail) VALUES (?, ?, ?, ?)", all_events)
    _stats(conn, ids, times, up, all_events, now)
    _services(conn, ids, times, up, rng, now)
    _install_plugins(conn, data_dir, ids, now)
    _guests(conn, ids, now)
    _proxy(conn, ids, now)
    _dns(conn, ids, now)
    _wifi(conn, ids, times, up, rng)
    _speedtests(conn, now, rng)
    settings = {
        "ranges": json.dumps([f"{net.SUBNET}.0/24"]), "map_default_layout": "horizontal", "map_show_guests": "1",
        "netchecks.gateway": json.dumps({"ip": f"{net.SUBNET}.1", "mac": mac(BY_KEY["gw"]), "since": fmt(now - timedelta(days=HISTORY_DAYS))}),
        "backup.schedule": json.dumps({"enabled": True, "every_hours": 6, "keep": 28}),
        "update_check.settings": json.dumps({"enabled": False}),
        "backup.last": json.dumps({"at": fmt(now - timedelta(hours=3)), "ok": True, "name": "netlens-demo.db", "error": None}),
        "speedtest.schedule": json.dumps({"enabled": True, "every_hours": 6}),
        "speedtest.iperf": json.dumps({"enabled": True, "port": 5201}),
        "demo.seeded": fmt(now),
    }
    for key, value in settings.items():
        set_setting(conn, key, value)
    from app.dns import service as dns_service
    from app.plugins.contract import validate_output

    dns_service.make_plan(conn, "technitium", validate_output("dns", json.loads(get_setting(conn, "plugin.technitium.data"))), fmt(now), persist=True)
    conn.execute("INSERT INTO share_links (token, name, mode, show_ips, show_macs, created, views) VALUES (?, 'Status page', 'status', 0, 0, ?, 12)", ("demo-status-page-token-0123456789abcdef", fmt(now - timedelta(days=5))))
    conn.commit()
    from app import tsdb
    from app.demo import health

    series = tsdb.for_conn(conn)
    if series is not None:      # the graphs start with the same weeks of history as the uptime page
        series.reset()
        series.backfill(conn, force=True)
    health.seed(conn, ids, now)
    return ids
