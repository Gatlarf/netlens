"""What the demo shows for the newer parts of Netlens: the Storage, Backups, Vulnerabilities and Smart home pages, the stored logins, the host probes and a
maintenance window. The plugins do not run in the demo, so the data they would report is made up here and fed through the same code the real plugins use
(apply_storage, apply_backup, apply_vulns, apply_inventory). `refresh` runs it again every few rounds so the times stay recent."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from app import credstore, vault
from app.db import get_setting, set_setting
from app.demo.network import BY_KEY, SUBNET, ip, mac
from app.plugins.contract import validate_output

GB = 1024 ** 3
TB = 1024 ** 4
STAMP = "%Y-%m-%dT%H:%M:%SZ"
REFRESH_EVERY = timedelta(minutes=30)
OWNER = "demo"


def _t(now: datetime, **ago) -> str:
    return (now - timedelta(**ago)).strftime(STAMP)


def storage_data(now: datetime) -> dict:
    """The TrueNAS: a big pool that is filling up (the story), a fast mirror, one disk that is degrading, shares used by the servers."""
    nas = f"{SUBNET}.31"
    disks = [{"id": f"d{i}", "system_id": "nas", "name": f"da{i}", "slot": str(i), "model": "WDC WD120EFBX", "size": 12 * TB, "state": "ok"} for i in range(1, 7)]
    disks[4]["state"] = "degraded"
    disks += [{"id": "n1", "system_id": "nas", "name": "nvd0", "slot": "M.2-1", "model": "Samsung 980 PRO 2TB", "size": 2 * TB, "state": "ok"},
              {"id": "n2", "system_id": "nas", "name": "nvd1", "slot": "M.2-2", "model": "Samsung 980 PRO 2TB", "size": 2 * TB, "state": "ok"},
              {"id": "b1", "system_id": "nas", "name": "ada0", "slot": "SATA-0", "model": "Kingston A400 120GB", "size": 120 * GB, "state": "ok"}]
    return {
        "systems": [{"id": "nas", "name": "truenas", "ip": nas, "vendor": "iXsystems", "model": "TrueNAS Community 25.04", "version": "25.04.2", "serial": "", "online": True, "health": "warning",
                     "warnings": ["Pool tank is 88% full", "Disk da5 reports read errors"]}],
        "controllers": [],
        "pools": [{"id": "tank", "system_id": "nas", "name": "tank", "total": 60 * TB, "used": int(52.8 * TB), "avail": int(7.2 * TB), "health": "warning", "raid": "RAIDZ2 (6 disks)"},
                  {"id": "fast", "system_id": "nas", "name": "fast", "total": int(1.8 * TB), "used": int(0.76 * TB), "avail": int(1.04 * TB), "health": "ok", "raid": "Mirror (2 disks)"},
                  {"id": "boot-pool", "system_id": "nas", "name": "boot-pool", "total": 110 * GB, "used": 9 * GB, "avail": 101 * GB, "health": "ok", "raid": "Single disk"}],
        "volumes": [
            {"id": "media", "system_id": "nas", "pool_id": "tank", "name": "tank/media", "kind": "share", "protocol": "nfs", "size": 40 * TB, "used": int(36.5 * TB), "health": "ok", "clients": [ip(BY_KEY["media"]), ip(BY_KEY["tv_living"])]},
            {"id": "photos", "system_id": "nas", "pool_id": "tank", "name": "tank/photos", "kind": "share", "protocol": "smb", "size": 8 * TB, "used": int(6.1 * TB), "health": "ok", "clients": [ip(BY_KEY["pc_anna"]), ip(BY_KEY["docker1"])]},
            {"id": "backups", "system_id": "nas", "pool_id": "tank", "name": "tank/backups", "kind": "share", "protocol": "nfs", "size": 12 * TB, "used": int(10.2 * TB), "health": "ok", "clients": [ip(BY_KEY["pbs"]), ip(BY_KEY["pve"])]},
            {"id": "vm", "system_id": "nas", "pool_id": "fast", "name": "fast/vm-disks", "kind": "lun", "protocol": "iscsi", "size": 1 * TB, "used": int(0.7 * TB), "health": "ok", "clients": [ip(BY_KEY["pve"])]},
            {"id": "appdata", "system_id": "nas", "pool_id": "fast", "name": "fast/appdata", "kind": "filesystem", "protocol": "", "size": 500 * GB, "used": 56 * GB, "health": "ok", "clients": []},
        ],
        "disks": disks,
        "alerts": [{"id": "a1", "system_id": "nas", "severity": "warning", "text": "Pool tank is 88% full. Free up space or add a disk before it reaches 95%.", "at": _t(now, hours=30)},
                   {"id": "a2", "system_id": "nas", "severity": "warning", "text": "Device da5 has 14 read errors. Check the SMART data and plan a replacement.", "at": _t(now, days=2, hours=4)}],
    }


def backup_data(now: datetime) -> dict:
    day = 86400
    targets = []
    for gid, key, kind, state, ago, count in (("100", "ha", "vm", "ok", dict(hours=5), 28), ("101", "docker1", "ct", "ok", dict(hours=5), 28), ("102", "web1", "ct", "ok", dict(hours=5), 28),
                                              ("103", "proxy", "ct", "ok", dict(hours=5), 28), ("104", "dns1", "ct", "ok", dict(hours=5), 28), ("105", "media", "vm", "warning", dict(days=3, hours=5), 25),
                                              ("106", "testvm", "vm", "failed", dict(days=2, hours=5), 12)):
        targets.append({"id": f"vm/{gid}", "server_id": "pbs", "store_id": "main", "type": kind, "backup_id": gid, "name": BY_KEY[key].name, "count": count, "last_backup": _t(now, **ago),
                        "last_state": state, "last_size": [14, 22, 3, 2, 1, 38, 9][int(gid) - 100] * GB // 4, "verify_state": "ok" if state == "ok" else "warning" if state == "warning" else "failed",
                        "interval": day, "protected": 2 if key in ("ha", "docker1") else 0})
    targets.append({"id": "host/pve-nuc", "server_id": "pbs", "store_id": "main", "type": "host", "backup_id": "pve-nuc", "name": "pve-nuc", "count": 14, "last_backup": _t(now, days=1, hours=2),
                    "last_state": "ok", "last_size": 3 * GB, "verify_state": "ok", "interval": day, "protected": 0})
    return {
        "servers": [{"id": "pbs", "name": "pbs", "ip": ip(BY_KEY["pbs"]), "version": "3.3.2", "online": True, "warnings": []}],
        "stores": [{"id": "main", "server_id": "pbs", "name": "main", "total": 8 * TB, "used": int(5.1 * TB), "avail": int(2.9 * TB), "full": _t(now, days=-71),
                    "gc_state": "ok", "gc_at": _t(now, days=1, hours=3), "prune_state": "ok", "prune_at": _t(now, hours=9), "verify_state": "warning", "verify_at": _t(now, days=2),
                    "sync_state": "none", "sync_at": None}],
        "targets": targets,
        "problems": [{"id": "p1", "server_id": "pbs", "kind": "backup", "state": "failed", "at": _t(now, days=2, hours=5), "text": "test-vm: the backup job failed (guest is stopped and has no snapshot support)", "target_id": "vm/106"},
                     {"id": "p2", "server_id": "pbs", "kind": "verify", "state": "warning", "at": _t(now, days=2), "text": "media-vm: one chunk could not be verified and was re-read", "target_id": "vm/105"}],
    }


def vuln_data(now: datetime) -> dict:
    def finding(fid, key, title, severity, score, port, cves=(), exploited=False, days=20, solution=""):
        s = BY_KEY[key]
        return {"id": fid, "server_id": "gvm", "host_ip": ip(s), "host_mac": mac(s), "host_name": s.name, "title": title, "cve": list(cves), "severity": severity, "score": score, "port": port,
                "proto": "tcp", "first_seen": _t(now, days=days), "last_seen": _t(now, days=1, hours=4), "exploited": exploited, "solution": solution, "url": ""}

    return {
        "servers": [{"id": "gvm", "name": "greenbone", "version": "22.9", "online": True, "last_scan": _t(now, days=1, hours=4), "warnings": []}],
        "findings": [
            finding("f1", "cam_attic", "Hikvision camera: command injection in the web server", "critical", 9.8, 80, ("CVE-2021-36260",), True, 41, "Install the newest firmware from the vendor. Keep the camera off the internet."),
            finding("f2", "cam_shed", "Reolink camera: authentication bypass", "high", 8.1, 80, ("CVE-2019-11001",), False, 41, "Update the firmware or remove the device from the network."),
            finding("f3", "tv_bed", "Samsung Tizen TV: outdated web engine", "medium", 6.5, 8001, ("CVE-2022-1096",), False, 33, "Check for a system update on the TV."),
            finding("f4", "nas", "OpenSSH: older version with known weaknesses", "medium", 5.3, 22, ("CVE-2023-48795",), False, 12, "Update the system and disable the weak ciphers."),
            finding("f5", "web1", "nginx: HTTP/2 rapid reset", "high", 7.5, 443, ("CVE-2023-44487",), False, 6, "Update nginx to a fixed version."),
            finding("f6", "printer", "Printer: SNMP community 'public' is open", "medium", 5.0, 161, (), False, 41, "Change the SNMP community or turn SNMP off."),
            finding("f7", "docker1", "Docker API reachable without TLS on port 2375", "high", 8.0, 2375, (), False, 41, "Put the Docker socket behind a proxy that only allows reading, or use TLS."),
            finding("f8", "rpi_docker", "Telnet service is open", "low", 3.1, 23, (), False, 41, "Turn the Telnet service off; use SSH."),
            finding("f9", "plug", "Smart plug: unencrypted local API", "info", 0.0, 80, (), False, 41, ""),
        ],
    }


def smarthome_data(now: datetime) -> dict:
    def dev(did, name, maker, model, area, protocol, via=None, battery=None, available=True, update=False, key=None, entities=2):
        s = BY_KEY.get(key) if key else None
        return {"id": did, "server_id": "ha", "name": name, "manufacturer": maker, "model": model, "area": area, "sw": "1.0", "protocol": protocol, "mac": mac(s) if s else None,
                "ip": ip(s) if s else None, "via_id": via, "available": available, "battery": battery, "battery_low": battery is not None and battery <= 20, "update": update, "url": None, "entities": entities}

    return {
        "servers": [{"id": "ha", "name": "Home Assistant", "ip": ip(BY_KEY["ha"]), "version": "2025.10.2", "online": True, "warnings": []}],
        "devices": [
            dev("z-coord", "Zigbee coordinator", "Texas Instruments", "CC2652P", "Technical room", "zigbee", key="rpi_docker", entities=1),
            dev("z-hall", "Hallway motion sensor", "Aqara", "RTCGQ11LM", "Hallway", "zigbee", "z-coord", 78, entities=4),
            dev("z-door", "Front door sensor", "Aqara", "MCCGQ11LM", "Hallway", "zigbee", "z-coord", 64, entities=3),
            dev("z-bath", "Bathroom humidity sensor", "Aqara", "WSDCGQ11LM", "Bathroom", "zigbee", "z-coord", 17, entities=4),
            dev("z-attic", "Attic temperature sensor", "Aqara", "WSDCGQ11LM", "Attic", "zigbee", "z-coord", 9, False, entities=4),
            dev("z-lamp1", "Living room lamp", "IKEA", "TRADFRI E27", "Living room", "zigbee", "z-coord", update=True, entities=3),
            dev("z-lamp2", "Kitchen light strip", "IKEA", "TRADFRI driver", "Kitchen", "zigbee", "z-coord", entities=3),
            dev("w-plug", "Kitchen smart plug", "TP-Link", "Tapo P110", "Kitchen", "wifi", key="plug", entities=5),
            dev("w-p1", "Energy meter", "HomeWizard", "P1 meter", "Technical room", "wifi", key="p1", entities=12),
            dev("w-tv", "Living room TV", "LG", "OLED55C3", "Living room", "wifi", key="tv_living", entities=6),
            dev("w-cast", "Chromecast", "Google", "Chromecast", "Attic", "wifi", key="cast", entities=2),
            dev("t-therm", "Thermostat", "Tado", "Smart Thermostat X", "Living room", "cloud", entities=6),
        ],
    }


PLUGINS = (("truenas", "storage", storage_data), ("pbs", "backup", backup_data), ("greenbone", "vulnerability", vuln_data), ("homeassistant", "inventory", smarthome_data))


def _apply(conn, now: datetime) -> None:
    from app.guestbackups import apply_backup
    from app.inventory import apply_inventory
    from app.storage import apply_storage
    from app.vulns import apply_vulns

    apply_storage(conn, "truenas", validate_output("storage", storage_data(now)), None, now)
    apply_backup(conn, "pbs", validate_output("backup", backup_data(now)), None, now)
    apply_vulns(conn, "greenbone", validate_output("vulnerability", vuln_data(now)), None, now)
    apply_inventory(conn, "homeassistant", validate_output("inventory", smarthome_data(now)), None, now)
    for plugin in ("pbs", "greenbone", "homeassistant", "truenas"):
        raw = get_setting(conn, f"plugin.{plugin}.status")
        if raw:
            status = json.loads(raw)
            status["ts"] = now.strftime(STAMP)
            set_setting(conn, f"plugin.{plugin}.status", json.dumps(status))
    conn.commit()


def _logins(conn) -> dict[str, str]:
    """Stored logins (made-up passwords) and the health monitors that use them."""
    made = {}
    for key, name, kind, fields, shared in (
        ("linux", "Linux servers (read-only)", "login", {"username": "netlens-ro", "password": "demo-password"}, True),
        ("pve", "Proxmox root login", "login", {"username": "root@pam", "password": "demo-password"}, False),
        ("win", "Windows monitoring", "login", {"username": "netlens", "password": "demo-password", "domain": "HOME"}, True),
        ("key", "Backup server key", "ssh_key", {"username": "netlens-ro", "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\ndemo-not-a-real-key\n-----END OPENSSH PRIVATE KEY-----\n"}, False),
    ):
        made[key] = credstore.create(conn, OWNER, name, kind, fields, shared=shared)["id"]
    for device_key, cred in (("pve", "linux"), ("pbs", "key"), ("rpi_docker", "linux")):
        row = conn.execute("SELECT m.id FROM host_monitors m JOIN devices d ON d.id = m.device_id WHERE d.hostname = ?", (BY_KEY[device_key].name,)).fetchone()
        if row:
            conn.execute("UPDATE host_monitors SET credential = ? WHERE id = ?", (vault.encrypt(conn, json.dumps({"credential_id": made[cred]})), row["id"]))
    conn.commit()
    return made


def _probes(conn, ids, now: datetime) -> None:
    """Host probes: two hosts have the read-only script (one with an older version, so 'update available' shows), with a few days of storage snapshots."""
    from app.hostprobe import scripts, service

    setting = json.loads(get_setting(conn, service.SETTINGS_KEY) or "{}")
    setting.setdefault("devices", {})
    setting["names_to_llm"] = False
    for key, version in (("rpi_docker", scripts.SCRIPT_VERSION - 1), ("pve", scripts.SCRIPT_VERSION)):
        device_id = ids[key]
        setting["devices"][str(device_id)] = {"enabled": True, "interval_h": 6, "provider": "static", "username": "netlens-ro", "ssh_port": 22}
        for step in range(12):                                              # three days, every six hours
            taken = (now - timedelta(hours=6 * (11 - step))).timestamp()
            growth = step * (2.4 if key == "rpi_docker" else 0.3)
            used = int((38 + growth) * GB)
            data = {"platform": "linux", "script_version": version, "partial": False,
                    "mounts": [{"mount": "/", "fs": "ext4", "size": 58 * GB, "used": used,
                                "dirs": [{"path": "/var/lib/docker", "bytes": int((21 + growth) * GB)}, {"path": "/var/log", "bytes": int((3 + growth / 2) * GB)}, {"path": "/home", "bytes": 6 * GB}],
                                "files": [{"path": "/var/log/journal/system.journal", "bytes": int((1.2 + growth / 3) * GB), "mtime": int(taken)}]}],
                    "docker": {"usage": [{"type": "Images", "total": 18, "active": 15, "bytes": 9 * GB, "reclaimable": 2 * GB}, {"type": "Containers", "total": 22, "active": 19, "bytes": int((1 + growth / 2) * GB), "reclaimable": 0}],
                               "containers": [{"name": "esphome", "status": "restarting", "layer_bytes": 300 * 1024 ** 2, "log_bytes": int((0.4 + growth / 2) * GB), "restarts": 7}]},
                    "deleted": []}
            service.store(conn, device_id, True, "locked", None, data, now=taken, reason="schedule")
    service._save(conn, setting)


def _maintenance(conn, now: datetime) -> None:
    """A weekly window for the servers: Sunday 03:00-04:00 (updates), so alerts of those devices are held back then."""
    from app import maintenance

    group = conn.execute("SELECT id FROM device_groups WHERE name = 'Servers'").fetchone()
    if group is None:
        return
    window = maintenance.clean_window({"name": "Weekly server updates", "scope": {"groups": [group["id"]]}, "schedule": {"type": "weekly", "days": [6], "start": "03:00", "end": "04:00"}, "tz": "Europe/Brussels"})
    maintenance.save_windows(conn, maintenance.load_windows(conn) + [window])


def _operations(conn, ids, now: datetime) -> None:
    """Channels (switched off: the demo never sends anything), an on-call rota, and remediation rules with a few runs. The rules only ask or suggest; nothing runs by itself."""
    from app import oncall, remediation
    from app.notify import channels

    mail = {"id": "d1a2b3c4", "type": "email", "name": "E-mail to the family", "enabled": False, "events": ["device_new", "device_offline", "service_down"],
            "settings": {"smtp_host": "smtp.example.net", "security": "starttls", "smtp_port": "587", "username": "netlens", "password": "demo-password", "from_addr": "netlens@home.example.net", "to_addrs": "admin@home.example.net"},
            "last_event_id": 0}
    channels.save_channels(conn, [mail])
    oncall.save_policy(conn, {"enabled": True, "tz": "Europe/Brussels",
                              "people": [{"name": "Anna", "channels": ["d1a2b3c4"]}, {"name": "Ben", "channels": ["d1a2b3c4"]}],
                              "shifts": [{"name": "Week rota", "days": [0, 1, 2, 3, 4, 5, 6], "start": "00:00", "end": "23:59", "people": ["anna", "ben"], "rotate": "weekly"}],
                              "overrides": [], "fallback": ["anna"]})
    rules = [
        ({"name": "Restart the scratch VM when it stops answering", "kinds": ["device_offline"], "device_id": ids["testvm"], "mode": "ask", "action": {"type": "vm", "power": "reboot"}}, "pending", None, dict(hours=2)),
        ({"name": "Wake the build server", "kinds": ["device_offline"], "device_id": ids["build"], "mode": "suggest", "action": {"type": "wake"}}, "suggested", None, dict(hours=20)),
        ({"name": "Restart the esphome container", "kinds": ["service_down"], "mode": "ask", "action": {"type": "ssh", "command": "docker restart esphome"}}, "ok", "Ran on rpi-docker: esphome restarted", dict(days=1, hours=3)),
    ]
    for data, state, result, ago in rules:
        rule = remediation.save_rule(conn, data)
        created = _t(now, **ago)
        conn.execute("INSERT INTO remediation_runs (rule_id, rule_name, action_type, device_id, kind, detail, state, result, created, decided_by, decided_at, finished) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                     (rule["id"], rule["name"], data["action"]["type"], data.get("device_id"), data["kinds"][0], "", state, result, created,
                      "demo" if state == "ok" else None, created if state == "ok" else None, created if state == "ok" else None))
    conn.commit()


def _trial(conn, data_dir, now: datetime) -> None:
    """The demo runs with the features of the full version switched on (the trial), and starts the trial over at every reset so it never ends."""
    from app import licence

    stamp = (now - timedelta(days=1)).strftime(STAMP)
    set_setting(conn, licence.TRIAL_SETTING, stamp)
    try:
        (data_dir / licence.MARKER).write_text(stamp + "\n")
    except OSError:
        pass


def seed(conn, data_dir, ids, now: datetime) -> None:
    _trial(conn, data_dir, now)
    _apply(conn, now)
    _logins(conn)
    _probes(conn, ids, now)
    _maintenance(conn, now)
    _operations(conn, ids, now)
    set_setting(conn, "demo.extras", now.strftime(STAMP))
    conn.commit()


def refresh(conn, now: datetime) -> None:
    """Every half hour: report the same picture again with recent times (the plugins would have synced)."""
    last = get_setting(conn, "demo.extras")
    if last and now - datetime.strptime(last, STAMP).replace(tzinfo=timezone.utc) < REFRESH_EVERY:
        return
    _apply(conn, now)
    set_setting(conn, "demo.extras", now.strftime(STAMP))
    conn.commit()
