"""What a backup plugin (Proxmox Backup Server ...) reports, tied to the guests Netlens knows.

Every *target* of the plugin (the backups of one VM, container or host) is matched to a guest of a hypervisor plugin by its id (the Proxmox VM id),
and through the guest to the device. From that Netlens works out per guest: the last backup and its age, whether it failed, whether it is late
(older than the usual interval of that guest), and which guests have no backup at all. Events are only written when something *changes* (a backup
starts failing, a guest becomes late, a store is on course to fill up, a problem is over), never on every sync.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from app.db import add_event

STAMP = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_LATE = timedelta(hours=36)          # no interval known: a daily backup that is a day and a half old is late
MIN_LATE = timedelta(hours=6)
LATE_FACTOR = 2.5                           # late = older than this many usual intervals
ACTIVE_ORPHAN = timedelta(days=14)          # a host or unmatched target that has not been backed up for this long is retired, not late
GUEST_KINDS = {"vm": ("qemu", "vm"), "ct": ("lxc", "ct")}
FULL_WARN_DAYS, FULL_CRITICAL_DAYS = 30, 3


def _parse(text: str | None) -> datetime | None:
    try:
        return datetime.strptime(text, STAMP).replace(tzinfo=timezone.utc) if text else None
    except (TypeError, ValueError):
        return None


def late_after(interval: int | None) -> timedelta:
    """How old the newest backup may be before it counts as late."""
    if not interval:
        return DEFAULT_LATE
    return max(MIN_LATE, timedelta(seconds=interval * LATE_FACTOR))


def _guests(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT plugin_id, guest_id, name, kind, status, device_id FROM hypervisor_guests WHERE kind IN ('qemu', 'vm', 'lxc', 'ct')").fetchall()


def match_guest(target: dict, guests: list[sqlite3.Row]) -> sqlite3.Row | None:
    kinds = GUEST_KINDS.get(target["type"])
    if not kinds:
        return None
    found = [g for g in guests if str(g["guest_id"]) == str(target["backup_id"]) and g["kind"] in kinds]
    if len(found) > 1 and target["name"]:          # two hypervisors with the same id: the name that was saved with the backup tells them apart
        named = [g for g in found if (g["name"] or "").lower() == target["name"].lower()]
        found = named or found
    return found[0] if found else None


def _level(full: str | None, now: datetime) -> str:
    when = _parse(full)
    if when is None:
        return "ok"
    days = (when - now).total_seconds() / 86400
    return "critical" if days <= FULL_CRITICAL_DAYS else "warning" if days <= FULL_WARN_DAYS else "ok"


def is_late(row: dict, matched: bool, now: datetime) -> bool:
    last = _parse(row["last_backup"])
    if last is None:
        return False
    age = now - last
    if not matched and age > ACTIVE_ORPHAN:
        return False                                  # nothing in Netlens to blame: an old backup of something that is gone
    return age > late_after(row["interval"])


def _label(row: dict) -> str:
    return f"{row['name'] or row['backup_id']} ({row['type']} {row['backup_id']})" if row["type"] in ("vm", "ct") else (row["name"] or row["backup_id"])


def apply_backup(conn: sqlite3.Connection, plugin_id: str, data: dict, config: dict | None = None, now: datetime | None = None) -> dict:
    """Store a backup plugin's output, match the targets to guests and write the events for what changed. Returns the summary."""
    now = now or datetime.now(timezone.utc)
    stamp = now.strftime(STAMP)
    before = {r["target_id"]: dict(r) for r in conn.execute("SELECT * FROM backup_targets WHERE plugin_id = ?", (plugin_id,))}
    store_before = {r["store_id"]: r["level"] for r in conn.execute("SELECT store_id, level FROM backup_stores WHERE plugin_id = ?", (plugin_id,))}
    seen_before = {r["problem_id"] for r in conn.execute("SELECT problem_id FROM backup_problems WHERE plugin_id = ?", (plugin_id,))}
    for table in ("backup_servers", "backup_stores", "backup_targets", "backup_problems"):
        conn.execute(f"DELETE FROM {table} WHERE plugin_id = ?", (plugin_id,))
    by_ip = {r["primary_ip"]: r["id"] for r in conn.execute("SELECT id, primary_ip FROM devices WHERE primary_ip IS NOT NULL")}
    names = {s["id"]: s["name"] for s in data["servers"]}
    for s in data["servers"]:
        conn.execute("INSERT INTO backup_servers (plugin_id, server_id, name, ip, version, online, device_id, warnings, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (plugin_id, s["id"], s["name"], s["ip"], s["version"], int(s["online"]), by_ip.get(s["ip"]), json.dumps(s["warnings"]), stamp))
    events = 0
    for st in data["stores"]:
        level = _level(st["full"], now)
        conn.execute(
            """INSERT INTO backup_stores (plugin_id, store_id, server_id, name, total, used, avail, full, level, gc_state, gc_at, prune_state, prune_at, verify_state, verify_at, sync_state, sync_at, updated)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (plugin_id, st["id"], st["server_id"], st["name"], st["total"], st["used"], st["avail"], st["full"], level, st["gc_state"], st["gc_at"], st["prune_state"], st["prune_at"],
             st["verify_state"], st["verify_at"], st["sync_state"], st["sync_at"], stamp))
        old = store_before.get(st["id"], "ok")
        if level != "ok" and level != old and (old == "ok" or level == "critical"):
            days = max(0, int((_parse(st["full"]) - now).total_seconds() // 86400))
            add_event(conn, "capacity_critical" if level == "critical" else "capacity_warning", f"Backup store {st['name']} on {names.get(st['server_id'], st['server_id'])} is on course to be full in {days} day{'s' if days != 1 else ''}",
                      now=stamp, subject=f"backupstore:{plugin_id}:{st['id']}")
            events += 1
    guests = _guests(conn)
    late = failed = 0
    for t in data["targets"]:
        guest = match_guest(t, guests)
        row = {"type": t["type"], "backup_id": t["backup_id"], "name": t["name"], "last_backup": t["last_backup"], "interval": t["interval"]}
        stale = is_late(row, guest is not None, now)
        conn.execute(
            """INSERT INTO backup_targets (plugin_id, target_id, server_id, store_id, type, backup_id, name, count, last_backup, last_state, last_size, verify_state, interval, protected,
                                           guest_plugin_id, guest_id, device_id, stale, updated)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (plugin_id, t["id"], t["server_id"], t["store_id"], t["type"], t["backup_id"], t["name"], t["count"], t["last_backup"], t["last_state"], t["last_size"], t["verify_state"],
             t["interval"], t["protected"], guest["plugin_id"] if guest else None, guest["guest_id"] if guest else None, guest["device_id"] if guest else None, int(stale), stamp))
        late += 1 if stale else 0
        failed += 1 if t["last_state"] == "failed" else 0
        old = before.get(t["id"])
        if old is None:
            continue                                              # the first sync after switching the plugin on is not news
        who, device_id = _label({**t, "name": t["name"] or (guest["name"] if guest else "")}), guest["device_id"] if guest else None
        subject = f"guest-backup:{plugin_id}:{t['id']}"
        if t["last_state"] == "failed" and old["last_state"] != "failed":
            add_event(conn, "guest_backup_failed", f"{who}: the last backup failed", device_id=device_id, now=stamp, subject=subject)
            events += 1
        elif stale and not old["stale"] and t["last_state"] != "failed":
            add_event(conn, "guest_backup_late", f"{who}: no new backup since {t['last_backup']}", device_id=device_id, now=stamp, subject=subject)
            events += 1
        elif not stale and t["last_state"] == "ok" and (old["stale"] or old["last_state"] == "failed"):
            add_event(conn, "guest_backup_recovered", f"{who}: backed up again", device_id=device_id, now=stamp, subject=subject)
            events += 1
    for p in data["problems"]:
        conn.execute("INSERT INTO backup_problems (plugin_id, problem_id, server_id, kind, state, at, text, target_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                     (plugin_id, p["id"], p["server_id"], p["kind"], p["state"], p["at"], p["text"], p["target_id"]))
    conn.commit()
    return {"servers": len(data["servers"]), "stores": len(data["stores"]), "targets": len(data["targets"]), "late": late, "failed": failed,
            "problems": len(data["problems"]), "events": events, "matched": conn.execute("SELECT COUNT(*) FROM backup_targets WHERE plugin_id = ? AND guest_id IS NOT NULL", (plugin_id,)).fetchone()[0]}


def remove_plugin(conn: sqlite3.Connection, plugin_id: str) -> None:
    for table in ("backup_servers", "backup_stores", "backup_targets", "backup_problems"):
        conn.execute(f"DELETE FROM {table} WHERE plugin_id = ?", (plugin_id,))
    conn.commit()


# ----------------------------------------------------------------------------- for the API
def _age(text: str | None, now: datetime) -> int | None:
    when = _parse(text)
    return None if when is None else max(0, int((now - when).total_seconds()))


def unprotected(conn: sqlite3.Connection) -> list[dict]:
    """Guests (virtual machines and containers of the hypervisor plugins) that no backup target is matched to. Empty until a backup plugin has data."""
    if not conn.execute("SELECT 1 FROM backup_targets LIMIT 1").fetchone():
        return []
    rows = conn.execute(
        """SELECT g.plugin_id, g.guest_id, g.name, g.kind, g.status, g.device_id FROM hypervisor_guests g
           WHERE g.kind IN ('qemu', 'vm', 'lxc', 'ct')
             AND NOT EXISTS (SELECT 1 FROM backup_targets t WHERE t.guest_plugin_id = g.plugin_id AND t.guest_id = g.guest_id)
           ORDER BY g.name COLLATE NOCASE"""
    ).fetchall()
    return [{"plugin_id": r["plugin_id"], "guest_id": r["guest_id"], "name": r["name"], "kind": r["kind"], "status": r["status"], "device_id": r["device_id"]} for r in rows]


def overview(conn: sqlite3.Connection, now: datetime | None = None) -> dict[str, Any]:
    """Everything the Backups page shows."""
    now = now or datetime.now(timezone.utc)
    devices = {r["id"]: r["custom_name"] or r["hostname"] or r["primary_ip"] or f"device {r['id']}" for r in conn.execute("SELECT id, custom_name, hostname, primary_ip FROM devices")}
    servers = [{"plugin_id": r["plugin_id"], "id": r["server_id"], "name": r["name"], "ip": r["ip"], "version": r["version"], "online": bool(r["online"]), "device_id": r["device_id"],
                "device": devices.get(r["device_id"]), "warnings": json.loads(r["warnings"] or "[]")} for r in conn.execute("SELECT * FROM backup_servers ORDER BY name COLLATE NOCASE")]
    stores = []
    for r in conn.execute("SELECT * FROM backup_stores ORDER BY name COLLATE NOCASE"):
        days = None if not _parse(r["full"]) else int((_parse(r["full"]) - now).total_seconds() // 86400)
        stores.append({"plugin_id": r["plugin_id"], "id": r["store_id"], "server_id": r["server_id"], "name": r["name"], "total": r["total"], "used": r["used"], "avail": r["avail"],
                       "percent": round(r["used"] / r["total"] * 100, 1) if r["total"] and r["used"] is not None else None, "full": r["full"], "days_to_full": days, "level": r["level"],
                       **{f"{j}_{k}": r[f"{j}_{k}"] for j in ("gc", "prune", "verify", "sync") for k in ("state", "at")}})
    targets = []
    for r in conn.execute("SELECT * FROM backup_targets ORDER BY name COLLATE NOCASE, backup_id"):
        age = _age(r["last_backup"], now)
        targets.append({"plugin_id": r["plugin_id"], "id": r["target_id"], "server_id": r["server_id"], "store_id": r["store_id"], "type": r["type"], "backup_id": r["backup_id"],
                        "name": r["name"] or f"{r['type']} {r['backup_id']}", "count": r["count"], "last_backup": r["last_backup"], "age_s": age, "last_state": r["last_state"], "last_size": r["last_size"],
                        "verify_state": r["verify_state"], "interval": r["interval"], "protected": r["protected"], "late": bool(r["stale"]), "matched": r["guest_id"] is not None,
                        "guest_plugin_id": r["guest_plugin_id"], "guest_id": r["guest_id"], "device_id": r["device_id"], "device": devices.get(r["device_id"])})
    problems = [{"plugin_id": r["plugin_id"], "id": r["problem_id"], "server_id": r["server_id"], "kind": r["kind"], "state": r["state"], "at": r["at"], "text": r["text"], "target_id": r["target_id"]}
                for r in conn.execute("SELECT * FROM backup_problems ORDER BY at DESC")]
    missing = unprotected(conn)
    guests_total = conn.execute("SELECT COUNT(*) FROM hypervisor_guests WHERE kind IN ('qemu', 'vm', 'lxc', 'ct')").fetchone()[0]
    matched = sum(1 for t in targets if t["matched"])
    return {"servers": servers, "stores": stores, "targets": targets, "problems": problems, "unprotected": missing,
            "summary": {"configured": bool(servers), "guests": guests_total, "protected": guests_total - len(missing) if servers else 0, "unprotected": len(missing), "targets": len(targets), "matched": matched,
                        "failed": sum(1 for t in targets if t["last_state"] == "failed"), "late": sum(1 for t in targets if t["late"]), "stores_at_risk": sum(1 for s in stores if s["level"] != "ok"),
                        "problems": len(problems)}}


def summary(conn: sqlite3.Connection) -> dict[str, Any]:
    """The few numbers of the dashboard card, the attention list and /metrics (cheap: counts only)."""
    servers = conn.execute("SELECT COUNT(*) FROM backup_servers").fetchone()[0]
    if not servers:
        return {"configured": False, "targets": 0, "failed": 0, "late": 0, "unprotected": 0, "guests": 0, "protected": 0, "stores_at_risk": 0, "problems": 0, "newest": None}
    guests = conn.execute("SELECT COUNT(*) FROM hypervisor_guests WHERE kind IN ('qemu', 'vm', 'lxc', 'ct')").fetchone()[0]
    matched = conn.execute(
        """SELECT COUNT(*) FROM hypervisor_guests g WHERE g.kind IN ('qemu', 'vm', 'lxc', 'ct')
           AND EXISTS (SELECT 1 FROM backup_targets t WHERE t.guest_plugin_id = g.plugin_id AND t.guest_id = g.guest_id)""").fetchone()[0]
    one = lambda sql: conn.execute(sql).fetchone()[0]    # noqa: E731 - fixed statements, no user input
    return {"configured": True, "targets": one("SELECT COUNT(*) FROM backup_targets"), "failed": one("SELECT COUNT(*) FROM backup_targets WHERE last_state = 'failed'"),
            "late": one("SELECT COUNT(*) FROM backup_targets WHERE stale = 1"), "unprotected": guests - matched, "guests": guests, "protected": matched,
            "stores_at_risk": one("SELECT COUNT(*) FROM backup_stores WHERE level != 'ok'"), "problems": one("SELECT COUNT(*) FROM backup_problems"),
            "newest": conn.execute("SELECT MAX(last_backup) FROM backup_targets").fetchone()[0]}


def for_device(conn: sqlite3.Connection, device_id: int, now: datetime | None = None) -> dict | None:
    """The backup state of a guest device (None when no backup target is matched to it)."""
    now = now or datetime.now(timezone.utc)
    rows = conn.execute("SELECT * FROM backup_targets WHERE device_id = ? ORDER BY last_backup DESC", (device_id,)).fetchall()
    if not rows:
        return None
    r = rows[0]
    return {"plugin_id": r["plugin_id"], "type": r["type"], "backup_id": r["backup_id"], "count": r["count"], "last_backup": r["last_backup"], "age_s": _age(r["last_backup"], now),
            "last_state": r["last_state"], "last_size": r["last_size"], "verify_state": r["verify_state"], "late": bool(r["stale"]), "interval": r["interval"]}
