import sqlite3
from app.notify.config import NotifyConfig


def current_max_event_id(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT MAX(id) AS max_id FROM events").fetchone()
    return row["max_id"] if row["max_id"] is not None else 0


def collect_events(
    conn: sqlite3.Connection, after_id: int, cfg: NotifyConfig
) -> tuple[list[dict], int]:
    rows = conn.execute(
        """
        SELECT e.id, e.ts, e.kind, e.device_id, e.detail,
               d.custom_name, d.hostname, d.primary_ip, d.mac, d.vendor, d.notify_offline
        FROM events e
        LEFT JOIN devices d ON d.id = e.device_id
        WHERE e.id > ?
        ORDER BY e.id
        """,
        (after_id,),
    ).fetchall()

    kept: list[dict] = []
    max_seen = after_id

    for row in rows:
        max_seen = row["id"]

        if row["kind"] == "device_new" and cfg.notify_new:
            detail = row["detail"] or ""
            first_word = detail.split()[0] if detail else ""
            name = row["custom_name"] or row["hostname"] or row["primary_ip"] or first_word or "unknown device"
            ip = row["primary_ip"] or first_word
            kept.append({
                "id": row["id"],
                "ts": row["ts"],
                "kind": row["kind"],
                "device_id": row["device_id"],
                "name": name,
                "ip": ip,
                "mac": row["mac"],
                "vendor": row["vendor"],
            })
        elif row["kind"] == "device_offline" and cfg.notify_offline:
            if row["device_id"] is None or row["notify_offline"] != 1:
                continue
            detail = row["detail"] or ""
            first_word = detail.split()[0] if detail else ""
            name = row["custom_name"] or row["hostname"] or row["primary_ip"] or first_word or "unknown device"
            ip = row["primary_ip"] or first_word
            kept.append({
                "id": row["id"],
                "ts": row["ts"],
                "kind": row["kind"],
                "device_id": row["device_id"],
                "name": name,
                "ip": ip,
                "mac": row["mac"],
                "vendor": row["vendor"],
            })

    return kept, max_seen


def build_message(events: list[dict], app_name: str = "Netlens") -> tuple[str, str]:
    if not events:
        return ("", "")

    new_events = [e for e in events if e["kind"] == "device_new"]
    offline_events = [e for e in events if e["kind"] == "device_offline"]

    parts: list[str] = []
    if new_events:
        n = len(new_events)
        parts.append(f"{n} new device{'s' if n > 1 else ''}")
    if offline_events:
        n = len(offline_events)
        parts.append(f"{n} device{'s' if n > 1 else ''} offline")

    subject = f"[{app_name}] " + ", ".join(parts)

    lines: list[str] = []
    if new_events:
        lines.append("New devices:")
        for e in new_events:
            lines.append(f"  - {e['name']} ({e['ip']}) MAC {e['mac'] or '-'} vendor {e['vendor'] or '-'} at {e['ts']}")
        lines.append("")

    if offline_events:
        lines.append("Went offline:")
        for e in offline_events:
            lines.append(f"  - {e['name']} ({e['ip']}) at {e['ts']}")

    lines.append("")
    lines.append(f"-- sent by {app_name}")

    body = "\n".join(lines)
    return subject, body