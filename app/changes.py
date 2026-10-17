"""What changed: one timeline of everything that happened, for "what went on last night?".

It merges the events Netlens raised (devices that appeared or went away, alerts, address changes, ports that opened) with the
changes people made (the audit log, administrators only) and sorts them by time. Nothing new is stored: it is a view.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

CATEGORIES = {
    "devices": "Devices",
    "availability": "Up and down",
    "health": "Health and capacity",
    "network": "Network",
    "security": "Security",
    "settings": "Changes made",
}
KIND_CATEGORY = {
    "device_new": "devices", "device_deleted": "devices", "ip_changed": "devices", "ip_reused": "devices", "os_changed": "devices", "wifi_roamed": "devices",
    "wake_sent": "devices",
    "device_offline": "availability", "device_online": "availability", "service_up": "availability", "service_down": "availability",
    "probe_offline": "availability", "probe_online": "availability",
    "metric_warning": "health", "metric_critical": "health", "metric_ok": "health", "capacity_warning": "health", "capacity_critical": "health", "anomaly": "health",
    "cert_expiring": "health", "backup_failed": "health",
    "gateway_changed": "network", "dns_failed": "network", "dhcp_rogue": "network",
    "port_unexpected": "security", "login_failed": "security",
}
# routine noise a person asking "what changed" does not want between the real changes
QUIET = {"wake_sent"}
STAMP = "%Y-%m-%dT%H:%M:%SZ"
PERIODS = {"6h": 6, "24h": 24, "3d": 72, "7d": 168, "30d": 720}


def category_of(kind: str) -> str:
    if kind in KIND_CATEGORY:
        return KIND_CATEGORY[kind]
    if kind.startswith(("service_", "probe_", "device_")):
        return "availability" if kind.endswith(("_up", "_down", "_online", "_offline")) else "devices"
    return "health" if kind.startswith(("metric_", "capacity_")) else "network"


def timeline(conn: sqlite3.Connection, period: str = "24h", category: str = "", include_audit: bool = False, limit: int = 300,
             now: datetime | None = None) -> dict[str, Any]:
    hours = PERIODS.get(period, 24)
    now = now or datetime.now(timezone.utc)
    since = (now - timedelta(hours=hours)).strftime(STAMP)
    limit = max(1, min(int(limit), 1000))
    items: list[dict[str, Any]] = []
    names = {r["id"]: r["name"] for r in conn.execute("SELECT id, COALESCE(custom_name, hostname, primary_ip) AS name FROM devices")}
    for r in conn.execute("SELECT id, ts, device_id, kind, detail FROM events WHERE ts >= ? ORDER BY id DESC LIMIT ?", (since, 2000)):
        if r["kind"] in QUIET:
            continue
        items.append({"ts": r["ts"], "category": category_of(r["kind"]), "kind": r["kind"], "text": r["detail"] or r["kind"].replace("_", " "),
                      "device_id": r["device_id"], "device": names.get(r["device_id"]), "who": None})
    if include_audit:
        for r in conn.execute("SELECT ts, user, action, path, status FROM audit_log WHERE ts >= ? AND status < 400 AND method != 'GET' AND path NOT LIKE '/api/login%' AND path NOT LIKE '/api/logout%' ORDER BY id DESC LIMIT ?", (since, 1000)):
            action = r["action"]
            items.append({"ts": r["ts"], "category": "settings", "kind": "change", "text": action, "device_id": None, "device": None, "who": r["user"] or None})
    counts: dict[str, int] = {}
    for it in items:
        counts[it["category"]] = counts.get(it["category"], 0) + 1
    if category in CATEGORIES:
        items = [it for it in items if it["category"] == category]
    items.sort(key=lambda it: it["ts"], reverse=True)
    return {"since": since, "period": period if period in PERIODS else "24h", "total": len(items), "counts": counts,
            "categories": {k: v for k, v in CATEGORIES.items() if include_audit or k != "settings"}, "items": items[:limit]}
