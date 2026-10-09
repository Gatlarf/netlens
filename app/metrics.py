"""Prometheus metrics (text exposition format 0.0.4) built from the same data as the Statistics page."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from app.db import utcnow
from app.stats import _ago, compute_stats, summary
from app.version import VERSION


def _esc(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _ts(value: str | None) -> float | None:
    if not value:
        return None
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()


class _Out:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self._declared: set[str] = set()

    def sample(self, name: str, value: float | int | None, help_text: str, type_: str = "gauge", /, **labels: object) -> None:
        if value is None:
            return
        if name not in self._declared:
            self._declared.add(name)
            self.lines.append(f"# HELP {name} {help_text}")
            self.lines.append(f"# TYPE {name} {type_}")
        label_text = "{" + ",".join(f'{k}="{_esc(v)}"' for k, v in labels.items()) + "}" if labels else ""
        self.lines.append(f"{name}{label_text} {value:g}" if isinstance(value, float) else f"{name}{label_text} {value}")


def render_metrics(conn: sqlite3.Connection, now: str | None = None, scan_running: bool = False, data_dir=None, passive: dict | None = None) -> str:
    now = now or utcnow()
    doc = summary(conn, now, scan_running=scan_running, data_dir=data_dir, passive=passive)
    db_file = next((r[2] for r in conn.execute("PRAGMA database_list") if r[1] == "main"), None)
    stats = compute_stats(conn, "24h", now, db_path=db_file or None)
    out = _Out()
    out.sample("netlens_info", 1, "Netlens version", version=VERSION)
    for state in ("total", "online", "offline", "unknown"):
        out.sample("netlens_devices", doc["devices"][state] if state != "total" else doc["devices"]["total"], "Devices by state (total counts every device)", state=state)
    out.sample("netlens_devices_new", doc["devices"]["new_24h"], "Devices first seen in the last 24 hours")
    out.sample("netlens_devices_flapping", doc["devices"]["flapping"], "Devices that changed between online and offline at least 6 times in the last 24 hours")
    for t in stats["composition"]["by_type"]:
        out.sample("netlens_devices_by_type", t["count"], "Devices by type", type=t["label"])
    for g in stats["composition"]["by_group"]:
        out.sample("netlens_devices_by_group", g["count"], "Devices by group", group=g["label"])
    for kind, count in doc["identification"].items():
        out.sample("netlens_identification_devices", count, "Devices by how well Netlens knows them (unknown_type, private_mac, no_vendor, manual_type, gentle, nameless, no_os)", kind=kind)
    out.sample("netlens_uptime_ratio", None if doc["uptime"]["24h"] is None else doc["uptime"]["24h"] / 100, "Share of successful presence checks", window="24h")
    out.sample("netlens_uptime_ratio", None if doc["uptime"]["7d"] is None else doc["uptime"]["7d"] / 100, "Share of successful presence checks", window="7d")
    out.sample("netlens_open_ports", doc["ports"]["open"], "Open ports found on all devices")
    out.sample("netlens_events_24h", doc["events"]["24h"], "Events logged in the last 24 hours")
    out.sample("netlens_update_available", 1 if doc["update"]["available"] else 0, "1 when a newer Netlens version has been published")
    out.sample("netlens_plugin_updates_available", doc["update"]["plugin_updates"], "Installed plugins that have a newer release in the plugin index")
    out.sample("netlens_problem", 1 if doc["problem"] else 0, "1 when Netlens sees a problem (failed scan, failing plugin or service, old scan)")

    for d in doc["device_list"]:
        labels = {"name": d["name"], "ip": d["ip"] or "", "mac": d["mac"] or "", "type": d["type"]}
        out.sample("netlens_device_up", 1 if d["online"] else 0, "1 when the device is online", **labels)
        out.sample("netlens_device_last_seen_timestamp_seconds", _ts(d["last_seen"]), "When the device was last seen", **labels)

    scans = conn.execute("SELECT kind, status, COUNT(*) AS n FROM scans GROUP BY kind, status").fetchall()
    for r in scans:
        out.sample("netlens_scans_total", r["n"], "Scans recorded, by kind and status", "counter", kind=r["kind"], status=r["status"])
    for kind in sorted({r["kind"] for r in scans}):
        last = conn.execute("SELECT started, finished, hosts_found FROM scans WHERE kind = ? AND status = 'done' AND finished IS NOT NULL ORDER BY id DESC LIMIT 1", (kind,)).fetchone()
        if last:
            out.sample("netlens_scan_last_success_timestamp_seconds", _ts(last["finished"]), "When the last successful scan of this kind finished", kind=kind)
            out.sample("netlens_scan_last_duration_seconds", _ts(last["finished"]) - _ts(last["started"]), "How long the last successful scan of this kind took", kind=kind)
            out.sample("netlens_scan_hosts_found", last["hosts_found"], "Hosts found by the last successful scan of this kind", kind=kind)
    out.sample("netlens_scan_running", 1 if scan_running else 0, "1 while a scan is running")
    out.sample("netlens_scans_failed_24h", doc["scans"]["failed_24h"], "Scans that failed in the last 24 hours")

    b = doc["backup"]
    out.sample("netlens_backup_enabled", 1 if b["enabled"] else 0, "1 when scheduled backups are switched on")
    if b["last_ok"] is not None:
        out.sample("netlens_backup_last_ok", 1 if b["last_ok"] else 0, "1 when the last scheduled backup worked")
        out.sample("netlens_backup_last_timestamp_seconds", _ts(b["last_at"]), "When the last scheduled backup was attempted")
    nc = doc["netchecks"]
    out.sample("netlens_dhcp_servers", nc["dhcp_servers"] - nc["untrusted"], "DHCP servers found on the network, by whether they are trusted", trusted="true")
    out.sample("netlens_dhcp_servers", nc["untrusted"], "DHCP servers found on the network, by whether they are trusted", trusted="false")

    sys_info = stats["system"]
    out.sample("netlens_database_size_bytes", sys_info["db_bytes"], "Size of the Netlens database file")
    out.sample("netlens_vendor_registry_entries", sys_info["vendor_entries"], "Manufacturers in the MAC address registry")
    for table, count in sys_info["rows"].items():
        out.sample("netlens_database_rows", count, "Rows in the main database tables", table=table)
    p = doc["passive"]
    if p is not None:
        out.sample("netlens_passive_running", 1 if p["running"] else 0, "1 while passive listening (DHCP / mDNS / SSDP) runs")
        out.sample("netlens_passive_announcements_total", p["frames"], "Device announcements heard since Netlens started", "counter")
        out.sample("netlens_passive_devices_updated_total", p["applied"], "Devices updated from announcements since Netlens started", "counter")

    for e in stats["events"]["by_kind"]:
        out.sample("netlens_events_by_kind_24h", e["count"], "Events in the last 24 hours, by kind", kind=e["label"])

    for p in doc["plugins"]:
        if p["enabled"]:
            out.sample("netlens_plugin_up", 1 if p["ok"] else 0, "1 when the plugin's last sync worked", plugin=p["id"])
            out.sample("netlens_plugin_last_sync_timestamp_seconds", _ts(p["ts"]), "When the plugin last synced", plugin=p["id"])

    for c in stats["services"]["checks"]:
        if c["enabled"] and c["state"] is not None:
            out.sample("netlens_service_up", 1 if c["state"] == "up" else 0, "1 when the service check is up", name=c["name"], kind=c["kind"])
            out.sample("netlens_service_response_seconds", None if c["ms"] is None else c["ms"] / 1000, "Response time of the last service check", name=c["name"])

    w = stats["wifi"]
    out.sample("netlens_wifi_clients", w["clients"], "Wi-Fi clients seen in the last two hours")
    out.sample("netlens_wifi_weak_clients", w["weak"], "Wi-Fi clients with a signal below -75 dBm")
    for r in conn.execute(
        "SELECT COALESCE(d.custom_name, d.hostname, d.primary_ip) AS n, s.node, s.band, s.rssi FROM wifi_samples s JOIN devices d ON d.id = s.device_id "
        "WHERE s.id = (SELECT MAX(id) FROM wifi_samples WHERE device_id = d.id) AND s.ts >= ? AND s.rssi IS NOT NULL", (_ago(now, hours=2),)):
        out.sample("netlens_wifi_signal_dbm", r["rssi"], "Signal strength of a Wi-Fi client", device=r["n"], node=r["node"] or "", band=r["band"] or "")
    return "\n".join(out.lines) + "\n"
