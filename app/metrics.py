"""Prometheus metrics (text exposition format 0.0.4) built from the same data as the Statistics page."""

from __future__ import annotations

import sqlite3

from app import sites
from app.db import utcnow
from app.stats import _ago, _parse, _shared, compute_stats, summary
from app.version import VERSION


def _esc(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _parse_now(now: str) -> float:
    return _parse(now).timestamp()


def _ts(value: str | None) -> float | None:
    if not value:
        return None
    return _parse(value).timestamp()


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


@_shared
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
    core = doc.get("core") or {}
    if core.get("devices"):
        out.sample("netlens_core_devices", core["devices"], "Devices marked as always on")
        out.sample("netlens_core_devices_online", core["online"], "Always-on devices that are online now")
        out.sample("netlens_core_uptime_ratio", None if core["uptime"]["24h"] is None else core["uptime"]["24h"] / 100, "Share of successful presence checks of the always-on devices", window="24h")
        out.sample("netlens_core_uptime_ratio", None if core["uptime"]["7d"] is None else core["uptime"]["7d"] / 100, "Share of successful presence checks of the always-on devices", window="7d")
        out.sample("netlens_core_uptime_ratio", None if core["uptime"]["30d"] is None else core["uptime"]["30d"] / 100, "Share of successful presence checks of the always-on devices", window="30d")
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

    for state, count in doc["dns"].items():
        out.sample("netlens_dns_devices", count, "Devices by DNS registration state (registered, pending, conflicts, registers_itself, waiting)", state=state)

    c = doc["containers"]
    if c["total"]:
        for state in ("running", "stopped", "restarting"):
            out.sample("netlens_containers", c[state], "Containers reported by container plugins (Docker), by state", state=state)
        out.sample("netlens_containers_unhealthy", c["unhealthy"], "Containers whose health check is failing")
        out.sample("netlens_containers_exposed", c["exposed"], "Running containers that publish a port on all interfaces")
        out.sample("netlens_container_hosts", c["hosts"], "Container hosts reported by container plugins")

    g = doc["guests"]
    if g["total"]:
        for kind, k in sorted(g["by_kind"].items()):
            out.sample("netlens_guests", k["running"], "Guests reported by hypervisor and container plugins, by kind and state", kind=kind, state="running")
            out.sample("netlens_guests", k["total"] - k["running"], "Guests reported by hypervisor and container plugins, by kind and state", kind=kind, state="not_running")
        out.sample("netlens_guests_update_available", g["update_available"], "Guests (apps) with an update available")
        out.sample("netlens_containers_old_images", g["old_images"], "Running containers whose image was built more than a year ago")
        out.sample("netlens_containers_image_updates", g["image_updates"], "Containers whose image tag now points to a newer image in the registry")

    st = doc["sites"]
    if st["total"]:
        out.sample("netlens_sites", st["enabled"], "Sites published by reverse proxies, by state", state="enabled")
        out.sample("netlens_sites", st["total"] - st["enabled"], "Sites published by reverse proxies, by state", state="disabled")
        out.sample("netlens_sites_unmatched", st["unmatched"], "Enabled proxy sites that Netlens could not tie to a device or container")
        out.sample("netlens_sites_down", st["down"], "Sites whose check fails (a server error or no answer)")
        for cert in sites.certificates(conn):
            out.sample("netlens_certificate_expires_timestamp_seconds", _ts(cert["expires"]), "When a certificate used by a reverse proxy site ends", certificate=cert["name"], proxy=cert["proxy"] or "")
            out.sample("netlens_certificate_days_left", cert["days"], "Days until a certificate used by a reverse proxy site ends (negative: expired)", certificate=cert["name"], proxy=cert["proxy"] or "")

    gb = doc.get("guest_backups") or {}
    if gb.get("configured"):
        from app import guestbackups

        view = guestbackups.overview(conn)
        out.sample("netlens_backup_guests_unprotected", gb["unprotected"], "Guests (virtual machines and containers) that no backup is matched to")
        out.sample("netlens_backup_targets_failed", gb["failed"], "Backed up guests or hosts whose last backup failed")
        out.sample("netlens_backup_targets_late", gb["late"], "Backed up guests or hosts without a new backup for longer than usual")
        for t in view["targets"]:
            labels = {"name": t["name"], "type": t["type"], "id": t["backup_id"]}
            if t["age_s"] is not None:
                out.sample("netlens_backup_age_seconds", t["age_s"], "Seconds since the newest backup of a guest or host", **labels)
            out.sample("netlens_backup_last_ok", 0 if t["last_state"] == "failed" else 1, "0 when the last backup of a guest or host failed", **labels)
        for st in view["stores"]:
            labels = {"store": st["name"]}
            for key, name, helptext in (("used", "used_bytes", "Bytes used"), ("total", "total_bytes", "Size in bytes")):
                if st[key] is not None:
                    out.sample(f"netlens_backup_store_{name}", st[key], f"{helptext} of a backup datastore", **labels)
            if st["days_to_full"] is not None:
                out.sample("netlens_backup_store_days_to_full", st["days_to_full"], "Days until the datastore is expected to be full (the backup server's own estimate)", **labels)

    sp = doc["speed"]
    if sp["internet"]:
        net = sp["internet"]
        out.sample("netlens_speedtest_download_bits_per_second", net["down_mbps"] * 1e6, "Download speed of the last successful internet speed test")
        out.sample("netlens_speedtest_upload_bits_per_second", net["up_mbps"] * 1e6, "Upload speed of the last successful internet speed test")
        out.sample("netlens_speedtest_latency_seconds", net["latency_ms"] / 1000, "Delay measured by the last successful internet speed test")
        out.sample("netlens_speedtest_jitter_seconds", net["jitter_ms"] / 1000, "Jitter measured by the last successful internet speed test")
        out.sample("netlens_speedtest_timestamp_seconds", _ts(net["ts"]), "When the last successful internet speed test ran")
        out.sample("netlens_speedtest_last_ok", 1 if sp["last_ok"] else 0, "1 when the latest internet speed test succeeded")
        out.sample("netlens_speedtest_failures_24h", sp["failed_24h"], "Internet speed tests that failed in the last 24 hours")
    if sp["iperf"]:
        out.sample("netlens_iperf_last_bits_per_second", max(sp["iperf"]["down_mbps"] or 0, sp["iperf"]["up_mbps"] or 0) * 1e6, "Speed of the latest iperf3 test", peer=sp["iperf"]["target"])

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

    # health readings of the devices that have a monitor (SNMP / SSH)
    from app import tsdb

    store = tsdb.for_conn(conn)
    if store is not None:
        names = {"cpu_pct": ("netlens_host_cpu_ratio", "Processor busy share of a monitored device (0-1)", 100.0),
                 "mem_pct": ("netlens_host_memory_used_ratio", "Memory in use on a monitored device (0-1)", 100.0),
                 "disk_pct": ("netlens_host_disk_used_ratio", "Used share of a disk on a monitored device (0-1)", 100.0),
                 "disk_free_b": ("netlens_host_disk_free_bytes", "Free space of a disk on a monitored device", 1.0),
                 "temp_c": ("netlens_host_temperature_celsius", "Temperature sensor of a monitored device", 1.0),
                 "uptime_s": ("netlens_host_uptime_seconds", "Time since a monitored device started", 1.0),
                 "net_rx_bps": ("netlens_host_receive_bits_per_second", "Received traffic of a monitored device", 1.0),
                 "net_tx_bps": ("netlens_host_transmit_bits_per_second", "Sent traffic of a monitored device", 1.0),
                 "ups_load_pct": ("netlens_host_ups_load_ratio", "UPS output load (0-1)", 100.0),
                 "fan_rpm": ("netlens_host_fan_speed_rpm", "Fan speed of a monitored device", 1.0),
                 "voltage_v": ("netlens_host_voltage_volts", "Voltage sensor of a monitored device", 1.0),
                 "sensor_fault": ("netlens_host_sensor_fault", "0 when a fan or power supply is fine, 1 when a sensor reports a failure, 2 when a fan has stopped", 1.0),
                 "if_up": ("netlens_host_interface_up", "1 when the link of a network interface is up (monitored devices)", 1.0),
                 "if_util_pct": ("netlens_host_interface_utilization_ratio", "How full a network interface is, the busier direction against the link speed (0-1)", 100.0),
                 "if_err_ps": ("netlens_host_interface_errors_per_second", "Errors and discards per second on a network interface", 1.0),
                 "battery_pct": ("netlens_host_battery_ratio", "UPS battery charge (0-1)", 100.0),
                 "supply_pct": ("netlens_host_supply_ratio", "Printer supply left (0-1)", 100.0)}
        for m in conn.execute("SELECT m.device_id, COALESCE(d.custom_name, d.hostname, d.primary_ip) AS n FROM host_monitors m JOIN devices d ON d.id = m.device_id WHERE m.enabled = 1"):
            for series in store.metrics_of("device", m["device_id"]):
                spec = names.get(series["metric"])
                if spec and series["last"] is not None and series["last_ts"] is not None and _parse_now(now) - series["last_ts"] < 3600:
                    labels = {"device": m["n"]}
                    if series["label"]:
                        labels["name"] = series["label"]
                    out.sample(spec[0], series["last"] / spec[2], spec[1], **labels)

    # remote sites that report to this Netlens
    from app import probes as probes_mod

    for row in conn.execute("SELECT * FROM probes ORDER BY name COLLATE NOCASE"):
        site = probes_mod.present(conn, row)
        if site["locked"]:
            continue
        out.sample("netlens_remote_site_up", 1 if site["state"] == "connected" else 0, "1 while a remote site is reporting", site=site["name"])
        out.sample("netlens_remote_site_devices", site["devices"]["online"], "Devices of a remote site, by state", site=site["name"], state="online")
        out.sample("netlens_remote_site_devices", site["devices"]["total"] - site["devices"]["online"], "Devices of a remote site, by state", site=site["name"], state="offline")
        out.sample("netlens_remote_site_services_down", site["services"]["down"], "Service checks of a remote site that are down", site=site["name"])
        out.sample("netlens_remote_site_health_problems", site["problems"]["count"], "Health readings of a remote site past a limit", site=site["name"])

    w = stats["wifi"]
    out.sample("netlens_wifi_clients", w["clients"], "Wi-Fi clients seen in the last two hours")
    out.sample("netlens_wifi_weak_clients", w["weak"], "Wi-Fi clients with a signal below -75 dBm")
    for r in conn.execute(
        "SELECT COALESCE(d.custom_name, d.hostname, d.primary_ip) AS n, s.node, s.band, s.rssi FROM wifi_samples s JOIN devices d ON d.id = s.device_id "
        "WHERE s.id = (SELECT MAX(id) FROM wifi_samples WHERE device_id = d.id) AND s.ts >= ? AND s.rssi IS NOT NULL", (_ago(now, hours=2),)):
        out.sample("netlens_wifi_signal_dbm", r["rssi"], "Signal strength of a Wi-Fi client", device=r["n"], node=r["node"] or "", band=r["band"] or "")
    return "\n".join(out.lines) + "\n"
