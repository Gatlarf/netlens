#!/usr/bin/env python3
"""Writes netlens-dashboard.json, the Grafana dashboard for the numbers Netlens exports at /metrics.

    python contrib/grafana/build_dashboard.py            (run it from the repository root)

The dashboard is generated, so every panel looks the same way and the file stays easy to change: edit this script, run it, commit both.
"""
import json
import re
from pathlib import Path

DS = {"type": "prometheus", "uid": "${ds}"}
GREEN, AMBER, RED, BLUE, CYAN, PURPLE, GREY = "#2ecc8f", "#f5a623", "#ef4b5f", "#3b82f6", "#22d3ee", "#a78bfa", "#64748b"
_id = [0]


def _base(kind, title, x, y, w, h, targets, unit="short", description=None, **extra):
    _id[0] += 1
    return {"id": _id[0], "type": kind, "title": title, "description": description or "", "datasource": DS, "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "targets": [{"datasource": DS, "refId": chr(65 + i), "editorMode": "code", "range": True, **t} for i, t in enumerate(targets)],
            "fieldConfig": {"defaults": {"unit": unit, **extra.pop("defaults", {})}, "overrides": extra.pop("overrides", [])}, "options": extra.pop("options", {}), **extra}


def one(expr):
    """A single number from a plain metric: max() merges the same series reported twice (two Netlens scrapes, a restart) so a tile never shows two values."""
    if re.fullmatch(r"[a-z_]+(\{[^}]*\})?", expr):
        return f"max({expr})"
    m = re.fullmatch(r"time\(\) - ([a-z_]+)", expr)
    return f"time() - max({m.group(1)})" if m else expr


def steps(*pairs):
    """steps((None, RED), (50, AMBER), (80, GREEN)): the colour from each value upward."""
    return {"mode": "absolute", "steps": [{"color": c, "value": v} for v, c in pairs]}


def stat(title, expr, x, y, w=4, h=4, unit="short", thresholds=None, mappings=None, color_mode="value", graph="area", decimals=None, description=None, reduce="lastNotNull", legend=None, text="auto", instant_=False, **kw):
    d = {"thresholds": thresholds or steps((None, BLUE)), "mappings": mappings or [], "color": {"mode": "thresholds"}}
    if decimals is not None:
        d["decimals"] = decimals
    return _base("stat", title, x, y, w, h, [{"expr": one(expr) if not legend else expr, **({"legendFormat": legend} if legend else {}), **({"instant": True, "range": False} if instant_ else {})}], unit, description, defaults=d,
                 options={"colorMode": color_mode, "graphMode": graph, "textMode": text, "justifyMode": "center", "wideLayout": True, "reduceOptions": {"calcs": [reduce], "fields": "", "values": False}}, **kw)


def gauge(title, expr, x, y, w, h, unit="percent", thresholds=None, minimum=0, maximum=100, description=None):
    return _base("gauge", title, x, y, w, h, [{"expr": one(expr)}], unit, description,
                 defaults={"min": minimum, "max": maximum, "thresholds": thresholds or steps((None, RED), (50, AMBER), (80, GREEN)), "color": {"mode": "thresholds"}},
                 options={"showThresholdMarkers": True, "showThresholdLabels": False, "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}})


def series(title, targets, x, y, w, h, fmt=None, unit="short", fill=22, stack=False, minimum=None, maximum=None, description=None, palette="palette-classic", thresholds=None, bars=False, legend="list", overrides=None):
    d = {"color": {"mode": palette}, "custom": {"drawStyle": "bars" if bars else "line", "lineInterpolation": "smooth", "lineWidth": 2, "fillOpacity": fill if not bars else 70, "gradientMode": "opacity",
                                                  "showPoints": "never", "spanNulls": True, "stacking": {"mode": "normal" if stack else "none", "group": "A"}, "axisSoftMin": 0 if minimum == 0 else None,
                                                  "thresholdsStyle": {"mode": "off"}}}
    d["custom"] = {k: v for k, v in d["custom"].items() if v is not None}
    if minimum is not None:
        d["min"] = minimum
    if maximum is not None:
        d["max"] = maximum
    if thresholds:
        d["thresholds"] = thresholds
        d["custom"]["thresholdsStyle"] = {"mode": "dashed+area"}
    return _base("timeseries", title, x, y, w, h, targets if isinstance(targets, list) else [{"expr": targets, **({"legendFormat": fmt} if fmt else {})}], unit, description, defaults=d, overrides=overrides,
                 options={"legend": {"displayMode": legend, "placement": "bottom", "showLegend": legend != "hidden", "calcs": ["lastNotNull"] if legend == "table" else []}, "tooltip": {"mode": "multi", "sort": "desc"}})


def bars(title, expr, x, y, w, h, unit="short", legend="{{name}}", thresholds=None, minimum=0, maximum=None, description=None, mode="gradient", orientation="horizontal", palette="thresholds", sort="desc"):
    d = {"min": minimum, "thresholds": thresholds or steps((None, BLUE)), "color": {"mode": palette}}
    if maximum is not None:
        d["max"] = maximum
    return _base("bargauge", title, x, y, w, h, [{"expr": expr, "legendFormat": legend, "instant": True, "range": False}], unit, description, defaults=d,
                 options={"displayMode": mode, "orientation": orientation, "valueMode": "color", "showUnfilled": True, "namePlacement": "left", "minVizHeight": 14, "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                          "sizing": "auto"})


def donut(title, expr, x, y, w, h, legend, description=None):
    return _base("piechart", title, x, y, w, h, [{"expr": expr, "legendFormat": legend, "instant": True, "range": False}], "short", description,
                 defaults={"color": {"mode": "palette-classic"}},
                 options={"pieType": "donut", "displayLabels": ["percent"], "legend": {"displayMode": "table", "placement": "right", "showLegend": True, "values": ["value"]}, "tooltip": {"mode": "single"},
                          "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}})


def timeline(title, expr, x, y, w, h, legend, description=None, on="up", off="down", off_color=RED):
    return _base("state-timeline", title, x, y, w, h, [{"expr": expr, "legendFormat": legend}], "short", description,
                 defaults={"color": {"mode": "thresholds"}, "custom": {"fillOpacity": 78, "lineWidth": 0, "mergeValues": True}, "thresholds": steps((None, off_color), (1, GREEN)),
                           "mappings": [{"type": "value", "options": {"0": {"text": off, "color": off_color}, "1": {"text": on, "color": GREEN}}}]},
                 options={"showValue": "never", "rowHeight": 0.82, "mergeValues": True, "alignValue": "center", "legend": {"showLegend": False}, "tooltip": {"mode": "single"}})


def table(title, expr, x, y, w, h, unit="short", description=None, overrides=None, hide=("Time", "__name__", "job", "instance")):
    return _base("table", title, x, y, w, h, [{"expr": expr, "instant": True, "range": False, "format": "table"}], unit, description, overrides=overrides,
                 defaults={"custom": {"cellOptions": {"type": "color-text"}}},
                 options={"showHeader": True, "cellHeight": "sm"},
                 transformations=[{"id": "organize", "options": {"excludeByName": {k: True for k in hide}, "renameByName": {"Value": "Value"}}}])


def row(title, y, collapsed=False):
    _id[0] += 1
    return {"id": _id[0], "type": "row", "title": title, "collapsed": collapsed, "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}, "panels": []}


OK_PROBLEM = [{"type": "value", "options": {"0": {"text": "All good", "color": GREEN}, "1": {"text": "Look here", "color": RED}}}]
YES_NO = lambda yes, no: [{"type": "value", "options": {"1": {"text": yes, "color": GREEN}, "0": {"text": no, "color": RED}}}]  # noqa: E731


def build():
    p = []
    y = 0
    # ---------------------------------------------------------------------------------------------------- the whole picture at a glance
    p.append(gauge("Network health", "netlens_health_score", 0, y, 5, 9, description="One number for the always-on and critical devices: how reachable, fast and cool they are. 80 and up is good, below 50 is poor."))
    p += [stat("Online", 'netlens_devices{state="online"}', 5, y, 4, 4, thresholds=steps((None, GREEN)), description="Devices that answer right now."),
          stat("Offline", 'netlens_devices{state="offline"}', 9, y, 3, 4, thresholds=steps((None, GREY), (1, AMBER))),
          stat("Unknown", 'netlens_devices{state="unknown"}', 12, y, 3, 4, thresholds=steps((None, GREEN), (1, AMBER)), description="Devices that nobody has marked as known yet."),
          stat("Uptime, 24 h", 'max(netlens_core_uptime_ratio{window="24h"}) or max(netlens_uptime_ratio{window="24h"})', 15, y, 3, 4, unit="percentunit", decimals=2, thresholds=steps((None, RED), (0.95, AMBER), (0.99, GREEN)), graph="none",
               description="Share of successful checks of the always-on devices (all devices when none is marked)."),
          stat("Attention", "clamp_min((max(netlens_containers_unhealthy) or vector(0)) + (count(netlens_service_up == 0) or vector(0)) + (max(netlens_scans_failed_24h) or vector(0)) + (count(netlens_plugin_up == 0) or vector(0)), scalar(max(netlens_problem) or vector(0)))",
               18, y, 3, 4, unit="suffix: to check", mappings=[{"type": "value", "options": {"0": {"text": "All good", "color": GREEN}}}], thresholds=steps((None, GREEN), (1, AMBER), (3, RED)), color_mode="background", graph="none",
               description="Failing services, containers, plugins and scans, and anything else Netlens wants a look at. Open Netlens for the list."),
          stat("Events, 24 h", "netlens_events_24h", 21, y, 3, 4, thresholds=steps((None, PURPLE)))]
    p += [stat("Internet down", "netlens_speedtest_download_bits_per_second", 5, y + 4, 4, 5, unit="bps", decimals=0, thresholds=steps((None, CYAN)), graph="none"),
          stat("Internet up", "netlens_speedtest_upload_bits_per_second", 9, y + 4, 3, 5, unit="bps", decimals=0, thresholds=steps((None, BLUE)), graph="none"),
          stat("Delay", "netlens_speedtest_latency_seconds", 12, y + 4, 3, 5, unit="s", decimals=3, thresholds=steps((None, GREEN), (0.05, AMBER), (0.15, RED)), graph="none"),
          stat("Wi-Fi clients", "netlens_wifi_clients", 15, y + 4, 3, 5, thresholds=steps((None, CYAN)), graph="none"),
          stat("Weak Wi-Fi", "netlens_wifi_weak_clients", 18, y + 4, 3, 5, thresholds=steps((None, GREEN), (1, AMBER), (5, RED)), description="Clients with a signal below -75 dBm."),
          stat("Last backup", "time() - netlens_backup_last_timestamp_seconds", 21, y + 4, 3, 5, unit="s", thresholds=steps((None, GREEN), (172800, AMBER), (604800, RED)), graph="none")]
    y += 9
    p += [series("Devices online", [{"expr": 'netlens_devices{state="online"}', "legendFormat": "online"}, {"expr": 'netlens_devices{state="offline"}', "legendFormat": "offline"}], 0, y, 8, 8, minimum=0,
                 overrides=[{"matcher": {"id": "byName", "options": "online"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": GREEN}}]},
                            {"matcher": {"id": "byName", "options": "offline"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": GREY}}]}]),
          series("Health score by part", [{"expr": "avg_over_time(max by (part) (netlens_health_score_part)[3h:15m])", "legendFormat": "{{part}}"}, {"expr": "avg_over_time(max(netlens_health_score)[3h:15m])", "legendFormat": "overall"}], 8, y, 8, 8, unit="none", minimum=80, maximum=100, fill=6,
                 thresholds=steps((None, "transparent"), (50, "transparent")), description="Latency, loss, uptime and temperature of the counted devices, and the score they add up to."),
          series("Internet speed", [{"expr": "netlens_speedtest_download_bits_per_second", "legendFormat": "download"}, {"expr": "netlens_speedtest_upload_bits_per_second", "legendFormat": "upload"}], 16, y, 8, 8, unit="bps", minimum=0,
                 overrides=[{"matcher": {"id": "byName", "options": "download"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": CYAN}}]},
                            {"matcher": {"id": "byName", "options": "upload"}, "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": PURPLE}}]}])]
    y += 8
    # ---------------------------------------------------------------------------------------------------- devices
    p.append(row("Devices and services", y)); y += 1
    p += [timeline("Device presence", "netlens_device_up", 0, y, 12, 18, "{{name}}", on="online", off="offline", off_color=GREY),
          timeline("Service checks", "netlens_service_up", 12, y, 12, 18, "{{name}}", on="up", off="down")]
    y += 18
    p += [bars("Weakest devices (health score)", "bottomk(12, netlens_device_health_score)", 0, y, 8, 9, legend="{{name}}", maximum=100, thresholds=steps((None, RED), (50, AMBER), (80, GREEN)), mode="basic",
               description="The devices with the lowest score. Open one in Netlens to see what holds it back."),
          donut("Devices by type", "netlens_devices_by_type", 8, y, 8, 9, "{{type}}"),
          bars("How well Netlens knows the devices", "netlens_identification_devices", 16, y, 8, 9, legend="{{kind}}", thresholds=steps((None, BLUE)), palette="continuous-BlPu")]
    y += 9
    p += [series("Service response time", "avg_over_time(netlens_service_response_seconds[1h:15m])", 0, y, 12, 8, "{{name}}", unit="s", minimum=0, legend="table"),
          series("Events by kind, 24 h", "netlens_events_by_kind_24h", 12, y, 12, 8, "{{kind}}", stack=True, minimum=0, fill=45)]
    y += 8
    # ---------------------------------------------------------------------------------------------------- wi-fi and internet connections
    p.append(row("Wi-Fi", y)); y += 1
    p += [series("Airtime in use per radio", '100 * netlens_wifi_radio_airtime_ratio', 0, y, 8, 8, "{{access_point}} {{band}}", unit="percent", minimum=0, maximum=100, legend="table",
                 thresholds=steps((None, "transparent"), (80, RED)), description="How busy the air is around each radio. Above 80 % everything on it slows down."),
          series("Neighbouring networks on the same channel", "netlens_wifi_radio_neighbour_networks", 8, y, 8, 8, "{{access_point}} {{band}}", minimum=0, legend="table", description="Other people's networks that share the channel of one of your radios."),
          series("Clients per radio", "netlens_wifi_radio_clients", 16, y, 8, 8, "{{access_point}} {{band}}", minimum=0, stack=True, fill=40, legend="table")]
    y += 8
    p += [series("Average Wi-Fi signal per access point", "avg by (node, band) (avg_over_time(netlens_wifi_signal_dbm[1h:15m]))", 0, y, 12, 8, "{{node}} {{band}}", unit="dBm", minimum=-85, maximum=-35, legend="table", fill=6,
                 description="The average signal of the clients on each access point and band; closer to 0 is stronger. The dashed line is the weak-signal limit.", thresholds=steps((None, RED), (-75, "transparent"))),
          bars("Networks each access point hears", "netlens_wifi_neighbour_networks", 12, y, 6, 8, legend="{{access_point}} {{band}}", thresholds=steps((None, GREEN), (10, AMBER), (20, RED)), palette="thresholds"),
          stat("Radios with a quieter channel available", "sum(netlens_wifi_radio_channel_advice) or vector(0)", 18, y, 6, 8, thresholds=steps((None, GREEN), (1, AMBER)), graph="none", color_mode="background",
               description="Radios for which Netlens found a much quieter channel. Open the access point's Wi-Fi channels card to see which.")]
    y += 8
    p.append(row("Internet connections", y)); y += 1
    p += [timeline("Connections (up or down)", "netlens_uplink_up", 0, y, 12, 6, "{{gateway}}: {{connection}}"),
          timeline("Connection carrying the traffic", "netlens_uplink_active", 12, y, 12, 6, "{{gateway}}: {{connection}}", on="active", off="standby", off_color=GREY),
          series("Delay and jitter", [{"expr": "netlens_speedtest_latency_seconds", "legendFormat": "delay"}, {"expr": "netlens_speedtest_jitter_seconds", "legendFormat": "jitter"}], 0, y + 6, 24, 7, unit="s", minimum=0)]
    y += 13
    # ---------------------------------------------------------------------------------------------------- infrastructure
    p.append(row("Containers, virtual machines and sites", y)); y += 1
    p += [bars("Containers", "netlens_containers", 0, y, 6, 7, legend="{{state}}", thresholds=steps((None, GREEN))),
          bars("Virtual machines, containers and apps", "netlens_guests", 6, y, 6, 7, legend="{{kind}} {{state}}", palette="continuous-BlPu", thresholds=steps((None, BLUE))),
          bars("Certificates: days left", "sort(netlens_certificate_days_left)", 12, y, 6, 7, legend="{{certificate}}", unit="d", thresholds=steps((None, RED), (14, AMBER), (30, GREEN)), maximum=90),
          bars("Reverse proxy sites", "netlens_sites", 18, y, 6, 7, legend="{{state}}", thresholds=steps((None, CYAN)))]
    y += 7
    p += [bars("DNS registration", "netlens_dns_devices", 0, y, 8, 7, legend="{{state}}", palette="continuous-BlPu", thresholds=steps((None, BLUE))),
          bars("Backups: age of the newest", "netlens_backup_age_seconds", 8, y, 8, 7, legend="{{name}}", unit="s", thresholds=steps((None, GREEN), (172800, AMBER), (604800, RED)), maximum=864000),
          stat("Containers to check", "(max(netlens_containers_unhealthy) or vector(0)) + (max(netlens_containers_image_updates) or vector(0))", 16, y, 8, 7, thresholds=steps((None, GREEN), (1, AMBER)), graph="none", color_mode="background",
               description="Unhealthy containers plus containers whose image has a newer version.")]
    y += 7
    # ---------------------------------------------------------------------------------------------------- Netlens itself
    p.append(row("Netlens itself", y, collapsed=False)); y += 1
    p += [series("Scan duration", "netlens_scan_last_duration_seconds", 0, y, 8, 7, "{{kind}}", unit="s", minimum=0),
          series("Hosts found per scan", "netlens_scan_hosts_found", 8, y, 8, 7, "{{kind}}", minimum=0),
          series("Plugin sync age", "time() - netlens_plugin_last_sync_timestamp_seconds", 16, y, 8, 7, "{{plugin}}", unit="s", minimum=0, legend="table")]
    y += 7
    p += [stat("Database", "netlens_database_size_bytes", 0, y, 4, 4, unit="bytes", thresholds=steps((None, PURPLE))),
          stat("Failed scans, 24 h", "netlens_scans_failed_24h", 4, y, 4, 4, thresholds=steps((None, GREEN), (1, RED))),
          stat("Flapping devices", "netlens_devices_flapping", 8, y, 4, 4, thresholds=steps((None, GREEN), (1, AMBER))),
          stat("Passive listening", "netlens_passive_running or vector(0)", 12, y, 4, 4, mappings=[{"type": "value", "options": {"1": {"text": "Listening", "color": GREEN}, "0": {"text": "Off", "color": GREY}}}], thresholds=steps((None, GREY), (1, GREEN)), graph="none"),
          stat("Plugin updates", "netlens_plugin_updates_available", 16, y, 4, 4, thresholds=steps((None, GREEN), (1, AMBER)), graph="none"),
          stat("Version", "netlens_info", 20, y, 4, 4, thresholds=steps((None, BLUE)), graph="none", legend="{{version}}", color_mode="none", reduce="lastNotNull", text="name", instant_=True)]
    y += 4
    # ---------------------------------------------------------------------------------------------------- monitored hosts
    p.append(row("Monitored devices (SNMP and SSH)", y)); y += 1
    p += [series("Traffic received", 'netlens_host_receive_bits_per_second{device=~"$device"}', 0, y, 12, 8, "{{device}} {{name}}", unit="bps", minimum=0, legend="table"),
          series("Traffic sent", 'netlens_host_transmit_bits_per_second{device=~"$device"}', 12, y, 12, 8, "{{device}} {{name}}", unit="bps", minimum=0, legend="table")]
    y += 8
    p += [series("Link utilisation", 'netlens_host_interface_utilization_ratio{device=~"$device"}', 0, y, 12, 8, "{{device}} {{name}}", unit="percentunit", minimum=0, maximum=1, legend="hidden", thresholds=steps((None, "transparent"), (0.8, RED))),
          series("Errors and discards", 'netlens_host_interface_errors_per_second{device=~"$device"}', 12, y, 12, 8, "{{device}} {{name}}", unit="ops", minimum=0, legend="hidden")]
    y += 8
    p += [series("Processor", 'netlens_host_cpu_ratio{device=~"$device"}', 0, y, 8, 8, "{{device}} {{name}}", unit="percentunit", minimum=0, maximum=1, legend="table"),
          series("Memory in use", 'netlens_host_memory_used_ratio{device=~"$device"}', 8, y, 8, 8, "{{device}} {{name}}", unit="percentunit", minimum=0, maximum=1, legend="table"),
          series("Temperature", 'netlens_host_temperature_celsius{device=~"$device"}', 16, y, 8, 8, "{{device}} {{name}}", unit="celsius", legend="table", thresholds=steps((None, "transparent"), (70, RED)))]
    y += 8
    p += [bars("Disk used", 'netlens_host_disk_used_ratio{device=~"$device"}', 0, y, 12, 8, legend="{{device}} {{name}}", unit="percentunit", maximum=1, thresholds=steps((None, GREEN), (0.8, AMBER), (0.92, RED))),
          table("Links that are down", 'netlens_host_interface_up{device=~"$device"} == 0', 12, y, 12, 8, hide=("Time", "__name__", "job", "instance", "Value"))]
    return p


def dashboard():
    return {
        "uid": "netlens-overview", "title": "Netlens", "description": "Your network at a glance: health, devices, Wi-Fi, internet, services and monitored hosts. Data: the Netlens /metrics endpoint.",
        "tags": ["netlens", "network"], "style": "dark", "timezone": "browser", "editable": True, "graphTooltip": 1, "liveNow": False, "refresh": "1m", "schemaVersion": 39, "version": 1,
        "time": {"from": "now-24h", "to": "now"}, "timepicker": {"refresh_intervals": ["30s", "1m", "5m", "15m"]},
        "links": [{"title": "Netlens", "type": "link", "icon": "external link", "url": "https://www.codeshrimp.com", "targetBlank": True}],
        "annotations": {"list": [{"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"}, "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)", "name": "Annotations & Alerts", "type": "dashboard"}]},
        "templating": {"list": [
            {"name": "ds", "label": "Data source", "type": "datasource", "query": "prometheus", "current": {}, "hide": 0, "refresh": 1, "regex": ""},
            {"name": "device", "label": "Monitored device", "type": "query", "datasource": DS, "query": {"query": "label_values(netlens_host_cpu_ratio, device)", "refId": "q"}, "definition": "label_values(netlens_host_cpu_ratio, device)",
             "includeAll": True, "multi": True, "allValue": ".*", "current": {"selected": True, "text": "All", "value": "$__all"}, "refresh": 2, "sort": 1, "hide": 0}]},
        "panels": build(),
    }


if __name__ == "__main__":
    out = Path(__file__).with_name("netlens-dashboard.json")
    out.write_text(json.dumps(dashboard(), indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {out} with {len(dashboard()['panels'])} panels")
