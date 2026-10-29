"""MCP server: lets an AI agent (Claude, OpenClaw, anything that speaks the Model Context Protocol) look at Netlens and, when allowed, change it.

It is one endpoint, POST /mcp (streamable HTTP, JSON replies, no session), and a catalogue of tools. A tool is only a named, documented way to make one
call to Netlens' own API: the call is made inside this process, with the token the agent presented, so every rule that applies to an assistant token
(app/assistant.py: no users, secrets, backups, remote sessions or licence; read tokens only read; a change token needs the licence) and the audit log
apply unchanged. Nothing in here can do more than the same token could do against the REST API.

Settings → AI → MCP server switches the endpoint on and off and chooses which groups of tools exist. It is off until the owner turns it on.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from typing import Any
from urllib.parse import quote, urlencode

from app import assistant
from app.db import get_setting, set_setting
from app.version import VERSION

PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
MAX_CHARS = 80000          # a reply longer than this is cut, with a note that tells the agent to ask for less
CALL_TIMEOUT = 120.0
DEFAULT_RATE = 120

INSTRUCTIONS = (
    "Netlens is a self-hosted network scanner and monitor. Look before you change: read the current state first, then say in plain words what you are about to change and why, "
    "and wait for the person to agree. One change at a time; check the result afterwards. Never delete anything the person did not ask you to delete. "
    "Do not ask for passwords or keys in the chat: secrets are entered by the person in the Netlens interface. A refusal (403) is final: tell the person what to do themselves, "
    "do not look for another way round it."
)

# (id, title, what it holds, changes something)
GROUPS: list[tuple[str, str, str, bool]] = [
    ("overview", "Overview and reports", "dashboard, summary, what changed, events, insights, forecast, uptime and availability reports", False),
    ("devices", "Devices and history", "devices, one device, its uptime, flapping, metrics, groups, hierarchy and vulnerabilities", False),
    ("services", "Service checks (read)", "service checks and their results", False),
    ("sites", "Remote sites (read)", "remote sites, their availability and what is managed there", False),
    ("system", "System (read)", "settings, scans, system log, audit log, database, plugins, alert channels, maintenance windows and snoozes", False),
    ("scans", "Start scans and tests", "start or cancel a scan, scan, ping, trace or wake a device, run a service check, read a device's health, run a speed test", True),
    ("devices_edit", "Change devices and groups", "rename, annotate, group, trust or mark a device always-on; create, change and delete groups", True),
    ("checks", "Change service checks", "add, change and delete service checks", True),
    ("alerts", "Alerts and planned work", "snooze, maintenance windows, notification channels, quiet hours, acknowledge an escalation", True),
    ("sites_edit", "Change remote sites", "rename a site, set its alert mode and mute list, send a command (scan now), change what is managed there", True),
    ("settings", "Change settings", "scan intervals and ranges, data retention, database maintenance, weekly report, health limits, speed test schedule", True),
    ("ai", "Ask Netlens Insights", "ask a question that Netlens answers with its language model (uses the model you set up)", True),
    ("raw", "Any other API call", "api_request and list_api_endpoints: every call a token of this kind may make, not only the ones above", True),
]
GROUP_IDS = [g[0] for g in GROUPS]


# --- the catalogue ------------------------------------------------------------------------------------------------------------------------------------------

def i(desc: str) -> dict:
    return {"type": "integer", "description": desc}


def s(desc: str, enum: list[str] | None = None) -> dict:
    out: dict[str, Any] = {"type": "string", "description": desc}
    if enum:
        out["enum"] = enum
    return out


def b(desc: str) -> dict:
    return {"type": "boolean", "description": desc}


def o(desc: str) -> dict:
    return {"type": "object", "description": desc}


def a(desc: str, items: dict | None = None) -> dict:
    return {"type": "array", "description": desc, "items": items or {}}


TOOLS: dict[str, dict] = {}


def tool(name: str, group: str, desc: str, method: str, path: str, props: dict | None = None, required: tuple = (), query: tuple = ()) -> None:
    """One tool. {braces} in the path are arguments; `query` names the arguments that go in the query string; every other argument is the JSON body."""
    TOOLS[name] = {"name": name, "group": group, "description": desc, "method": method, "path": path, "props": props or {}, "required": list(required), "query": list(query)}


DEV = {"device_id": i("The device's id, from list_devices")}
SITE = {"site_id": i("The remote site's id, from list_sites")}

# overview
tool("get_dashboard", "overview", "What needs attention now: the dashboard's verdict, attention list and key numbers. The quickest overview of the whole network.", "GET", "/api/dashboard")
tool("get_summary", "overview", "Short statistics: devices, online now, events, scans, health.", "GET", "/api/stats/summary")
tool("get_statistics", "overview", "Statistics over a period (devices, vendors, types, scan history).", "GET", "/api/stats", {"range": s("Period: 6h, 24h, 7d, 30d or 90d")}, query=("range",))
tool("get_insights", "overview", "Netlens' own findings: incidents, anomalies, predictions and advice, with the reason for each.", "GET", "/api/insights", {"include_all": b("Include devices that are not always-on")}, query=("include_all",))
tool("get_changes", "overview", "What changed in a period: new, gone, moved and renamed devices, open ports, certificates.", "GET", "/api/changes",
     {"period": s("6h, 24h, 7d or 30d"), "category": s("Only this kind of change"), "limit": i("Maximum rows"), "always_on": b("Only always-on devices")}, query=("period", "category", "limit", "always_on"))
tool("list_events", "overview", "Recent events (device offline/online, new device, service down, certificate, ...), newest first.", "GET", "/api/events",
     {"limit": i("Maximum rows, default 100"), "kind": s("Only this event kind"), "device_id": i("Only this device"), "since_id": i("Only events after this event id")}, query=("limit", "kind", "device_id", "since_id"))
tool("get_forecast", "overview", "Predictions: disks that fill up, certificates that expire, memory trends.", "GET", "/api/forecast")
tool("get_uptime", "overview", "Uptime of every device over a range, with the bars shown on the Uptime page.", "GET", "/api/uptime", {"bars": i("Number of bars"), "range": s("6h, 24h, 7d or 30d")}, query=("bars", "range"))
tool("get_availability_report", "overview", "Availability report for a month: per device or service, outages, target met or not.", "GET", "/api/reports/availability",
     {"month": s("YYYY-MM"), "scope": s("devices or services"), "group": i("Only this group id"), "only_outages": b("Only rows with outages"), "target": i("Target percentage"),
      "ignore_maintenance": b("Do not count maintenance windows as downtime")}, query=("month", "scope", "group", "only_outages", "target", "ignore_maintenance"))
tool("get_networks", "overview", "The scanned networks (ranges, VLANs): name, whether the range keeps answering (a quiet one is a routing, firewall or VPN problem), devices per network, hosts in the last scan against the usual number, devices without a MAC address.", "GET", "/api/networks")
tool("get_link_groups", "overview", "Bonded connections (NIC teaming, LACP) that the owner linked to switch ports: per bond how many links are up and which ports have no link.", "GET", "/api/link-groups", {"device_id": i("Only the bonds of this host or switch")}, query=("device_id",))
tool("get_storage", "overview", "Storage systems from the storage plugins (NAS, SAN, Ceph, BMC): health, pools with their fill level, volumes and who uses them, disks and open alerts.", "GET", "/api/storage")
tool("get_guest_backups", "overview", "Backups of virtual machines and containers from the backup plugins: servers, stores, the newest backup of each guest, failures and guests without a backup.", "GET", "/api/guest-backups")
tool("get_reliability", "overview", "Reliability of the devices and services that matter: outages, average time to recover (MTTR), availability against the target, how fast a problem is noticed, alert quality.", "GET", "/api/reliability",
     {"days": i("7, 30 or 90")}, query=("days",))
tool("get_coverage", "overview", "Monitoring gaps: devices marked always-on or critical that have no service check, health monitor, backup or alerts.", "GET", "/api/coverage")
tool("get_weekly_report", "overview", "The weekly report as it would be sent now.", "GET", "/api/reports/weekly")
tool("investigate_incident", "overview", "Find the probable cause of an incident (ids come from get_insights): what started it, which device moved first (host or guest), what was running at the time, what else broke, devices that only flapped, and whether anybody was told.", "GET", "/api/insights/incidents/{incident_id}/investigate",
     {"incident_id": i("Incident id"), "words": b("Also write it out in plain language with the language model")}, ("incident_id",), query=("words",))
tool("get_storage_breakdown", "overview", "The read-only host probes of one host (storage, processor, memory, network, applications, recent changes, scheduled jobs, hardware, security): which have run, the latest storage breakdown (biggest folders and files, Docker logs, what grew) and the engineer's diagnosis from the snapshots. Administrators only.", "GET", "/api/devices/{device_id}/hostprobe",
     {"device_id": i("Device id")}, ("device_id",))
tool("get_host_probe", "overview", "The newest answer of one host probe with its findings: storage, cpu (busiest processes and containers, pressure, steal), memory (biggest users, swap, OOM kills), network (traffic, errors, TCP health, who talks, gateway/internet/DNS), apps (failed services, restarting containers), changes (reboots, packages, /etc), schedule (timers, cron), hardware (SMART, RAID, ZFS, temperatures), security (failed logins, updates, clock).", "GET", "/api/devices/{device_id}/hostprobe/{probe}",
     {"device_id": i("Device id"), "probe": s("Which probe", ["storage", "cpu", "memory", "network", "apps", "changes", "schedule", "hardware", "security"])}, ("device_id", "probe"))
tool("diagnose_host", "overview", "Ask the digital engineer to find the root cause of a symptom on one host ('slow', 'out of memory', 'network timeouts', 'keeps restarting', 'disk full'). It picks the probes the symptom calls for, chains what they find (memory -> OOM kill -> restart loop -> full disk) and names the probable cause. live=true looks at the host first (read-only, audited, at most once a minute per host); otherwise it uses the snapshots Netlens already has.", "POST", "/api/devices/{device_id}/hostprobe/diagnose",
     {"device_id": i("Device id"), "symptom": s("What is wrong, in a few words"), "live": b("Look at the host now first")}, ("device_id",))
tool("get_monitoring_coverage", "overview", "Which hosts are monitored and how: for every device whether it can be reached over SSH or WinRM, whether it has a health monitor (and whether that works), and whether the read-only host probes are on and which script version they run. Read-only; no logins or secrets are ever shown.", "GET", "/api/hosts", {})
tool("list_analysis_reports", "overview", "The analysis reports of the digital engineer (read-only information): id, incident id, title and probable cause, newest first. An automation system that received a message about an incident finds the report here.", "GET", "/api/analysis",
     {"limit": i("How many"), "incident_id": i("Only this incident (INC-<id>)"), "device_id": i("Only this device")}, query=("limit", "incident_id", "device_id"))
tool("get_analysis_report", "overview", "One analysis report by its id (AR-<id>): the incident id, probable cause, findings (including what is different from normal), what was ruled out, and how to fetch it again. INFORMATION ONLY: nothing was changed on any host; whoever acts on it needs their own rights.", "GET", "/api/analysis/{report_id}",
     {"report_id": i("Report id")}, ("report_id",))
tool("get_incident_analysis", "overview", "The newest analysis of an incident by its id (INC-<id>, the id in get_insights and in the messages Netlens sends); makes one now when there is none. Read-only information about the cause, for a person or an automation system.", "GET", "/api/insights/incidents/{incident_id}/analysis",
     {"incident_id": i("Incident id")}, ("incident_id",))
tool("get_incident_for_event", "overview", "Which incident an alert event belongs to (the event id is in every message and webhook Netlens sends), with the id of the newest analysis report.", "GET", "/api/events/{event_id}/incident",
     {"event_id": i("Event id")}, ("event_id",))
tool("send_analysis", "overview", "Send an analysis report through the alert channels now (e-mail gets a formatted report, a webhook the JSON). It only informs: it changes nothing on any host.", "POST", "/api/analysis/{report_id}/send",
     {"report_id": i("Report id"), "channels": a("Channel ids (default: every enabled channel)", s("id"))}, ("report_id",))
tool("get_traffic", "overview", "Bandwidth in and out of the internet line and of the monitored devices together, over 1h, 6h, 24h or 7d.", "GET", "/api/traffic",
     {"range": s("Period", ["1h", "6h", "24h", "7d"]), "mode": s("all, or endpoints (no double counting)", ["all", "endpoints"])}, query=("range", "mode"))
tool("get_oncall", "overview", "Who is on call now and the shifts of the coming week.", "GET", "/api/oncall")
tool("get_smart_home", "overview", "Smart-home devices (Home Assistant and others): unavailable ones, low batteries, updates.", "GET", "/api/inventory")
tool("get_dns", "overview", "DNS names of the devices and the conflicts between them.", "GET", "/api/dns")
tool("get_agent_status", "overview", "Which hosts report through an agent (a collector on a locked-down host that pushes its readings): state, last time it sent data, whether it is silent, days left on its certificate. No secrets.", "GET", "/api/agent-status")
tool("get_monitors", "overview", "The health monitors (memory, processor, disk, temperature ...) of the monitored hosts, their latest readings and the readings past their limit.", "GET", "/api/monitors")
tool("get_remediation", "overview", "The automatic fixes: rules, what ran, what waits for approval and whether it helped.", "GET", "/api/remediation")
tool("get_network_checks", "overview", "DHCP servers seen on the network (trusted or not), the gateway and the DNS registration.", "GET", "/api/netchecks")

# devices
tool("list_devices", "devices", "Every device Netlens knows: name, addresses, vendor, type, online, group, always-on, trusted.", "GET", "/api/devices",
     {"online": b("Only online (true) or offline (false) devices"), "trusted": b("Only trusted (true) or untrusted (false) devices"), "q": s("Search text (name, address, vendor, MAC)")}, query=("online", "trusted", "q"))
tool("get_device", "devices", "One device with its ports, services, history, monitoring and notes.", "GET", "/api/devices/{device_id}", DEV, ("device_id",))
tool("get_device_uptime", "devices", "Online/offline history of one device.", "GET", "/api/devices/{device_id}/uptime", {**DEV, "limit": i("Maximum rows"), "range": s("6h, 24h, 7d or 30d")}, ("device_id",), ("limit", "range"))
tool("get_device_flapping", "devices", "How often a device went on and off, by hour of the day.", "GET", "/api/devices/{device_id}/flapping", {**DEV, "days": i("Days to look back")}, ("device_id",), ("days",))
tool("list_metrics", "devices", "The measured series that exist for an entity (for example cpu, memory, disk, temperature for a device).", "GET", "/api/timeseries/{entity}/{entity_id}",
     {"entity": s("What it belongs to", ["device", "service", "probe", "remote", "remote_service", "plugin"]), "entity_id": i("Its id")}, ("entity", "entity_id"))
tool("get_metric", "devices", "Points of one measured series over a range (graph data).", "GET", "/api/timeseries/{entity}/{entity_id}/{metric}",
     {"entity": s("What it belongs to", ["device", "service", "probe", "remote", "remote_service", "plugin"]), "entity_id": i("Its id"), "metric": s("Series name, from list_metrics"),
      "label": s("Label of the series when it has several"), "range": s("For example 1h, 24h, 7d"), "points": i("Maximum points")}, ("entity", "entity_id", "metric"), ("label", "range", "points"))
tool("get_hierarchy", "devices", "The network hierarchy: which device sits behind which.", "GET", "/api/hierarchy", {"guests": b("Include virtual machines and containers")}, query=("guests",))
tool("list_groups", "devices", "Device groups (rooms, floors, owners).", "GET", "/api/groups")
tool("list_vulnerabilities", "devices", "Vulnerabilities found by the scanner plugins.", "GET", "/api/vulns",
     {"device_id": i("Only this device"), "severity": s("Only this severity"), "q": s("Search text"), "limit": i("Maximum rows")}, query=("device_id", "severity", "q", "limit"))

# services
tool("list_service_checks", "services", "Service checks (web, port, certificate, ping ...) with their latest result.", "GET", "/api/service-checks", {"device_id": i("Only checks on this device")}, query=("device_id",))
tool("get_service_results", "services", "History of one service check.", "GET", "/api/service-checks/{check_id}/results", {"check_id": i("The check's id"), "limit": i("Maximum rows")}, ("check_id",), ("limit",))

# sites
tool("list_sites", "sites", "Remote sites (probes) with state, last report, device and service counts and open problems.", "GET", "/api/probes")
tool("get_site", "sites", "One remote site in detail: devices, services, events, clock skew, settings.", "GET", "/api/probes/{site_id}", SITE, ("site_id",))
tool("get_site_availability", "sites", "Monthly availability of a remote site.", "GET", "/api/probes/{site_id}/availability", {**SITE, "month": s("YYYY-MM"), "scope": s("devices or services"), "services": b("Include services")}, ("site_id",), ("month", "scope", "services"))
tool("get_site_config", "sites", "The checks and monitors the central Netlens manages at a remote site.", "GET", "/api/probes/{site_id}/config", SITE, ("site_id",))

# system
tool("get_config", "system", "General settings: scan intervals, networks scanned, terminal on or off.", "GET", "/api/config")
tool("list_scans", "system", "Recent scans with result and error text.", "GET", "/api/scans", {"limit": i("Maximum rows")}, query=("limit",))
tool("get_scan_status", "system", "The scan that is running now, with progress.", "GET", "/api/scans/current")
tool("diagnose_scans", "system", "Why scans fail: capabilities, network mode, file system, with the fix.", "GET", "/api/scans/diagnose")
tool("get_system_log", "system", "Netlens' own log (what the program did and which errors it hit).", "GET", "/api/system-log", {"level": s("Lowest level", ["DEBUG", "INFO", "WARNING", "ERROR"]), "q": s("Search text"), "limit": i("Maximum lines")}, query=("level", "q", "limit"))
tool("get_audit_log", "system", "Who changed what and when (including changes made through MCP).", "GET", "/api/audit", {"limit": i("Maximum rows"), "user": s("Only this user"), "q": s("Search text")}, query=("limit", "user", "q"))
tool("get_database_status", "system", "Database size, tables, retention and the last maintenance.", "GET", "/api/database")
tool("list_plugins", "system", "Installed plugins with state and last sync.", "GET", "/api/plugins")
tool("list_channels", "system", "Notification channels (e-mail, webhook, ...).", "GET", "/api/notify-channels")
tool("list_maintenance", "system", "Maintenance windows.", "GET", "/api/maintenance")
tool("list_snoozes", "system", "Active snoozes.", "GET", "/api/snoozes")
tool("get_update_status", "system", "Which version runs and whether a newer one exists.", "GET", "/api/update")
tool("get_speedtests", "system", "Speed test history and schedule.", "GET", "/api/speedtest")

# scans and tests
tool("start_scan", "scans", "Start a network scan now.", "POST", "/api/scans", {"kind": s("quick looks for devices, deep also reads ports and services", ["quick", "deep"])})
tool("cancel_scan", "scans", "Cancel the running scan.", "POST", "/api/scans/cancel")
tool("scan_device", "scans", "Run a full scan of one device (ports, services, operating system).", "POST", "/api/devices/{device_id}/scan", DEV, ("device_id",))
tool("ping_device", "scans", "Ping one device now.", "POST", "/api/devices/{device_id}/ping", DEV, ("device_id",))
tool("trace_device", "scans", "Trace the route to one device.", "POST", "/api/devices/{device_id}/trace", DEV, ("device_id",))
tool("wake_device", "scans", "Send a Wake-on-LAN packet to one device.", "POST", "/api/devices/{device_id}/wake", DEV, ("device_id",))
tool("run_service_check", "scans", "Run one service check now and return the result.", "POST", "/api/service-checks/{check_id}/run", {"check_id": i("The check's id")}, ("check_id",))
tool("read_device_health", "scans", "Read the health of one monitored device now (SNMP, SSH, ...).", "POST", "/api/devices/{device_id}/monitor/run", DEV, ("device_id",))
tool("run_speedtest", "scans", "Run an internet speed test now.", "POST", "/api/speedtest/internet")

# devices and groups
tool("update_device", "devices_edit", "Change a device: name, notes, tags, type, group, always-on, trusted, whether it alerts when offline. Only send the fields to change.", "PATCH", "/api/devices/{device_id}",
     {**DEV, "custom_name": s("Name shown instead of the host name"), "notes": s("Free text"), "tags": a("Tags", s("tag")), "type_override": s("Device type"), "notify_offline": b("Alert when it goes offline"),
      "report_exclude": b("Leave out of reports"), "always_on": b("Should be online all the time"), "tier": s("How much a problem with it matters", ["critical", "normal", "low"]), "trusted": b("Known and trusted"), "group_id": i("Group id, or 0 for none")}, ("device_id",))
tool("set_devices_group", "devices_edit", "Put several devices in a group.", "POST", "/api/devices/group", {"ids": a("Device ids", i("id")), "group_id": i("Group id, or 0 to remove from groups")}, ("ids", "group_id"))
tool("trust_devices", "devices_edit", "Mark several devices as trusted or untrusted. Ask the person which ones; never trust everything.", "POST", "/api/devices/trust", {"ids": a("Device ids", i("id")), "trusted": b("true to trust")}, ("ids", "trusted"))
tool("create_group", "devices_edit", "Create a device group.", "POST", "/api/groups", {"name": s("Group name"), "color": s("Colour as #rrggbb")}, ("name",))
tool("update_group", "devices_edit", "Rename or recolour a group.", "PATCH", "/api/groups/{group_id}", {"group_id": i("Group id"), "name": s("New name"), "color": s("Colour as #rrggbb")}, ("group_id",))
tool("delete_group", "devices_edit", "Delete a group. Its devices stay, ungrouped. Only on the person's explicit request.", "DELETE", "/api/groups/{group_id}", {"group_id": i("Group id")}, ("group_id",))

# service checks
CHECK = {"device_id": i("Device the check belongs to"), "name": s("Name"), "kind": s("Kind of check, for example http, https, tcp, ping, tls, dns"), "host": s("Host or address"), "port": i("Port"),
         "path": s("URL path for web checks"), "expect": s("Text or status code the answer must contain"), "interval_s": i("Seconds between checks"), "timeout_s": i("Seconds before it counts as failed"), "enabled": b("On or off")}
tool("create_service_check", "checks", "Add a service check.", "POST", "/api/service-checks", CHECK, ("name", "kind"))
tool("update_service_check", "checks", "Change a service check. Only send the fields to change.", "PATCH", "/api/service-checks/{check_id}", {"check_id": i("The check's id"), **CHECK}, ("check_id",))
tool("delete_service_check", "checks", "Delete a service check and its history. Only on the person's explicit request.", "DELETE", "/api/service-checks/{check_id}", {"check_id": i("The check's id")}, ("check_id",))

# alerts and planned work
tool("snooze", "alerts", "Silence the alerts of a device, service or whole site for a while. Subject looks like device:12, service:3 or site:2.", "POST", "/api/snoozes",
     {"subject": s("device:<id>, service:<id> or site:<id>"), "minutes": i("How long"), "note": s("Why")}, ("subject", "minutes"))
tool("end_snooze", "alerts", "End a snooze.", "DELETE", "/api/snoozes", {"subject": s("The snoozed subject")}, ("subject",), ("subject",))
tool("create_maintenance", "alerts", "Create a maintenance window (silences alerts for what it covers). scope selects devices, groups or sites; schedule says when.", "POST", "/api/maintenance",
     {"name": s("Name"), "enabled": b("On or off"), "scope": o("What it covers: {all, device_ids, group_ids, sites}"), "schedule": o("When: a one-time start and end, or weekdays with a start time and duration"), "tz": s("Time zone, for example Europe/Brussels"), "offset_min": i("Offset from UTC in minutes")}, ("name",))
tool("start_maintenance_now", "alerts", "Start a one-time maintenance window now for some devices.", "POST", "/api/maintenance/now",
     {"device_ids": a("Device ids", i("id")), "minutes": i("How long, 5 to 10080"), "behind": b("Also cover the devices behind them")}, ("device_ids", "minutes"))
tool("update_maintenance", "alerts", "Change a maintenance window (send the whole window).", "PUT", "/api/maintenance/{window_id}",
     {"window_id": i("Window id"), "name": s("Name"), "enabled": b("On or off"), "scope": o("What it covers"), "schedule": o("When"), "tz": s("Time zone"), "offset_min": i("Offset from UTC in minutes")}, ("window_id",))
tool("delete_maintenance", "alerts", "Delete a maintenance window.", "DELETE", "/api/maintenance/{window_id}", {"window_id": i("Window id")}, ("window_id",))
CHANNEL = {"type": s("Channel type, as in list_channels"), "name": s("Name"), "enabled": b("On or off"), "events": a("Event kinds it sends", s("kind")), "filters": o("Minimum severity, devices, groups"),
           "quiet": o("This channel's own quiet hours"), "settings": o("Type-specific settings. Keys and passwords are entered by the person in the interface, not here")}
tool("create_channel", "alerts", "Add a notification channel. Do not pass passwords or keys; ask the person to enter those in Settings → Alerts.", "POST", "/api/notify-channels", CHANNEL, ("type", "name"))
tool("update_channel", "alerts", "Change a notification channel. Only send the fields to change.", "PUT", "/api/notify-channels/{channel_id}", {"channel_id": i("Channel id"), **CHANNEL}, ("channel_id",))
tool("delete_channel", "alerts", "Delete a notification channel. Only on the person's explicit request.", "DELETE", "/api/notify-channels/{channel_id}", {"channel_id": i("Channel id")}, ("channel_id",))
tool("test_channel", "alerts", "Send a test message through a channel. Ask the person whether it arrived.", "POST", "/api/notify-channels/{channel_id}/test", {"channel_id": i("Channel id")}, ("channel_id",))
tool("set_quiet_hours", "alerts", "Set the quiet hours for all channels.", "PUT", "/api/notify-quiet",
     {"enabled": b("On or off"), "start": s("HH:MM"), "end": s("HH:MM"), "tz": s("Time zone"), "offset_min": i("Offset from UTC in minutes"), "bypass_critical": b("Critical events still come through"), "group_by_cause": b("Group alerts by cause")})
tool("acknowledge_escalation", "alerts", "Acknowledge an escalated event so that nobody else is called.", "POST", "/api/escalation/{event_id}/ack", {"event_id": i("Event id")}, ("event_id",))

# remote sites
tool("update_site", "sites_edit", "Change a remote site: name, customer, keep_days, alert_mode (always, always_on_only, off) and the muted device list.", "PATCH", "/api/probes/{site_id}",
     {**SITE, "name": s("Name"), "enabled": b("On or off"), "customer": s("Customer name"), "keep_days": i("Days of history kept for this site, 0 for the general setting"),
      "alert_mode": s("Which devices alert", ["all", "always_on", "off"]), "muted": a("Device keys that never alert", s("key"))}, ("site_id",))
tool("send_site_command", "sites_edit", "Tell a remote site to do something at its next report, for example scan now.", "POST", "/api/probes/{site_id}/command", {**SITE, "command": s("The command, for example scan")}, ("site_id", "command"))
tool("set_site_config", "sites_edit", "Change the checks and monitors the central Netlens manages at a remote site (send the whole list).", "PUT", "/api/probes/{site_id}/config",
     {**SITE, "services": a("Managed service checks", o("check")), "monitors": a("Managed health monitors", o("monitor"))}, ("site_id",))

# settings
tool("set_scan_intervals", "settings", "Set how often Netlens does a quick and a deep scan (seconds).", "PUT", "/api/config/general", {"quick_interval": i("Seconds between quick scans"), "deep_interval": i("Seconds between deep scans")})
tool("set_scan_ranges", "settings", "Set the networks that are scanned, for example 192.168.1.0/24. Use only networks the person named.", "PUT", "/api/config/ranges", {"ranges": a("Networks in CIDR notation", s("cidr"))}, ("ranges",))
tool("set_data_retention", "settings", "Set how many days events, scans, check results and the audit log are kept.", "PUT", "/api/database/retention",
     {"events_days": i("Events"), "scans_days": i("Scans"), "checks_days": i("Health checks"), "service_results_days": i("Service check results"), "audit_days": i("Audit log")})
tool("run_database_maintenance", "settings", "Run a database task: optimize, reindex, integrity, tidy, compact, or purge/orphans (these two only report what they would remove unless dry_run is false).", "POST", "/api/database/{task}",
     {"task": s("Which task", ["optimize", "reindex", "integrity", "tidy", "compact", "purge", "orphans"]), "dry_run": b("For purge and orphans: only report. Default true")}, ("task",))
tool("set_weekly_report", "settings", "Change the weekly report settings (on or off, day, hour, what it contains).", "PUT", "/api/reports/weekly/settings",
     {"enabled": b("On or off"), "day": i("Weekday 0-6"), "hour": i("Hour 0-23"), "scope": s("devices or services"), "new_devices": b("List new devices"), "health": b("Include health"), "disks": b("Include disks"),
      "sites": b("Include remote sites"), "max_items": i("Rows per section"), "summary": b("Add a written summary"), "monthly": b("Also send a monthly report")})
tool("send_weekly_report", "settings", "Send the weekly report now.", "POST", "/api/reports/weekly/send")
tool("set_health_limits", "settings", "Set the general health limits (when a disk, CPU or temperature is a problem). Send the whole rule list.", "PUT", "/api/monitoring/limits", {"rules": a("Limit rules", o("rule"))}, ("rules",))
tool("set_speedtest_schedule", "settings", "Schedule the internet speed test.", "PUT", "/api/speedtest/schedule", {"enabled": b("On or off"), "every_hours": i("Hours between tests")}, ("enabled",))

# ai
tool("ask_insights", "ai", "Ask Netlens a question about the network; its language model answers from the data. Needs a language model under Settings → AI.", "POST", "/api/insights/ask",
     {"question": s("The question"), "mode": s("Answer style"), "include_all": b("Include devices that are not always-on")}, ("question",))

RAW_TOOLS = {
    "api_request": {
        "name": "api_request", "group": "raw",
        "description": "Make any call to the Netlens API that this token may make (see list_api_endpoints). Prefer the specific tools; use this for what they do not cover. GET looks, other methods change things.",
        "props": {"method": s("HTTP method", ["GET", "POST", "PUT", "PATCH", "DELETE"]), "path": s("Path starting with /api/, for example /api/plugins"),
                  "query": o("Query string arguments"), "body": o("JSON body")},
        "required": ["method", "path"], "method": None, "path": None, "query": [],
    },
    "list_api_endpoints": {
        "name": "list_api_endpoints", "group": "raw",
        "description": "Every API call this token may make, with the fields of the request body. Calls with allowed false are not for an assistant.",
        "props": {}, "required": [], "method": "GET", "path": None, "query": [],
    },
}
TOOLS.update(RAW_TOOLS)
for _name, _t in TOOLS.items():
    _t["write"] = _t["method"] not in ("GET", None)        # api_request is not "write" here: it is listed for a read token too, and refuses a change at the call


# --- settings -----------------------------------------------------------------------------------------------------------------------------------------------

def get_settings(conn: sqlite3.Connection) -> dict:
    try:
        disabled = [g for g in json.loads(get_setting(conn, "mcp.disabled_groups") or "[]") if g in GROUP_IDS]
    except (TypeError, ValueError):
        disabled = []
    rate = get_setting(conn, "mcp.rate_per_minute")
    return {"enabled": get_setting(conn, "mcp.enabled") == "1", "allow_changes": get_setting(conn, "mcp.allow_changes") != "0",
            "disabled_groups": disabled, "rate_per_minute": int(rate) if rate and rate.lstrip("-").isdigit() else DEFAULT_RATE}


def set_settings(conn: sqlite3.Connection, enabled: bool | None = None, allow_changes: bool | None = None, disabled_groups: list[str] | None = None, rate_per_minute: int | None = None) -> dict:
    if disabled_groups is not None:
        unknown = [g for g in disabled_groups if g not in GROUP_IDS]
        if unknown:
            raise ValueError("unknown tool group: " + ", ".join(unknown))
        set_setting(conn, "mcp.disabled_groups", json.dumps(sorted(set(disabled_groups))))
    if rate_per_minute is not None:
        if not 0 <= rate_per_minute <= 10000:
            raise ValueError("the rate limit is 0 (none) to 10000 calls per minute")
        set_setting(conn, "mcp.rate_per_minute", str(int(rate_per_minute)))
    if enabled is not None:
        set_setting(conn, "mcp.enabled", "1" if enabled else "0")
    if allow_changes is not None:
        set_setting(conn, "mcp.allow_changes", "1" if allow_changes else "0")
    conn.commit()
    return get_settings(conn)


def catalogue() -> list[dict]:
    """For the settings page: the groups with the names of their tools."""
    return [{"id": gid, "title": title, "about": about, "changes": changes, "tools": [t["name"] for t in TOOLS.values() if t["group"] == gid]} for gid, title, about, changes in GROUPS]


def visible(settings: dict, mode: str) -> list[dict]:
    """The tools this token sees: its group is on, and a tool that changes something needs a change token and 'allow changes'."""
    can_change = mode == "change" and settings["allow_changes"]
    return [t for t in TOOLS.values() if t["group"] not in settings["disabled_groups"] and (can_change or not t["write"])]


def schema(t: dict) -> dict:
    return {"name": t["name"], "description": t["description"] + ("" if not t["write"] else " (changes something)"),
            "inputSchema": {"type": "object", "properties": t["props"], "required": t["required"], "additionalProperties": False},
            "annotations": {"readOnlyHint": not t["write"] and t["name"] != "api_request", "destructiveHint": t["method"] == "DELETE", "openWorldHint": False}}


# --- the call ------------------------------------------------------------------------------------------------------------------------------------------------

_calls: dict[str, list[float]] = {}


def rate_ok(key: str, limit: int, now: float | None = None) -> bool:
    """At most `limit` calls per minute per token (0 = no limit)."""
    if limit <= 0:
        return True
    now = time.monotonic() if now is None else now
    recent = [x for x in _calls.get(key, []) if now - x < 60.0]
    if len(recent) >= limit:
        _calls[key] = recent
        return False
    recent.append(now)
    _calls[key] = recent
    return True


def _coerce(name: str, spec: dict, value: Any) -> Any:
    kind = spec.get("type")
    if kind == "integer":
        if isinstance(value, bool):
            raise ValueError(f"{name} must be a whole number")
        if isinstance(value, str) and value.strip().lstrip("-").isdigit():
            return int(value)
        if isinstance(value, float) and value.is_integer():
            return int(value)
        if not isinstance(value, int):
            raise ValueError(f"{name} must be a whole number")
    elif kind == "boolean":
        if isinstance(value, str) and value.lower() in ("true", "false"):
            return value.lower() == "true"
        if not isinstance(value, bool):
            raise ValueError(f"{name} must be true or false")
    elif kind == "string":
        if not isinstance(value, str):
            raise ValueError(f"{name} must be text")
        if spec.get("enum") and value not in spec["enum"]:
            raise ValueError(f"{name} must be one of: {', '.join(spec['enum'])}")
    elif kind == "object" and not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    elif kind == "array" and not isinstance(value, list):
        raise ValueError(f"{name} must be a list")
    return value


def build_request(t: dict, args: dict) -> tuple[str, str, dict, Any]:
    """Turn a tool call into (method, path, query, body). Raises ValueError with a sentence the agent can act on."""
    if not isinstance(args, dict):
        raise ValueError("the arguments must be an object")
    if t["name"] == "api_request":
        method = str(args.get("method", "")).upper()
        path = str(args.get("path", ""))
        if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            raise ValueError("method must be GET, POST, PUT, PATCH or DELETE")
        if not path.startswith("/api/") or ".." in path or "?" in path or "#" in path:
            raise ValueError("path must start with /api/ and carry no query string (use the query argument)")
        query = args.get("query") or {}
        body = args.get("body")
        if not isinstance(query, dict) or (body is not None and not isinstance(body, (dict, list))):
            raise ValueError("query and body must be objects")
        return method, path, query, body
    unknown = [k for k in args if k not in t["props"]]
    if unknown:
        raise ValueError(f"unknown argument: {', '.join(unknown)}. This tool takes: {', '.join(t['props']) or 'no arguments'}")
    missing = [k for k in t["required"] if args.get(k) is None]
    if missing:
        raise ValueError(f"missing argument: {', '.join(missing)}")
    values = {k: _coerce(k, t["props"][k], v) for k, v in args.items() if v is not None}
    if t["name"] == "run_database_maintenance" and values.get("task") in ("purge", "orphans"):
        values.setdefault("dry_run", True)
    elif t["name"] == "run_database_maintenance":
        values.pop("dry_run", None)
    if t["name"] in ("update_device", "set_devices_group") and values.get("group_id") == 0:
        values["group_id"] = None                        # the API takes null, a model finds 0 easier to say
    path = t["path"]
    for key in [k for k in t["props"] if "{" + k + "}" in path]:
        path = path.replace("{" + key + "}", quote(str(values.pop(key)), safe=""))
    query = {k: ("true" if values[k] is True else "false" if values[k] is False else values[k]) for k in t["query"] if k in values}
    body = {k: v for k, v in values.items() if k not in query}
    return t["method"], path, query, (body if t["method"] in ("POST", "PUT", "PATCH") else None)


async def call_api(app, method: str, path: str, query: dict, body: Any, request) -> tuple[int, str]:
    """Make one request to this very application and return (status, text). The caller's own Authorization header goes with it, so the normal rules decide."""
    raw = json.dumps(body).encode() if body is not None else b""
    pass_on = ("authorization", "host", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-real-ip", "user-agent")
    headers = [(k.encode(), v.encode()) for k, v in request.headers.items() if k.lower() in pass_on]
    headers.append((b"accept", b"application/json"))
    if body is not None:
        headers += [(b"content-type", b"application/json"), (b"content-length", str(len(raw)).encode())]
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method, "scheme": request.url.scheme, "path": path, "raw_path": path.encode(),
             "query_string": urlencode(query, doseq=True).encode(), "root_path": "", "headers": headers, "client": tuple(request.client) if request.client else ("127.0.0.1", 0),
             "server": ("netlens", 80)}
    finished = asyncio.Event()
    sent = False
    status = 500
    chunks: list[bytes] = []

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": raw, "more_body": False}
        await finished.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        nonlocal status
        if message["type"] == "http.response.start":
            status = message["status"]
        elif message["type"] == "http.response.body":
            chunks.append(message.get("body", b""))
            if not message.get("more_body"):
                finished.set()

    try:
        await asyncio.wait_for(app(scope, receive, send), CALL_TIMEOUT)
    except asyncio.TimeoutError:
        return 504, "Netlens did not answer within two minutes"
    finally:
        finished.set()
    return status, b"".join(chunks).decode("utf-8", "replace")


def render(status: int, text: str) -> dict:
    """The tool result: the reply as text, cut when it is huge, and an error flag with the reason when Netlens refused."""
    error = status >= 400
    if error:
        try:
            detail = json.loads(text).get("detail")
            text = detail if isinstance(detail, str) else json.dumps(detail)
        except (ValueError, AttributeError):
            pass
        text = f"Netlens answered {status}: {text}"
    elif not text:
        text = "Done."
    if len(text) > MAX_CHARS:
        text = text[:MAX_CHARS] + f"\n\n[cut after {MAX_CHARS} characters: ask for less, with a filter such as q, limit, device_id or a shorter range]"
    return {"content": [{"type": "text", "text": text}], "isError": error}


def refusal(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": True}


async def handle(app, request, mode: str, settings: dict, message: dict) -> dict | None:
    """One JSON-RPC message in, the reply out (None for a notification)."""
    mid = message.get("id")
    method = message.get("method")
    params = message.get("params") or {}

    def ok(result):
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def err(code, text):
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": text}}

    if mid is None and isinstance(method, str):          # a notification (initialized, cancelled): nothing to answer
        return None
    if not isinstance(method, str):
        return err(-32600, "not a JSON-RPC request")
    if method == "initialize":
        wanted = params.get("protocolVersion")
        return ok({"protocolVersion": wanted if wanted in PROTOCOLS else PROTOCOLS[0], "capabilities": {"tools": {"listChanged": False}, "resources": {}},
                   "serverInfo": {"name": "netlens", "title": "Netlens", "version": VERSION}, "instructions": INSTRUCTIONS})
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": [schema(t) for t in visible(settings, mode)]})
    if method == "tools/call":
        name = params.get("name")
        t = TOOLS.get(name) if isinstance(name, str) else None
        if t is None:
            return err(-32602, f"unknown tool {name!r}")
        if t not in visible(settings, mode):
            if t["group"] in settings["disabled_groups"]:
                return ok(refusal("The owner switched this group of tools off (Settings → AI → MCP server)."))
            if not settings["allow_changes"]:
                return ok(refusal("The owner does not allow changes through MCP (Settings → AI → MCP server). You can only look."))
            return ok(refusal(assistant.WHY["read"]))
        if t["name"] == "list_api_endpoints":
            return ok({"content": [{"type": "text", "text": json.dumps({"mode": mode, "endpoints": assistant.endpoints(app.openapi(), mode)})}], "isError": False})
        try:
            http_method, path, query, body = build_request(t, params.get("arguments") or {})
        except ValueError as exc:
            return ok(refusal(str(exc)))
        if t["name"] == "api_request" and http_method != "GET" and not (mode == "change" and settings["allow_changes"]):
            return ok(refusal(assistant.WHY["read"] if mode != "change" else "The owner does not allow changes through MCP (Settings → AI → MCP server). You can only look."))
        status, text = await call_api(app, http_method, path, query, body, request)
        return ok(render(status, text))
    if method == "resources/list":
        return ok({"resources": [{"uri": "netlens://guide", "name": "Instructions for an assistant", "description": "How to look after Netlens: first look, workflows, what to ask the person.", "mimeType": "text/markdown"}]})
    if method == "resources/templates/list":
        return ok({"resourceTemplates": []})
    if method == "resources/read":
        if params.get("uri") != "netlens://guide":
            return err(-32002, "no such resource")
        base = f"{request.headers.get('x-forwarded-proto') or request.url.scheme}://{request.headers.get('x-forwarded-host') or request.headers.get('host') or request.url.netloc}"
        return ok({"contents": [{"uri": "netlens://guide", "mimeType": "text/markdown", "text": assistant.guide_text(base, mode, VERSION)}]})
    if method == "prompts/list":
        return ok({"prompts": []})
    return err(-32601, f"method not found: {method}")
