"""Open-ended questions for "Ask your network": any stored reading of any device, usage per device and application, the state of the network checks, and
what the host probes found on every host.

The specific questions (app/ask.py, ask_extra.py, ask_more.py) answer what somebody thought of in advance. These tools answer the rest: they read what
Netlens stores through a short, fixed list of fields (never a free query), so nothing beyond what the pages show can be reached, names go through the
same redaction as every other answer, and the size of an answer is limited.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any

from app import ask
from app.ask import _days

# What a person says -> the stored reading. The first word that appears in the question or the argument wins.
ALIASES = [
    (r"reboot|restart|boot|uptime|up ?time|booted", "uptime_s"), (r"swap", "swap_pct"), (r"\bram\b|memory|mem\b", "mem_pct"), (r"\bcpu|processor", "cpu_pct"),
    (r"load", "load1"), (r"free (disk )?space|disk free", "disk_free_b"), (r"disk|storage|space|full", "disk_pct"), (r"temp|hot|heat|warm|degrees", "temp_c"),
    (r"upload|tx|sent|outgoing", "net_tx_bps"), (r"download|rx|received|incoming|bandwidth|traffic|throughput", "net_rx_bps"), (r"latency|ping|rtt|response|slow", "rtt_ms"),
    (r"battery|ups\b", "battery_pct"), (r"fan", "fan_rpm"), (r"error|drop|discard", "if_err_ps"), (r"util|busy|saturat", "if_util_pct"), (r"link|port|interface", "if_up"),
]
# name -> (what it is, a function that turns the stored number into what a person reads, its unit)
METRICS = {
    "cpu_pct": ("processor use", None, "%"), "mem_pct": ("memory use", None, "%"), "swap_pct": ("swap use", None, "%"), "load1": ("load average (1 minute)", None, ""),
    "disk_pct": ("disk use (fullest value per label)", None, "%"), "disk_free_b": ("free disk space", lambda v: v / 1e9, "GB"), "temp_c": ("temperature", None, "°C"),
    "uptime_s": ("time since the last start (a drop means a reboot)", lambda v: v / 86400, "days"), "net_rx_bps": ("traffic received", lambda v: v / 1e6, "Mbit/s"),
    "net_tx_bps": ("traffic sent", lambda v: v / 1e6, "Mbit/s"), "rtt_ms": ("answer time to a ping", None, "ms"), "battery_pct": ("battery charge", None, "%"),
    "ups_load_pct": ("UPS load", None, "%"), "fan_rpm": ("fan speed", None, "rpm"), "if_err_ps": ("interface errors per second", None, "/s"),
    "if_util_pct": ("how full a link is", None, "%"), "if_up": ("link state (1 up, 0 down)", None, ""), "up": ("device answered (1) or not (0)", None, ""),
    "supply_pct": ("printer supply left", None, "%"), "battery_minutes": ("battery minutes left", None, "min"), "on_battery": ("running on battery (1)", None, ""),
}
MAX_SERIES = 60                      # series read per question: every one costs a query
STALE_S = 2 * 86400


def pick_metric(text: str) -> str | None:
    text = (text or "").strip().lower()
    if text in METRICS:
        return text
    for pattern, name in ALIASES:
        if re.search(pattern, text):
            return name
    return None


def _show(metric: str, value: float | None) -> float | None:
    if value is None:
        return None
    convert = METRICS[metric][1]
    return round(convert(value) if convert else value, 2)


def _stats(store, did: int, metric: str, label: str, span: int, end: int) -> dict[str, Any] | None:
    q = store.query("device", did, metric, label, span=span, end=end, points=120)
    pts = [p for p in q["points"] if p[1] is not None]
    if not pts:
        return None
    avg = sum(p[1] for p in pts) / len(pts)
    lo, hi = min(p[2] if p[2] is not None else p[1] for p in pts), max(p[3] if p[3] is not None else p[1] for p in pts)
    out = {"min": _show(metric, lo), "avg": _show(metric, avg), "max": _show(metric, hi)}
    if len(pts) >= 6:                                         # first third against last third: rising, falling or steady
        k = len(pts) // 3
        a, b = sum(p[1] for p in pts[:k]) / k, sum(p[1] for p in pts[-k:]) / k
        spread = (hi - lo) or 1
        out["trend"] = "rising" if (b - a) > 0.25 * spread else "falling" if (a - b) < -0.25 * spread else "steady"
    if metric == "uptime_s":                                  # the counter starts again at 0 when a machine restarts
        # the moment of the last start is (time - uptime); it stays the same while the machine runs and jumps forward at a reboot. Averaged buckets blur it by up to
        # a few steps, so only a jump larger than that counts (a counter that merely dips, or reads oddly between two samples, is not a reboot).
        tol = max(900, 3 * (q.get("step") or 0))
        boots, prev = [], None
        for t, v, *_ in pts:
            start = t - v
            if prev is not None and start - prev > tol:
                boots.append(datetime.fromtimestamp(start, timezone.utc).strftime("%Y-%m-%d %H:%M"))
            prev = start
        out["reboots"] = len(boots)
        out["rebooted_at"] = boots[-3:]
    return out


def t_metric(conn, args, now=None) -> dict:
    """Any stored reading of the devices Netlens reads (a number over time): latest values ranked, or one device's history (min, average, max, trend, reboots)."""
    from app import tsdb

    metric = pick_metric(str(args.get("metric") or ""))
    store = tsdb.for_conn(conn)
    if store is None:
        return {"error": "No readings are stored yet."}
    end = int(now.timestamp()) if now else int(time.time())
    try:
        days = max(0.04, min(float(args.get("days") or 1), 30))
    except (TypeError, ValueError):
        days = 1
    span = int(days * 86400)
    keep = ask.important_ids(conn)
    names = {r["id"]: r["n"] for r in conn.execute("SELECT id, COALESCE(custom_name, hostname, primary_ip) AS n FROM devices")}
    needle = str(args.get("device") or "").strip().lower()
    ids = [i for i, n in names.items() if (keep is None or i in keep) and (not needle or needle in (n or "").lower())]
    if needle and not ids:
        return {"error": f"I don't know a device called {needle}."}
    series = store.metrics_of_many("device", ids)
    if metric is None:
        have: dict[str, set] = {}
        for did, rows in series.items():
            for r in rows:
                have.setdefault(r["metric"], set()).add(did)
        return {"metric": None, "available": [{"metric": m, "what": METRICS[m][0] if m in METRICS else m, "devices": len(d)} for m, d in sorted(have.items(), key=lambda kv: -len(kv[1]))],
                "note": "Name one of these as args.metric."}
    label = str(args.get("label") or "").strip().lower()
    rows = []
    for did, items in series.items():
        for r in items:
            if r["metric"] != metric or (label and label not in (r["label"] or "").lower()) or end - (r["last_ts"] or 0) > max(STALE_S, span):
                continue
            rows.append((did, r))
    higher = str(args.get("order") or "highest").lower() not in ("lowest", "asc", "smallest", "least")
    rows.sort(key=lambda x: -(x[1]["last"] or 0) if higher else (x[1]["last"] or 0))
    limit = max(1, min(int(args.get("limit") or 10), 20)) if str(args.get("limit") or "").isdigit() else 10
    out, checked = [], 0
    for did, r in rows[:MAX_SERIES]:
        full = metric == "uptime_s" or len(out) < limit or bool(needle)
        row = {"device": names.get(did), "label": r["label"] or None, "latest": _show(metric, r["last"]), "unit": METRICS[metric][2]}
        if full and checked < MAX_SERIES:
            checked += 1
            st = _stats(store, did, metric, r["label"], span, end)
            if st:
                row["period"] = st
        out.append(row)
    if metric == "uptime_s":
        rebooted = [{"device": r["device"], **{k: r["period"][k] for k in ("reboots", "rebooted_at")}} for r in out if r.get("period", {}).get("reboots")]
        return {"metric": metric, "what": METRICS[metric][0], "days": days, "devices_read": len(out), "rebooted": rebooted, "uptime_days": [{k: r[k] for k in ("device", "latest")} for r in out[:limit]],
                "note": "uptime is counted since the last start; a drop in the stored counter is a reboot. Only devices whose uptime is read (SNMP, host monitor) are listed."}
    return {"metric": metric, "what": METRICS[metric][0], "days": days, "devices_read": len(rows), "values": out[:limit if not needle else MAX_SERIES],
            "note": "latest is the newest stored reading; period is the minimum, average and maximum over the days asked."}


def t_host_findings(conn, args, now=None) -> dict:
    """What the read-only host probes found on EVERY host that has them switched on, optionally only the findings about a topic."""
    from app.hostprobe import diagnose, service as probes

    topic = str(args.get("topic") or "").strip().lower()
    words = [w for w in re.findall(r"[a-z0-9]{3,}", topic) if w not in ("the", "and", "for", "any", "which", "have", "has", "with", "host", "hosts", "system", "systems")]
    hide = ask.for_model() and not probes._load(conn)["names_to_llm"]
    keep = ask.important_ids(conn)
    hosts, found, silent = 0, [], []
    for r in conn.execute("SELECT id, COALESCE(custom_name, hostname, primary_ip) AS n FROM devices"):
        if (keep is not None and r["id"] not in keep) or not probes.device_config(conn, r["id"])["enabled"]:
            continue
        rep = diagnose.diagnose(conn, r["id"], topic or None, now.timestamp() if now else None)
        if not rep["taken"]:
            silent.append(r["n"])
            continue
        hosts += 1
        for f in rep["findings"]:
            text = (f.get("llm_text") or "A finding with names was withheld.") if f.get("private") and hide else f["text"]
            wanted = (f["level"] != "fact") if not words else any(w in text.lower() or w in f["text"].lower() for w in words)
            if wanted:
                found.append({"device": r["n"], "level": f["level"], "text": text[:300]})
    order = {"cause": 0, "bad": 0, "warn": 1}
    found.sort(key=lambda f: order.get(f["level"], 2))
    return {"topic": topic or None, "hosts_looked_at": hosts, "no_probe_data_yet": silent[:10], "findings": found[:25], "count": len(found),
            "note": "Only hosts with Host probes switched on are covered. An empty list with hosts_looked_at above 0 means none of them reported it."}


def t_usage(conn, args, now=None) -> dict:
    """Traffic per device and per application, from the router's traffic analyser (plugins such as UniFi or Omada), over some days."""
    from app import stats

    got = stats._applications(conn, _days(args.get("days"), 7))
    if not got.get("available"):
        return {"available": False, "enabled": got.get("enabled", False), "note": "No plugin reports traffic per device or per application (or it is switched off under Settings)."}
    gb = lambda b: round(b / 1e9, 2)  # noqa: E731
    return {"available": True, "from": got["from"], "to": got["to"], "total_down_gb": gb(got["rx"]), "total_up_gb": gb(got["tx"]),
            "top_applications": [{"name": a["name"], "gb": gb(a["rx"] + a["tx"]), "share_percent": a["share"]} for a in got["applications"][:10]],
            "top_devices": [{"name": c["name"], "gb": gb(c["rx"] + c["tx"]), "down_gb": gb(c["rx"]), "up_gb": gb(c["tx"])} for c in got["clients"][:10]]}


def t_network_health(conn, args, now=None) -> dict:
    """The newest result of the IPv4 and IPv6 network checks (the Network health page): the gateway, DNS, DHCP, internet, how full each address range is."""
    from app import ipv4health, ipv6health

    out: dict[str, Any] = {}
    for fam, mod in (("ipv4", ipv4health), ("ipv6", ipv6health)):
        r = mod.last(conn)
        if not r:
            out[fam] = {"checked": False}
            continue
        out[fam] = {"checked": r.get("ts"), "verdict": r.get("verdict"), "headline": r.get("headline"),
                    "findings": [{"level": f["level"], "title": f["title"], "text": f["text"][:240]} for f in r.get("findings", [])][:12],
                    "ranges": [{"range": s["range"], "addresses": s["size"], "devices_known": s["known"], "online": s["online"], "percent_used": s["usage"],
                                "roughly_free": max(0, s["size"] - s["known"])} for s in r.get("subnets", [])]}
    return out


TOOLS = {
    "metric": (t_metric, "ANY STORED READING over time of the monitored devices: cpu, memory (ram), swap, load, disk use or free space, temperature (switches, servers), UPS battery, fans, traffic in and out, ping time, interface errors, link state, and UPTIME and REBOOTS. Ranks the devices (highest or lowest) or shows one device's minimum, average, maximum and trend over a period. Use it for 'which devices rebooted', 'how hot is the switch', 'swap in use', 'CPU of X yesterday', 'which has the least free space'. Call it without args.metric to see which readings exist. args: metric (name or plain word), device (optional name), days (0.25 to 30, default 1), order (highest or lowest), limit, label (optional, such as eth0 or C:\\)"),
    "host_findings": (t_host_findings, "what the read-only host probes found on ALL hosts at once, filtered by a topic: failed services, who logged in, kernel or disk errors, swap, containers restarting, updates, listening ports, scheduled jobs. Use for 'which systems have ...' questions about the inside of a host. args: topic (words such as failed service, login, swap, restart)"),
    "usage": (t_usage, "TRAFFIC PER DEVICE and PER APPLICATION (who and what uses the bandwidth) over some days, as the router counts it. args: days (1-30)"),
    "network_health": (t_network_health, "the NETWORK HEALTH checks (IPv4 and IPv6): gateway, internet, DNS, DHCP servers, rogue DHCP, and how full each address range is with roughly how many addresses are free. Use for 'is my network in good order', 'free IP addresses', 'DHCP range'. args: none"),
}


def r_metric(r: dict) -> str:
    if r.get("metric") is None:
        return "Readings Netlens stores: " + ", ".join(f"{a['what']} ({a['devices']} devices)" for a in r["available"][:12]) + "."
    unit = METRICS[r["metric"]][2]
    if r["metric"] == "uptime_s":
        if r["rebooted"]:
            return f"In the last {r['days']:g} days: " + "; ".join(f"{x['device']} rebooted {x['reboots']}x (last around {x['rebooted_at'][-1]})" for x in r["rebooted"]) + "."
        return f"None of the {r['devices_read']} devices that report their uptime rebooted in the last {r['days']:g} days."
    if not r["values"]:
        return f"No device has a recent {r['what']} reading."
    parts = []
    for v in r["values"][:8]:
        p = v.get("period")
        parts.append(f"{v['device']}{(' ' + v['label']) if v['label'] else ''}: {v['latest']} {unit}" + (f" (period {p['min']}-{p['max']}, average {p['avg']})" if p else ""))
    return f"{r['what'].capitalize()}, {r['values'][0]['device']} first: " + "; ".join(parts) + "."


def r_host_findings(r: dict) -> str:
    if not r["hosts_looked_at"]:
        return "No host probe has data yet: switch on Host probes for a host (device page → Host probes)."
    if not r["findings"]:
        return f"None of the {r['hosts_looked_at']} hosts with probes reported anything" + (f" about {r['topic']}" if r["topic"] else "") + "."
    return f"{r['count']} findings on {r['hosts_looked_at']} hosts: " + " ".join(f"{f['device']}: {f['text']}" for f in r["findings"][:8])


def r_usage(r: dict) -> str:
    if not r["available"]:
        return r["note"]
    return (f"Between {r['from']} and {r['to']}: {r['total_down_gb']} GB down, {r['total_up_gb']} GB up. Most by application: " + ", ".join(f"{a['name']} {a['gb']} GB" for a in r["top_applications"][:5])
            + ". Most by device: " + ", ".join(f"{d['name']} {d['gb']} GB" for d in r["top_devices"][:5]) + ".")


def r_network_health(r: dict) -> str:
    parts = []
    for fam in ("ipv4", "ipv6"):
        x = r[fam]
        if not x.get("checked"):
            parts.append(f"{fam.upper()} has not been checked yet.")
            continue
        parts.append(f"{fam.upper()}: {x['headline']}" + "".join(f" {f['title']}." for f in x["findings"] if f["level"] in ("bad", "warn")) +
                     "".join(f" {g['range']} has about {g['roughly_free']} of {g['addresses']} addresses free ({g['percent_used']}% used)." for g in x["ranges"]))
    return " ".join(parts)


RENDERERS = {"metric": r_metric, "host_findings": r_host_findings, "usage": r_usage, "network_health": r_network_health}
PRESETS = [
    {"id": "reboots", "text": "Which devices rebooted in the last week?", "tool": "metric", "args": {"metric": "uptime", "days": 7}},
    {"id": "hot", "text": "Which devices run the hottest?", "tool": "metric", "args": {"metric": "temperature"}},
    {"id": "freeips", "text": "Is my network in good order, and how full are the address ranges?", "tool": "network_health", "args": {}},
    {"id": "usage", "text": "Which devices and applications use the most traffic?", "tool": "usage", "args": {"days": 7}},
]
RULES = [
    ("network_health", r"free (ip|address)|ip addresses? (are )?(free|left|available)|dhcp (range|scope|pool)|address (range|space)|network health|is my network (healthy|in good order|ok)|packet loss to .{0,20}gateway|(gateway|internet|dns) (check|ok|working)"),
    ("usage", r"(which|what) (devices?|clients?|machines?|applications?|apps?).{0,30}(most|biggest|top).{0,20}(traffic|bandwidth|data)|(most|top|biggest) (talkers?|bandwidth|traffic|data users?)|(who|what|which).{0,25}(uses?|using|eats?|hogs?).{0,15}(the )?(bandwidth|data|traffic|internet)"),
    ("metric", r"\breboot(s|ed)?\b|restarted|\buptime\b|how long .{0,30}(been )?(up|running|online)|swap|how (hot|warm)|temperatures?|which .{0,20}(hottest|coolest)|battery level|ups battery"),
]


def route(q: str, names: list[str]) -> tuple[str, dict] | None:
    for tool, pattern in RULES:
        if re.search(pattern, q):
            if tool == "metric":
                days = 7 if re.search(r"week|7 ?d", q) else 30 if "month" in q else 1
                name = next((n for n in sorted(names, key=len, reverse=True) if len(n) > 2 and n.lower() in q), "")
                return tool, {k: v for k, v in (("metric", pick_metric(q) or ""), ("device", name), ("days", days)) if v}
            if tool == "usage":
                return tool, {"days": 7 if re.search(r"week|7 ?d", q) else 30 if "month" in q else 1}
            return tool, {}
    return None


def register() -> None:
    ask.TOOLS.update(TOOLS)
    ask.RENDERERS.update(RENDERERS)
    ask.PRESETS.extend(p for p in PRESETS if p["id"] not in {x["id"] for x in ask.PRESETS})
