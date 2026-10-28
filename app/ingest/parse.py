"""What a collector sends, turned into the readings Netlens already knows (cpu_pct, mem_pct, disk_pct, net_rx_bps ...).

Two formats are accepted, both as JSON only (no protobuf, no gRPC: a plain JSON parse cannot corrupt memory):

  * OTLP/HTTP JSON (`POST /v1/metrics`) from the OpenTelemetry Collector or Grafana Alloy, with the `hostmetrics` receiver;
  * the Telegraf JSON format (`POST /telegraf`), which is also the format a small shell script can produce on a Unix system without a collector.

Nothing else gets through: metrics outside the allow-list are dropped and counted, every attribute is limited to a few known keys, every text is length-capped and
restricted to a safe alphabet, and numbers must be finite and plausible. The host name in the payload is only used to choose between hosts a gateway may report for;
it is never shown or stored. No free text of the sender reaches the database, the screens or the AI.
"""

from __future__ import annotations

import math
import re
import time
from typing import Any

from app.hostmetrics.snmp import MAX_INTERFACES, SKIP_MOUNTS, _delta
from app.hostmetrics.ssh import SKIP_IFACES, SKIP_TYPES

MAX_POINTS = 2000                  # data points in one request
MAX_RESOURCES = 200                # hosts in one request (a gateway)
MAX_DISKS = 80
PAST_S, FUTURE_S = 86400, 300      # how old / how far ahead a timestamp may be
LABEL_RE = re.compile(r"^[A-Za-z0-9 _.:/\\@+()\[\]-]{1,40}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
ATTR_KEYS = ("state", "direction", "device", "mountpoint", "type", "cpu", "mode")
OTEL_ALLOWED = frozenset({
    "system.cpu.time", "system.cpu.utilization", "system.cpu.load_average.1m", "system.memory.usage", "system.memory.utilization",
    "system.paging.usage", "system.filesystem.usage", "system.network.io", "system.uptime"})
IDLE_STATES = ("idle", "iowait")
UNITS = {"cpu_pct": "%", "load1": "", "mem_pct": "%", "swap_pct": "%", "disk_pct": "%", "disk_free_b": "B", "net_rx_bps": "bps", "net_tx_bps": "bps", "uptime_s": "s"}


class ParseError(ValueError):
    """The request cannot be used at all (too large, not what it says it is)."""


def _list(v: Any) -> list:
    return v if isinstance(v, list) else []


def _num(v: Any) -> float | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, str):
        if not re.fullmatch(r"-?\d{1,20}(\.\d{1,20})?([eE][+-]?\d{1,3})?", v):
            return None
        v = float(v)
    if isinstance(v, (int, float)) and math.isfinite(v):
        return float(v)
    return None


def _label(raw: Any) -> str | None:
    s = str(raw if raw is not None else "")
    return s if LABEL_RE.match(s) else None


def _host(raw: Any) -> str:
    s = str(raw or "").strip().lower()
    return s if HOST_RE.match(s) else ""


# ----------------------------------------------------------------------------------------------- OTLP
def _any_value(v: Any) -> str | None:
    if not isinstance(v, dict):
        return None
    for key in ("stringValue", "intValue", "boolValue"):
        if key in v and isinstance(v[key], (str, int, bool)):
            return str(v[key])[:64]
    return None


def _attrs(items: Any, keep: tuple[str, ...]) -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(items, list):
        for it in items[:64]:
            if isinstance(it, dict) and it.get("key") in keep:
                val = _any_value(it.get("value"))
                if val is not None:
                    out[it["key"]] = val
    return out


def otlp(doc: Any) -> tuple[list[tuple[str, list[tuple]]], int]:
    """([(host name or "", [(metric, attrs, ts, value)])], dropped data points) from an OTLP/JSON body."""
    if not isinstance(doc, dict):
        raise ParseError("the body is not an OTLP metrics document")
    resources = doc.get("resourceMetrics")
    if not isinstance(resources, list):
        raise ParseError("the body is not an OTLP metrics document")
    if len(resources) > MAX_RESOURCES:
        raise ParseError("too many resources in one request")
    out, dropped, seen = [], 0, 0
    for res in resources:
        if not isinstance(res, dict):
            continue
        host = _host(_find_host(res.get("resource") if isinstance(res.get("resource"), dict) else {}))
        samples: list[tuple] = []
        for scope in _list(res.get("scopeMetrics")):
            if not isinstance(scope, dict):
                continue
            for metric in _list(scope.get("metrics")):
                if not isinstance(metric, dict):
                    continue
                name = metric.get("name")
                name = name if isinstance(name, str) else ""
                if name not in OTEL_ALLOWED:               # not a metric Netlens uses: ignored, not an error (a collector sends many more than are wanted)
                    continue
                body = metric.get("sum") or metric.get("gauge")
                points = body.get("dataPoints") if isinstance(body, dict) else None
                if not isinstance(points, list):
                    dropped += 1
                    continue
                seen += len(points)
                if seen > MAX_POINTS:
                    raise ParseError("too many data points in one request")
                for p in points:
                    if not isinstance(p, dict):
                        dropped += 1
                        continue
                    value = _num(p.get("asDouble") if "asDouble" in p else p.get("asInt"))
                    ns = _num(p.get("timeUnixNano"))
                    if value is None:
                        dropped += 1
                        continue
                    samples.append((name, _attrs(p.get("attributes"), ATTR_KEYS), ns / 1e9 if ns else None, value))
        out.append((host, samples))
    return out, dropped


def _find_host(resource: dict) -> str:
    for it in _list(resource.get("attributes")):
        if isinstance(it, dict) and it.get("key") == "host.name":
            return _any_value(it.get("value")) or ""
    return ""


def _latest(samples: list[tuple], name: str, now: float) -> tuple[dict[tuple, tuple], int]:
    """The newest sample of each series of one metric, and how many were left out because their time is implausible."""
    best: dict[tuple, tuple] = {}
    bad = 0
    for n, attrs, ts, value in samples:
        if n != name:
            continue
        t = ts if ts else now
        if t < now - PAST_S or t > now + FUTURE_S:
            bad += 1
            continue
        key = tuple(sorted(attrs.items()))
        if key not in best or t >= best[key][0]:
            best[key] = (t, value, attrs)
    return best, bad


def otlp_points(samples: list[tuple], state: dict, now: float | None = None) -> tuple[list[tuple], float, int]:
    """(points (metric, label, value, unit), time, dropped) for one host. `state` keeps the counters of the previous request."""
    now = now if now is not None else time.time()
    points: list[tuple] = []
    stamp = 0.0
    bad = 0

    def add(metric: str, label: str, value: float, lo: float = 0.0, hi: float | None = None) -> None:
        if value != value or value < lo or (hi is not None and value > hi):
            return
        points.append((metric, label, value, UNITS[metric]))

    # processor: busy share between two requests from the counters; the utilization gauge when the collector sends that instead
    cpu, b = _latest(samples, "system.cpu.time", now)
    bad += b
    if cpu:
        total = sum(v for _t, v, _a in cpu.values())
        idle = sum(v for _t, v, a in cpu.values() if a.get("state") in IDLE_STATES)
        t = max(t for t, _v, _a in cpu.values())
        before = state.get("cpu")
        state["cpu"] = (t, total, idle)
        stamp = max(stamp, t)
        if before and t > before[0] and total > before[1] and total - before[1] > 0 and idle >= before[2]:
            add("cpu_pct", "", 100.0 * (1 - (idle - before[2]) / (total - before[1])), 0, 100)
    else:
        util, b = _latest(samples, "system.cpu.utilization", now)
        bad += b
        idles = [v for _t, v, a in util.values() if a.get("state") == "idle"]
        if idles:
            add("cpu_pct", "", 100.0 * (1 - sum(idles) / len(idles)), 0, 100)
            stamp = max(stamp, max(t for t, _v, _a in util.values()))
    load, b = _latest(samples, "system.cpu.load_average.1m", now)
    bad += b
    for t, v, _a in load.values():
        add("load1", "", v, 0, 1e5)
        stamp = max(stamp, t)
        break

    mem, b = _latest(samples, "system.memory.usage", now)
    bad += b
    if mem:
        by = {a.get("state"): v for _t, v, a in mem.values()}
        whole = sum(v for v in by.values() if v >= 0)
        if whole > 0 and "used" in by:
            add("mem_pct", "", 100.0 * by["used"] / whole, 0, 100)
            stamp = max(stamp, max(t for t, _v, _a in mem.values()))
    else:
        util, b = _latest(samples, "system.memory.utilization", now)
        bad += b
        for t, v, a in util.values():
            if a.get("state") == "used":
                add("mem_pct", "", 100.0 * v, 0, 100)
                stamp = max(stamp, t)
    paging, b = _latest(samples, "system.paging.usage", now)
    bad += b
    if paging:
        by = {a.get("state"): v for _t, v, a in paging.values()}
        if by.get("used") is not None and by.get("free") is not None and by["used"] + by["free"] > 0:
            add("swap_pct", "", 100.0 * by["used"] / (by["used"] + by["free"]), 0, 100)

    fs, b = _latest(samples, "system.filesystem.usage", now)
    bad += b
    mounts: dict[str, dict] = {}
    for t, v, a in fs.values():
        mount = _label(a.get("mountpoint"))
        if mount is None or a.get("type") in SKIP_TYPES or mount.startswith(SKIP_MOUNTS) or a.get("state") not in ("used", "free"):
            continue
        mounts.setdefault(mount, {})[a["state"]] = v
        stamp = max(stamp, t)
    n = 0
    for mount, by in mounts.items():
        if "used" in by and "free" in by and by["used"] + by["free"] >= 64 * 1024:
            add("disk_pct", mount, 100.0 * by["used"] / (by["used"] + by["free"]), 0, 100)
            add("disk_free_b", mount, by["free"], 0, 1e18)
            n += 1
            if n >= MAX_DISKS:
                break

    net, b = _latest(samples, "system.network.io", now)
    bad += b
    seen: dict[str, dict] = {}
    for t, v, a in net.values():
        dev = _label(a.get("device"))
        if dev is None or SKIP_IFACES.match(dev) or a.get("direction") not in ("receive", "transmit"):
            continue
        seen.setdefault(dev, {"t": t})[a["direction"]] = v
        seen[dev]["t"] = max(seen[dev]["t"], t)
    count = 0
    for dev, d in seen.items():
        if "receive" not in d or "transmit" not in d:
            continue
        mark = state.get(("if", dev))
        state[("if", dev)] = (d["t"], d["receive"], d["transmit"])
        stamp = max(stamp, d["t"])
        if mark is None or d["t"] <= mark[0]:
            continue
        da, db = _delta(d["receive"], mark[1], 64), _delta(d["transmit"], mark[2], 64)
        if da is None or db is None:
            continue
        dt = d["t"] - mark[0]
        add("net_rx_bps", dev, da * 8 / dt, 0, 1e13)
        add("net_tx_bps", dev, db * 8 / dt, 0, 1e13)
        count += 1
        if count >= MAX_INTERFACES:
            break

    up, b = _latest(samples, "system.uptime", now)
    bad += b
    for t, v, _a in up.values():
        add("uptime_s", "", v, 0, 1e10)
        stamp = max(stamp, t)
        break
    return points, (stamp or now), bad


# ----------------------------------------------------------------------------------------------- Telegraf / generic JSON
def telegraf(doc: Any) -> list[dict]:
    """The metric objects of a Telegraf JSON body: one object, a list, or {"metrics": [...]}."""
    if isinstance(doc, dict) and isinstance(doc.get("metrics"), list):
        items = doc["metrics"]
    elif isinstance(doc, list):
        items = doc
    elif isinstance(doc, dict):
        items = [doc]
    else:
        raise ParseError("the body is not a Telegraf JSON document")
    if len(items) > MAX_POINTS:
        raise ParseError("too many metrics in one request")
    return [i for i in items if isinstance(i, dict)]


def telegraf_points(items: list[dict], state: dict, now: float | None = None) -> tuple[list[tuple], float, int]:
    now = now if now is not None else time.time()
    points: list[tuple] = []
    stamp, dropped = 0.0, 0
    nets: dict[str, dict] = {}
    for it in items:
        name, tags, fields = it.get("name"), it.get("tags"), it.get("fields")
        name = name if isinstance(name, str) else ""
        if not isinstance(tags, dict) or not isinstance(fields, dict):
            dropped += 1
            continue
        ts = _num(it.get("timestamp")) or now
        if ts > 1e11:                               # milliseconds
            ts /= 1000.0
        if ts < now - PAST_S or ts > now + FUTURE_S:
            dropped += 1
            continue
        stamp = max(stamp, ts)

        def put(metric: str, label: str, value: float | None, hi: float | None = None) -> None:
            if value is None or value < 0 or (hi is not None and value > hi):
                return
            points.append((metric, label, value, UNITS[metric]))

        if name == "cpu" and tags.get("cpu") == "cpu-total":
            idle = _num(fields.get("usage_idle"))
            if idle is not None and 0 <= idle <= 100:
                put("cpu_pct", "", 100.0 - idle, 100)
        elif name == "mem":
            put("mem_pct", "", _num(fields.get("used_percent")), 100)
        elif name == "swap":
            if (_num(fields.get("total")) or 0) > 0:
                put("swap_pct", "", _num(fields.get("used_percent")), 100)
        elif name == "disk":
            mount = _label(tags.get("path"))
            fstype = tags.get("fstype")
            if mount is None or (isinstance(fstype, str) and fstype in SKIP_TYPES) or mount.startswith(SKIP_MOUNTS):
                continue
            put("disk_pct", mount, _num(fields.get("used_percent")), 100)
            put("disk_free_b", mount, _num(fields.get("free")), 1e18)
        elif name == "net":
            dev = _label(tags.get("interface"))
            rx, tx = _num(fields.get("bytes_recv")), _num(fields.get("bytes_sent"))
            if dev and dev != "all" and not SKIP_IFACES.match(dev) and rx is not None and tx is not None:
                nets[dev] = {"t": ts, "rx": rx, "tx": tx}
        elif name == "system":
            put("load1", "", _num(fields.get("load1")), 1e5)
            put("uptime_s", "", _num(fields.get("uptime")), 1e10)
    count = 0
    for dev, d in nets.items():
        mark = state.get(("if", dev))
        state[("if", dev)] = (d["t"], d["rx"], d["tx"])
        if mark is None or d["t"] <= mark[0]:
            continue
        da, db = _delta(d["rx"], mark[1], 64), _delta(d["tx"], mark[2], 64)
        if da is None or db is None:
            continue
        dt = d["t"] - mark[0]
        put_rx, put_tx = da * 8 / dt, db * 8 / dt
        if put_rx <= 1e13 and put_tx <= 1e13:
            points.append(("net_rx_bps", dev, put_rx, "bps"))
            points.append(("net_tx_bps", dev, put_tx, "bps"))
            count += 1
        if count >= MAX_INTERFACES:
            break
    return points, (stamp or now), dropped


def telegraf_hosts(items: list[dict]) -> dict[str, list[dict]]:
    """The items grouped by the `host` tag (a gateway sends several hosts in one request); "" when there is no tag."""
    out: dict[str, list[dict]] = {}
    for it in items:
        tags = it.get("tags") if isinstance(it.get("tags"), dict) else {}
        out.setdefault(_host(tags.get("host")), []).append(it)
    if len(out) > MAX_RESOURCES:
        raise ParseError("too many hosts in one request")
    return out
