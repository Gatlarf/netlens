"""The answers of every probe as one structure per probe (the same for Linux and Windows), so that the analysis does not care where it came from.

  cpu       {"cpus", "load": [1,5,15], "cpu_pct": {"us","sy","id","wa","st"}, "pressure": {"cpu": avg10 ...}, "procs": [{"pid","name","cpu","container"}], "containers": [{"name","cpu"}]}
  memory    {"total","available","used_pct","swap_total","swap_used","swap_io": {"si","so"}, "pressure", "procs": [{"pid","name","rss","container"}], "oom": [text], "containers": [...], "container_oom": [...]}
  network   {"interfaces": [{"name","rx_bps","tx_bps","rx_err","tx_err","rx_drop","tx_drop","rx_pkts","tx_pkts"}], "tcp": {...}, "states", "remote", "processes", "listening", "ping", "dns"}
  apps      {"failed_units", "errors", "sample", "containers", "uptime_s"}
  changes   {"events": [{"at": epoch, "kind", "text"}]}
  schedule  {"jobs": [{"name","source","last","next","detail"}], "runs": [{"at","text"}]}
  hardware  {"disks", "raid", "zfs", "temps", "errors", "readonly", "ups"}
  security  {"failed","failed_total","accepted","sudo","exposed","users","admins","updates","time_synced","firewall"}

Storage has its own parser (app/hostprobe/parse.py).
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from app.hostprobe.parse import ProbeError, _int, _sections, docker_size


# ----------------------------------------------------------------------------- small helpers
def _f(text: Any, default: float | None = None) -> float | None:
    try:
        return float(str(text).strip().rstrip("%"))
    except ValueError:
        return default


def _size(text: str) -> float:
    """top prints sizes like 1234, 56.7m, 1.2g (KiB by default)."""
    m = re.match(r"^([\d.]+)([kmgtp]?)$", (text or "").strip().lower())
    if not m:
        return 0.0
    return float(m.group(1)) * {"": 1024, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3, "t": 1024 ** 4, "p": 1024 ** 5}[m.group(2)]


def _need(sec: dict[str, list[str]]) -> None:
    if "end" not in sec:
        raise ProbeError("the answer from the host was cut off")


def _version(sec: dict[str, list[str]]) -> int | None:
    return next((int(k.split()[1]) for k in sec if k.startswith("version ") and k.split()[1].isdigit()), None)


def _win_json(text: str) -> dict[str, Any]:
    at = text.find("##netlens-probe")
    if at < 0:
        raise ProbeError("the answer from the host was cut off")
    try:
        data = json.loads(text[at + len("##netlens-probe"):].strip())
    except ValueError:
        raise ProbeError("the answer from the host could not be read") from None
    if not isinstance(data, dict):
        raise ProbeError("the answer from the host could not be read")
    return data


def _many(v: Any) -> list:
    return v if isinstance(v, list) else ([v] if isinstance(v, dict) else [])


def _iso(text: Any) -> float | None:
    try:
        return datetime.fromisoformat(str(text).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _local_epoch(text: str, fmt: str, tz: str) -> float | None:
    """Local wall-clock text with the host's UTC offset (+0100) to epoch seconds."""
    try:
        sign = -1 if tz.startswith("-") else 1
        offset = timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5])) * sign
        return (datetime.strptime(text, fmt) - offset).replace(tzinfo=timezone.utc).timestamp()
    except (ValueError, IndexError):
        return None


def _containers(sec: dict[str, list[str]]) -> dict[str, str]:
    """pid -> container name, from the cgroup of the process and the map of container ids."""
    names = {}
    for line in sec.get("containers", []):
        cid, _, name = line.partition("|")
        if name:
            names[cid] = name.lstrip("/")
    out = {}
    for line in sec.get("cgroups", []):
        pid, _, cid = line.partition("|")
        if cid:
            out[pid] = names.get(cid, cid)
    return out


def _pressure(lines: list[str]) -> dict[str, float]:
    out = {}
    for line in lines:
        m = re.match(r"^(\w+) some avg10=([\d.]+)", line.strip())
        if m:
            out[m.group(1)] = float(m.group(2))
    return out


def _vmstat(lines: list[str]) -> dict[str, float]:
    nums = lines[-1].split() if lines else []
    if len(nums) < 17:
        return {}
    keys = ["r", "b", "swpd", "free", "buff", "cache", "si", "so", "bi", "bo", "in", "cs", "us", "sy", "id", "wa", "st"]
    return {k: float(v) for k, v in zip(keys, nums[:17]) if re.fullmatch(r"-?\d+", v)}


# ----------------------------------------------------------------------------- Linux
def parse_cpu_linux(text: str) -> dict[str, Any]:
    sec = _sections(text)
    _need(sec)
    load = [float(x) for x in (sec.get("loadavg") or [""])[0].split()[:3] if re.fullmatch(r"[\d.]+", x)]
    cpus = _int((sec.get("cpus") or ["0"])[0]) or None
    cgroup = _containers(sec)
    procs: list[dict[str, Any]] = []
    cpu_pct: dict[str, float] = {}
    for line in sec.get("top", []):
        if line.startswith("%Cpu"):
            for value, key in re.findall(r"([\d.]+)\s+(us|sy|ni|id|wa|hi|si|st)", line):
                cpu_pct[key] = float(value)
        m = re.match(r"^\s*(\d+)\s+(\S+)\s+\S+\s+\S+\s+\S+\s+(\S+)\s+\S+\s+\S\s+([\d.,]+)\s+([\d.,]+)\s+\S+\s+(.+)$", line)
        if m:
            procs.append({"pid": int(m.group(1)), "name": m.group(6).strip(), "user": m.group(2), "cpu": float(m.group(4).replace(",", ".")), "mem_pct": float(m.group(5).replace(",", ".")),
                          "container": cgroup.get(m.group(1))})
    if not procs:                                      # a system without a usable top: ps (average over the life of the process, better than nothing)
        for line in sec.get("ps", [])[1:]:
            p = line.split(None, 6)
            if len(p) == 7 and p[0].isdigit():
                procs.append({"pid": int(p[0]), "name": p[6], "user": p[5], "cpu": float(p[1]), "mem_pct": float(p[2]), "container": cgroup.get(p[0])})
    procs.sort(key=lambda p: -p["cpu"])
    containers = []
    for line in sec.get("dockerstats", []):
        p = line.split("|")
        if len(p) >= 2:
            containers.append({"name": p[0], "cpu": _f(p[1], 0.0), "mem": p[2] if len(p) > 2 else "", "net": p[3] if len(p) > 3 else "", "block": p[4] if len(p) > 4 else ""})
    containers.sort(key=lambda c: -c["cpu"])
    return {"platform": "linux", "script_version": _version(sec), "cpus": cpus, "load": load, "cpu_pct": cpu_pct, "pressure": _pressure(sec.get("pressure", [])),
            "vmstat": _vmstat(sec.get("vmstat", [])), "procs": procs[:12], "containers": containers[:10]}


def parse_memory_linux(text: str) -> dict[str, Any]:
    sec = _sections(text)
    _need(sec)
    info = {}
    for line in sec.get("meminfo", []):
        k, _, v = line.partition(":")
        info[k] = _int(v.split()[0]) * 1024 if v.split() else 0
    total, avail = info.get("MemTotal", 0), info.get("MemAvailable", info.get("MemFree", 0))
    cgroup = _containers(sec)
    procs = []
    for line in sec.get("ps", [])[1:]:
        p = line.split(None, 5)
        if len(p) == 6 and p[0].isdigit():
            procs.append({"pid": int(p[0]), "name": p[5], "user": p[4], "rss": _int(p[1]) * 1024, "pmem": _f(p[2], 0.0), "container": cgroup.get(p[0])})
    vm = _vmstat(sec.get("vmstat", []))
    containers = []
    for line in sec.get("dockerstats", []):
        p = line.split("|")
        if len(p) >= 4:
            containers.append({"name": p[0], "cpu": _f(p[1], 0.0), "mem": p[2], "mem_pct": _f(p[3], 0.0)})
    containers.sort(key=lambda c: -(c["mem_pct"] or 0))
    oom = []
    for line in sec.get("dockeroom", []):
        p = line.split("|")
        if len(p) >= 3:
            oom.append({"name": p[0].lstrip("/"), "oom": p[1].strip().lower() == "true", "restarts": _int(p[2]), "limit": _int(p[3]) if len(p) > 3 else 0})
    return {"platform": "linux", "script_version": _version(sec), "total": total, "available": avail, "used_pct": round(100 * (1 - avail / total), 1) if total else None,
            "swap_total": info.get("SwapTotal", 0), "swap_used": info.get("SwapTotal", 0) - info.get("SwapFree", 0), "cached": info.get("Cached", 0), "slab": info.get("Slab", 0),
            "committed": info.get("Committed_AS", 0), "commit_limit": info.get("CommitLimit", 0), "swap_io": {"si": vm.get("si", 0.0), "so": vm.get("so", 0.0)},
            "pressure": _pressure(sec.get("pressure", [])), "procs": procs, "oom": sec.get("oom", [])[:10], "containers": containers[:10], "container_oom": oom}


def _net_dev(lines: list[str]) -> dict[str, list[int]]:
    out = {}
    for line in lines:
        name, sep, rest = line.partition(":")
        nums = rest.split()
        if sep and len(nums) >= 16:
            out[name.strip()] = [int(x) for x in nums[:16]]
    return out


def _kv_pair(lines: list[str], prefix: str) -> dict[str, int]:
    rows = [l for l in lines if l.startswith(prefix + ":")]
    if len(rows) < 2:
        return {}
    return {k: int(v) for k, v in zip(rows[0].split()[1:], rows[1].split()[1:]) if v.lstrip("-").isdigit()}


def parse_network_linux(text: str) -> dict[str, Any]:
    sec = _sections(text)
    _need(sec)
    a, b = _net_dev(sec.get("net1", [])), _net_dev(sec.get("net2", []))
    nics = []
    for name, now in b.items():
        if name == "lo" or name.startswith(("veth", "docker", "br-")):
            continue
        before = a.get(name, now)
        d = [x - y for x, y in zip(now, before)]
        nics.append({"name": name, "rx_bps": d[0] * 8.0, "tx_bps": d[8] * 8.0, "rx_pkts": d[1], "tx_pkts": d[9], "rx_err": d[2], "tx_err": d[10], "rx_drop": d[3], "tx_drop": d[11],
                     "rx_err_total": now[2], "tx_err_total": now[10], "rx_drop_total": now[3], "tx_drop_total": now[11], "rx_pkts_total": now[1], "tx_pkts_total": now[9]})
    nics.sort(key=lambda n: -(n["rx_bps"] + n["tx_bps"]))
    tcp = _kv_pair(sec.get("snmp", []), "Tcp")
    ext = _kv_pair(sec.get("tcpext", []), "TcpExt")
    states = {}
    for line in sec.get("states", []):
        k, _, v = line.partition("|")
        states[k] = _int(v)
    remote = [{"ip": ip, "count": _int(c)} for c, _, ip in (l.partition("|") for l in sec.get("remote", []))]
    processes = []
    for line in sec.get("processes", []):
        m = re.match(r"^\s*(\d+)\s+(.+)$", line)
        if m:
            processes.append({"name": m.group(2), "count": int(m.group(1))})
    listening = []
    for line in sec.get("listening", []):
        addr, _, users = line.partition("|")
        m = re.search(r'\(\("([^"]*)"', users)
        listening.append({"addr": addr, "process": m.group(1) if m else ""})
    ping = []
    for line in sec.get("ping", []):
        kind, _, rest = line.partition("|")
        target, _, tail = rest.partition("|")
        if kind == "dns":
            continue
        loss = re.search(r"(\d+(?:\.\d+)?)% packet loss", tail)
        rtt = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)", tail)
        ping.append({"kind": kind, "target": target, "loss": float(loss.group(1)) if loss else 100.0, "rtt": float(rtt.group(2)) if rtt else None})
    dns = None
    for line in sec.get("ping", []):
        m = re.match(r"^dns\|[^|]*\|rc=(\d+) ms=(\d+)", line)
        if m:
            dns = {"ok": m.group(1) == "0", "ms": int(m.group(2))}
    return {"platform": "linux", "script_version": _version(sec), "interfaces": nics[:10], "tcp": {**{k: tcp.get(k) for k in ("RetransSegs", "OutSegs", "InSegs", "AttemptFails", "EstabResets") if k in tcp},
            **{k: ext.get(k) for k in ("ListenOverflows", "ListenDrops", "TCPTimeouts") if k in ext}}, "states": states, "remote": remote, "processes": processes, "listening": listening[:25],
            "ping": ping, "dns": dns, "route": (sec.get("route") or [""])[0]}


def parse_apps_linux(text: str) -> dict[str, Any]:
    sec = _sections(text)
    _need(sec)
    failed = []
    info = {}
    for line in sec.get("failedinfo", []):
        kv = dict(re.findall(r"(\w+)=(\S*(?: \S+)*?)(?=\s+\w+=|\s*\|?$)", line))
        if kv.get("Id"):
            info[kv["Id"]] = kv
    for line in sec.get("failed", []):
        unit = line.split()[0].lstrip("●* ")
        i = info.get(unit, {})
        failed.append({"unit": unit, "result": i.get("Result", ""), "exit": _int(i.get("ExecMainStatus", 0)), "restarts": _int(i.get("NRestarts", 0)), "since": i.get("InactiveEnterTimestamp", "")})
    errors = [{"unit": u, "count": _int(c)} for c, _, u in (l.partition("|") for l in sec.get("journal", []))]
    containers = []
    bad_errors = {}
    for line in sec.get("dockererrors", []):
        name, _, n = line.partition("|")
        bad_errors[name.lstrip("/")] = _int(n)
    for line in sec.get("docker", []):
        p = line.split("|")
        if len(p) >= 9:
            name = p[0].lstrip("/")
            containers.append({"name": name, "state": p[1], "exit": _int(p[2]), "oom": p[3].strip().lower() == "true", "restarts": _int(p[4]), "health": p[5], "started": _iso(p[6]),
                               "finished": _iso(p[7]) if not p[7].startswith("0001") else None, "image": p[8], "errors": bad_errors.get(name)})
    return {"platform": "linux", "script_version": _version(sec), "failed_units": failed, "errors": errors, "sample": sec.get("journalsample", [])[:6], "containers": containers,
            "uptime_s": _f((sec.get("uptime") or [""])[0].split()[0] if sec.get("uptime") else None)}


def parse_changes_linux(text: str) -> dict[str, Any]:
    sec = _sections(text)
    _need(sec)
    tz = (sec.get("tz") or ["+0000"])[0].strip()
    now = _f((sec.get("time") or ["0"])[0], 0.0)
    events: list[dict[str, Any]] = []
    for line in sec.get("boots", []):
        m = re.match(r"^(reboot|shutdown)\s+system (?:boot|down)\s+\S+\s+(\w{3} \w{3}\s+\d+ [\d:]+ \d{4})", line)
        if m:
            at = _local_epoch(re.sub(r"\s+", " ", m.group(2)), "%a %b %d %H:%M:%S %Y", tz)
            if at and (not now or now - at < 7 * 86400):
                events.append({"at": at, "kind": "reboot" if m.group(1) == "reboot" else "shutdown", "text": "The host started" if m.group(1) == "reboot" else "The host was shut down"})
    for line in sec.get("packages", []):
        p = line.split()
        if len(p) >= 5 and re.match(r"\d{4}-\d\d-\d\d", p[0]):
            at = _local_epoch(f"{p[0]} {p[1]}", "%Y-%m-%d %H:%M:%S", tz)
            events.append({"at": at, "kind": "package", "text": f"Package {p[3]} {p[2]}d" + (f" to {p[5]}" if len(p) > 5 and p[2] == "upgrade" else "")})
    for line in sec.get("etc", []):
        t, _, path = line.partition("\t")
        if path:
            events.append({"at": _f(t), "kind": "file", "text": f"{path} was changed", "private": True})
    for line in sec.get("docker", []):
        p = line.split("|")
        if len(p) >= 4:
            at = _iso(p[1])
            if at and (not now or now - at < 3 * 86400):
                events.append({"at": at, "kind": "container", "text": f"Container {p[0].lstrip('/')} was created from {p[2]}"})
    for line in sec.get("keys", []):
        p = line.split("|")
        if len(p) >= 3 and _f(p[1]) and now and now - _f(p[1]) < 7 * 86400:
            events.append({"at": _f(p[1]), "kind": "account", "text": f"The SSH keys of {p[0]} were changed ({p[2]})", "private": True})
    events = [e for e in events if e["at"]]
    events.sort(key=lambda e: -e["at"])
    return {"platform": "linux", "script_version": _version(sec), "events": events[:80], "users": [l.split("|")[0] for l in sec.get("users", [])]}


def parse_schedule_linux(text: str) -> dict[str, Any]:
    sec = _sections(text)
    _need(sec)
    jobs = []
    for line in sec.get("timers", []):
        p = line.split("|")
        if len(p) >= 4:
            jobs.append({"name": p[0], "source": "timer", "last": _f(p[2]), "next": _f(p[3]), "detail": p[1]})
    for line in sec.get("cron", []):
        m = re.match(r"^(\S+): (\S+ \S+ \S+ \S+ \S+)\s+(\S+)\s+(.+)$", line)
        if m and not line.split(": ", 1)[1].startswith(("SHELL=", "PATH=", "MAILTO=", "HOME=")):
            jobs.append({"name": m.group(4)[:80], "source": "cron", "last": None, "next": None, "detail": f"{m.group(2)} as {m.group(3)}", "private": True})
    runs = []
    for line in sec.get("cronrun", []):
        m = re.match(r"^(\d+(?:\.\d+)?) \S+ CRON\[\d+\]: \((\S+)\) CMD \((.*)\)$", line)
        if m:
            runs.append({"at": float(m.group(1)), "text": f"cron ran as {m.group(2)}: {m.group(3)[:100]}", "private": True})
    return {"platform": "linux", "script_version": _version(sec), "jobs": jobs, "runs": runs[-40:], "dirs": {l.split("|")[0]: l.split("|", 1)[1].split() for l in sec.get("crondirs", []) if "|" in l}}


def parse_hardware_linux(text: str) -> dict[str, Any]:
    sec = _sections(text)
    _need(sec)
    disks = []
    for line in sec.get("smart", []):
        dev, _, rest = line.partition("|")
        health, _, attrs = rest.partition("|")
        bad = bool(re.search(r"fail", health, re.I)) or any(_int(v) > 0 for k, v in re.findall(r"(Reallocated_Sector_Ct|Current_Pending_Sector|Offline_Uncorrectable)=(\d+)", attrs))
        disks.append({"dev": dev, "health": health.strip() or "unknown", "detail": attrs.strip(), "bad": bad})
    raid = []
    text_md = "\n".join(sec.get("mdstat", []))
    for m in re.finditer(r"^(md\d+) : (\S+) .*?\n\s+\d+ blocks.*?\[(\d+)/(\d+)\] \[([U_]+)\]", text_md, re.M | re.S):
        raid.append({"name": m.group(1), "state": m.group(2), "degraded": "_" in m.group(5), "detail": f"{m.group(4)} of {m.group(3)} disks up"})
    zfs = [{"line": l} for l in sec.get("zpool", []) if l.strip()]
    temps = []
    for line in sec.get("temps", []):
        name, _, t = line.partition(" ")
        if t.strip().lstrip("-").isdigit():
            temps.append({"name": name, "c": int(t) / 1000.0})
    ups = []
    for line in sec.get("ups", []):
        name, _, rest = line.partition("|")
        ups.append({"name": name, "detail": rest.strip()})
    return {"platform": "linux", "script_version": _version(sec), "virt": (sec.get("virt") or [""])[0], "disks": disks, "raid": raid, "zfs": zfs, "temps": temps, "errors": sec.get("ioerrors", [])[:12],
            "readonly": [l.replace("|", " (") + ")" for l in sec.get("readonly", [])], "ups": ups}


def parse_security_linux(text: str) -> dict[str, Any]:
    sec = _sections(text)
    _need(sec)
    failed = [{"ip": m.group(2), "count": int(m.group(1))} for m in (re.match(r"^\s*(\d+)\s+(\S+)$", l) for l in sec.get("failedlogins", [])) if m]
    accepted = []
    for line in sec.get("accepted", []):
        m = re.match(r"^\s*(\d+)\s+([^|]+)\|([^|]+)\|(\S+)$", line)
        if m:
            accepted.append({"count": int(m.group(1)), "method": m.group(2), "user": m.group(3), "ip": m.group(4)})
    updates = {"pending": 0, "security": 0, "reboot": False}
    for line in sec.get("updates", []):
        p = line.split("|")
        if p[0] in ("apt", "dnf") and len(p) >= 2:
            updates["pending"] = _int(p[1])
            updates["security"] = _int(p[2]) if len(p) > 2 else 0
        elif p[0] == "reboot-required":
            updates["reboot"] = True
    ts = None
    for line in sec.get("timesync", []):
        if line.startswith("NTPSynchronized="):
            ts = line.split("=", 1)[1].strip() == "yes"
    firewall = {l.split("|")[0]: l.split("|")[1].strip() for l in sec.get("firewall", []) if "|" in l}
    return {"platform": "linux", "script_version": _version(sec), "failed": failed, "failed_total": sum(f["count"] for f in failed), "accepted": accepted, "sudo": _int((sec.get("sudo") or ["0"])[0]),
            "exposed": sec.get("exposed", []), "docker_ports": sec.get("dockerports", []), "users": [l.split("|")[0] for l in sec.get("users", [])], "admins": sec.get("admins", []),
            "updates": updates, "time_synced": ts, "firewall": firewall}


# ----------------------------------------------------------------------------- Windows
def parse_cpu_windows(text: str) -> dict[str, Any]:
    d = _win_json(text)
    procs = [{"pid": _int(p.get("id")), "name": str(p.get("n") or ""), "user": None, "cpu": _f(p.get("cpu"), 0.0), "mem_pct": None, "container": None} for p in _many(d.get("procs"))]
    return {"platform": "windows", "script_version": d.get("version"), "cpus": _int(d.get("cpus")) or None, "load": [], "cpu_pct": {"busy": _f(d.get("load"))} if d.get("load") is not None else {},
            "pressure": {}, "vmstat": {"r": _f(d.get("queue")), "b": _f(d.get("diskq"))}, "procs": procs, "containers": []}


def parse_memory_windows(text: str) -> dict[str, Any]:
    d = _win_json(text)
    total, free = (_f(d.get("total_kb"), 0.0) or 0) * 1024, (_f(d.get("free_kb"), 0.0) or 0) * 1024
    page = _many(d.get("pagefile"))
    return {"platform": "windows", "script_version": d.get("version"), "total": total, "available": free, "used_pct": round(100 * (1 - free / total), 1) if total else None,
            "swap_total": sum(_int(p.get("size")) for p in page) * 1024 ** 2, "swap_used": sum(_int(p.get("used")) for p in page) * 1024 ** 2, "swap_io": {"si": 0.0, "so": 0.0}, "pressure": {},
            "procs": [{"pid": _int(p.get("id")), "name": str(p.get("n") or ""), "rss": _int(p.get("ws")), "container": None} for p in _many(d.get("procs"))],
            "oom": [f"{e.get('t')} {e.get('m')}" for e in _many(d.get("events"))], "containers": [], "container_oom": []}


def parse_network_windows(text: str) -> dict[str, Any]:
    d = _win_json(text)
    nics = [{"name": str(n.get("n") or ""), "rx_bps": _f(n.get("rx"), 0.0), "tx_bps": _f(n.get("tx"), 0.0), "rx_pkts": 0, "tx_pkts": 0, "rx_err": 0, "tx_err": 0, "rx_drop": 0, "tx_drop": 0,
             "rx_err_total": _int(n.get("rxerr")), "tx_err_total": _int(n.get("txerr")), "rx_drop_total": _int(n.get("rxdrop")), "tx_drop_total": _int(n.get("txdrop")), "rx_pkts_total": 0, "tx_pkts_total": 0}
            for n in _many(d.get("nics"))]
    nics.sort(key=lambda n: -(n["rx_bps"] + n["tx_bps"]))
    ping = [{"kind": str(p.get("t")), "target": str(p.get("ip")), "loss": round(100 - 100 * _int(p.get("ok")) / 3, 1), "rtt": _f(p.get("ms"))} for p in _many(d.get("ping"))]
    dns = d.get("dns") if isinstance(d.get("dns"), dict) else None
    return {"platform": "windows", "script_version": d.get("version"), "interfaces": nics[:10], "tcp": {}, "states": {str(s.get("s")): _int(s.get("c")) for s in _many(d.get("states"))},
            "remote": [{"ip": str(r.get("ip")), "count": _int(r.get("c"))} for r in _many(d.get("remote"))], "processes": [{"name": str(p.get("n") or "?"), "count": _int(p.get("c"))} for p in _many(d.get("processes"))],
            "listening": [{"addr": str(l.get("a")), "process": str(l.get("n") or "")} for l in _many(d.get("listening"))], "ping": ping,
            "dns": {"ok": bool(dns.get("ok")), "ms": _int(dns.get("ms"))} if dns else None, "route": str(d.get("gateway") or "")}


def parse_apps_windows(text: str) -> dict[str, Any]:
    d = _win_json(text)
    boot = _iso(d.get("boot"))
    return {"platform": "windows", "script_version": d.get("version"), "failed_units": [{"unit": str(s.get("n")), "result": str(s.get("state")), "exit": _int(s.get("exit")), "restarts": 0, "since": ""} for s in _many(d.get("services"))],
            "errors": [{"unit": str(e.get("n")), "count": _int(e.get("c"))} for e in _many(d.get("errors"))],
            "sample": [f"{e.get('t')} {e.get('n')}: {e.get('m')}" for e in _many(d.get("sample"))] + [f"{e.get('t')} crash: {e.get('m')}" for e in _many(d.get("crashes"))][:4],
            "containers": [], "uptime_s": (datetime.now(timezone.utc).timestamp() - boot) if boot else None}


def parse_changes_windows(text: str) -> dict[str, Any]:
    d = _win_json(text)
    events = []
    names = {41: "The host restarted after a crash or power loss", 1074: "A restart or shutdown was started", 6005: "The host started", 6006: "The host was shut down cleanly", 6008: "The previous shutdown was unexpected"}
    for e in _many(d.get("boots")):
        events.append({"at": _iso(e.get("t")), "kind": "reboot", "text": names.get(_int(e.get("id")), "The host restarted")})
    for e in _many(d.get("hotfixes")):
        events.append({"at": _iso(e.get("t")), "kind": "package", "text": f"Windows update {e.get('id')} was installed"})
    for e in _many(d.get("installs")):
        events.append({"at": _iso(e.get("t")), "kind": "package", "text": f"Installer: {e.get('m')}"})
    for e in _many(d.get("services")):
        events.append({"at": _iso(e.get("t")), "kind": "service", "text": f"A service was installed: {e.get('m')}"})
    events = [e for e in events if e["at"]]
    events.sort(key=lambda e: -e["at"])
    return {"platform": "windows", "script_version": d.get("version"), "events": events[:80], "users": [str(u.get("n")) for u in _many(d.get("users"))]}


def parse_schedule_windows(text: str) -> dict[str, Any]:
    d = _win_json(text)
    return {"platform": "windows", "script_version": d.get("version"), "runs": [], "dirs": {},
            "jobs": [{"name": str(t.get("n")), "source": "task", "last": _iso(t.get("last")), "next": _iso(t.get("next")), "detail": f"last result {_int(t.get('res'))}", "result": _int(t.get("res"))} for t in _many(d.get("tasks"))]}


def parse_hardware_windows(text: str) -> dict[str, Any]:
    d = _win_json(text)
    disks = []
    for x in _many(d.get("disks")):
        bad = str(x.get("health")).lower() not in ("healthy", "") or _int(x.get("werr")) > 0 or _int(x.get("rerr")) > 0
        disks.append({"dev": str(x.get("n")), "health": str(x.get("health")), "detail": f"temperature {x.get('temp')} C, wear {x.get('wear')}, read errors {x.get('rerr')}, write errors {x.get('werr')}", "bad": bad})
    return {"platform": "windows", "script_version": d.get("version"), "virt": "", "disks": disks, "raid": [], "zfs": [], "temps": [{"name": x["dev"], "c": float(re.search(r"temperature (\d+)", x["detail"]).group(1))} for x in disks if re.search(r"temperature (\d+)", x["detail"])],
            "errors": [f"{e.get('t')} event {e.get('id')}: {e.get('m')}" for e in _many(d.get("ioerrors"))], "readonly": [], "ups": [{"name": "battery", "detail": f"{b.get('charge')}% status {b.get('status')}"} for b in _many(d.get("battery"))]}


def parse_security_windows(text: str) -> dict[str, Any]:
    d = _win_json(text)
    return {"platform": "windows", "script_version": d.get("version"), "failed": [{"ip": str(f.get("ip")), "count": _int(f.get("c"))} for f in _many(d.get("failed"))], "failed_total": _int(d.get("failed_total")),
            "accepted": [], "sudo": 0, "exposed": [], "docker_ports": [], "users": [str(u) for u in _many(d.get("users"))], "admins": [str(a) for a in _many(d.get("admins"))],
            "updates": {"pending": 0, "security": 0, "reboot": bool(d.get("reboot_pending"))}, "time_synced": None, "firewall": {str(f.get("n")): ("active" if f.get("on") else "inactive") for f in _many(d.get("firewall"))},
            "defender": d.get("defender") if isinstance(d.get("defender"), dict) else None}


LINUX = {"cpu": parse_cpu_linux, "memory": parse_memory_linux, "network": parse_network_linux, "apps": parse_apps_linux, "changes": parse_changes_linux,
         "schedule": parse_schedule_linux, "hardware": parse_hardware_linux, "security": parse_security_linux}
WINDOWS = {"cpu": parse_cpu_windows, "memory": parse_memory_windows, "network": parse_network_windows, "apps": parse_apps_windows, "changes": parse_changes_windows,
           "schedule": parse_schedule_windows, "hardware": parse_hardware_windows, "security": parse_security_windows}


def parse_probe(name: str, platform: str, text: str) -> dict[str, Any]:
    """The structure for one probe's answer (any probe but storage). Raises ProbeError with a sentence."""
    table = LINUX if platform == "linux" else WINDOWS
    if name not in table:
        raise ProbeError(f"no such probe: {name}")
    return table[name](text)
