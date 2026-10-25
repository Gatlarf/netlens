"""Different from normal: a probe's answer compared with what the same probe saw on the same host before.

`compare(probe, current, history)` takes the newest answer and the earlier answers (taken on a calm day: the ones taken while a reading was over its limit are
left out) and returns evidence like "java holds 11.4 GB; it usually holds about 1.2 GB". With fewer than MIN_HISTORY earlier answers nothing is said:
a host has to be watched for a few days before "normal" means anything.

Rules, all small on purpose: a number is unusual when it is far above what it normally is *and* big enough to matter; a name, a port or an address is unusual
when it was never there before and is big enough to matter.
"""

from __future__ import annotations

import statistics
from typing import Any

from app.hostprobe import analyze
from app.hostprobe.parse import nice_bytes

MIN_HISTORY = 3
GB = 1024 ** 3
MB = 1024 ** 2


def _med(values: list[float]) -> float:
    return statistics.median(values) if values else 0.0


def _unusual(now: float, normal: list[float], factor: float, floor: float, rise: float = 0.0) -> bool:
    """`now` is far above normal: at least `factor` times the median, at least `rise` above it, and at least `floor` in absolute terms."""
    m = _med(normal)
    return now >= floor and now >= m * factor and now - m >= rise


def _ev(probe: str, text: str, weight: int, tags: list[str], private: bool = False, llm_text: str | None = None) -> dict[str, Any]:
    return analyze.ev(probe, "warn" if weight >= 60 else "fact", weight, text, ["unusual", *tags], private=private, llm_text=llm_text)


def _busy(d: dict[str, Any]) -> float | None:
    pct = d.get("cpu_pct") or {}
    if "busy" in pct:
        return pct["busy"]
    return 100 - pct["id"] if "id" in pct else None


# ----------------------------------------------------------------------------- one per probe
def cpu(cur: dict[str, Any], hist: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    now_busy = _busy(cur)
    past = [b for b in (_busy(h) for h in hist) if b is not None]
    if now_busy is not None and len(past) >= MIN_HISTORY and _unusual(now_busy, past, 2.5, 50, 25):
        out.append(_ev("cpu", f"The processor is {now_busy:.0f}% busy; it is normally about {_med(past):.0f}%.", 66, ["cpu_busy"]))
    elif now_busy is not None and len(past) >= MIN_HISTORY and now_busy < _med(past) + 15:
        out.append(analyze.ev("cpu", "fact", 4, f"The processor load is normal ({now_busy:.0f}%, usually about {_med(past):.0f}%).", ["ok:cpu_normal"]))
    seen: dict[str, list[float]] = {}
    for h in hist:
        mine = {}
        for p in h.get("procs", []):
            mine[p.get("container") or p["name"]] = mine.get(p.get("container") or p["name"], 0) + p["cpu"]
        for name in set(seen) | set(mine):
            seen.setdefault(name, []).append(mine.get(name, 0.0))
    if len(hist) >= MIN_HISTORY:
        for p in cur.get("procs", [])[:5]:
            who = p.get("container") or p["name"]
            normal = seen.get(who, [0.0] * len(hist))
            if p["cpu"] >= 50 and _unusual(p["cpu"], normal, 4.0, 50, 40):
                never = max(normal) < 10
                out.append(_ev("cpu", f"{who} uses {p['cpu']:.0f}% of a core" + (" and is not normally among the busiest processes." if never else f"; it normally uses about {_med(normal):.0f}%."), 68, [f"cpu_hog_new:{who}"]))
    return out


def memory(cur: dict[str, Any], hist: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    used = cur.get("used_pct")
    past = [h["used_pct"] for h in hist if h.get("used_pct") is not None]
    if used is not None and len(past) >= MIN_HISTORY:
        if _unusual(used, past, 1.4, 60, 15):
            out.append(_ev("memory", f"Memory is {used:.0f}% used; it is normally about {_med(past):.0f}%.", 64, ["mem_high"]))
        elif used < _med(past) + 10:
            out.append(analyze.ev("memory", "fact", 4, f"Memory use is normal ({used:.0f}%, usually about {_med(past):.0f}%).", ["ok:mem_normal"]))
    if len(hist) >= MIN_HISTORY:
        usage: dict[str, list[float]] = {}
        for h in hist:
            mine: dict[str, float] = {}
            for p in h.get("procs", []):
                mine[p.get("container") or p["name"]] = mine.get(p.get("container") or p["name"], 0) + p["rss"]
            for name in set(usage) | set(mine):
                usage.setdefault(name, []).append(mine.get(name, 0.0))
        for p in cur.get("procs", [])[:4]:
            who = p.get("container") or p["name"]
            normal = usage.get(who, [0.0] * len(hist))
            if _unusual(p["rss"], normal, 2.0, 1 * GB, 0.7 * GB):
                out.append(_ev("memory", f"{who} holds {nice_bytes(p['rss'])}; it normally holds about {nice_bytes(_med(normal))}.", 70, [f"mem_hog_new:{who}"]))
        swap = [h.get("swap_used", 0) for h in hist]
        if cur.get("swap_used", 0) > 512 * MB and _unusual(cur["swap_used"], swap, 3.0, 512 * MB, 256 * MB):
            out.append(_ev("memory", f"{nice_bytes(cur['swap_used'])} of swap is in use; normally about {nice_bytes(_med(swap))}.", 55, ["swap_new"]))
    return out


def network(cur: dict[str, Any], hist: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    if len(hist) < MIN_HISTORY:
        return out
    rate = sum(n["rx_bps"] + n["tx_bps"] for n in cur.get("interfaces", []))
    past = [sum(n["rx_bps"] + n["tx_bps"] for n in h.get("interfaces", [])) for h in hist]
    if _unusual(rate, past, 3.0, 20e6, 15e6):
        out.append(_ev("network", f"Network traffic is {rate / 1e6:.0f} Mbit/s; it is normally about {_med(past) / 1e6:.0f} Mbit/s.", 58, ["net_high"]))
    known_remote = {r["ip"] for h in hist for r in h.get("remote", [])}
    for r in cur.get("remote", [])[:3]:
        if r["count"] >= 50 and r["ip"] not in known_remote:
            out.append(_ev("network", f"{r['ip']} has {r['count']} connections to this host and was never seen before.", 62, [f"new_remote:{r['ip']}"]))
    known_ports = {l["addr"].rsplit(":", 1)[-1] for h in hist for l in h.get("listening", [])}
    new = [l for l in cur.get("listening", []) if l["addr"].rsplit(":", 1)[-1] not in known_ports]
    if new:
        out.append(_ev("network", "New ports are listening that were not before: " + ", ".join(f"{l['addr']}{' (' + l['process'] + ')' if l['process'] else ''}" for l in new[:4]) + ".", 62, ["new_listener"]))
    estab = [h.get("states", {}).get("ESTAB", h.get("states", {}).get("ESTABLISHED", 0)) for h in hist]
    now_estab = cur.get("states", {}).get("ESTAB", cur.get("states", {}).get("ESTABLISHED", 0))
    if _unusual(now_estab, estab, 3.0, 300, 200):
        out.append(_ev("network", f"{now_estab} connections are established; normally about {_med(estab):.0f}.", 55, ["conn_high"]))
    return out


def apps(cur: dict[str, Any], hist: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    if len(hist) < 1:
        return out
    last = {c["name"]: c for c in hist[-1].get("containers", [])}
    for c in cur.get("containers", []):
        before = last.get(c["name"])
        if before and c["restarts"] - before["restarts"] >= 3:
            out.append(_ev("apps", f"The container {c['name']} restarted {c['restarts'] - before['restarts']} times since the look before.", 78, [f"restarts_new:{c['name']}"]))
        elif before and before["state"] == "running" and c["state"] not in ("running",):
            out.append(_ev("apps", f"The container {c['name']} was running at the look before and is now {c['state']}.", 70, [f"stopped_new:{c['name']}"]))
        elif not before and len(hist) >= MIN_HISTORY and c["state"] != "running":
            out.append(_ev("apps", f"The container {c['name']} is new and {c['state']}.", 50, ["container_new"]))
    known_units = {u["unit"] for h in hist for u in h.get("failed_units", [])}
    for u in cur.get("failed_units", []):
        if u["unit"] not in known_units and len(hist) >= MIN_HISTORY:
            out.append(_ev("apps", f"The service {u['unit']} fails now and never failed before.", 70, [f"failed_new:{u['unit']}"]))
    if len(hist) >= MIN_HISTORY:
        per: dict[str, list[float]] = {}
        for h in hist:
            mine = {e["unit"]: e["count"] for e in h.get("errors", [])}
            for k in set(per) | set(mine):
                per.setdefault(k, []).append(mine.get(k, 0))
        for e in cur.get("errors", [])[:3]:
            if _unusual(e["count"], per.get(e["unit"], [0] * len(hist)), 4.0, 30, 25):
                out.append(_ev("apps", f"{e['unit']} logged {e['count']} errors in the last hour; normally about {_med(per.get(e['unit'], [0])):.0f}.", 60, [f"errors_new:{e['unit']}"]))
    return out


def schedule(cur: dict[str, Any], hist: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(hist) < MIN_HISTORY:
        return []
    known = {j["name"] for h in hist for j in h.get("jobs", [])}
    new = [j for j in cur.get("jobs", []) if j["name"] not in known]
    return [_ev("schedule", "New scheduled jobs appeared: " + ", ".join(j["name"][:50] for j in new[:4]) + ".", 45, ["job_new"], private=any(j.get("private") for j in new), llm_text="New scheduled jobs appeared.")] if new else []


def hardware(cur: dict[str, Any], hist: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    if not hist:
        return out
    temps = {}
    for h in hist:
        for t in h.get("temps", []):
            temps.setdefault(t["name"], []).append(t["c"])
    for t in cur.get("temps", []):
        normal = temps.get(t["name"], [])
        if len(normal) >= MIN_HISTORY and t["c"] - _med(normal) >= 15 and t["c"] >= 60:
            out.append(_ev("hardware", f"{t['name']} is at {t['c']:.0f} °C; it is normally about {_med(normal):.0f} °C.", 60, ["temp_high"]))
    import re

    def counts(d):
        return {(x["dev"], k): int(v) for x in d.get("disks", []) for k, v in re.findall(r"(Reallocated_Sector_Ct|Current_Pending_Sector|Offline_Uncorrectable)=(\d+)", x["detail"])}

    before = counts(hist[-1])
    for key, value in counts(cur).items():
        if value > before.get(key, 0):
            out.append(_ev("hardware", f"{key[0]}: {key[1]} rose from {before.get(key, 0)} to {value}: the disk is wearing out.", 85, ["disk_degrading"]))
    return out


def security(cur: dict[str, Any], hist: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    if len(hist) < MIN_HISTORY:
        return out
    failed = [h.get("failed_total", 0) for h in hist]
    if _unusual(cur.get("failed_total", 0), failed, 5.0, 50, 40):
        out.append(_ev("security", f"{cur['failed_total']} failed sign-ins in 24 hours; normally about {_med(failed):.0f}.", 62, ["bruteforce_new"]))
    known_users = {u for h in hist for u in h.get("users", [])}
    new_users = [u for u in cur.get("users", []) if u not in known_users]
    if new_users:
        out.append(_ev("security", "New accounts that can sign in: " + ", ".join(new_users[:4]) + ".", 68, ["user_new"]))
    known_admins = {a for h in hist for a in h.get("admins", [])}
    if any(a not in known_admins for a in cur.get("admins", [])):
        out.append(_ev("security", "The members of an administrator group changed.", 66, ["admin_new"], private=True, llm_text="The members of an administrator group changed."))
    known_exposed = {x for h in hist for x in h.get("exposed", [])}
    new = [x for x in cur.get("exposed", []) if x not in known_exposed]
    if new:
        out.append(_ev("security", "Ports now listen on every interface that did not before: " + ", ".join(new[:4]) + ".", 64, ["exposed_new"], private=True, llm_text="New ports listen on every interface."))
    known_ips = {a["ip"] for h in hist for a in h.get("accepted", [])}
    fresh = [a for a in cur.get("accepted", []) if a["ip"] not in known_ips]
    if fresh:
        out.append(_ev("security", "Sign-ins from addresses never seen before: " + ", ".join(f"{a['user']} from {a['ip']}" for a in fresh[:3]) + ".", 58, ["login_new"], private=True, llm_text="Sign-ins came from addresses never seen before."))
    return out


def storage(cur: dict[str, Any], hist: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Used space against its own history: how much it grew since the look before, and what it usually grows in a day."""
    from app.hostprobe import parse

    if len(hist) < 2:
        return []
    out = []
    for m in cur.get("mounts", []):
        used = [next((x["used"] for x in h.get("mounts", []) if x["mount"] == m["mount"]), None) for h in hist]
        used = [u for u in used if u is not None]
        if len(used) < 2 or not m["size"]:
            continue
        jump = m["used"] - used[-1]
        typical = statistics.mean(abs(b - a) for a, b in zip(used, used[1:]))               # how much it changes between two looks, normally
        if jump >= max(2 * GB, 0.03 * m["size"]) and jump > 5 * max(typical, 100 * MB):
            out.append(_ev("storage", f"{m['mount']} grew by {parse.nice_bytes(jump)} since the look before; between two looks it normally changes by about {parse.nice_bytes(typical)}.", 66, ["disk_jump"]))
    return out


FUNCS = {"cpu": cpu, "memory": memory, "network": network, "apps": apps, "schedule": schedule, "hardware": hardware, "security": security, "storage": storage}


def compare(probe: str, current: dict[str, Any], history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Evidence about how `current` differs from the earlier answers `history` (oldest first). Never raises: a surprise in old data is not worth failing a diagnosis."""
    fn = FUNCS.get(probe)
    if not fn or current.get("platform") != (history[-1].get("platform") if history else current.get("platform")):
        return []
    try:
        return fn(current, history)
    except Exception:  # noqa: BLE001
        return []
