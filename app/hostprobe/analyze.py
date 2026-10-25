"""What a probe's answer means. One function per probe turns the structure from parsers.py into evidence, and `correlate` chains the evidence of
several probes into a root cause ("java used all the memory, the kernel killed postgres, which restarts in a loop, whose log fills the disk").

An evidence item: {"probe", "level": cause|warn|fact, "weight": 0-100, "tags": [...], "text", "llm_text", "private", "at": epoch or None}.
Tags are how probes talk to each other: cpu_hog:<who>, mem_hog:<who>, oom:<victim>, restart_loop:<container>, log_growth:<container>, steal, iowait, job:<name>, change, disk_full ...
`private` text holds names of files, folders or log lines: a language model gets `llm_text` instead unless the administrator allowed names.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from app.hostprobe.parse import nice_bytes

GB = 1024 ** 3


def ev(probe: str, level: str, weight: int, text: str, tags: list[str] | None = None, at: float | None = None, private: bool = False, llm_text: str | None = None) -> dict[str, Any]:
    return {"probe": probe, "level": level, "weight": weight, "tags": tags or [], "text": text, "at": at, "private": private, "llm_text": llm_text or (text if not private else None)}


def clock(epoch: float | None) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%d %b %H:%M UTC") if epoch else "?"


def _who(p: dict[str, Any]) -> str:
    return p.get("container") or p.get("name") or "?"


def _short(name: str) -> str:
    return re.sub(r"\s+", " ", name)[:40]


# ----------------------------------------------------------------------------- one function per probe
def cpu(d: dict[str, Any], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    pct = d.get("cpu_pct") or {}
    idle = pct.get("id")
    busy = pct.get("busy") if "busy" in pct else (100 - idle if idle is not None else None)
    cpus = d.get("cpus") or 1
    load = (d.get("load") or [None])[0]
    procs = [p for p in d.get("procs", []) if p["cpu"] > 0]
    hot = busy is not None and busy >= 70 or (load is not None and load / cpus >= 1.0)
    if hot:
        top = procs[0] if procs else None
        used = sum(p["cpu"] for p in procs) or 1
        text = f"The processor is {busy:.0f}% busy" if busy is not None else "The processor is overloaded"
        if load is not None:
            text += f" (load {load:g} on {cpus} core{'s' if cpus != 1 else ''})"
        tags, weight = [], 55
        if top:
            who = _who(top)
            share = top["cpu"] / used
            text += f". Most of it is {_short(who)}{' (a process in that container)' if top.get('container') else ''}: {top['cpu']:.0f}% of one core" + (f", {100 * share:.0f}% of what the busiest processes use" if len(procs) > 1 else "")
            tags.append(f"cpu_hog:{who}")
            weight = 75 if share >= 0.5 else 60
            others = [_short(_who(p)) for p in procs[1:3] if p["cpu"] >= 20]
            if others:
                text += "; then " + ", ".join(others)
        out.append(ev("cpu", "warn", weight, text + ".", tags))
    elif busy is not None:
        out.append(ev("cpu", "fact", 5, f"The processor was not busy at the time of the look ({busy:.0f}%).", ["ok:cpu"]))
    if pct.get("wa", 0) >= 20:
        out.append(ev("cpu", "warn", 65, f"{pct['wa']:.0f}% of the processor time is spent waiting for the disk: the load is I/O, not computing.", ["iowait"]))
    if pct.get("st", 0) >= 8:
        out.append(ev("cpu", "warn", 70, f"The hypervisor takes {pct['st']:.0f}% of the processor time (steal): another virtual machine on the same host is using the cores this one needs.", ["steal"]))
    for name, v in (d.get("pressure") or {}).items():
        if v >= 20 and name == "cpu":
            out.append(ev("cpu", "warn", 55, f"Processes spend {v:.0f}% of the time waiting for a processor (pressure).", ["cpu_wait"]))
    boxes = [c for c in d.get("containers", []) if (c["cpu"] or 0) >= 100]
    if boxes:
        out.append(ev("cpu", "fact", 50, "Containers using more than a core: " + ", ".join(f"{c['name']} {c['cpu']:.0f}%" for c in boxes[:3]) + ".", [f"cpu_hog:{c['name']}" for c in boxes[:3]]))
    return out


def memory(d: dict[str, Any], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    used = d.get("used_pct")
    total = d.get("total") or 0
    procs = d.get("procs", [])
    low = used is not None and (used >= 90 or (total and d.get("available", total) < 0.08 * total))
    if low:
        text = f"Memory is {used:.0f}% used ({nice_bytes(d['available'])} of {nice_bytes(total)} left)"
        tags, weight = [], 60
        if procs:
            top = procs[0]
            who = _who(top)
            text += f". The biggest user is {_short(who)} with {nice_bytes(top['rss'])}"
            if top["rss"] >= 0.25 * total:
                tags.append(f"mem_hog:{who}")
                weight = 75
            more = [f"{_short(_who(p))} {nice_bytes(p['rss'])}" for p in procs[1:3] if p["rss"] >= 0.08 * total]
            if more:
                text += "; then " + ", ".join(more)
        out.append(ev("memory", "warn", weight, text + ".", tags))
    elif used is not None:
        out.append(ev("memory", "fact", 5, f"Memory was fine at the time of the look ({used:.0f}% used).", ["ok:memory"]))
    swap_t, swap_u = d.get("swap_total", 0), d.get("swap_used", 0)
    io = d.get("swap_io") or {}
    if swap_t and swap_u > 0.25 * swap_t and (io.get("si", 0) + io.get("so", 0)) > 0:
        out.append(ev("memory", "warn", 70, f"The host is swapping ({nice_bytes(swap_u)} of swap used, {io.get('si', 0):g} kB/s in, {io.get('so', 0):g} kB/s out): memory is short and everything slows down.", ["swapping"]))
    elif swap_t and swap_u > 0.5 * swap_t:
        out.append(ev("memory", "fact", 35, f"{nice_bytes(swap_u)} of the swap is used.", ["swap_used"]))
    if (d.get("pressure") or {}).get("memory", 0) >= 10:
        out.append(ev("memory", "warn", 60, f"Processes spend {d['pressure']['memory']:.0f}% of the time stalled waiting for memory (pressure).", ["mem_pressure"]))
    for line in d.get("oom", [])[-3:]:
        m = re.search(r"[Kk]illed process \d+ \(([^)]+)\)", line) or re.search(r"Out of memory: Killed process \d+ \(([^)]+)\)", line)
        victim = m.group(1) if m else "a process"
        out.append(ev("memory", "cause", 88, f"The kernel killed {victim} because the host ran out of memory.", [f"oom:{victim}", "oom"], private=True, llm_text="The kernel killed a process because the host ran out of memory."))
    for c in d.get("container_oom", []):
        if c["oom"]:
            out.append(ev("memory", "cause", 85, f"The container {c['name']} was killed for exceeding its memory limit" + (f" (restarted {c['restarts']} times since)" if c["restarts"] else "") + ".", [f"oom:{c['name']}", "oom"]))
    return out


def network(d: dict[str, Any], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    nics = d.get("interfaces", [])
    if nics:
        top = nics[0]
        rate = top["rx_bps"] + top["tx_bps"]
        text = f"Busiest interface {top['name']}: {top['rx_bps'] / 1e6:.1f} Mbit/s in, {top['tx_bps'] / 1e6:.1f} out"
        who = d.get("processes", [])[:1]
        if rate >= 100e6 and who:
            text += f"; the process with most connections is {_short(who[0]['name'])} ({who[0]['count']})"
        out.append(ev("network", "warn" if rate >= 800e6 else "fact", 55 if rate >= 800e6 else 25, text + ".", ["net_hog:" + (who[0]["name"] if who and rate >= 100e6 else top["name"])] if rate >= 100e6 else []))
    for n in nics:
        pk = n["rx_pkts_total"] + n["tx_pkts_total"]
        bad = n["rx_err_total"] + n["tx_err_total"] + n["rx_drop_total"] + n["tx_drop_total"]
        if pk and bad >= 100 and bad / pk > 0.001 or (n["rx_err"] + n["tx_err"] + n["rx_drop"] + n["tx_drop"]) > 0 and bad >= 20:
            out.append(ev("network", "warn", 55, f"Interface {n['name']} has {bad} errors or dropped packets" + (f" ({100 * bad / pk:.2f}% of all packets)" if pk else "") + ": a bad cable, a duplex mismatch or a driver problem.", ["nic_errors"]))
    tcp = d.get("tcp") or {}
    if tcp.get("OutSegs") and tcp.get("RetransSegs") is not None:
        pct = 100 * tcp["RetransSegs"] / tcp["OutSegs"]
        if pct >= 2:
            out.append(ev("network", "warn", 60, f"{pct:.1f}% of the TCP segments sent had to be sent again (since the host started): packets are lost somewhere on the path.", ["retransmits"]))
    if tcp.get("ListenOverflows") or tcp.get("ListenDrops"):
        out.append(ev("network", "warn", 55, f"The host dropped incoming connections because an application did not accept them fast enough ({tcp.get('ListenDrops') or tcp.get('ListenOverflows')} times).", ["listen_drops"]))
    st = d.get("states") or {}
    for key, limit, why, tag in (("CLOSE-WAIT", 200, "an application does not close its connections", "app_leak"), ("CLOSE_WAIT", 200, "an application does not close its connections", "app_leak"),
                                 ("TIME-WAIT", 5000, "very many short connections", "conn_churn"), ("TIME_WAIT", 5000, "very many short connections", "conn_churn"), ("SYN-RECV", 100, "a flood of connection attempts", "syn_flood")):
        if st.get(key, 0) >= limit:
            out.append(ev("network", "warn", 50, f"{st[key]} connections are in state {key}: {why}.", [tag]))
    for p in d.get("ping", []):
        if p["kind"] == "gateway" and (p["loss"] > 0 or (p["rtt"] or 0) > 50):
            out.append(ev("network", "warn", 72, f"The gateway {p['target']} answers badly: {p['loss']:.0f}% loss" + (f", {p['rtt']:.0f} ms" if p["rtt"] else "") + " — the problem is on the local network or the gateway itself.", ["lan_problem"]))
        if p["kind"] == "internet" and (p["loss"] > 0 or (p["rtt"] or 0) > 150):
            gw = next((x for x in d.get("ping", []) if x["kind"] == "gateway"), None)
            where = "beyond the gateway (the internet connection)" if gw and gw["loss"] == 0 else "on the local network"
            out.append(ev("network", "warn", 66, f"The internet ({p['target']}) answers badly: {p['loss']:.0f}% loss" + (f", {p['rtt']:.0f} ms" if p["rtt"] else "") + f" — the problem is {where}.", ["wan_problem"]))
    dns = d.get("dns")
    if dns and (not dns["ok"] or dns["ms"] > 500):
        out.append(ev("network", "warn", 66, "Name lookups fail" if not dns["ok"] else f"Name lookups are slow ({dns['ms']} ms)" + ": applications seem slow or broken when DNS is.", ["dns_problem"]))
    remote = d.get("remote", [])
    if remote and remote[0]["count"] >= 200:
        out.append(ev("network", "warn", 45, f"{remote[0]['ip']} has {remote[0]['count']} open connections to this host.", ["conn_hog:" + remote[0]["ip"]]))
    return out


def apps(d: dict[str, Any], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for u in d.get("failed_units", [])[:3]:
        out.append(ev("apps", "warn", 75, f"The service {u['unit']} has failed" + (f" ({u['result']}" + (f", exit status {u['exit']}" if u["exit"] else "") + ")" if u["result"] else "") + (f" and was restarted {u['restarts']} times" if u["restarts"] else "") + ".", [f"failed:{u['unit']}"]))
    for c in d.get("containers", []):
        name = c["name"]
        if c["oom"]:
            out.append(ev("apps", "cause", 90, f"The container {name} was killed because it ran out of memory (restarted {c['restarts']} times).", [f"oom:{name}", f"restart_loop:{name}" if c["restarts"] >= 3 else "oom"]))
        elif c["state"] == "restarting" or c["restarts"] >= 5:
            code = f", last exit code {c['exit']}" if c["exit"] else ""
            out.append(ev("apps", "warn", 80, f"The container {name} keeps restarting ({c['restarts']} restarts{code})" + (f"; it logged {c['errors']} error lines in the last hour" if c.get("errors") else "") + ".", [f"restart_loop:{name}"]))
        elif c["health"] == "unhealthy":
            out.append(ev("apps", "warn", 62, f"The container {name} is unhealthy" + (f" ({c['errors']} error lines in its log in the last hour)" if c.get("errors") else "") + ".", [f"unhealthy:{name}"]))
        elif c["state"] == "exited" and c["exit"] not in (0,):
            out.append(ev("apps", "warn", 60, f"The container {name} stopped with exit code {c['exit']}" + (" (killed, often for lack of memory)" if c["exit"] == 137 else "") + ".", [f"exited:{name}"], at=c.get("finished")))
    for e in d.get("errors", [])[:2]:
        if e["count"] >= 20:
            out.append(ev("apps", "warn", 45, f"{e['unit']} logged {e['count']} errors in the last hour.", [f"errors:{e['unit']}"]))
    if d.get("sample"):
        out.append(ev("apps", "fact", 20, "Latest errors in the log: " + " | ".join(re.sub(r"^\w{3} +\d+ [\d:]+ \S+ ", "", s)[:110] for s in d["sample"][-3:]), private=True, llm_text="The system log holds recent error lines."))
    return out


def changes(d: dict[str, Any], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    onset = ctx.get("onset")
    events = d.get("events", [])
    if onset:
        near = [e for e in events if onset - 3 * 3600 <= e["at"] <= onset + 600]
        for e in sorted(near, key=lambda e: abs(onset - e["at"]))[:5]:
            gap = (onset - e["at"]) / 60
            when = f"{gap:.0f} minutes before the problem began" if gap >= 0 else "just after the problem began"
            weight = 70 if abs(gap) <= 30 else 45
            if e["kind"] == "reboot" and "unexpected" in e["text"].lower() or "crash" in e["text"].lower():
                weight = 85
            out.append(ev("changes", "warn" if weight >= 60 else "fact", weight, f"{clock(e['at'])}: {e['text']} ({when}).", ["change", f"change:{e['kind']}"], at=e["at"], private=e.get("private", False),
                          llm_text=f"A {e['kind']} change happened {when}."))
        if not near:
            out.append(ev("changes", "fact", 8, "Nothing was changed on the host (packages, /etc, containers, restarts) in the hours before.", ["ok:changes"]))
    else:
        for e in events[:4]:
            out.append(ev("changes", "fact", 10, f"{clock(e['at'])}: {e['text']}.", ["change"], at=e["at"], private=e.get("private", False), llm_text=f"A {e['kind']} change was made."))
    return out


def schedule(d: dict[str, Any], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    onset = ctx.get("onset")
    if not onset:
        return out
    seen = set()
    for j in d.get("jobs", []):
        if j.get("last") and onset - 20 * 60 <= j["last"] <= onset + 300:
            seen.add(j["name"])
            gap = (onset - j["last"]) / 60
            bad = j.get("result") not in (None, 0)
            out.append(ev("schedule", "warn", 78 if gap >= 0 else 60, f"The scheduled job {j['name']} started at {clock(j['last'])}, " + (f"{gap:.0f} minutes before the problem began" if gap >= 0 else "just after the problem began")
                          + (f" and ended with an error ({j['detail']})" if bad else "") + ".", ["job:" + j["name"]], at=j["last"], private=j.get("private", False), llm_text="A scheduled job started shortly before the problem."))
    for r in d.get("runs", []):
        if onset - 20 * 60 <= r["at"] <= onset + 300 and r["text"] not in seen:
            out.append(ev("schedule", "warn", 70, f"{clock(r['at'])}: {r['text']}, {(onset - r['at']) / 60:.0f} minutes before the problem began.", ["job:cron"], at=r["at"], private=True, llm_text="A cron job ran shortly before the problem."))
    if not out and (d.get("jobs") or d.get("runs")):
        out.append(ev("schedule", "fact", 8, "No scheduled job (timer, cron) started around the time the problem began.", ["ok:schedule"]))
    return out


def hardware(d: dict[str, Any], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for x in d.get("disks", []):
        if x["bad"]:
            out.append(ev("hardware", "cause", 92, f"The disk {x['dev']} reports trouble ({x['health']}; {x['detail']}): it is failing or about to.", ["disk_failing", f"disk_failing:{x['dev']}"]))
    for r in d.get("raid", []):
        if r["degraded"]:
            out.append(ev("hardware", "cause", 92, f"The RAID array {r['name']} is degraded ({r['detail']}).", ["raid_degraded"]))
    for z in d.get("zfs", []):
        if re.search(r"DEGRADED|FAULTED|UNAVAIL|OFFLINE|errors: [1-9]", z["line"]):
            out.append(ev("hardware", "cause", 90, f"ZFS reports a problem: {z['line'].strip()[:120]}", ["zfs_problem"]))
    for t in d.get("temps", []):
        if t["c"] >= 85:
            out.append(ev("hardware", "warn", 62, f"{t['name']} is at {t['c']:.0f} °C: the processor slows itself down and may shut the host off.", ["overheating"]))
    if d.get("errors"):
        out.append(ev("hardware", "cause", 82, f"The kernel logged {len(d['errors'])} hardware, disk or memory errors recently (last: {d['errors'][-1][-120:]}).", ["kernel_hw_errors"], private=True,
                      llm_text="The kernel logged hardware, disk or memory errors recently."))
    for r in d.get("readonly", []):
        out.append(ev("hardware", "cause", 86, f"The filesystem {r} is read-only: the kernel does that after disk errors, and everything that writes there fails.", ["readonly_fs"], private=True, llm_text="A filesystem is read-only."))
    for u in d.get("ups", []):
        if re.search(r"ups.status: (OB|LB)", u["detail"]):
            out.append(ev("hardware", "warn", 70, f"The UPS {u['name']} is on battery: the mains power failed.", ["power_loss"]))
    return out


def security(d: dict[str, Any], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    if d.get("failed_total", 0) >= 50:
        top = d["failed"][0] if d.get("failed") else None
        out.append(ev("security", "warn", 55, f"{d['failed_total']} failed sign-in attempts in the last 24 hours" + (f", most from {top['ip']} ({top['count']})" if top else "") + ": someone is guessing passwords.", ["bruteforce"]))
    u = d.get("updates") or {}
    if u.get("security"):
        out.append(ev("security", "warn", 40, f"{u['security']} security updates are waiting to be installed.", ["unpatched"]))
    elif u.get("pending", 0) >= 30:
        out.append(ev("security", "fact", 25, f"{u['pending']} software updates are waiting.", ["unpatched"]))
    if u.get("reboot"):
        out.append(ev("security", "fact", 30, "A restart is needed to finish installing updates.", ["reboot_pending"]))
    if d.get("time_synced") is False:
        out.append(ev("security", "warn", 52, "The clock is not synchronised with a time server: certificates, logins and logs can disagree with other machines.", ["clock_drift"]))
    fw = d.get("firewall") or {}
    if fw and not any(v == "active" for v in fw.values()):
        out.append(ev("security", "fact", 28, "No host firewall is active.", ["no_firewall"]))
    if d.get("exposed"):
        out.append(ev("security", "fact", 15, f"{len(d['exposed'])} ports listen on every interface.", ["exposed"], private=True, llm_text=f"{len(d['exposed'])} ports listen on every interface."))
    return out


ANALYZERS = {"cpu": cpu, "memory": memory, "network": network, "apps": apps, "changes": changes, "schedule": schedule, "hardware": hardware, "security": security}


def analyze(probe: str, data: dict[str, Any], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    fn = ANALYZERS.get(probe)
    return fn(data, ctx) if fn else []


# ----------------------------------------------------------------------------- chains across probes
def tagged(evidence: list[dict[str, Any]], prefix: str) -> list[tuple[str, dict[str, Any]]]:
    return [(t.split(":", 1)[1] if ":" in t else "", e) for e in evidence for t in e["tags"] if t == prefix or t.startswith(prefix + ":")]


def correlate(evidence: list[dict[str, Any]], ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """Chains: {"text", "weight", "probes", "private", "llm_text"}. Strongest first."""
    chains: list[dict[str, Any]] = []

    def chain(parts: list[dict[str, Any]], text: str, weight: int, llm: str | None = None) -> None:
        chains.append({"text": text, "weight": weight, "probes": sorted({e["probe"] for e in parts}), "private": any(e["private"] for e in parts), "llm_text": llm})

    restart = dict(tagged(evidence, "restart_loop"))
    hogs = tagged(evidence, "mem_hog")
    for victim, e_oom in tagged(evidence, "oom"):
        if not victim:
            continue
        parts = [e_oom]
        text = f"{victim} was killed for lack of memory"
        for hog, e_hog in hogs:
            if hog != victim:
                parts.append(e_hog)
                text = f"{hog} used most of the memory, so the kernel killed {victim}"
                break
        if victim in restart:
            parts.append(restart[victim])
            text += f"; {victim} restarts in a loop"
        grow = dict(tagged(evidence, "log_growth")).get(victim)
        if grow:
            parts.append(grow)
            text += ", and each start writes more log"
        chain(parts, text.capitalize() + ".", 92, "A memory shortage killed a process that restarts in a loop.")
    for name, e_loop in tagged(evidence, "restart_loop"):
        grow = dict(tagged(evidence, "log_growth")).get(name)
        full = tagged(evidence, "disk_full")
        if grow and full:
            chain([e_loop, grow, full[0][1]], f"The container {name} restarts in a loop, its log keeps growing, and that fills the disk.", 90, "A container that restarts in a loop fills the disk with its log.")
    cpu_hogs = tagged(evidence, "cpu_hog")
    jobs = tagged(evidence, "job")
    if cpu_hogs and jobs:
        hog, e_hog = cpu_hogs[0]
        job, e_job = jobs[0]
        chain([e_hog, e_job], f"The scheduled job {job} started at {clock(e_job['at'])} and the processor has been busy with {hog} since.", 84, "A scheduled job started and the processor has been busy since.")
    if cpu_hogs and any(t == "iowait" for e in evidence for t in e["tags"]):
        chain([cpu_hogs[0][1]] + [e for e in evidence if "iowait" in e["tags"]], f"{cpu_hogs[0][0]} drives the load and the processor mostly waits for the disk: the disk is the bottleneck.", 70)
    nets = tagged(evidence, "net_hog")
    for hog, e_cpu in cpu_hogs[:1]:
        for who, e_net in nets:
            if who and (who.lower() in hog.lower() or hog.lower() in who.lower()):
                chain([e_cpu, e_net], f"{hog} is behind both the processor load and the network traffic.", 72)
    if any(t == "steal" for e in evidence for t in e["tags"]) and cpu_hogs:
        chain([e for e in evidence if "steal" in e["tags"]], "Part of the slowness comes from the hypervisor, not from this machine: other virtual machines on the same host take processor time.", 68)
    changes_ = [e for e in evidence if "change" in e["tags"] and e["weight"] >= 60]
    bad = [e for e in evidence if e["level"] in ("warn", "cause") and "change" not in e["tags"] and e["probe"] in ("apps", "cpu", "memory", "network") and e["weight"] >= 60]
    if changes_ and bad:
        c = changes_[0]
        chain([c, bad[0]], f"A change preceded the trouble: {c['text'].split(' (')[0].split(': ', 1)[-1]} ({clock(c['at'])}), and then: {bad[0]['text'].rstrip('.')}.", 80, "A change on the host preceded the trouble.")
    for tag, why in (("lan_problem", "The host cannot reach its gateway reliably: look at the cable, the switch port or Wi-Fi first."), ("wan_problem", "The local network is fine but the internet connection is not: the problem is at the provider or the router's uplink."),
                     ("disk_failing", "A failing disk is the most likely cause of the I/O trouble and slowness.")):
        hit = [e for e in evidence if tag in e["tags"] or any(t.startswith(tag) for t in e["tags"])]
        if hit:
            chain(hit, why, 88 if tag == "disk_failing" else 78)
    chains.sort(key=lambda c: -c["weight"])
    return chains[:4]
