"""High processor load that is expected: a scheduled scan, an update, a backup, or simply something that happens at the same time every day.

A busy period (an *episode*) starts when the processor reading goes past its warning limit and ends when it has been below it for GAP_S. Every episode is
kept (also the ones that raised nothing), so Netlens learns when a host is normally busy. A new episode is *explained* (no warning) when

  * most of the load is a process that is known to be a heavy but harmless job (Windows Defender, Windows Update, a backup, a vulnerability scan ...) and it has
    not run longer than such a job normally does, or
  * the host has been busy at this time before: every day around the same hour, on the same weekday, or at a regular interval, and this one has not run
    longer than the earlier ones did.

An explained episode that runs on beyond what is usual is a problem after all, and the warning says what it was and how long it has been going on. Only the
processor reading is judged this way, and only while `enabled` (Settings → Host monitoring). Names are matched as written by the host, without the .exe.
"""

from __future__ import annotations

import fnmatch
import re
import statistics
from datetime import datetime, timezone
from typing import Any

from app.db import get_setting, set_setting

KEY = "hostmetrics.explain_load"
GAP_S = 600                  # below the limit for this long: the busy period is over
KEEP_DAYS = 60
LOOKBACK_DAYS = 28
MIN_EARLIER = 3              # a pattern needs this many earlier episodes
SHARE = 0.5                  # "mostly": the process holds at least this share of the load
MIN_ALLOWED_MIN = 15
MAX_ALLOWED_MIN = 360

# (names as the host writes them, without .exe; lower case; * allowed) -> what it is, how long (minutes) it normally runs at most
KNOWN: list[tuple[tuple[str, ...], str, int]] = [
    (("msmpeng", "mpdefendercoreservice", "mpcmdrun"), "Windows Defender, the anti-malware scan", 90),
    (("tiworker", "trustedinstaller", "tiworker*"), "Windows Update installing updates", 120),
    (("mousocoreworker", "usoclient", "musnotification*"), "Windows Update looking for updates", 45),
    (("compattelrunner", "devicecensus", "dismhost"), "Windows telemetry and compatibility check", 45),
    (("searchindexer", "searchprotocolhost", "searchfilterhost"), "Windows Search indexing", 60),
    (("ngen", "mscorsvw"), "the .NET native image compiler", 45),
    (("updatedb", "updatedb.*", "plocate-build", "mlocate"), "the locate database update", 30),
    (("unattended-upgr*", "apt", "apt-get", "dpkg", "aptitude", "packagekitd", "dnf", "yum", "zypper"), "a package update", 60),
    (("clamscan", "clamd", "freshclam"), "the ClamAV virus scan", 180),
    (("logrotate",), "log rotation", 20),
    (("fstrim",), "the weekly disk trim", 30),
    (("md*_resync", "md*_raid*", "mdcheck", "mdadm"), "a RAID check or rebuild", 720),
    (("borg", "restic", "duplicity", "duplicati*", "rsnapshot", "kopia", "pbs-client", "proxmox-backup-client"), "a backup run", 240),
    (("openvas", "ospd-openvas", "gvmd", "gvm-*", "greenbone*", "nmap"), "a Greenbone / OpenVAS vulnerability scan", 360),
    (("vmtoolsd", "vmware-vmx"), "the virtual machine tools", 20),
]


def enabled(conn) -> bool:
    return get_setting(conn, KEY) != "0"                          # on unless switched off


def set_enabled(conn, on: bool) -> bool:
    set_setting(conn, KEY, "1" if on else "0")
    return on


def normal(name: str) -> str:
    """'MsMpEng.exe' / 'svchost#3' -> 'msmpeng' / 'svchost'."""
    text = re.sub(r"#\d+$", "", str(name or "").strip().lower())
    return text[:-4] if text.endswith(".exe") else text


def known(name: str) -> tuple[str, int] | None:
    """(what it is, minutes it normally runs at most) for a process that is a known heavy but harmless job."""
    n = normal(name)
    for names, what, minutes in KNOWN:
        if any(fnmatch.fnmatchcase(n, pattern) for pattern in names):
            return what, minutes
    return None


# ----------------------------------------------------------------------------------------------------------- episodes
def _open(conn, monitor_id: int, metric: str, label: str):
    return conn.execute("SELECT * FROM load_episodes WHERE monitor_id = ? AND metric = ? AND label = ? AND end_ts IS NULL ORDER BY id DESC LIMIT 1", (monitor_id, metric, label)).fetchone()


def track(conn, monitor_id: int, metric: str, label: str, over: bool, value: float, top: list | None, now_ts: float):
    """Keep the busy periods: returns the open one while the reading is over its limit (or has only just dipped), else None."""
    now_ts = int(now_ts)
    ep = _open(conn, monitor_id, metric, label)
    who = top[0][0] if top and top[0][1] >= SHARE * max(value, 1.0) else None            # the process that holds most of the load, if one does
    if over:
        if ep is None:
            conn.execute("INSERT INTO load_episodes (monitor_id, metric, label, start_ts, last_ts, peak, process) VALUES (?,?,?,?,?,?,?)", (monitor_id, metric, label, now_ts, now_ts, value, who))
        else:
            conn.execute("UPDATE load_episodes SET last_ts = ?, peak = CASE WHEN peak > ? THEN peak ELSE ? END, process = COALESCE(?, process) WHERE id = ?", (now_ts, value, value, who, ep["id"]))
        conn.execute("DELETE FROM load_episodes WHERE start_ts < ?", (now_ts - KEEP_DAYS * 86400,))
        return _open(conn, monitor_id, metric, label)
    if ep is not None and now_ts - ep["last_ts"] >= GAP_S:
        conn.execute("UPDATE load_episodes SET end_ts = last_ts WHERE id = ?", (ep["id"],))
        return None
    return ep if ep is not None else None


def _local(ts: float) -> datetime:
    return datetime.fromtimestamp(ts)


def _tod(ts: float) -> int:
    t = _local(ts)
    return t.hour * 60 + t.minute


def _apart(a: int, b: int) -> int:
    d = abs(a - b)
    return min(d, 1440 - d)


def _hhmm(minutes: int) -> str:
    return f"{minutes // 60 % 24:02d}:{minutes % 60:02d}"


def _allowed(durations_s: list[int]) -> int:
    """How many minutes a busy period of this kind may run: a bit longer than the typical earlier one."""
    typical = statistics.median(durations_s) / 60 if durations_s else 0
    return int(min(MAX_ALLOWED_MIN, max(MIN_ALLOWED_MIN, typical * 1.5, typical + 10)))


def recurring(starts: list[tuple[int, int]], current: int) -> dict[str, Any] | None:
    """Does a busy period that starts at `current` fit what happened before? `starts` = [(start, duration in seconds)] of the earlier, finished ones.

    Returns {"text": "every day around 03:00", "typical_min", "allowed_min"} or None.
    """
    prior = sorted(s for s in starts if s[0] < current)
    if len(prior) < MIN_EARLIER:
        return None
    here = _tod(current)

    # the same time of day on most days
    recent = [s for s in prior if current - s[0] <= 14 * 86400]
    near = [s for s in recent if _apart(_tod(s[0]), here) <= 60]
    days = {_local(s[0]).date() for s in near}
    if recent and len(days) >= MIN_EARLIER:
        span = max(1, min(14, (current - recent[0][0]) // 86400 + 1))
        if len(days) >= 0.6 * span:
            return {"text": f"every day around {_hhmm(here)}", "typical_min": round(statistics.median(d for _s, d in near) / 60), "allowed_min": _allowed([d for _s, d in near])}

    # the same weekday and time of day, week after week
    weekday = _local(current).weekday()
    weekly = [s for s in prior if _local(s[0]).weekday() == weekday and _apart(_tod(s[0]), here) <= 90 and current - s[0] <= 8 * 7 * 86400]
    if len({_local(s[0]).date() for s in weekly}) >= MIN_EARLIER:
        name = _local(current).strftime("%A")
        return {"text": f"every {name} around {_hhmm(here)}", "typical_min": round(statistics.median(d for _s, d in weekly) / 60), "allowed_min": _allowed([d for _s, d in weekly])}

    # a steady interval (every 4 hours, every 90 minutes ...)
    if len(prior) >= MIN_EARLIER + 1:
        last = prior[-6:]
        gaps = [b[0] - a[0] for a, b in zip(last, last[1:])]
        middle = statistics.median(gaps)
        if 1800 <= middle <= 48 * 3600:
            regular = [g for g in gaps if abs(g - middle) <= 0.25 * middle]
            if len(regular) >= 3 and len(regular) >= 0.75 * len(gaps) and abs((current - last[-1][0]) - middle) <= 0.3 * middle:
                hours = middle / 3600
                every = f"{round(middle / 60)} minutes" if hours < 2 else (f"{hours:.0f} hours" if hours < 36 else f"{hours / 24:.0f} days")
                return {"text": f"about every {every}", "typical_min": round(statistics.median(d for _s, d in last) / 60), "allowed_min": _allowed([d for _s, d in last])}
    return None


def earlier(conn, monitor_id: int, metric: str, label: str, now_ts: float) -> list[tuple[int, int]]:
    rows = conn.execute("SELECT start_ts, end_ts FROM load_episodes WHERE monitor_id = ? AND metric = ? AND label = ? AND end_ts IS NOT NULL AND start_ts >= ?",
                        (monitor_id, metric, label, int(now_ts) - LOOKBACK_DAYS * 86400)).fetchall()
    return [(r["start_ts"], max(0, r["end_ts"] - r["start_ts"])) for r in rows]


# ----------------------------------------------------------------------------------------------------------- the verdict
def judge(conn, monitor_id: int, metric: str, label: str, episode, value: float, top: list | None, now_ts: float) -> dict[str, Any] | None:
    """What is known about the busy period that is going on: {"explained": bool, "cause": text, "minutes": how long it has run, "usual_min": ...} or None.

    `explained` = nothing to report yet. When it is False but `cause` is set, the warning is raised and says what the load is and that it is longer than usual.
    """
    if episode is None:
        return None
    minutes = max(0, int((now_ts - episode["start_ts"]) // 60))
    parts, allowed = [], 0
    process = None
    if top and top[0][1] >= SHARE * max(value, 1.0):
        process = top[0][0]
        info = known(process)
        if info:
            parts.append(f"mostly {normal(process)} ({info[0]})")
            allowed = max(allowed, info[1])
        else:
            parts.append(f"mostly {normal(process)}")
    pattern = recurring(earlier(conn, monitor_id, metric, label, now_ts), int(episode["start_ts"]))
    if pattern:
        parts.append(f"this host is busy {pattern['text']}")
        allowed = max(allowed, pattern["allowed_min"])
    if not parts:
        return None
    reason = ", ".join(parts)
    if not allowed:                              # an unknown process and no pattern: only named in the warning
        return {"explained": False, "cause": reason, "minutes": minutes}
    if minutes <= allowed:
        return {"explained": True, "cause": reason, "minutes": minutes, "usual_min": allowed}
    return {"explained": False, "cause": f"{reason}; it has been busy for {minutes} minutes, longer than the usual {allowed}", "minutes": minutes, "usual_min": allowed}


def note(conn, episode_id: int, text: str) -> None:
    conn.execute("UPDATE load_episodes SET explained = ? WHERE id = ?", (text[:300], episode_id))


def recent(conn, device_id: int, days: int = 14, now_ts: float | None = None) -> list[dict[str, Any]]:
    """The busy periods of a device (newest first), for its page: when, how long, how high, what, and whether Netlens explained it."""
    import time

    since = int((now_ts if now_ts is not None else time.time()) - days * 86400)
    rows = conn.execute("SELECT e.* FROM load_episodes e JOIN host_monitors m ON m.id = e.monitor_id WHERE m.device_id = ? AND e.start_ts >= ? ORDER BY e.start_ts DESC LIMIT 30", (device_id, since)).fetchall()
    return [{"start": datetime.fromtimestamp(r["start_ts"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "minutes": max(0, ((r["end_ts"] or r["last_ts"]) - r["start_ts"]) // 60),
             "peak": round(r["peak"]), "process": normal(r["process"]) if r["process"] else None, "explained": r["explained"], "open": r["end_ts"] is None} for r in rows]
