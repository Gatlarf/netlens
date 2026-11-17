#!/usr/bin/env python3
"""Makes believable history for a DEMO Netlens, so a fresh Prometheus + Grafana shows weeks of graphs on the first day.

    python backfill_demo.py http://demo-netlens:8080 TOKEN [days] > history.om

It reads what the demo exports at /metrics right now and writes an OpenMetrics file in which every series has the same shape as today's value (evening peaks,
a few short outages, slow drifts), ending a few minutes ago. Load it with `promtool tsdb create-blocks-from openmetrics history.om <blocks dir>` (see
stack/README.md). Only use it with the demo network: the numbers are invented.
"""
import hashlib
import math
import random
import re
import sys
import time
import urllib.request

STEP = 900                       # one point per 15 minutes: plenty for graphs of days, and a file of a sensible size
LINE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{.*\})?\s+(\S+)$')


def fetch(url: str, token: str) -> list[tuple[str, str, float, str]]:
    req = urllib.request.Request(url.rstrip("/") + "/metrics", headers={"Authorization": f"Bearer {token}"})
    text = urllib.request.urlopen(req, timeout=30).read().decode()
    kinds, rows = {}, []
    for line in text.splitlines():
        if line.startswith("# TYPE "):
            _, _, name, kind = line.split(None, 3)
            kinds[name] = kind
        elif line and not line.startswith("#"):
            m = LINE.match(line)
            if m:
                rows.append((m.group(1), m.group(2) or "", float(m.group(3)), kinds.get(m.group(1), "gauge")))
    return rows


def day_shape(t: float) -> float:
    """0..1: quiet at night, busy in the evening (local-ish time, UTC+1)."""
    hour = ((t / 3600) + 1) % 24
    return 0.5 + 0.5 * math.sin((hour - 14) / 24 * 2 * math.pi)


def make(name: str, labels: str, cur: float, kind: str, now: float, n: int, rng: random.Random):
    """The values for the n steps that end at `now`."""
    ts = [now - (n - 1 - i) * STEP for i in range(n)]
    binary = name.endswith(("_up", "_active", "_ok", "_running", "_enabled", "_problem", "_fault")) or name in ("netlens_problem",)
    if name.endswith("_timestamp_seconds"):
        age = max(0.0, now - cur)
        period = 86400 * (7 if "backup" in name else 1)
        return ts, [t - ((age + (now - t)) % period) for t in ts]
    if kind == "counter" or name.endswith("_total"):
        start = now - n * STEP
        return ts, [cur * (t - start) / (now - start) for t in ts]
    if name.endswith("_days_left"):
        return ts, [cur + (now - t) / 86400 for t in ts]
    if binary:
        out, state, left = [], 1.0 if cur >= 0.5 else 0.0, 0
        flip = 0.004 if "problem" not in name else 0.003
        for _ in ts:
            if left > 0:
                left -= 1
                out.append(1.0 - state if cur >= 0.5 else 1.0)
            elif rng.random() < flip:
                left = rng.randint(1, 6)
                out.append(1.0 - state if cur >= 0.5 else 1.0)
            else:
                out.append(state)
        out[-1] = cur
        return ts, out
    drift = rng.uniform(-0.04, 0.04)
    vals = []
    for i, t in enumerate(ts):
        k = i / max(1, n - 1)
        if name.endswith("_ratio") and "uptime" in name:
            v = min(1.0, cur * (1 - 0.01 * rng.random()))
        elif name.endswith("_ratio") or "_airtime" in name:
            v = cur * (0.75 + 0.5 * day_shape(t)) * (1 + drift * (k - 1)) + rng.gauss(0, 0.015)
            v = max(0.0, min(1.0, v))
        elif "health_score" in name:
            v = max(0.0, min(100.0, cur + rng.gauss(0, 1.5) - (6 if rng.random() < 0.01 else 0)))
        elif name.endswith("_dbm"):
            v = cur + rng.gauss(0, 2.5)
        elif name.endswith("_celsius"):
            v = cur + 3 * (day_shape(t) - 0.5) + rng.gauss(0, 0.4)
        elif name.endswith("_per_second") and "speedtest" not in name:
            v = max(0.0, cur * (0.4 + 1.2 * day_shape(t)) * rng.uniform(0.7, 1.3)) if cur else 0.0
        elif "speedtest" in name or name.endswith("_seconds"):
            v = max(0.0, cur * rng.uniform(0.85, 1.12))
        elif name.endswith("_bytes"):
            v = cur * (0.7 + 0.3 * k)
        else:
            v = cur * (0.96 + 0.08 * day_shape(t)) + rng.gauss(0, max(0.2, abs(cur) * 0.01))
            v = max(0.0, v) if cur >= 0 else v
        if float(cur).is_integer() and not name.endswith(("_ratio", "_seconds", "_dbm", "_celsius", "_per_second")):
            v = float(round(v))
        vals.append(v)
    vals[-1] = cur
    return ts, vals


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    url, token = sys.argv[1], sys.argv[2]
    days = int(sys.argv[3]) if len(sys.argv) > 3 else 45
    now = time.time() - 600                      # the history stops before Prometheus's own scrapes begin
    n = days * 86400 // STEP
    rows = fetch(url, token)
    out = []
    declared = set()
    series = {}
    for name, labels, cur, kind in rows:
        rng = random.Random(int(hashlib.sha256((name + labels).encode()).hexdigest()[:12], 16))
        series[(name, labels)] = (kind, make(name, labels, cur, kind, now, n, rng))
    for (name, labels), (kind, _) in series.items():
        if name not in declared:
            declared.add(name)
            out.append(f"# TYPE {name} gauge")            # stored as plain series, which is all rate() and increase() need
    # OpenMetrics wants the samples of one metric together, in time order
    for name in declared:
        for (n2, labels), (kind, (ts, vals)) in series.items():
            if n2 != name:
                continue
            for t, v in zip(ts, vals):
                out.append(f"{name}{labels} {v:.6g} {t:.0f}")
    out.append("# EOF")
    sys.stdout.write("\n".join(out) + "\n")
    print(f"{len(series)} series, {n} points each", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
