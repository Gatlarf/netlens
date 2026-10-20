"""Count the database round trips per page and show how a slower database would feel.

    python tools/dbbench.py [--devices 500] [--json out.json] [--compare before.json]

Builds the same made-up network as tools/bench.py plus service checks and health monitors, then asks for each page with nothing cached, and records
  * how many statements the page runs (every statement is a round trip when the database is on another machine), and
  * how long it takes when each statement costs an extra 0, 0.5 and 2 ms (a database server on the same host, on a good LAN, over a VPN).
The extra time is added by a wait inside the connection, so the numbers are the server's own plus what a network would add; the database server's own
run time is not included. Use it before and after a change to the queries; `tests/test_query_budget.py` holds the per-page limits.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sqlite3
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

PAGES = [("Session", "/api/session"), ("Device list", "/api/devices"), ("Device detail", "/api/devices/1"), ("Map", "/api/map"), ("Events", "/api/events?limit=100"),
         ("Uptime (24 h)", "/api/uptime?range=24h"), ("Service checks", "/api/service-checks"), ("Probes", "/api/probes"), ("Monitors", "/api/monitors"),
         ("Dashboard", "/api/dashboard"), ("Statistics summary", "/api/stats/summary"), ("Statistics (7 d)", "/api/stats?range=7d"), ("Availability report", "/api/reports/availability"),
         ("Insights", "/api/insights"), ("Changes", "/api/changes")]
RTTS = (0.0, 0.0005, 0.002)
STAMP = "%Y-%m-%dT%H:%M:%SZ"
state = {"delay": 0.0, "n": 0}


class Counting(sqlite3.Connection):
    def _tick(self):
        state["n"] += 1
        end = time.perf_counter() + state["delay"]
        while time.perf_counter() < end:
            pass

    def execute(self, *a, **k):
        self._tick()
        return super().execute(*a, **k)

    def executemany(self, *a, **k):
        self._tick()
        return super().executemany(*a, **k)

    def executescript(self, *a, **k):
        self._tick()
        return super().executescript(*a, **k)


def populate(folder: Path, devices: int, days: int = 7) -> None:
    import bench
    from app import tsdb
    from app.db import connect

    bench.build(folder, devices, days)
    conn = connect(folder / "netlens.db")
    rnd = random.Random(3)
    now = datetime.now(timezone.utc)
    ids = [r[0] for r in conn.execute("SELECT id FROM devices ORDER BY id")]
    kinds = [("tcp", 22, ""), ("tcp", 443, ""), ("http", 80, "/"), ("ping", None, "")]
    for k, d in enumerate(ids[::5]):
        kind, port, path = kinds[k % len(kinds)]
        cur = conn.execute("INSERT INTO service_checks (device_id, name, kind, host, port, path, interval_s, enabled, last_ts, last_up, last_ms, created) VALUES (?,?,?,?,?,?,60,1,?,?,?,?)",
                           (d, f"svc-{k}", kind, f"10.0.0.{k % 250 + 1}", port, path, now.strftime(STAMP), 1, 3.0, now.strftime(STAMP)))
        rows = [(cur.lastrowid, (now - timedelta(minutes=5 * s)).strftime(STAMP), 0 if rnd.random() < 0.02 else 1, 2.0 + rnd.random() * 6, "") for s in range(288)]
        conn.executemany("INSERT INTO service_results (check_id, ts, up, ms, detail) VALUES (?,?,?,?,?)", rows)
    conn.commit()
    store = tsdb.for_conn(conn)
    start = now - timedelta(days=2)
    for h in range(0, 48):
        ts = int((start + timedelta(hours=h)).timestamp())
        pts = []
        for d in ids[::10]:
            pts += [("device", d, "cpu_pct", rnd.random() * 60, "", "%"), ("device", d, "mem_pct", 40 + rnd.random() * 30, "", "%"), ("device", d, "disk_pct", 50 + rnd.random() * 20, "/", "%")]
            pts += [("device", d, "net_rx_bps", rnd.random() * 1e8, f"eth{i}", "bps") for i in range(3)]
        store.record(pts, ts=ts)
    conn.commit()
    from app import checkstats

    checkstats.backfill(conn)                           # the hourly roll-up an update does in the background on first start
    conn.close()


def counting_connect():
    """sqlite3.connect replacement that counts statements (and waits `state["delay"]` seconds for each); returns (replacement, original)."""
    real = sqlite3.connect
    mixed: dict[type, type] = {}

    def counted(*a, **k):                                   # put the counting in front of whatever connection class the application asks for
        base = k.get("factory") or sqlite3.Connection
        k["factory"] = mixed.setdefault(base, type("Counted" + base.__name__, (Counting, base), {}))
        return real(*a, **k)

    return counted, real


def measure(folder: Path) -> list[dict]:
    counted, real = counting_connect()
    sqlite3.connect = counted
    try:
        from fastapi.testclient import TestClient

        from app.config import load_settings
        from app.main import create_app

        app = create_app(load_settings({"NETLENS_TOKEN": "bench", "NETLENS_DATA_DIR": str(folder)}), db_path=folder / "netlens.db")
        auth = {"Authorization": "Bearer bench"}
        out = []
        with TestClient(app) as c:
            time.sleep(3)
            for label, path in PAGES:
                row = {"page": label, "path": path}
                for rtt in RTTS:
                    best, queries, status = 1e9, 0, 0
                    for _ in range(2):
                        app.state.__dict__.setdefault("stats_cache", {}).clear()
                        state["delay"], state["n"] = rtt, 0
                        t = time.perf_counter()
                        r = c.get(path, headers=auth)
                        ms = (time.perf_counter() - t) * 1000
                        if ms < best:
                            best, queries, status = ms, state["n"], r.status_code
                    row[f"ms_{int(rtt * 1e6)}us"] = round(best)
                    row["queries"], row["status"] = queries, status
                out.append(row)
    finally:
        sqlite3.connect = real
    return out


def show(rows: list[dict], before: dict | None) -> None:
    head = f"{'page':22}{'queries':>9}{'local ms':>10}{'+0.5 ms/q':>11}{'+2 ms/q':>10}"
    print(head + ("    (before -> after)" if before else ""))
    for r in rows:
        line = f"{r['page']:22}{r['queries']:>9}{r['ms_0us']:>10}{r['ms_500us']:>11}{r['ms_2000us']:>10}" + ("" if r["status"] == 200 else f"   HTTP {r['status']}")
        if before and r["page"] in before:
            b = before[r["page"]]
            line += f"    {b['queries']}q {b['ms_500us']}ms -> {r['queries']}q {r['ms_500us']}ms"
        print(line)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--devices", type=int, default=500)
    ap.add_argument("--json")
    ap.add_argument("--compare")
    ap.add_argument("--keep")
    a = ap.parse_args()
    folder = Path(a.keep) if a.keep else Path(tempfile.mkdtemp(prefix="netlens-dbbench-"))
    folder.mkdir(parents=True, exist_ok=True)
    if not (folder / "netlens.db").exists():
        populate(folder, a.devices)
    rows = measure(folder)
    before = {r["page"]: r for r in json.loads(Path(a.compare).read_text())["pages"]} if a.compare else None
    show(rows, before)
    if a.json:
        Path(a.json).write_text(json.dumps({"devices": a.devices, "pages": rows}, indent=1))


if __name__ == "__main__":
    main()
