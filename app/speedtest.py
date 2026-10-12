"""Speed tests: the internet (against Cloudflare's public test servers), iperf3 and the browser. This module keeps the results,
runs the internet test and decides when the scheduled one is due; app/iperf.py runs iperf3."""

from __future__ import annotations

import http.client
import json
import os
import ssl
import statistics
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone

from app.db import get_setting, set_setting, utcnow

KINDS = ("internet", "iperf-in", "iperf-out", "browser")
KEEP_DAYS = 365
KEEP_ROWS = 5000
HOST = "speed.cloudflare.com"
HEADERS = {"User-Agent": "Mozilla/5.0 (Netlens speed test)", "Referer": f"https://{HOST}/"}
SCHEDULE_KEY = "speedtest.schedule"
IPERF_KEY = "speedtest.iperf"
EVERY_CHOICES = (1, 3, 6, 12, 24)
DEFAULT_SCHEDULE = {"enabled": False, "every_hours": 6}
DEFAULT_IPERF = {"enabled": False, "port": 5201}


# ---------- settings ----------

def _load(conn, key: str, default: dict) -> dict:
    try:
        value = json.loads(get_setting(conn, key) or "null")
    except ValueError:
        value = None
    return {**default, **(value if isinstance(value, dict) else {})}


def get_schedule(conn) -> dict:
    s = _load(conn, SCHEDULE_KEY, DEFAULT_SCHEDULE)
    return {"enabled": bool(s["enabled"]), "every_hours": s["every_hours"] if s["every_hours"] in EVERY_CHOICES else DEFAULT_SCHEDULE["every_hours"]}


def set_schedule(conn, enabled: bool, every_hours: int) -> dict:
    if every_hours not in EVERY_CHOICES:
        raise ValueError(f"every_hours must be one of {', '.join(map(str, EVERY_CHOICES))}")
    set_setting(conn, SCHEDULE_KEY, json.dumps({"enabled": bool(enabled), "every_hours": every_hours}))
    conn.commit()
    return get_schedule(conn)


def get_iperf_settings(conn) -> dict:
    s = _load(conn, IPERF_KEY, DEFAULT_IPERF)
    port = s["port"] if isinstance(s["port"], int) and 1 <= s["port"] <= 65535 else DEFAULT_IPERF["port"]
    return {"enabled": bool(s["enabled"]), "port": port}


def set_iperf_settings(conn, enabled: bool, port: int) -> dict:
    if not 1 <= port <= 65535 or port in (8080,):
        raise ValueError("choose a free port between 1 and 65535")
    set_setting(conn, IPERF_KEY, json.dumps({"enabled": bool(enabled), "port": port}))
    conn.commit()
    return get_iperf_settings(conn)


# ---------- results ----------

def _round(v, n=1):
    return None if v is None else round(float(v), n)


def record(conn, kind: str, target: str = "", *, down=None, up=None, latency=None, jitter=None, ok: bool = True, error: str | None = None, detail: dict | None = None, now: str | None = None) -> int:
    cur = conn.execute(
        "INSERT INTO speedtests (ts, kind, target, down_mbps, up_mbps, latency_ms, jitter_ms, ok, error, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (now or utcnow(), kind, target[:200], _round(down), _round(up), _round(latency), _round(jitter, 2), 1 if ok else 0, (error or None) and error[:300], json.dumps(detail or {})),
    )
    conn.commit()
    return cur.lastrowid


def prune(conn, now: str | None = None) -> None:
    cutoff = (datetime.strptime(now or utcnow(), "%Y-%m-%dT%H:%M:%SZ") - timedelta(days=KEEP_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute("DELETE FROM speedtests WHERE ts < ?", (cutoff,))
    conn.execute("DELETE FROM speedtests WHERE id NOT IN (SELECT id FROM speedtests ORDER BY id DESC LIMIT ?)", (KEEP_ROWS,))
    conn.commit()


def _row(r) -> dict:
    try:
        detail = json.loads(r["detail"] or "{}")
    except ValueError:
        detail = {}
    return {"id": r["id"], "ts": r["ts"], "kind": r["kind"], "target": r["target"], "down_mbps": r["down_mbps"], "up_mbps": r["up_mbps"],
            "latency_ms": r["latency_ms"], "jitter_ms": r["jitter_ms"], "ok": bool(r["ok"]), "error": r["error"], "detail": detail}


def history(conn, kind: str | None = None, limit: int = 100) -> list[dict]:
    """Newest first."""
    if kind:
        rows = conn.execute("SELECT * FROM speedtests WHERE kind = ? ORDER BY id DESC LIMIT ?", (kind, limit)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM speedtests ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [_row(r) for r in rows]


def latest(conn, kind: str) -> dict | None:
    r = conn.execute("SELECT * FROM speedtests WHERE kind = ? AND ok = 1 ORDER BY id DESC LIMIT 1", (kind,)).fetchone()
    return _row(r) if r else None


def clear(conn) -> None:
    conn.execute("DELETE FROM speedtests")
    conn.commit()


def local_addresses() -> list[str]:
    """The IPv4 addresses of this machine (Netlens runs on the host network), private ones first: what another host types after `iperf3 -c`."""
    found: list[str] = []
    try:
        out = subprocess.run(["ip", "-j", "-4", "addr"], capture_output=True, text=True, timeout=5).stdout
        for iface in json.loads(out or "[]"):
            if iface.get("ifname", "").startswith(("lo", "docker", "br-", "veth")):
                continue
            found += [a["local"] for a in iface.get("addr_info", []) if a.get("local")]
    except (OSError, ValueError, subprocess.SubprocessError):
        pass

    def private(ip: str) -> bool:
        a, b = (int(x) for x in ip.split(".")[:2])
        return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)

    return sorted(set(found), key=lambda ip: (not private(ip), ip))


# ---------- the internet test (Cloudflare) ----------

class Progress:
    """What a running test is doing, for the page to poll."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.data: dict | None = None

    def start(self, kind: str, target: str = "") -> bool:
        with self.lock:
            if self.data is not None:
                return False
            self.data = {"kind": kind, "target": target, "phase": "starting", "live_mbps": None, "started": utcnow(), "result": None}
            return True

    def update(self, **fields) -> None:
        with self.lock:
            if self.data is not None:
                self.data.update(fields)

    def finish(self) -> None:
        with self.lock:
            self.data = None

    def snapshot(self) -> dict | None:
        with self.lock:
            return dict(self.data) if self.data else None


def _context() -> ssl.SSLContext:
    return ssl.create_default_context()


def _connect(timeout: float = 10.0) -> http.client.HTTPSConnection:
    return http.client.HTTPSConnection(HOST, timeout=timeout, context=_context())


def _get_json(path: str) -> dict:
    conn = _connect()
    try:
        conn.request("GET", path, headers=HEADERS)
        resp = conn.getresponse()
        return json.loads(resp.read() or b"{}") if resp.status == 200 else {}
    except (OSError, ValueError, http.client.HTTPException):
        return {}
    finally:
        conn.close()


def measure_latency(samples: int = 12) -> tuple[float | None, float | None]:
    times: list[float] = []
    conn = _connect()
    try:
        for i in range(samples):
            started = time.perf_counter()
            conn.request("GET", "/__down?bytes=0", headers=HEADERS)
            conn.getresponse().read()
            if i:  # the first request includes the TLS handshake
                times.append((time.perf_counter() - started) * 1000)
    except (OSError, http.client.HTTPException):
        pass
    finally:
        conn.close()
    if len(times) < 3:
        return None, None
    jitter = statistics.mean(abs(a - b) for a, b in zip(times, times[1:]))
    return statistics.median(times), jitter


def _run_streams(worker, streams: int, seconds: float, warmup: float, progress: Progress, phase: str) -> float:
    """Run `streams` workers for `seconds`; returns Mbps counted after the warm-up (TCP slow start is not the line speed)."""
    stop = threading.Event()
    counted = [0] * streams
    threads = [threading.Thread(target=worker, args=(i, counted, stop), daemon=True) for i in range(streams)]
    started = time.perf_counter()
    for t in threads:
        t.start()
    warm_bytes, warm_time, last_bytes, last_time = None, None, 0, started
    while True:
        time.sleep(0.4)
        now = time.perf_counter()
        total = sum(counted)
        progress.update(phase=phase, live_mbps=round((total - last_bytes) * 8 / max(now - last_time, 1e-6) / 1e6, 1))
        last_bytes, last_time = total, now
        if warm_bytes is None and now - started >= warmup:
            warm_bytes, warm_time = total, now
        if now - started >= seconds:
            break
    stop.set()
    end_bytes = sum(counted)
    for t in threads:
        t.join(timeout=3)
    if warm_bytes is None or now - warm_time < 1:
        return 0.0
    return (end_bytes - warm_bytes) * 8 / (now - warm_time) / 1e6


def measure_download(progress: Progress, seconds: float = 8, streams: int = 4) -> float:
    def worker(i, counted, stop):
        while not stop.is_set():
            conn = _connect(timeout=15)
            try:
                conn.request("GET", "/__down?bytes=50000000", headers=HEADERS)
                resp = conn.getresponse()
                while not stop.is_set():
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    counted[i] += len(chunk)
            except (OSError, http.client.HTTPException):
                time.sleep(0.2)
            finally:
                conn.close()

    return _run_streams(worker, streams, seconds, 1.5, progress, "download")


def measure_upload(progress: Progress, seconds: float = 8, streams: int = 3) -> float:
    payload = os.urandom(1_000_000)

    def worker(i, counted, stop):
        conn = _connect(timeout=15)
        try:
            while not stop.is_set():
                try:
                    conn.request("POST", "/__up", body=payload, headers={**HEADERS, "Content-Type": "application/octet-stream"})
                    conn.getresponse().read()
                    counted[i] += len(payload)
                except (OSError, http.client.HTTPException):
                    conn.close()
                    conn = _connect(timeout=15)
                    time.sleep(0.2)
        finally:
            conn.close()

    return _run_streams(worker, streams, seconds, 1.5, progress, "upload")


def run_internet_test(progress: Progress, seconds: float = 8) -> dict:
    """Latency, download and upload against the nearest Cloudflare test server. Raises OSError when the internet cannot be reached."""
    progress.update(phase="latency")
    meta = _get_json("/meta")
    latency, jitter = measure_latency()
    if latency is None:
        raise OSError("Could not reach the test server. Is the internet connection up?")
    down = measure_download(progress, seconds)
    up = measure_upload(progress, seconds)
    colo = meta.get("colo") if isinstance(meta.get("colo"), dict) else {}
    return {"down": down, "up": up, "latency": latency, "jitter": jitter,
            "detail": {"server": colo.get("city") or meta.get("city"), "server_code": colo.get("iata"), "isp": meta.get("asOrganization"), "country": meta.get("country")}}


def run_and_record(db_path: str, progress: Progress, kind: str = "internet") -> None:
    """Runs in a thread: the whole internet test, stored in the history (a failure is stored too)."""
    from app.db import connect

    conn = connect(db_path)
    try:
        try:
            r = run_internet_test(progress)
            record(conn, "internet", "Cloudflare", down=r["down"], up=r["up"], latency=r["latency"], jitter=r["jitter"], detail=r["detail"])
        except Exception as exc:  # noqa: BLE001 - shown on the page
            record(conn, "internet", "Cloudflare", ok=False, error=str(exc) or exc.__class__.__name__)
        prune(conn)
    finally:
        conn.close()
        progress.finish()


def due(conn, now: str | None = None) -> bool:
    s = get_schedule(conn)
    if not s["enabled"]:
        return False
    last = conn.execute("SELECT ts FROM speedtests WHERE kind = 'internet' ORDER BY id DESC LIMIT 1").fetchone()
    if last is None:
        return True
    then = datetime.strptime(last["ts"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    current = datetime.strptime(now or utcnow(), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return current - then >= timedelta(hours=s["every_hours"]) - timedelta(minutes=5)


PROGRESS = Progress()  # one test at a time (a speed test needs the whole line); the scheduler and the pages share this
