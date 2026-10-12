"""iperf3: a server that runs inside this container (so any host can test against Netlens) and a client (Netlens tests against a host).
Needs the iperf3 program, which the Docker image has."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
import time

from app import speedtest
from app.db import connect, utcnow

HOST_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:\-\[\]]{0,252}$")   # never starts with "-": it would be taken for an option


def available() -> str | None:
    return shutil.which("iperf3")


def valid_host(host: str) -> bool:
    return bool(HOST_RE.match(host or ""))


def _mbps(section: dict | None) -> float | None:
    bps = (section or {}).get("bits_per_second")
    return None if bps is None else bps / 1e6


class Server:
    """`iperf3 -s` as a child process. Every finished test of a visitor is stored in the speed test history."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.proc: subprocess.Popen | None = None
        self.port: int | None = None
        self.started: str | None = None
        self.error: str | None = None
        self.last_test: dict | None = None
        self._lock = threading.Lock()

    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, port: int) -> None:
        binary = available()
        if not binary:
            raise RuntimeError("iperf3 is not installed in this container.")
        with self._lock:
            if self.running():
                if self.port == port:
                    return
                self._stop()
            self.error = None
            self.proc = subprocess.Popen([binary, "-s", "-p", str(port), "-J", "--forceflush"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.port, self.started = port, utcnow()
            threading.Thread(target=self._read, args=(self.proc,), daemon=True).start()
            threading.Thread(target=self._read_errors, args=(self.proc,), daemon=True).start()
        time.sleep(0.4)  # an occupied port makes it quit at once: report that instead of "listening"
        if not self.running():
            raise RuntimeError(self.error or f"iperf3 could not listen on port {port}. Is the port in use?")

    def _stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    def stop(self) -> None:
        with self._lock:
            self._stop()
            self.started = None

    def status(self) -> dict:
        return {"installed": available() is not None, "running": self.running(), "port": self.port if self.running() else None, "since": self.started if self.running() else None,
                "error": self.error, "last_test": self.last_test}

    def _read_errors(self, proc) -> None:
        for line in proc.stderr:
            line = line.strip()
            if line:
                self.error = line[:200]

    def _read(self, proc) -> None:
        """iperf3 prints one JSON document per finished test on stdout."""
        depth, buf = 0, []
        for line in proc.stdout:
            buf.append(line)
            depth += line.count("{") - line.count("}")
            if depth <= 0 and any(l.strip() for l in buf):
                text = "".join(buf)
                buf, depth = [], 0
                try:
                    self._store(json.loads(text))
                except (ValueError, KeyError, TypeError):
                    continue

    def _store(self, doc: dict) -> None:
        result = parse_server_result(doc)
        if result is None:
            return
        conn = connect(self.db_path)
        try:
            speedtest.record(conn, "iperf-in", result["client"], down=result["down"], up=result["up"], ok=result["ok"], error=result["error"], detail=result["detail"])
            speedtest.prune(conn)
        finally:
            conn.close()
        self.last_test = {"ts": utcnow(), "client": result["client"], "up": result["up"], "down": result["down"], "ok": result["ok"]}


def parse_server_result(doc: dict) -> dict | None:
    """One finished test seen from the server. up = the client sent to Netlens, down = Netlens sent to the client (a reverse test)."""
    if not isinstance(doc, dict) or ("start" not in doc and "error" not in doc):
        return None
    start, end = doc.get("start") or {}, doc.get("end") or {}
    connected = (start.get("connected") or [{}])[0]
    client = connected.get("remote_host") or "unknown"
    if doc.get("error") and not end:
        return {"client": client, "up": None, "down": None, "ok": False, "error": str(doc["error"])[:300], "detail": {}}
    test = start.get("test_start") or {}
    reverse = bool(test.get("reverse"))
    bidir = bool(test.get("bidir"))
    received, sent = end.get("sum_received") or end.get("sum") or {}, end.get("sum_sent") or end.get("sum") or {}
    up = down = None
    if bidir:
        up, down = _mbps(end.get("sum_received")), _mbps(end.get("sum_sent"))
    elif reverse:
        down = _mbps(sent)
    else:
        up = _mbps(received)
    seconds = test.get("duration") or (end.get("sum_received") or {}).get("seconds")
    return {"client": client, "up": up, "down": down, "ok": True, "error": None,
            "detail": {"protocol": test.get("protocol"), "streams": test.get("num_streams"), "seconds": round(seconds, 1) if seconds else None,
                       "retransmits": (end.get("sum_sent") or {}).get("retransmits")}}


def run_client(host: str, port: int, seconds: int, direction: str, streams: int, timeout_pad: int = 20) -> dict:
    """Netlens tests against an iperf3 server on another host. direction: up (Netlens sends), down (the host sends) or both (one after the other)."""
    binary = available()
    if not binary:
        raise RuntimeError("iperf3 is not installed in this container.")
    if not valid_host(host):
        raise ValueError("That is not a valid host name or address.")
    out = {"up": None, "down": None, "retransmits": None}
    for reverse in ([False] if direction == "up" else [True] if direction == "down" else [False, True]):
        cmd = [binary, "-c", host, "-p", str(port), "-t", str(seconds), "-P", str(streams), "-J", "--connect-timeout", "5000"] + (["-R"] if reverse else [])
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=seconds + timeout_pad)
        try:
            doc = json.loads(proc.stdout or "{}")
        except ValueError:
            doc = {}
        if doc.get("error") or not doc.get("end"):
            raise RuntimeError(str(doc.get("error") or proc.stderr.strip() or "iperf3 gave no result").strip()[:300])
        end = doc["end"]
        if reverse:
            out["down"] = _mbps(end.get("sum_received"))
        else:
            out["up"] = _mbps(end.get("sum_sent"))
            out["retransmits"] = (end.get("sum_sent") or {}).get("retransmits")
    return out


def run_client_and_record(db_path: str, host: str, port: int, seconds: int, direction: str, streams: int) -> None:
    conn = connect(db_path)
    try:
        progress = speedtest.PROGRESS
        progress.update(phase="running", live_mbps=None)
        try:
            r = run_client(host, port, seconds, direction, streams)
            speedtest.record(conn, "iperf-out", f"{host}:{port}", down=r["down"], up=r["up"], detail={"seconds": seconds, "streams": streams, "retransmits": r["retransmits"], "direction": direction})
        except Exception as exc:  # noqa: BLE001 - shown on the page
            speedtest.record(conn, "iperf-out", f"{host}:{port}", ok=False, error=str(exc) or exc.__class__.__name__, detail={"direction": direction})
        speedtest.prune(conn)
    finally:
        conn.close()
        speedtest.PROGRESS.finish()
