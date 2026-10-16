"""A Proxmox Backup Server that replays the shapes recorded from PBS 4.2 (2026-10-16): token login, datastores, snapshots, jobs and tasks."""

import json
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

TOKEN = "PBSAPIToken=netlens@pbs!netlens:secret"


def make_certificate(folder: Path) -> tuple[Path, Path, str]:
    """A throwaway self-signed certificate (needs the openssl program); returns (cert file, key file, its SHA-256 fingerprint)."""
    cert, key = folder / "c.pem", folder / "k.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "2", "-subj", "/CN=pbs.test"], check=True, capture_output=True)
    fp = subprocess.run(["openssl", "x509", "-in", str(cert), "-noout", "-fingerprint", "-sha256"], check=True, capture_output=True, text=True).stdout.split("=", 1)[1].strip()
    return cert, key, fp


class FakePbs:
    def __init__(self, folder: Path, snapshots, tasks=(), problem_tasks=(), usage=None, jobs=None, token=TOKEN, allow_tasks=True):
        self.snapshots, self.tasks, self.problem_tasks, self.allow_tasks = snapshots, list(tasks), list(problem_tasks), allow_tasks
        self.usage = usage if usage is not None else [{"store": "main", "total": 1000, "used": 250, "avail": 750, "estimated-full-date": None}]
        self.jobs = jobs or {}
        self.seen = []
        outer = self
        cert, key, self.fingerprint = make_certificate(folder)

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                parts = urlsplit(self.path)
                outer.seen.append(parts.path)
                if self.headers.get("Authorization") != token:
                    return self._send(401, {"errors": "no permission"})
                path, q = parts.path.removeprefix("/api2/json/"), parse_qs(parts.query)
                if path == "version":
                    return self._send(200, {"data": {"version": "4.2", "release": "5", "repoid": "x"}})
                if path == "status/datastore-usage":
                    return self._send(200, {"data": outer.usage})
                if path.startswith("admin/datastore/") and path.endswith("/snapshots"):
                    return self._send(200, {"data": outer.snapshots.get(path.split("/")[2], [])})
                if path in ("admin/gc", "admin/prune", "admin/verify", "admin/sync"):
                    return self._send(200, {"data": outer.jobs.get(path.split("/")[1], [])})
                if path == "nodes/localhost/tasks":
                    if not outer.allow_tasks:
                        return self._send(403, {"errors": "permission check failed"})
                    return self._send(200, {"total": 1, "data": outer.problem_tasks if q.get("errors") else [t for t in outer.tasks if t["worker_type"] == (q.get("typefilter") or [t["worker_type"]])[0]]})
                self._send(404, {"errors": "no such path"})

            def _send(self, code, data):
                raw = json.dumps(data).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.url = f"https://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
