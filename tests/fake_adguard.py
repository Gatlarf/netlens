"""A tiny stand-in for the AdGuard Home API (v0.107.79, behaviour recorded 2026-10-16): basic auth, 200 for everything,
a duplicate add or a missing delete is silently accepted."""

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeAdguard:
    def __init__(self, user="admin", password="pw", rewrites=None):
        self.expected = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self.rewrites = [dict(r) for r in (rewrites or [])]
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, code, body=""):
                raw = (json.dumps(body) if body != "" else "").encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def handle_any(self, method):
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else {}
                if self.headers.get("Authorization") != outer.expected:
                    return self.reply(401, "Unauthorized")
                if self.path == "/control/status":
                    return self.reply(200, {"version": "v0.107.79", "running": True})
                if self.path == "/control/rewrite/list":
                    return self.reply(200, outer.rewrites)
                pair = {"domain": body.get("domain"), "answer": body.get("answer")}
                if self.path == "/control/rewrite/add":
                    if not any(r["domain"] == pair["domain"] and r["answer"] == pair["answer"] for r in outer.rewrites):
                        outer.rewrites.append({**pair, "enabled": True})
                    return self.reply(200)
                if self.path == "/control/rewrite/delete":
                    outer.rewrites = [r for r in outer.rewrites if not (r["domain"] == pair["domain"] and r["answer"] == pair["answer"])]
                    return self.reply(200)
                self.reply(404, "not found")

            do_GET = lambda self: self.handle_any("GET")
            do_POST = lambda self: self.handle_any("POST")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
