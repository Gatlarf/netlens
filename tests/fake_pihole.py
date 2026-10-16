"""A tiny stand-in for the Pi-hole v6 API, behaving as a real Pi-hole 6.4.3 does (recorded 2026-10-16): login with a session id,
Local DNS records as strings, 400 "Item already present" for a duplicate, 204 for a delete."""

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SID = "fake-session-id"


class FakePihole:
    def __init__(self, password="pw", hosts=None, cnames=None):
        self.password, self.hosts, self.cnames = password, list(hosts or []), list(cnames or [])
        self.logins = self.logouts = 0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, code, body=None):
                raw = json.dumps(body).encode() if body is not None else b""
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def handle_any(self, method):
                path = urllib.parse.unquote(self.path)
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else {}
                if path == "/api/auth" and method == "POST":
                    if body.get("password") != outer.password:
                        return self.reply(401, {"session": {"valid": False, "totp": False, "sid": None, "message": "password incorrect"}})
                    outer.logins += 1
                    return self.reply(200, {"session": {"valid": True, "totp": False, "sid": SID, "validity": 1800}})
                if self.headers.get("sid") != SID:
                    return self.reply(401, {"error": {"key": "unauthorized", "message": "Unauthorized"}})
                if path == "/api/auth" and method == "DELETE":
                    outer.logouts += 1
                    return self.reply(204)
                if path == "/api/info/version":
                    return self.reply(200, {"version": {"core": {"local": {"version": "v6.4.3"}}}})
                for section, store in (("hosts", outer.hosts), ("cnameRecords", outer.cnames)):
                    base = f"/api/config/dns/{section}"
                    if path == base and method == "GET":
                        return self.reply(200, {"config": {"dns": {section: list(store)}}})
                    if path.startswith(base + "/"):
                        item = path[len(base) + 1:]
                        if method == "PUT":
                            if item in store:
                                return self.reply(400, {"error": {"key": "bad_request", "message": "Item already present", "hint": "Uniqueness of items is enforced"}})
                            store.append(item)
                            return self.reply(201)
                        if method == "DELETE":
                            if item in store:
                                store.remove(item)
                            return self.reply(204)
                self.reply(404, {"error": {"key": "not_found", "message": "Not found"}})

            do_GET = lambda self: self.handle_any("GET")
            do_POST = lambda self: self.handle_any("POST")
            do_PUT = lambda self: self.handle_any("PUT")
            do_DELETE = lambda self: self.handle_any("DELETE")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
