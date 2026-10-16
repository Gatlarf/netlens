"""A fixture for plugin tests: a local HTTP server that answers GET requests with canned JSON (recorded from the real software)."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Canned:
    """Canned(routes, auth=None): routes maps a path (or ("POST", path)) to a JSON-able answer (or to an int status). auth is the expected Authorization header."""

    def __init__(self, routes, auth=None):
        self.routes, self.auth, self.seen = routes, auth, []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                self.do_GET(("POST", self.path.split("?")[0]))

            def do_GET(self, key=None):
                path = self.path.split("?")[0]
                outer.seen.append(path)
                answer = outer.routes.get(key or path, 404)
                if outer.auth and self.headers.get("Authorization") != outer.auth:
                    answer = 401
                code, body = (answer, {}) if isinstance(answer, int) else (200, answer)
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
