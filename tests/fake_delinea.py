"""A stand-in for Delinea Secret Server's REST API as documented (OAuth2 password grant, GET /api/v1/secrets/{id}, POST .../check-in). Not the product."""

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Fake:
    def __init__(self):
        self.requests: list[dict] = []
        self.check_ins: list[str] = []
        self.secrets = {"1234": {"checkOut": False, "items": [{"fieldName": "Username", "slug": "username", "itemValue": "svc-web"}, {"fieldName": "Password", "slug": "password", "itemValue": "pw-dsm-1", "isPassword": True},
                                                              {"fieldName": "Notes", "slug": "notes", "itemValue": "n"}]},
                        "2000": {"checkOut": True, "items": [{"fieldName": "Username", "slug": "username", "itemValue": "root"}, {"fieldName": "Password", "slug": "password", "itemValue": "pw-dsm-2"}]},
                        "3000": {"checkOut": False, "items": [{"fieldName": "Host", "slug": "host", "itemValue": "h"}]}}
        self.user, self.password = "netlens-app", "app-pw"
        self.deny = set()

    def start(self):
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body):
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _handle(self, method):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n).decode() if n else ""
                url = urllib.parse.urlparse(self.path)
                fake.requests.append({"method": method, "path": url.path, "query": urllib.parse.parse_qs(url.query), "headers": dict(self.headers), "body": raw})
                if url.path == "/oauth2/token":
                    f = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
                    if f.get("grant_type") == "password" and f.get("username") == fake.user and f.get("password") == fake.password:
                        return self._send(200, {"access_token": "tok-1", "token_type": "bearer", "expires_in": 1199})
                    return self._send(400, {"error": "invalid_grant"})
                if self.headers.get("Authorization") != "Bearer tok-1":
                    return self._send(401, {"message": "Authentication failed"})
                parts = url.path.strip("/").split("/")
                if parts[:3] == ["api", "v1", "secrets"] and len(parts) >= 4:
                    sid = parts[3]
                    s = fake.secrets.get(sid)
                    if s is None:
                        return self._send(404, {"message": "Secret not found"})
                    if sid in fake.deny:
                        return self._send(403, {"message": "Access denied: comment required"})
                    if method == "POST" and parts[4:] == ["check-in"]:
                        fake.check_ins.append(sid)
                        return self._send(200, {})
                    if method == "GET" and len(parts) == 4:
                        return self._send(200, {"id": int(sid), "items": s["items"], "checkedOut": s["checkOut"], "checkOutEnabled": s["checkOut"]})
                return self._send(404, {"message": "no such route"})

            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                self._handle("POST")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
