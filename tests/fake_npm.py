"""A small fake Nginx Proxy Manager API (2.15 behaviour: a wrong password is HTTP 400, the token request takes no extra properties)."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

TOKEN = "tok-123"


def proxy_host(i, domains, host, port, cert=0, enabled=True, scheme="http", access=0, ssl_forced=False):
    return {"id": i, "domain_names": domains, "forward_scheme": scheme, "forward_host": host, "forward_port": port, "certificate_id": cert, "ssl_forced": ssl_forced,
            "enabled": enabled, "allow_websocket_upgrade": True, "access_list_id": access, "meta": {}, "locations": []}


class FakeNpm:
    def __init__(self, user="netlens@example.com", password="pw", proxy_hosts=None, redirections=None, streams=None, dead=None, certificates=None, access_lists=None,
                 permissions=None, roles=None, requires_2fa=False, forbid=()):
        self.user, self.password = user, password
        self.data = {"/api/nginx/proxy-hosts": proxy_hosts or [], "/api/nginx/redirection-hosts": redirections or [], "/api/nginx/streams": streams or [],
                     "/api/nginx/dead-hosts": dead or [], "/api/nginx/certificates": certificates or [], "/api/nginx/access-lists": access_lists or []}
        self.permissions = permissions or {"visibility": "all", "proxy_hosts": "view", "redirection_hosts": "view", "dead_hosts": "view", "streams": "view", "access_lists": "view", "certificates": "view"}
        self.roles, self.requires_2fa, self.forbid = roles or [], requires_2fa, set(forbid)
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body):
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                outer.requests.append(("POST", self.path))
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                if self.path != "/api/tokens":
                    return self._send(405, {"error": {"code": 405, "message": "read-only"}})
                if set(body) - {"identity", "secret", "scope"}:
                    return self._send(400, {"error": {"code": 400, "message": "data must NOT have additional properties"}})
                if body.get("identity") != outer.user or body.get("secret") != outer.password:
                    return self._send(400, {"error": {"code": 400, "message": "Invalid email or password"}})
                if outer.requires_2fa:
                    return self._send(200, {"requires_2fa": True, "challenge_token": "c"})
                self._send(200, {"token": TOKEN, "expires": "2026-12-01T00:00:00.000Z"})

            def do_GET(self):
                path = urlsplit(self.path).path
                outer.requests.append(("GET", path))
                if path == "/api/":
                    return self._send(200, {"status": "OK", "setup": True, "version": {"major": 2, "minor": 15, "revision": 1}})
                if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    return self._send(401, {"error": {"code": 401, "message": "Unauthorized"}})
                if path in outer.forbid:
                    return self._send(403, {"error": {"code": 403, "message": "Forbidden"}})
                if path == "/api/users/me":
                    return self._send(200, {"id": 2, "email": outer.user, "roles": outer.roles, "permissions": outer.permissions})
                if path in outer.data:
                    return self._send(200, outer.data[path])
                self._send(404, {"error": {"code": 404, "message": "Not Found"}})

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
