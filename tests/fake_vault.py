"""A small stand-in for HashiCorp Vault / OpenBao with just what Netlens uses: AppRole login, token revoke, KV v1 and v2 reads, policy by path.
Its behaviour was checked against a real OpenBao 2.7.2 (see tests/test_pam_live.py, which runs only when one is given)."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROLE, SECRET = "role-1", "secret-1"


class Fake:
    def __init__(self):
        self.tokens: dict[str, str] = {}            # token -> "approle" or "static"
        self.revoked: list[str] = []
        self.requests: list[dict] = []
        self.kv2 = {"netlens/linux": {"username": "svc", "password": "pw-1"}, "netlens/key": {"user": "root", "key": "KEYDATA", "pass": "kp"}, "netlens/nouser": {"password": "pw"}}
        self.kv1 = {"old/db": {"username": "legacy", "password": "pw-v1"}}
        self.allowed = ("netlens/",)
        self.down = 0                               # answer 503 this many times
        self.static_token = "static-token"
        self.transit_version = 1
        self.transit_key = "netlens"
        self.transit_calls: list[str] = []
        self.big = False
        self.transit_allowed = True
        self.tokens[self.static_token] = "static"
        self.server = None

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

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n) or b"{}") if n else {}

            def _handle(self, method):
                body = self._body() if method == "POST" else {}
                fake.requests.append({"method": method, "path": self.path, "headers": dict(self.headers), "body": body})
                if fake.down:
                    fake.down -= 1
                    return self._send(503, {"errors": ["Vault is sealed"]})
                if self.path == "/v1/auth/approle/login":
                    if body.get("role_id") == ROLE and body.get("secret_id") == SECRET:
                        token = f"tok-{len(fake.tokens)}"
                        fake.tokens[token] = "approle"
                        return self._send(200, {"auth": {"client_token": token}})
                    return self._send(400, {"errors": ["invalid role or secret ID"]})
                token = self.headers.get("X-Vault-Token", "")
                if token not in fake.tokens or token in fake.revoked:
                    return self._send(403, {"errors": ["permission denied"]})
                if self.path.startswith("/v1/transit/"):
                    import base64

                    parts = self.path.split("/")                          # ['', 'v1', 'transit', op, key]
                    op, key = parts[3], parts[4] if len(parts) > 4 else ""
                    fake.transit_calls.append(op)
                    if key != fake.transit_key:
                        return self._send(404, {"errors": ["no such key"]})
                    if not fake.transit_allowed:
                        return self._send(403, {"errors": ["permission denied"]})

                    def wrap(raw_b64):
                        return f"vault:v{fake.transit_version}:" + base64.b64encode(base64.b64decode(raw_b64)[::-1]).decode()

                    def unwrap(ct):
                        return base64.b64encode(base64.b64decode(ct.split(":", 2)[2])[::-1]).decode()

                    if op == "encrypt":
                        return self._send(200, {"data": {"ciphertext": wrap(body["plaintext"])}})
                    if op == "decrypt":
                        return self._send(200, {"data": {"plaintext": unwrap(body["ciphertext"])}})
                    if op == "rewrap":
                        return self._send(200, {"data": {"ciphertext": wrap(unwrap(body["ciphertext"]))}})
                    if op == "keys":
                        return self._send(200, {"data": {"latest_version": fake.transit_version}})
                if method == "GET" and self.path == "/v1/transit/keys/" + fake.transit_key:
                    return self._send(200, {"data": {"latest_version": fake.transit_version}})
                if self.path == "/v1/auth/token/revoke-self":
                    fake.revoked.append(token)
                    return self._send(200, {})
                if method == "GET" and self.path.startswith("/v1/secret/data/"):
                    name = self.path[len("/v1/secret/data/"):]
                    if not name.startswith(fake.allowed):
                        return self._send(403, {"errors": ["permission denied"]})
                    if name not in fake.kv2:
                        return self._send(404, {"errors": []})
                    data = dict(fake.kv2[name])
                    if fake.big:
                        data["pad"] = "x" * (2 << 20)
                    return self._send(200, {"request_id": "req-" + name.replace("/", "-"), "data": {"data": data, "metadata": {"version": 3}}})
                if method == "GET" and self.path.startswith("/v1/kv1/"):
                    name = self.path[len("/v1/kv1/"):]
                    if name not in fake.kv1:
                        return self._send(404, {"errors": []})
                    return self._send(200, {"request_id": "req-v1", "data": fake.kv1[name]})
                return self._send(404, {"errors": ["unsupported path"]})

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
