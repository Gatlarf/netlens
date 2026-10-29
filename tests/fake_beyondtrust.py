"""A stand-in for BeyondTrust Password Safe's API v3 as documented (PS-Auth sign-in with a session cookie, ManagedAccounts, Requests, Credentials, Checkin, Signout). Not the product."""

import json
import re
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Fake:
    def __init__(self):
        self.requests: list[dict] = []
        self.signed_in: set[str] = set()
        self.check_ins: list[str] = []
        self.signouts = 0
        self.needs_approval = False
        self.key, self.runas = "KEY-1", "svc-netlens"
        self.accounts = {("web01", "svc"): {"SystemId": 11, "AccountId": 22, "AccountName": "svc", "DomainName": None, "SystemName": "web01"}}
        self.pw = "pw-bt-1"

    def start(self):
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body, cookie=None):
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                if cookie:
                    self.send_header("Set-Cookie", cookie)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _handle(self, method):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n).decode() if n else ""
                url = urllib.parse.urlparse(self.path)
                cookie = (self.headers.get("Cookie") or "")
                fake.requests.append({"method": method, "path": url.path, "query": urllib.parse.parse_qs(url.query), "headers": dict(self.headers), "body": json.loads(raw) if raw.strip() else None})
                base = "/BeyondTrust/api/public/v3"
                if not url.path.startswith(base):
                    return self._send(404, {})
                route = url.path[len(base):]
                if route == "/Auth/SignAppIn":
                    auth = self.headers.get("Authorization", "")
                    if re.search(rf"key={re.escape(fake.key)};", auth) and f"runas={fake.runas};" in auth:
                        sid = f"sess-{len(fake.signed_in) + 1}"
                        fake.signed_in.add(sid)
                        return self._send(200, {"UserId": 1, "UserName": fake.runas}, cookie=f"ASP.NET_SessionId={sid}; Path=/; HttpOnly")
                    return self._send(401, {"Message": "bad key"})
                sid = cookie.split("ASP.NET_SessionId=")[-1].split(";")[0]
                if sid not in fake.signed_in:
                    return self._send(401, {"Message": "not signed in"})
                if route == "/Auth/Signout":
                    fake.signed_in.discard(sid)
                    fake.signouts += 1
                    return self._send(200, {})
                if route == "/ManagedAccounts" and method == "GET":
                    q = urllib.parse.parse_qs(url.query)
                    acct = fake.accounts.get((q.get("systemName", [""])[0], q.get("accountName", [""])[0]))
                    return self._send(200, acct) if acct else self._send(404, {"Message": "not found"})
                if route == "/Requests" and method == "POST":
                    body = json.loads(raw)
                    if body.get("AccessType") != "View" or not body.get("Reason"):
                        return self._send(400, {"Message": "bad request"})
                    return self._send(200, "4711")
                m = re.fullmatch(r"/Credentials/(\w+)", route)
                if m and method == "GET":
                    if fake.needs_approval:
                        return self._send(403, {"Message": "Request is pending approval"})
                    return self._send(200, fake.pw)
                m = re.fullmatch(r"/Requests/(\w+)/Checkin", route)
                if m and method == "PUT":
                    fake.check_ins.append(m.group(1))
                    return self._send(200, {})
                return self._send(404, {"Message": "no such route"})

            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                self._handle("POST")

            def do_PUT(self):
                self._handle("PUT")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
