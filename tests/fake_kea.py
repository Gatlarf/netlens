"""A Kea Control Agent that replays answers recorded from Kea 2.6.3 (Debian 13): basic authentication, one POST endpoint, answers by command."""

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeKea:
    def __init__(self, leases, reservations=(), user="netlens", password="labpass", unsupported=()):
        self.leases, self.reservations, self.unsupported = leases, list(reservations), set(unsupported)
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self.seen = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                name = body.get("command")
                outer.seen.append(name)
                if self.headers.get("Authorization") != outer.auth:
                    return self._send(401, {"result": 401, "text": "Unauthorized"})
                self._send(200, outer.answer(name))

            def _send(self, code, data):
                raw = json.dumps(data).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def answer(self, name):
        if name in self.unsupported:
            return [{"result": 2, "text": f"'{name}' command not supported."}]
        if name == "version-get":
            return [{"arguments": {"extended": "2.6.3 (tarball)\npremium: no\nlinked with:\n- log4cplus 2.0.8"}, "result": 0, "text": "2.6.3"}]
        if name == "lease4-get-all":
            if not self.leases:
                return [{"arguments": {"leases": []}, "result": 3, "text": "0 IPv4 lease(s) found."}]
            return [{"arguments": {"leases": self.leases}, "result": 0, "text": f"{len(self.leases)} IPv4 lease(s) found."}]
        if name == "config-get":
            return [{"arguments": {"Dhcp4": {"subnet4": [{"id": 1, "subnet": "192.168.77.0/24", "reservations": self.reservations}]}}, "result": 0}]
        return [{"result": 2, "text": f"'{name}' command not supported."}]

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
