"""A tiny stand-in for the PowerDNS Authoritative API (4.9.17, behaviour recorded 2026-10-16): X-API-Key, zones with record sets and comments, PATCH REPLACE / DELETE (204)."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def rrset(name, rtype, contents, ttl=3600, comment=None):
    return {"name": name, "type": rtype, "ttl": ttl, "records": [{"content": c, "disabled": False} for c in contents],
            "comments": [{"content": comment, "account": "netlens", "modified_at": 1}] if comment else []}


class FakePowerdns:
    def __init__(self, key="k", zones=None, daemon="authoritative"):
        self.key, self.zones, self.daemon = key, zones or {}, daemon      # zones: {"home.lan.": {"kind": "Native", "rrsets": [...]}}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, code, body=None):
                raw = json.dumps(body).encode() if body is not None else b""
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def handle_any(self, method):
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else {}
                if self.headers.get("X-API-Key") != outer.key:
                    return self.reply(401, {"error": "Unauthorized"})
                path = self.path.split("?")[0]
                base = "/api/v1/servers/localhost"
                if path == base:
                    return self.reply(200, {"id": "localhost", "version": "4.9.17", "daemon_type": outer.daemon})
                if path == base + "/zones":
                    return self.reply(200, [{"id": n, "name": n, "kind": z["kind"], "rrsets": None} for n, z in outer.zones.items()])
                if path.startswith(base + "/zones/") and path[len(base) + 7:] in outer.zones:
                    zone = outer.zones[path[len(base) + 7:]]
                    if method == "GET":
                        return self.reply(200, {"name": path[len(base) + 7:], "rrsets": zone["rrsets"]})
                    if method == "PATCH":
                        for change in body["rrsets"]:
                            zone["rrsets"] = [r for r in zone["rrsets"] if not (r["name"] == change["name"] and r["type"] == change["type"])]
                            if change["changetype"] == "REPLACE":
                                zone["rrsets"].append({**change, "comments": change.get("comments", [])})
                        return self.reply(204)
                self.reply(404, {"error": "Not found"})

            do_GET = lambda self: self.handle_any("GET")
            do_PATCH = lambda self: self.handle_any("PATCH")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
