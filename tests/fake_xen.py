"""A simulated Xen Orchestra (REST) and XAPI pool master (JSON-RPC) that replay answers recorded from a real XCP-ng 8.3 and Xen Orchestra 6
(tests/fixtures/xen, recorded 2026-10-28 on the playground)."""

import base64
import copy
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "xen"


def load(kind, name):
    return json.loads((FIXTURES / kind / f"{name}.json").read_text())


class FakeXen:
    """xo=True answers /rest/v0 (login admin@admin.net / admin, or the token 'tok'); xapi=True answers /jsonrpc (login root / secret)."""

    def __init__(self, xo=True, xapi=False):
        self.xo_on, self.xapi_on = xo, xapi
        self.xo = {n: load("xo", n) for n in ("hosts", "pools", "srs", "vms", "vifs", "vbds", "vdis", "pifs", "backup-repositories", "backup-jobs",
                                               "schedules", "backup-logs")}
        self.dashboards = {"b35fce12-befd-a53c-1fd1-55c62eb4abb2": load("xo", "vm-dashboard")}
        self.xapi = {n: load("xapi", n)["result"] for n in ("VM", "host", "pool", "SR", "PIF", "VIF", "VM_guest_metrics", "VM_metrics", "host_metrics", "VDI", "VBD")}
        self.seen, self.actions, self.sessions_open = [], [], 0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, code, body):
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def authorised(self):
                auth, cookie = self.headers.get("Authorization", ""), self.headers.get("Cookie", "")
                return auth == "Basic " + base64.b64encode(b"admin@admin.net:admin").decode() or cookie == "authenticationToken=tok"

            def do_GET(self):
                path, _, _q = self.path.partition("?")
                outer.seen.append(path)
                if not (outer.xo_on and path.startswith("/rest/v0/")):
                    return self.reply(404, {})
                name = path[len("/rest/v0/"):]
                if name == "ping":
                    return self.reply(200, {"result": "pong", "timestamp": 1})
                if not self.authorised():
                    return self.reply(401, {"error": "unauthorized"})
                parts = name.split("/")
                if len(parts) == 3 and parts[0] == "vms" and parts[2] == "dashboard":
                    return self.reply(200, {"backupsInfo": (outer.dashboards.get(parts[1]) or {"backupsInfo": {"lastRuns": [], "backupArchives": []}})["backupsInfo"]})
                if len(parts) == 2 and parts[0] == "vms":
                    vm = next((v for v in outer.xo["vms"] if v["id"] == parts[1]), None)
                    return self.reply(200, vm) if vm else self.reply(404, {})
                return self.reply(200, outer.xo[name]) if name in outer.xo else self.reply(404, {})

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                path = self.path.split("?")[0]
                outer.seen.append(path)
                if path == "/jsonrpc" and outer.xapi_on:
                    return self.reply(200, outer.rpc(json.loads(body)))
                if outer.xo_on and path.startswith("/rest/v0/vms/") and "/actions/" in path:
                    if not self.authorised():
                        return self.reply(401, {})
                    outer.actions.append(path.rsplit("/", 3)[-3:])
                    return self.reply(202, {"taskId": "t"})
                self.reply(404, {})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def rpc(self, call):
        method, params, ident = call["method"], call.get("params", []), call.get("id")

        def ok(result):
            return {"jsonrpc": "2.0", "result": result, "id": ident}

        def err(message):
            return {"jsonrpc": "2.0", "error": {"code": 1, "message": message, "data": []}, "id": ident}

        if method == "session.login_with_password":
            if params[:2] != ["root", "secret"]:
                return err("SESSION_AUTHENTICATION_FAILED")
            self.sessions_open += 1
            return ok("OpaqueRef:session")
        if method == "session.logout":
            self.sessions_open -= 1
            return ok("")
        if not params or params[0] != "OpaqueRef:session":
            return err("SESSION_INVALID")
        cls, _, name = method.partition(".")
        if name == "get_all_records":
            return ok(self.xapi[cls])
        vms = self.xapi["VM"]
        if method == "VM.get_by_uuid":
            ref = next((r for r, v in vms.items() if v["uuid"] == params[1]), None)
            return ok(ref) if ref else err("UUID_INVALID")
        if method == "VM.get_power_state":
            return ok(vms[params[1]]["power_state"])
        if method == "VM.get_name_label":
            return ok(vms[params[1]]["name_label"])
        if method in ("VM.start", "VM.clean_reboot", "VM.hard_reboot", "VM.clean_shutdown"):
            if method == "VM.clean_reboot" and getattr(self, "no_tools", False):
                return err("VM_LACKS_FEATURE")
            self.actions.append([method, vms[params[1]]["uuid"]])
            return ok("")
        return err("MESSAGE_METHOD_UNKNOWN")

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def copy_of(self, kind, name):
        return copy.deepcopy(getattr(self, kind)[name])
