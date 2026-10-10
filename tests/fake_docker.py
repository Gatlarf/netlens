"""A small fake Docker Engine API (read-only subset) for the Docker plugin tests."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

NETWORKS = [
    {"Id": "n-bridge", "Name": "bridge", "Driver": "bridge"},
    {"Id": "n-host", "Name": "host", "Driver": "host"},
    {"Id": "n-lan", "Name": "lan", "Driver": "macvlan"},
    {"Id": "n-ipv", "Name": "ipv", "Driver": "ipvlan"},
]


def container(cid, name, state="running", image="img:1", networks=None, ports=None, labels=None, mode="default"):
    return {"Id": cid, "Names": [f"/{name}"], "Image": image, "State": state, "Status": state,
            "Ports": ports or [], "Labels": labels or {}, "HostConfig": {"NetworkMode": mode},
            "NetworkSettings": {"Networks": networks or {}}}


class FakeDocker:
    """`with FakeDocker(containers=[...], inspect={id: {...}}) as d:` then use `d.url`. `forbid` lists paths answered with 403."""

    def __init__(self, containers=None, inspect=None, name="dockerhost", forbid=()):
        self.containers, self.inspect_data, self.name, self.forbid = containers or [], inspect or {}, name, set(forbid)
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                path = urlsplit(self.path).path
                outer.requests.append(("GET", path))
                if any(path.startswith(f) for f in outer.forbid):
                    return self._send(403, {"message": "forbidden"})
                if path == "/info":
                    return self._send(200, {"Name": outer.name, "ServerVersion": "29.8.2", "Containers": len(outer.containers), "ContainersRunning": 1})
                if path == "/networks":
                    return self._send(200, NETWORKS)
                if path == "/containers/json":
                    return self._send(200, outer.containers)
                if path.startswith("/containers/") and path.endswith("/json"):
                    cid = path.split("/")[2]
                    if cid in outer.inspect_data:
                        return self._send(200, outer.inspect_data[cid])
                    return self._send(404, {"message": "no such container"})
                self._send(404, {"message": "not found"})

            def do_POST(self):
                outer.requests.append(("POST", self.path))
                self._send(405, {"message": "read-only"})

            def _send(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
