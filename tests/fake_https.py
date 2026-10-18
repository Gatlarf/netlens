"""A small HTTPS server for plugin tests: routes map a path (without the query) to a JSON answer, a callable (query dict -> answer) or an int status; one header must match."""

import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from tests.fake_pbs import make_certificate


class FakeHttps:
    def __init__(self, folder: Path, routes, header=("X-ApiKeys", "accessKey=AK; secretKey=SK")):
        self.routes, self.header, self.seen = routes, header, []
        outer = self
        cert, key, self.fingerprint = make_certificate(folder)

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                parts = urlsplit(self.path)
                outer.seen.append(parts.path)
                if self.headers.get(outer.header[0]) != outer.header[1]:
                    return self._send(401, {"error": "unauthorized"})
                answer = outer.routes.get(parts.path, 404)
                if callable(answer):
                    answer = answer({k: v[0] for k, v in parse_qs(parts.query).items()})
                if isinstance(answer, int):
                    return self._send(answer, {"error": "no"})
                self._send(200, answer)

            def _send(self, code, data):
                raw = json.dumps(data).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.url = f"https://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
