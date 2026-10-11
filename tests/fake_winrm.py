"""A small fake WinRM service (remote command shell over HTTPS) for the Hyper-V plugin tests.

It checks the login the way Windows does (NTLMv2 challenge and response on a kept-alive connection, or Basic), then understands
the shell messages Create, Command, Receive and Delete. `scripts` collects what the client asked PowerShell to run.
"""

import base64
import hashlib
import hmac
import json
import re
import ssl
import struct
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

CHALLENGE = bytes.fromhex("0123456789abcdef")
NS = ('xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
      'xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"')


def make_cert(folder):
    key, crt = folder / "k.pem", folder / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt), "-days", "2", "-subj", "/CN=localhost"],
                   check=True, capture_output=True)
    return str(crt), str(key)


def vm(id, name, state="Running", cpu=2, mem=2048, nics=(), up=3600, gen=2, auto="Nothing"):
    return {"Id": id, "Name": name, "State": state, "Cpu": cpu, "Mem": mem if state == "Running" else 0, "MemStartup": mem, "Gen": gen, "Up": up if state == "Running" else 0,
            "Auto": auto, "Nics": [{"Mac": m, "Ips": ips, "Switch": sw} for m, ips, sw in nics]}


def envelope(body):
    return f'<?xml version="1.0"?><s:Envelope {NS}><s:Body>{body}</s:Body></s:Envelope>'


def fault(code_text, text):
    return f'<?xml version="1.0"?><s:Envelope {NS}><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code><s:Reason><s:Text xml:lang="en-US">{text}</s:Text></s:Reason><s:Detail><f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="{code_text}"><f:Message>{text}</f:Message></f:WSManFault></s:Detail></s:Fault></s:Body></s:Envelope>'


class FakeWinRM:
    def __init__(self, folder, user="netlens", password="pw", auth="ntlm", output=None, stderr="", exit_code=0, slow_first_receive=False, domain=""):
        self.user, self.password, self.auth, self.domain = user, password, auth, domain
        self.output, self.stderr, self.exit_code, self.slow = output, stderr, exit_code, slow_first_receive
        self.scripts, self.actions, self.logins = [], [], 0
        self.shells_open = 0
        outer = self
        crt, key = make_cert(folder)

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            authed = False
            seen_slow = False

            def log_message(self, *a):
                pass

            def _reply(self, code, body=b"", headers=None):
                self.send_response(code)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _challenge(self):
                info = struct.pack("<HH", 7, 8) + b"\x00" * 8 + struct.pack("<HH", 0, 0)
                msg = b"NTLMSSP\x00" + struct.pack("<I", 2) + struct.pack("<HHI", 0, 0, 56) + struct.pack("<I", 0xE2898215) + CHALLENGE + b"\x00" * 8
                msg += struct.pack("<HHI", len(info), len(info), 56) + b"\x00" * 8 + info
                return msg

            def _check_type3(self, msg):
                def field(i):
                    length, _, offset = struct.unpack_from("<HHI", msg, 12 + 8 * i)
                    return msg[offset:offset + length]
                nt, domain, user = field(1), field(2).decode("utf-16-le"), field(3).decode("utf-16-le")
                from importlib import import_module
                plugin = import_module("tests.test_plugin_hyperv").plugin
                key_ = plugin.nt_hash_v2(user, outer.password, domain)
                return user == outer.user and domain == outer.domain and hmac.new(key_, CHALLENGE + nt[16:], hashlib.md5).digest() == nt[:16]

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length)
                header = self.headers.get("Authorization") or ""
                if outer.auth == "basic":
                    expect = base64.b64encode(f"{outer.user}:{outer.password}".encode()).decode()
                    if header != "Basic " + expect:
                        return self._reply(401, headers={"WWW-Authenticate": "Basic realm=WSMAN"})
                elif not self.authed:
                    match = re.match(r"(?:Negotiate|NTLM) (\S+)", header)
                    if not match:
                        return self._reply(401, headers={"WWW-Authenticate": "Negotiate"})
                    token = base64.b64decode(match.group(1))
                    if struct.unpack_from("<I", token, 8)[0] == 1:
                        return self._reply(401, headers={"WWW-Authenticate": "Negotiate " + base64.b64encode(self._challenge()).decode()})
                    if not self._check_type3(token):
                        return self._reply(401)
                    self.authed = True
                    outer.logins += 1
                self.handle_soap(body.decode("utf-8"))

            def handle_soap(self, text):
                action = re.search(r"<a:Action[^>]*>([^<]+)</a:Action>", text).group(1).rsplit("/", 1)[-1]
                outer.actions.append(action)
                xml = {"Content-Type": "application/soap+xml;charset=UTF-8"}
                if action == "Create":
                    outer.shells_open += 1
                    return self._reply(200, envelope("<rsp:Shell><rsp:ShellId>SHELL1</rsp:ShellId></rsp:Shell>").encode(), xml)
                if action == "Command":
                    command = re.search(r"-EncodedCommand ([A-Za-z0-9+/=]+)", text).group(1)
                    outer.scripts.append(base64.b64decode(command).decode("utf-16-le"))
                    return self._reply(200, envelope("<rsp:CommandResponse><rsp:CommandId>CMD1</rsp:CommandId></rsp:CommandResponse>").encode(), xml)
                if action == "Receive":
                    if outer.slow and not self.seen_slow:
                        self.seen_slow = True
                        return self._reply(500, fault("2150858793", "The WS-Management service cannot complete the operation within the time specified in OperationTimeout.").encode(), xml)
                    out = outer.output if isinstance(outer.output, str) else json.dumps(outer.output)
                    streams = ""
                    if out:
                        streams += f'<rsp:Stream Name="stdout" CommandId="CMD1">{base64.b64encode(out.encode()).decode()}</rsp:Stream>'
                    if outer.stderr:
                        streams += f'<rsp:Stream Name="stderr" CommandId="CMD1">{base64.b64encode(outer.stderr.encode()).decode()}</rsp:Stream>'
                    state = f'<rsp:CommandState CommandId="CMD1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>{outer.exit_code}</rsp:ExitCode></rsp:CommandState>'
                    return self._reply(200, envelope(f"<rsp:ReceiveResponse>{streams}{state}</rsp:ReceiveResponse>").encode(), xml)
                if action == "Delete":
                    outer.shells_open -= 1
                    return self._reply(200, envelope("").encode(), xml)
                self._reply(500, fault("1", "unknown action").encode(), xml)

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(crt, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_port
        self.url = f"https://127.0.0.1:{self.port}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
