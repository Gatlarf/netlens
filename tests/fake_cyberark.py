"""A stand-in for the CyberArk Central Credential Provider web service, following CyberArk's documentation: HTTPS with a required client certificate,
GET /AIMWebService/api/Accounts?AppID=..&Safe=..&Object=.., JSON answers with Content/UserName/Name, ErrorCode/ErrorMsg for errors.
It proves how Netlens reads the documentation, not how the product behaves (no CyberArk instance was available)."""

import datetime
import json
import ssl
import tempfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _pem_key(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()


def _cert(subject, key, issuer_name, issuer_key, ca=False, san=None, client=False):
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])).issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
         .public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=2))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(san), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]), critical=False)
    return b.sign(issuer_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


class Pki:
    """A CA, a server certificate for 127.0.0.1 and a client certificate; plus a second, unrelated CA to test distrust."""

    def __init__(self):
        self.ca_key = _key()
        self.ca = _cert("Test CA", self.ca_key, "Test CA", self.ca_key, ca=True)
        self.server_key = _key()
        self.server = _cert("cyberark.test", self.server_key, "Test CA", self.ca_key, san="localhost")
        self.client_key = _key()
        self.client = _cert("netlens-app", self.client_key, "Test CA", self.ca_key)
        self.client_key_pem = _pem_key(self.client_key)
        self.other_key = _key()
        self.other_ca = _cert("Other CA", self.other_key, "Other CA", self.other_key, ca=True)
        self.rogue_client = _cert("rogue", self.client_key, "Other CA", self.other_key)


class Fake:
    def __init__(self, pki: Pki, require_client=True):
        self.pki = pki
        self.require_client = require_client
        self.requests: list[dict] = []
        self.accounts = {("Linux", "svc-web01"): {"Content": "pw-ccp-1", "UserName": "svc", "Address": "web01", "Name": "svc-web01", "Safe": "Linux", "Folder": "Root",
                                                  "PasswordChangeInProcess": "False"},
                         ("Linux", "svc-key"): {"Content": "KEYDATA", "UserName": "root", "Name": "svc-key", "Safe": "Linux", "PasswordChangeInProcess": "False"},
                         ("Linux", "changing"): {"Content": "x", "UserName": "u", "Name": "changing", "Safe": "Linux", "PasswordChangeInProcess": "True"}}
        self.allowed_app = "Netlens"
        self.status_override = 0

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

            def do_GET(self):
                url = urllib.parse.urlparse(self.path)
                q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query, keep_blank_values=True).items()}
                fake.requests.append({"path": url.path, "query": q, "peer": self.connection.getpeercert()})
                if fake.status_override:
                    return self._send(fake.status_override, {"ErrorCode": "CAWS00E", "ErrorMsg": "Server problem"})
                if url.path != "/AIMWebService/api/Accounts":
                    return self._send(404, {"ErrorCode": "X", "ErrorMsg": "no such service"})
                if q.get("AppID") != fake.allowed_app:
                    return self._send(403, {"ErrorCode": "APPAP004E", "ErrorMsg": "Failed to authenticate application (AppID not defined)"})
                acct = fake.accounts.get((q.get("Safe"), q.get("Object")))
                if acct is None:
                    return self._send(404, {"ErrorCode": "APPAP008E", "ErrorMsg": "Account not found"})
                return self._send(200, acct)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        with tempfile.NamedTemporaryFile("w", suffix=".pem") as cert, tempfile.NamedTemporaryFile("w", suffix=".pem") as ca:
            cert.write(self.pki.server + _pem_key(self.pki.server_key))
            cert.flush()
            ctx.load_cert_chain(cert.name)
            ca.write(self.pki.ca)
            ca.flush()
            ctx.load_verify_locations(ca.name)
        ctx.verify_mode = ssl.CERT_REQUIRED if self.require_client else ssl.CERT_NONE
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    @property
    def url(self):
        return f"https://127.0.0.1:{self.server.server_address[1]}"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
