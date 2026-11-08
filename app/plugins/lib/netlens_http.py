"""netlens_http: the one way a plugin talks to a device over HTTP or HTTPS (standard library only).

Netlens puts this module on the plugin's import path (`import netlens_http`), so every plugin gets the same rules and a fix here
reaches all of them:

* certificates are checked unless the plugin was told (`verify_tls=False`, the admin's choice) not to; the hostname is checked with them;
* every call has a timeout and a size limit (a device that answers with gigabytes cannot fill the memory of the plugin process);
* no proxy from the environment, only http and https, at most 3 redirects, never from https back to http, never to the cloud
  metadata service, and login details (Authorization, cookies, API keys) are not sent along to another host;
* errors say what went wrong (certificate / timeout / unreachable / too large) and carry no address, header or query string.

    resp = netlens_http.request("GET", url, headers={"Authorization": "Bearer " + token}, verify_tls=cfg.verify_tls, timeout=10)
    resp.status, resp.body, resp.json(), resp.text()

    session = netlens_http.Session(verify_tls=cfg.verify_tls, cookies=True)       # keeps the cookies of a login
    session.request("POST", url, form={"user": u, "password": p})

Only network trouble raises (`NetError` and its subclasses); an HTTP answer such as 401 or 500 is returned as `resp.status`.
"""

from __future__ import annotations

import base64
import http.client
import hashlib
import http.cookiejar
import ipaddress
import json as _json
import os
import socket
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request

MAX_BODY = 50_000_000          # bytes of an answer that are accepted
MAX_ERROR_BODY = 1_000_000     # an error page is cut off here instead of refused
MAX_REDIRECTS = 3
SECRET_HEADERS = frozenset({"authorization", "cookie", "x-api-key", "x-auth-token", "x-api-token", "csrftoken", "x-csrf-token", "private-token", "csrfpreventiontoken"})
METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata", "instance-data", "instance-data.ec2.internal", "metadata.azure.internal"})


class NetError(Exception):
    """Network trouble. `kind` is one of certificate, tls, timeout, unreachable, too_large, bad_url."""

    kind = "unreachable"

    def __init__(self, message: str, host: str = "", detail: str = ""):
        super().__init__(message)
        self.host = host
        self.detail = detail


class CertificateError(NetError):
    kind = "certificate"


class NetTimeout(NetError):
    kind = "timeout"


class Unreachable(NetError):
    kind = "unreachable"


class TooLarge(NetError):
    kind = "too_large"


class BadUrl(NetError):
    kind = "bad_url"


class ClientCertError(NetError):
    kind = "client_cert"


_URLLIB_REDIRECT = urllib.request.HTTPRedirectHandler.redirect_request      # urllib's own rule, kept before guard_urllib() replaces it


def ssl_context(verify_tls: bool = True, client_cert: tuple[str, str] | None = None) -> ssl.SSLContext:
    """The TLS settings every plugin uses. verify_tls=False accepts any certificate (the admin chose it, for a device with a self-signed one).
    client_cert=(certificate PEM text, key PEM text) presents a client certificate (mutual TLS); the text only touches the disk for a moment, in a private file."""
    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if client_cert:
        paths = []
        try:
            for text in client_cert:
                handle, path = tempfile.mkstemp(prefix="netlens-tls-")        # 0600
                paths.append(path)
                with os.fdopen(handle, "w") as f:
                    f.write(text)
            try:
                context.load_cert_chain(paths[0], paths[1])
            except (ssl.SSLError, OSError) as exc:
                raise ClientCertError(f"the client certificate and key do not fit together or are not valid ({exc.__class__.__name__})") from None
        finally:
            for path in paths:
                try:
                    os.unlink(path)
                except OSError:
                    pass
    return context


def normalize_fingerprint(text: str) -> str:
    """The SHA-256 fingerprint of a certificate as 64 lowercase hex digits (colons, spaces and capitals are fine). Raises ValueError when it is not one."""
    digits = "".join(c for c in str(text or "").lower() if c in "0123456789abcdef")
    if len(digits) != 64 or any(c not in "0123456789abcdef: \t-" for c in str(text).lower()):
        raise ValueError("the fingerprint must be 64 hexadecimal digits (SHA-256)")
    return digits


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Checks the certificate against the pinned fingerprint right after the handshake, before a single byte of the request is sent."""

    pin = ""

    def connect(self):
        super().connect()
        der = self.sock.getpeercert(binary_form=True)
        if not der or hashlib.sha256(der).hexdigest() != self.pin:
            self.sock.close()
            raise CertificateError("the certificate does not match the fingerprint; nothing was sent", self.host, "fingerprint")


def origin(scheme: str, host: str, port: int) -> str:
    """scheme://host:port, with brackets around an IPv6 address."""
    return f"{scheme}://{'[' + host + ']' if ':' in host else host}:{port}"


def basic_auth(user: str, password: str) -> str:
    """The value of an Authorization header for HTTP basic authentication."""
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def _translate(exc: BaseException, host: str) -> NetError:
    """Turn what the standard library raises into one of our errors (no URL, header or query string in the text)."""
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    if isinstance(reason, ssl.SSLCertVerificationError):
        return CertificateError("the TLS certificate could not be verified", host, str(getattr(reason, "verify_message", "") or ""))
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return NetTimeout("the connection timed out", host)
    if isinstance(reason, ssl.SSLError):
        return NetError(f"the TLS handshake failed ({getattr(reason, 'reason', None) or 'no common protocol or certificate problem'})", host)
    if isinstance(reason, http.client.HTTPException):
        return Unreachable(f"the answer is not valid HTTP ({reason.__class__.__name__})", host)
    return Unreachable(str(reason), host)


def redirect_request(handler, req, fp, code, msg, headers, newurl):
    """urllib's redirect rule with the limits above. A refused redirect hands the 3xx answer itself back (it becomes a response with that status)."""

    def refused(why):
        return urllib.error.HTTPError(req.full_url, code, f"redirect refused: {why}", headers, fp)

    target = urllib.parse.urlsplit(urllib.parse.urljoin(req.full_url, newurl))
    source = urllib.parse.urlsplit(req.full_url)
    if target.scheme.lower() not in ("http", "https"):
        raise refused("not a web address")
    if source.scheme.lower() == "https" and target.scheme.lower() == "http":
        raise refused("from https back to http")
    host = (target.hostname or "").lower()
    if host in METADATA_HOSTS:
        raise refused("the metadata service of a cloud provider")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and (ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved):
        raise refused("that address is not allowed")
    new = _URLLIB_REDIRECT(handler, req, fp, code, msg, headers, newurl)
    if new is not None and host != (source.hostname or "").lower():
        for store in (new.headers, new.unredirected_hdrs):
            for name in [k for k in store if k.lower() in SECRET_HEADERS]:
                del store[name]
    return new


class _Redirects(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return redirect_request(self, req, fp, code, msg, headers, newurl)


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """For a plugin that decides itself where to go next: the 3xx answer is returned as it is."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def guard_urllib() -> None:
    """For plugin code that still calls urllib itself: apply the redirect rules to urllib globally (the worker does this)."""
    def guarded(self, req, fp, code, msg, headers, newurl):
        return redirect_request(self, req, fp, code, msg, headers, newurl)

    if getattr(urllib.request.HTTPRedirectHandler.redirect_request, "_netlens_guard", False):
        return
    guarded._netlens_guard = True
    urllib.request.HTTPRedirectHandler.redirect_request = guarded


class Response:
    def __init__(self, status: int, body: bytes, headers):
        self.status = status
        self.body = body
        self.headers = headers

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name, default) if self.headers is not None else default

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self):
        """The body as JSON; raises ValueError when it is not."""
        return _json.loads(self.text())


def _read(source, limit: int, *, strict: bool) -> bytes:
    data = source.read(limit + 1)
    if len(data) > limit:
        if strict:
            raise TooLarge(f"the answer is larger than {limit // 1_000_000} MB")
        return data[:limit]
    return data


class Session:
    """A connection setup shared by several calls: the TLS rule, the timeout and, with cookies=True, the cookies of a login."""

    def __init__(self, *, verify_tls: bool = True, timeout: float = 10.0, cookies: bool = False, max_bytes: int = MAX_BODY, client_cert: tuple[str, str] | None = None, fingerprint: str = "", follow_redirects: bool = True):
        self.verify_tls = bool(verify_tls)
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.jar = http.cookiejar.CookieJar() if cookies else None
        self.fingerprint = normalize_fingerprint(fingerprint) if fingerprint else ""
        context = ssl_context(self.verify_tls and not self.fingerprint, client_cert)      # a pinned certificate replaces the chain check (a self-signed one has no chain)
        if self.fingerprint:
            connection = type("PinnedConnection", (_PinnedHTTPSConnection,), {"pin": self.fingerprint})
            https = type("PinnedHandler", (urllib.request.HTTPSHandler,), {"https_open": lambda this, req: this.do_open(connection, req, context=context)})()
        else:
            https = urllib.request.HTTPSHandler(context=context)
        handlers = [urllib.request.ProxyHandler({}), urllib.request.HTTPHandler(), https, _Redirects() if follow_redirects else _NoRedirects()]
        if self.jar is not None:
            handlers.append(urllib.request.HTTPCookieProcessor(self.jar))
        self._opener = urllib.request.build_opener(*handlers)

    def cookie(self, name: str) -> str | None:
        for c in self.jar or []:
            if c.name == name:
                return c.value
        return None

    def request(self, method: str, url: str, *, headers: dict | None = None, data: bytes | str | None = None, json=None, form: dict | None = None,
                timeout: float | None = None, max_bytes: int | None = None) -> Response:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            raise BadUrl("the address is not a web address (it must start with http:// or https://)")
        host = parts.hostname
        hdrs = dict(headers or {})
        if json is not None:
            data = _json.dumps(json).encode()
            hdrs.setdefault("Content-Type", "application/json")
        elif form is not None:
            data = urllib.parse.urlencode(form).encode()
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif isinstance(data, str):
            data = data.encode()
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method.upper())
        limit = max_bytes or self.max_bytes
        try:
            with self._opener.open(req, timeout=timeout or self.timeout) as resp:
                return Response(resp.status, _read(resp, limit, strict=True), resp.headers)
        except urllib.error.HTTPError as exc:
            try:
                body = _read(exc, MAX_ERROR_BODY, strict=False)
            except (OSError, http.client.HTTPException):
                body = b""
            return Response(exc.code, body, exc.headers)
        except NetError:
            raise
        except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            raise _translate(exc, host) from None


class Connection:
    """One kept-alive connection, for the rare protocol that ties a login to the TCP connection (NTLM/Negotiate of WinRM). Same rules as Session:
    TLS check or pinned fingerprint, timeout, size limit, no redirects (they are returned as the 3xx answer). `request` takes a path, not a URL."""

    def __init__(self, host: str, port: int, *, https: bool, verify_tls: bool = True, timeout: float = 10.0, max_bytes: int = MAX_BODY, fingerprint: str = ""):
        self.host, self.port, self.max_bytes = host, port, max_bytes
        pin = normalize_fingerprint(fingerprint) if fingerprint else ""
        if not https:
            self._conn = http.client.HTTPConnection(host, port, timeout=timeout)
        elif pin:
            self._conn = type("PinnedConnection", (_PinnedHTTPSConnection,), {"pin": pin})(host, port, timeout=timeout, context=ssl_context(False))
        else:
            self._conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl_context(verify_tls))

    def request(self, method: str, path: str, *, headers: dict | None = None, data: bytes | str | None = None, max_bytes: int | None = None) -> Response:
        if isinstance(data, str):
            data = data.encode()
        try:
            self._conn.request(method.upper(), path, body=data, headers=headers or {})
            resp = self._conn.getresponse()
            return Response(resp.status, _read(resp, max_bytes or self.max_bytes, strict=resp.status < 400), resp.msg)
        except NetError:
            self.close()
            raise
        except (OSError, http.client.HTTPException) as exc:
            self.close()
            raise _translate(exc, self.host) from None

    def close(self) -> None:
        try:
            self._conn.close()
        except OSError:
            pass


def request(method: str, url: str, *, verify_tls: bool = True, timeout: float = 10.0, max_bytes: int = MAX_BODY, fingerprint: str = "", **kwargs) -> Response:
    """One call without cookies. Takes headers=, data=, json=, form= (see Session.request); fingerprint= pins the certificate (SHA-256)."""
    return Session(verify_tls=verify_tls, timeout=timeout, max_bytes=max_bytes, fingerprint=fingerprint).request(method, url, **kwargs)


def connect(host: str, port: int, *, timeout: float = 10.0, tls: bool = False, verify_tls: bool = True, fingerprint: str = "") -> socket.socket:
    """A TCP connection, with TLS when asked, for a protocol that is not HTTP (Greenbone GMP, a WebSocket). Raises NetError."""
    pin = normalize_fingerprint(fingerprint) if fingerprint else ""
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        if not tls:
            return raw
        try:
            wrapped = ssl_context(verify_tls and not pin).wrap_socket(raw, server_hostname=host)
            if pin and hashlib.sha256(wrapped.getpeercert(binary_form=True) or b"").hexdigest() != pin:
                wrapped.close()
                raise CertificateError("the certificate does not match the fingerprint; nothing was sent", host, "fingerprint")
            return wrapped
        except BaseException:
            raw.close()
            raise
    except NetError:
        raise
    except (OSError, ssl.SSLError) as exc:
        raise _translate(exc, host) from None
