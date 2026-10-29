"""The one place where the PAM providers talk to the network: address guard, TLS that is always verified (with the customer's own CA if given), a size cap, a timeout."""

from __future__ import annotations

import json
import os
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from app import safenet
from app.pam import PamError

TIMEOUT_S = 10.0
MAX_BYTES = 1 << 20


def base_url(value: Any, what: str = "the address of the PAM system") -> str:
    text = str(value or "").strip().rstrip("/")
    if not text.startswith(("http://", "https://")):
        raise PamError(f"{what} is missing: it starts with https://")
    try:
        safenet.check_url(text, what=what)
    except safenet.BlockedAddress as exc:
        raise PamError(str(exc)) from None
    return text


def context(url: str, ca_cert: str = "", client_cert: str = "", client_key: str = "") -> ssl.SSLContext | None:
    """Certificates are always verified; a PAM with a private CA brings that CA here. There is deliberately no switch to skip verification. A client certificate
    (mutual TLS, how CyberArk's Central Credential Provider identifies an application) is loaded from a private temporary file that is removed at once."""
    if not url.startswith("https://"):
        if client_cert:
            raise PamError("a client certificate is only sent over https")
        return None
    try:
        ctx = ssl.create_default_context(cadata=ca_cert.strip()) if ca_cert and ca_cert.strip() else ssl.create_default_context()
    except (ssl.SSLError, ValueError):
        raise PamError("the CA certificate for the PAM system is not valid (it must be PEM text)") from None
    if client_cert.strip():
        directory = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else None      # memory, not disk, where there is one
        fd, name = tempfile.mkstemp(prefix="nl-cc-", dir=directory)                                            # mkstemp creates it 0600
        try:
            with os.fdopen(fd, "w") as handle:
                handle.write(client_cert.strip() + "\n" + client_key.strip() + "\n")
            ctx.load_cert_chain(name)
        except (ssl.SSLError, ValueError, OSError):
            raise PamError("the client certificate and key for the PAM system are not valid (PEM text, and the key must belong to the certificate)") from None
        finally:
            try:
                os.unlink(name)
            except OSError:
                pass
    return ctx


def _tls_message(exc: ssl.SSLError) -> str:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return f"the certificate of the PAM system is not trusted ({exc.verify_message}): add its CA certificate to the login"
    text = str(exc)
    if "ALERT" in text.upper() or "CERTIFICATE_REQUIRED" in text.upper():
        return "the PAM system did not accept the connection: it wants a client certificate it trusts (check the certificate and key of the login)"
    return f"the TLS connection to the PAM system failed ({exc.reason or 'TLS error'})"


def call(method: str, url: str, *, headers: dict[str, str] | None = None, body: dict | None = None, ca_cert: str = "", client_cert: str = "", client_key: str = "", timeout: float = TIMEOUT_S) -> tuple[int, Any]:
    """(status, parsed JSON or None). Network problems become a PamError with a sentence; an HTTP error status is returned for the provider to explain."""
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers={"Accept": "application/json", **({"Content-Type": "application/json"} if data else {}), **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context(url, ca_cert, client_cert, client_key)) as response:     # noqa: S310 - scheme and address were checked by base_url
            raw = response.read(MAX_BYTES + 1)
            status = response.status
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read(MAX_BYTES + 1)
    except ssl.SSLError as exc:
        raise PamError(_tls_message(exc)) from None
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLError):
            raise PamError(_tls_message(exc.reason)) from None
        raise PamError(f"cannot reach the PAM system: {exc.reason}") from None
    except (OSError, ValueError) as exc:
        raise PamError(f"cannot reach the PAM system: {exc}") from None
    if len(raw) > MAX_BYTES:
        raise PamError("the PAM system sent a larger answer than expected")
    try:
        return status, (json.loads(raw.decode() or "null") if raw else None)
    except ValueError:
        return status, None


def form_call(method: str, url: str, *, fields: dict[str, str], headers: dict[str, str] | None = None, ca_cert: str = "", timeout: float = TIMEOUT_S) -> tuple[int, Any]:
    """Like call, with an application/x-www-form-urlencoded body (OAuth2 token requests)."""
    data = urllib.parse.urlencode(fields).encode()
    request = urllib.request.Request(url, data=data, method=method, headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context(url, ca_cert)) as response:     # noqa: S310 - scheme and address were checked by base_url
            raw, status = response.read(MAX_BYTES + 1), response.status
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read(MAX_BYTES + 1)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise PamError(f"cannot reach the PAM system: {getattr(exc, 'reason', exc)}") from None
    try:
        return status, (json.loads(raw.decode() or "null") if raw else None)
    except ValueError:
        return status, None


def quote_path(path: str) -> str:
    return "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))
