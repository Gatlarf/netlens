"""The one place where the PAM providers talk to the network: address guard, TLS that is always verified (with the customer's own CA if given), a size cap, a timeout."""

from __future__ import annotations

import json
import ssl
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


def context(url: str, ca_cert: str = "") -> ssl.SSLContext | None:
    """Certificates are always verified; a PAM with a private CA brings that CA here. There is deliberately no switch to skip verification."""
    if not url.startswith("https://"):
        return None
    try:
        return ssl.create_default_context(cadata=ca_cert.strip()) if ca_cert and ca_cert.strip() else ssl.create_default_context()
    except (ssl.SSLError, ValueError):
        raise PamError("the CA certificate for the PAM system is not valid (it must be PEM text)") from None


def call(method: str, url: str, *, headers: dict[str, str] | None = None, body: dict | None = None, ca_cert: str = "", timeout: float = TIMEOUT_S) -> tuple[int, Any]:
    """(status, parsed JSON or None). Network problems become a PamError with a sentence; an HTTP error status is returned for the provider to explain."""
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers={"Accept": "application/json", **({"Content-Type": "application/json"} if data else {}), **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context(url, ca_cert)) as response:     # noqa: S310 - scheme and address were checked by base_url
            raw = response.read(MAX_BYTES + 1)
            status = response.status
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read(MAX_BYTES + 1)
    except ssl.SSLError as exc:
        raise PamError(f"the certificate of the PAM system is not trusted ({exc.reason or 'TLS error'}): add its CA certificate to the login") from None
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, ssl.SSLCertVerificationError):
            raise PamError(f"the certificate of the PAM system is not trusted ({reason.verify_message}): add its CA certificate to the login") from None
        raise PamError(f"cannot reach the PAM system: {reason}") from None
    except (OSError, ValueError) as exc:
        raise PamError(f"cannot reach the PAM system: {exc}") from None
    if len(raw) > MAX_BYTES:
        raise PamError("the PAM system sent a larger answer than expected")
    try:
        return status, (json.loads(raw.decode() or "null") if raw else None)
    except ValueError:
        return status, None


def quote_path(path: str) -> str:
    return "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))
