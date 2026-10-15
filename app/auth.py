import hmac
import ipaddress
import hashlib
import re
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional

from fastapi import HTTPException
from starlette.requests import HTTPConnection

from app import users
from app.db import connect


COOKIE_NAME = "netlens_session"


def session_value(token: str) -> str:
    return hmac.new(token.encode(), b"netlens-session-v1", hashlib.sha256).hexdigest()


def is_authorized(token: str, cookie: Optional[str], authorization: Optional[str]) -> bool:
    if not token:  # no access token configured: nothing can match it (an empty cookie or bearer must not)
        return False
    if cookie is not None:
        try:
            if hmac.compare_digest(cookie.encode(), session_value(token).encode()):
                return True
        except Exception:
            pass

    if authorization is not None:
        try:
            if authorization.startswith("Bearer "):
                rest = authorization[7:]
                if hmac.compare_digest(rest.encode(), token.encode()):
                    return True
        except Exception:
            pass

    return False


def client_ip(conn: HTTPConnection) -> str:
    """The address of whoever is really asking. Behind a reverse proxy every request arrives from the proxy's own address, so
    when that address is in NETLENS_TRUSTED_PROXIES the real client is the last X-Forwarded-For entry that is not a trusted proxy
    (entries further left can be made up by the client). Without that setting only the connection's address is used."""
    peer = conn.client.host if conn.client else "unknown"
    nets = []
    for item in getattr(conn.app.state.settings, "trusted_proxies", ()) or ():
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue

    def trusted(text: str) -> bool:
        try:
            ip = ipaddress.ip_address(text.strip())
        except ValueError:
            return False
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return any(ip.version == n.version and ip in n for n in nets)

    if not nets or not trusted(peer):
        return peer
    for entry in reversed([e.strip() for e in conn.headers.get("x-forwarded-for", "").split(",") if e.strip()]):
        if not trusted(entry):
            try:
                return str(ipaddress.ip_address(entry))
            except ValueError:
                return peer       # not an address: do not let a made-up value become a key
    return peer


class LoginLimiter:
    def __init__(self, max_failures: int = 5, window: float = 60.0, clock=time.monotonic):
        self.max_failures = max_failures
        self.window = window
        self.clock = clock
        self._failures: dict[str, list[float]] = defaultdict(list)

    MAX_KEYS = 5000     # an attacker who invents user names must not grow this without limit

    def _prune(self, cutoff: float) -> None:
        if len(self._failures) > self.MAX_KEYS:
            for k in [k for k, v in self._failures.items() if not v or v[-1] <= cutoff]:
                del self._failures[k]

    def allowed(self, key: str) -> bool:
        now = self.clock()
        cutoff = now - self.window
        failures = self._failures[key]
        # Remove expired entries
        self._failures[key] = [t for t in failures if t > cutoff]
        return len(self._failures[key]) < self.max_failures

    def record_failure(self, key: str) -> None:
        now = self.clock()
        cutoff = now - self.window
        failures = self._failures[key]
        # Remove expired entries
        self._failures[key] = [t for t in failures if t > cutoff]
        self._prune(cutoff)
        # Bound memory by max_failures entries
        if len(self._failures[key]) >= self.max_failures:
            self._failures[key] = self._failures[key][-self.max_failures:]
        self._failures[key].append(now)

    def reached(self, key: str) -> bool:
        """True right after the failure that used up the budget (the moment to raise an alarm, once per window)."""
        return len(self._failures.get(key, ())) == self.max_failures

    def reset(self, key: str) -> None:
        self._failures[key] = []


@dataclass(frozen=True)
class Principal:
    username: str
    role: str  # "admin" | "viewer"
    user_id: Optional[int] = None  # None = the built-in NETLENS_TOKEN login
    builtin: bool = False

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


BUILTIN = Principal(username="access token", role="admin", builtin=True)

# What a viewer may read. Everything else, and every request that changes something, needs an administrator.
VIEWER_READABLE = re.compile(
    r"^/(metrics"
    r"|api/(session|update|changelog|map|map-settings|hierarchy|relations|events|uptime|uptime/core|scans|scans/current|service-checks|service-checks/\d+/results|monitors|monitoring/limits|forecast|snoozes|changes|reports/availability|reports/availability\.csv|reports/weekly|probes|probes/\d+|timeseries/(device|service|probe)/\d+|timeseries/(device|service|probe)/\d+/[A-Za-z0-9_.-]+"
    r"|stats|stats/summary|dashboard|dashboard/layout|dashboard/default|dashboard/shared|speedtest|speedtest/(status|ping|down)|groups|devices|devices/\d+|devices/\d+/(wifi|uptime)))$"
)
VIEWER_MAY_POST = ("/api/logout", "/api/me/password", "/api/speedtest/up", "/api/speedtest/browser")  # a viewer may test the line from their own device


def identify(conn: HTTPConnection) -> Optional[Principal]:
    """Who is making this request (cookie or bearer token), or None."""
    token = conn.app.state.settings.token
    cookie = conn.cookies.get(COOKIE_NAME)
    authorization = conn.headers.get("authorization")
    if is_authorized(token, cookie, authorization):
        return BUILTIN
    bearer = authorization[7:] if authorization and authorization.startswith("Bearer ") else None
    if (cookie and cookie.startswith(users.SESSION_PREFIX)) or (bearer and bearer.startswith(users.TOKEN_PREFIX)):
        db = connect(conn.app.state.db_path)
        try:
            row = users.user_for_session(db, cookie) if cookie and cookie.startswith(users.SESSION_PREFIX) else None
            row = row or (users.user_for_token(db, bearer) if bearer else None)
        finally:
            db.close()
        if row:
            return Principal(username=row["username"], role=row["role"], user_id=row["id"])
    return None


def require_auth(request: HTTPConnection) -> None:
    principal = identify(request)
    if principal is None:
        raise HTTPException(status_code=401, detail="authentication required")
    request.state.user = principal
    if principal.role != "admin":
        method = request.scope.get("method", "GET")
        path = request.url.path
        allowed = ((method in ("GET", "HEAD") and VIEWER_READABLE.match(path)) or (method == "POST" and path in VIEWER_MAY_POST)
                   or (method in ("PUT", "DELETE") and path == "/api/dashboard/layout")     # everybody arranges their own dashboard
                   or (method in ("GET", "PUT") and path == "/api/me/preferences"))          # and chooses the page to start on
        if not allowed:
            raise HTTPException(status_code=403, detail="this needs an administrator")


def require_admin(request: HTTPConnection) -> None:
    """For routes outside require_auth's role filter that must also be administrator-only."""
    principal = getattr(request.state, "user", None) or identify(request)
    if principal is None:
        raise HTTPException(status_code=401, detail="authentication required")
    if not principal.is_admin:
        raise HTTPException(status_code=403, detail="this needs an administrator")
