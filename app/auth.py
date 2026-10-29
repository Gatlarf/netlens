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
    role: str  # "admin" | "operator" | "viewer"
    user_id: Optional[int] = None  # None = the built-in NETLENS_TOKEN login
    builtin: bool = False
    scope: Optional[tuple] = None  # group ids a (viewer) user is limited to; None = no limit. () for a customer who sees remote sites only
    sites: Optional[tuple] = None  # remote site ids a (viewer) user is limited to; None = not a site customer
    assistant: Optional[str] = None  # 'read' or 'change' for a token made for an AI assistant (app/assistant.py); it is never a full administrator
    restricted: bool = False  # a second factor is required of this user, the grace period is over and none is set up: only the set-up pages work (app/secpolicy.py)
    mfa: Optional[dict] = None  # {"required", "enrolled", "deadline", "restricted"} for a signed-in user session
    auth_at: Optional[str] = None  # when this session last proved the user's identity (sign-in, or step-up)
    auth_method: Optional[str] = None  # password | totp | recovery | webauthn | oidc
    break_glass: bool = False  # an emergency administrator account: not held to the list of networks administration is limited to (app/secpolicy.py)
    grants: tuple = ()  # the read-only capabilities of a custom role (app/roles.py), already checked against the licence

    @property
    def is_admin(self) -> bool:
        return self.role == "admin" and self.assistant is None and not self.restricted


BUILTIN = Principal(username="access token", role="admin", builtin=True)

# What a viewer may read. Everything else, and every request that changes something, needs an administrator.
VIEWER_READABLE = re.compile(
    r"^/(metrics"
    r"|api/(session|update|changelog|map|map-settings|hierarchy|relations|events|uptime|uptime/core|scans|scans/current|service-checks|service-checks/\d+/results|monitors|agent-status|monitoring/limits|forecast|snoozes|changes|reports/availability|reports/availability\.csv|reports/weekly|probes|probes/\d+|probes/\d+/availability(\.csv)?|timeseries/(device|service|probe)/\d+|timeseries/(device|service|probe)/\d+/[A-Za-z0-9_.-]+"
    r"|me/totp|me/webauthn|me/sessions|me/stepup|stats|stats/summary|dashboard|dashboard/layout|dashboard/default|dashboard/shared|speedtest|speedtest/(status|ping|down)|groups|devices|devices/\d+|devices/\d+/(wifi|uptime)))$"
)
VIEWER_MAY_POST = ("/api/logout", "/api/me/password", "/api/me/totp/begin", "/api/me/totp/confirm", "/api/me/totp/disable", "/api/me/totp/recovery", "/api/me/webauthn/begin", "/api/me/webauthn/finish", "/api/me/webauthn/remove", "/api/me/sessions/end", "/api/me/sessions/revoke-others", "/api/me/stepup", "/api/speedtest/up", "/api/speedtest/browser")  # a viewer may test the line from their own device

# An operator looks like a viewer and may also act on what happens: scan, test, wake, acknowledge, snooze, plan maintenance, approve fixes, edit a device's
# name and group. Settings, users, credentials, backups, plugins, remote access and deleting things stay with the administrator.
OPERATOR_READABLE = re.compile(r"^/api/(maintenance|escalation|oncall|remediation(/(rules|runs|paused|status))?|audit)$")
OPERATOR_WRITABLE = (
    ("POST", re.compile(r"^/api/(scans|scans/cancel|snoozes|maintenance|maintenance/now|speedtest/internet|speedtest/iperf/run|devices/group|devices/trust)$")),
    ("POST", re.compile(r"^/api/devices/\d+/(scan|ping|trace|wake|monitor/run|flapping/probe)$")),
    ("POST", re.compile(r"^/api/(service-checks/\d+/run|escalation/\d+/ack|remediation/runs/\d+/(decide|ask))$")),
    ("PUT", re.compile(r"^/api/maintenance/\d+$")),
    ("DELETE", re.compile(r"^/api/(snoozes|maintenance/\d+)$")),
    ("PATCH", re.compile(r"^/api/devices/\d+$")),
)
# A viewer limited to some groups (a customer view) reads only the devices of those groups: the device list, a device and its history, the uptime page and the events.
SCOPED_READABLE = re.compile(
    r"^/api/(session|me/totp|me/webauthn|me/sessions|me/stepup|groups|devices|devices/\d+|devices/\d+/(wifi|uptime)|events|uptime|timeseries/device/\d+|timeseries/device/\d+/[A-Za-z0-9_.-]+)$"
)
SCOPED_MAY_POST = ("/api/logout", "/api/me/password", "/api/me/totp/begin", "/api/me/totp/confirm", "/api/me/totp/disable", "/api/me/totp/recovery", "/api/me/webauthn/begin", "/api/me/webauthn/finish", "/api/me/webauthn/remove", "/api/me/sessions/end", "/api/me/sessions/revoke-others", "/api/me/stepup")
SCOPED_SITE_READABLE = re.compile(r"^/api/(probes|probes/\d+|probes/\d+/availability(\.csv)?|timeseries/(remote|remote_service)/\d+(/[A-Za-z0-9_.-]+)?)$")
_SITE_IN_PATH = re.compile(r"^/api/probes/(\d+)")
_REMOTE_IN_PATH = re.compile(r"^/api/timeseries/(remote|remote_service)/(\d+)")
_DEVICE_IN_PATH = re.compile(r"^/api/(?:devices|timeseries/device)/(\d+)(?:/|$)")


def scope_of(request: HTTPConnection) -> Optional[tuple]:
    """The group ids the signed-in user is limited to, or None when there is no limit."""
    principal = getattr(request.state, "user", None)
    return principal.scope if principal is not None else None


def sites_of(request: HTTPConnection) -> Optional[tuple]:
    """The remote site ids the signed-in user is limited to, or None when there is no site limit (a user limited to groups only has none: scope_of tells)."""
    principal = getattr(request.state, "user", None)
    if principal is None or principal.scope is None:
        return None
    return principal.sites or ()


def devices_in_scope(conn, scope: tuple) -> set[int]:
    marks = ",".join("?" * len(scope))
    return {r[0] for r in conn.execute(f"SELECT id FROM devices WHERE group_id IN ({marks})", tuple(scope))}


def identify(conn: HTTPConnection) -> Optional[Principal]:
    """Who is making this request (cookie or bearer token), or None."""
    from app import relay

    if relay.is_relay(conn):          # the central Netlens looking at this site: reads only (the relay refuses anything else), never the parts relay.DENIED lists
        return Principal(username="central Netlens", role="admin")
    token = conn.app.state.settings.token
    cookie = conn.cookies.get(COOKIE_NAME)
    authorization = conn.headers.get("authorization")
    if is_authorized(token, cookie, authorization) and _static_token_allowed(conn):
        return BUILTIN
    bearer = authorization[7:] if authorization and authorization.startswith("Bearer ") else None
    if (cookie and cookie.startswith(users.SESSION_PREFIX)) or (bearer and bearer.startswith(users.TOKEN_PREFIX)):
        db = connect(conn.app.state.db_path)
        try:
            row = users.user_for_session(db, cookie) if cookie and cookie.startswith(users.SESSION_PREFIX) else None
            token_row = None if row else (users.user_for_token(db, bearer, client_ip(conn)) if bearer else None)
            row = row or token_row
        finally:
            db.close()
        if row:
            # a read-only token never writes, even when it belongs to an administrator
            role = "viewer" if token_row is not None and token_row["readonly"] else row["role"]
            if token_row is not None and token_row["assistant"]:
                from app import assistant, licence

                db = connect(conn.app.state.db_path)
                try:
                    mode = assistant.effective_mode(db, token_row["assistant"], row["role"])
                finally:
                    db.close()
                return Principal(username=f"{row['username']} (assistant: {token_row['token_name']})", role="admin" if mode == "change" else "viewer", user_id=row["id"], assistant=mode)
            if role == "operator":
                db = connect(conn.app.state.db_path)
                try:
                    from app import licence

                    if not licence.allows(db, "teams"):         # without a licence (or the trial) an operator is a viewer again; nothing is deleted
                        role = "viewer"
                finally:
                    db.close()
            groups = tuple(users.parse_scope(row["scope"]) or ()) or None
            sites = tuple(users.parse_scope(row["site_scope"]) or ()) or None
            mfa = None
            if token_row is None:                       # a signed-in user (a person); an API token is not interactive and has no second factor
                from app import secpolicy

                db = connect(conn.app.state.db_path)
                try:
                    mfa = secpolicy.mfa_state(db, {"role": row["role"], "created": row["user_created"], "oidc_sub": row["oidc_sub"], "totp_enabled": row["totp_enabled"], "webauthn_enabled": row["webauthn_enabled"]})
                finally:
                    db.close()
            grants: tuple = ()
            if row["custom_role"] and role in ("viewer", "operator") and groups is None and sites is None:
                from app import roles

                db = connect(conn.app.state.db_path)
                try:
                    grants = roles.grants_of(db, row["custom_role"])
                finally:
                    db.close()
            return Principal(username=row["username"], role=role, user_id=row["id"], grants=grants, break_glass=bool(row["break_glass"]), scope=groups if groups is not None else (() if sites is not None else None), sites=sites,
                             restricted=bool(mfa and mfa["restricted"]), mfa=mfa, auth_at=row["auth_at"] if token_row is None else None, auth_method=row["auth_method"] if token_row is None else None)
    return None


def secpolicy_enrol_paths() -> tuple[str, ...]:
    from app import secpolicy

    return secpolicy.ENROL_PATHS


def _static_token_allowed(conn: HTTPConnection) -> bool:
    """The access token (NETLENS_TOKEN) may be switched off, or limited to the local network (Settings → Sign-in security, Enterprise)."""
    from app import secpolicy

    mode = secpolicy.get_by_path(getattr(conn.app.state, "db_path", None))["static_token"]
    if mode == "allowed":
        return True
    if mode == "off":
        return False
    from app.terminal.access import _address, is_local_address

    peer = _address(client_ip(conn))
    return peer is not None and is_local_address(peer)


def require_auth(request: HTTPConnection) -> None:
    principal = identify(request)
    if principal is None:
        raise HTTPException(status_code=401, detail="authentication required")
    request.state.user = principal
    if principal.restricted and request.url.path not in secpolicy_enrol_paths():
        raise HTTPException(status_code=403, detail="mfa_enrolment_required")       # the administrator requires a second factor; only the set-up pages work until it is set up
    if principal.assistant:
        from app import assistant

        assistant.check(request.scope.get("method", "GET"), request.url.path, principal.assistant)
        return
    if principal.role == "admin" and not principal.break_glass and principal.username != "central Netlens":
        from app import secpolicy

        pol = secpolicy.get_by_path(getattr(request.app.state, "db_path", None))
        if pol["admin_networks"] and not secpolicy.admin_allowed(pol, client_ip(request)):
            raise HTTPException(status_code=403, detail="administration is limited to certain networks (Settings → Sign-in security); this address is not one of them")
    from app import stepup

    stepup.check(request, principal, request.scope.get("method") or "WS", request.url.path)
    if principal.role != "admin":
        method = request.scope.get("method", "GET")
        path = request.url.path
        if principal.scope is not None:
            _check_scoped(request, principal, method, path)
            return
        allowed = ((method in ("GET", "HEAD") and VIEWER_READABLE.match(path)) or (method == "POST" and path in VIEWER_MAY_POST)
                   or (method in ("PUT", "DELETE") and path == "/api/dashboard/layout")     # everybody arranges their own dashboard
                   or (method in ("GET", "PUT") and path == "/api/me/preferences"))          # and chooses the page to start on
        if not allowed and principal.grants:
            from app import roles

            allowed = roles.allows(principal.grants, method, path)               # a custom role: more reading, nothing else
        if not allowed and principal.role == "operator":
            allowed = ((method in ("GET", "HEAD") and OPERATOR_READABLE.match(path))
                       or any(method == m and rx.match(path) for m, rx in OPERATOR_WRITABLE))
        if not allowed:
            raise HTTPException(status_code=403, detail="this needs an administrator" if principal.role == "viewer" else "an operator may not do this")


def _check_scoped(request: HTTPConnection, principal: Principal, method: str, path: str) -> None:
    site_ok = bool(principal.sites) and method in ("GET", "HEAD") and SCOPED_SITE_READABLE.match(path)
    allowed = ((method in ("GET", "HEAD") and SCOPED_READABLE.match(path)) or site_ok or (method == "POST" and path in SCOPED_MAY_POST)
               or (method in ("GET", "PUT") and path == "/api/me/preferences"))
    if not allowed:
        raise HTTPException(status_code=403, detail="this account can only see its own devices")
    if site_ok:
        m = _SITE_IN_PATH.match(path)
        r = _REMOTE_IN_PATH.match(path)
        if m or r:
            db = connect(request.app.state.db_path)
            try:
                if m:
                    probe_id = int(m.group(1))
                else:
                    table = "remote_devices" if r.group(1) == "remote" else "remote_services"
                    row = db.execute(f"SELECT probe_id FROM {table} WHERE id = ?", (int(r.group(2)),)).fetchone()
                    probe_id = row["probe_id"] if row else -1
                if probe_id not in principal.sites:
                    raise HTTPException(status_code=404, detail="no such remote site")
            finally:
                db.close()
    m = _DEVICE_IN_PATH.match(path)
    if m:
        db = connect(request.app.state.db_path)
        try:
            if int(m.group(1)) not in devices_in_scope(db, principal.scope):
                raise HTTPException(status_code=404, detail="no such device")
        finally:
            db.close()


def require_admin(request: HTTPConnection) -> None:
    """For routes outside require_auth's role filter that must also be administrator-only."""
    principal = getattr(request.state, "user", None) or identify(request)
    if principal is None:
        raise HTTPException(status_code=401, detail="authentication required")
    if not principal.is_admin:
        raise HTTPException(status_code=403, detail="this needs an administrator")
