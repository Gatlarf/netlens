"""Step-up re-authentication: a privileged action needs a recent proof of who is acting (Enterprise, `privileged`; switched on in Settings → Sign-in security).

A session remembers when its user last proved who they are (`auth_at`: the sign-in, or the last step-up). A privileged action within `step_up_minutes` of that goes
through. Later, the request is answered `401 step_up_required:<how>` and the interface asks once: a code if the user has a second factor, else their password, and for a
single-sign-on user a fresh sign-in at the identity provider.

Never satisfiable by something that cannot be asked: the access token (NETLENS_TOKEN) and API tokens are refused on these actions (`403`), because there is nobody to
ask. That is the point: with step-up on, a stolen token cannot create users, read the credential store or open a terminal.

The list below is what counts as privileged. `tests/test_stepup.py` walks every route of the application and fails when a route that touches secrets, accounts, remote
access or code execution is neither in this list nor in `NOT_PRIVILEGED` with a reason, so a new route forces the decision.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone

from fastapi import HTTPException
from starlette.requests import HTTPConnection

WRITE = ("POST", "PUT", "PATCH", "DELETE")
_BARE = r"(?:/[^/]+)*"
# (methods, path regex) of what is privileged
PRIVILEGED: list[tuple[tuple[str, ...], re.Pattern]] = [
    (WRITE, re.compile(r"^/api/(credentials|users|roles|tls|approvals|vault|ingest|sso|assistant|mcp|security-policy|cert-login|restore|central|hostprobe|hosts|engineer|siem)(/|$)")),
    (("PUT", "DELETE"), re.compile(r"^/api/licence$")),
    (WRITE, re.compile(r"^/api/plugins(/[^/]+)?$")),                                        # install by upload, change the settings (they hold logins), remove
    (WRITE, re.compile(r"^/api/plugin-index/(settings|[^/]+/(install|rollback|auto-update))$")),
    (("PUT",), re.compile(r"^/api/plugin-settings$")),
    (WRITE, re.compile(r"^/api/backups/[^/]+/restore$")),
    (WRITE, re.compile(r"^/api/remediation/rules(/[^/]+)?(/run)?$")),                      # a rule can run a command on a host
    (WRITE, re.compile(r"^/api/probes(/\d+)?(/(command|config|token))?$")),                # a remote site: its token and the commands sent to it
    (WRITE, re.compile(r"^/api/remote/\d+/(session|saved/[^/]+)$")),
    (("PUT", "POST"), re.compile(r"^/api/devices/\d+/(hostprobe(/install)?|monitor(/test)?)$")),   # logins for a host (also trying one: it may use a stored login)
    (("GET",), re.compile(r"^/api/vault/key$")),
    (("WS",), re.compile(r"^/api/(terminal/\d+|remote)/ws$")),                              # a shell or desktop on a host
]
# routes that look privileged by their path but are not, each with the reason (the inventory test reads this)
NOT_PRIVILEGED: dict[tuple[str, str], str] = {
    ("POST", "/api/plugins/{plugin_id}/test"): "tries a plugin's settings, saves nothing",
    ("POST", "/api/plugins/{plugin_id}/diagnose"): "makes an anonymised report, saves nothing",
    ("POST", "/api/plugins/{plugin_id}/sync"): "runs a plugin that is already set up",
    ("POST", "/api/plugin-compat/dismiss"): "hides a notice",
    ("POST", "/api/licence/trial"): "starts the free trial, which can be started once",
    ("POST", "/api/devices/{device_id}/hostprobe/run"): "runs the read-only probes that are already set up",
    ("POST", "/api/devices/{device_id}/hostprobe/diagnose"): "runs the read-only probes that are already set up",
    ("POST", "/api/devices/{device_id}/monitor/run"): "reads a monitor that is already set up",
    ("DELETE", "/api/devices/{device_id}/monitor"): "removes a monitor (the stored login stays in the credential store)",
    ("POST", "/api/me/stepup"): "the step-up itself",
    ("PUT", "/api/monitoring/limits"): "the thresholds of the health alerts: no secrets and no access to a host",
    ("POST", "/api/remediation/runs/{run_id}/ask"): "asks the digital engineer, runs nothing",
    ("POST", "/api/remediation/runs/{run_id}/decide"): "approves or declines a fix that an administrator's rule proposed (an operator may)",
    ("PUT", "/api/remediation/paused"): "pauses automatic fixes, which makes things safer",
    ("POST", "/api/siem/test"): "sends one test message",
    ("POST", "/api/sso/test"): "tries the settings, saves nothing",
    ("POST", "/api/approvals"): "only asks for permission: nothing happens until another administrator approves, which is the privileged step",
    ("POST", "/api/approvals/{approval_id}/cancel"): "withdraws the person's own request",
    ("POST", "/api/ingest/window"): "covered below: every ingest write is privileged (this entry only documents the window)",
}


def protected(method: str, path: str) -> bool:
    return any(method in methods and rx.match(path) for methods, rx in PRIVILEGED)


def enabled(request: HTTPConnection) -> dict | None:
    from app import secpolicy

    pol = secpolicy.get_by_path(getattr(request.app.state, "db_path", None))
    return pol if pol["step_up"] else None


def method_for(principal) -> str:
    if principal.auth_method == "oidc":
        return "oidc"
    if principal.mfa and principal.mfa.get("webauthn"):
        return "webauthn"
    return "totp" if principal.mfa and principal.mfa.get("enrolled") else "password"


def fresh(principal, minutes: int, now: float | None = None) -> bool:
    try:
        at = datetime.strptime(principal.auth_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return False
    return ((time.time() if now is None else now) - at) <= minutes * 60


def check(request: HTTPConnection, principal, method: str, path: str) -> None:
    """Raise when this request needs a fresh proof that the principal does not have. Called for every authenticated request."""
    if not protected(method, path):
        return
    pol = enabled(request)
    if pol is None or principal.username == "central Netlens":
        return
    if principal.builtin or (principal.user_id is not None and principal.auth_method is None):
        raise HTTPException(status_code=403, detail="step_up_unavailable: this action needs a person signed in with a user account and a fresh confirmation; the access token and API tokens cannot give one (Settings → Sign-in security)")
    if not fresh(principal, pol["step_up_minutes"]):
        raise HTTPException(status_code=401, detail=f"step_up_required:{method_for(principal)}")
