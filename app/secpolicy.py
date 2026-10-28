"""Sign-in security policy: who must have a second factor, and how long a session may live.

    require_totp     off | admins | operators (administrators and operators) | everyone      Small business and Enterprise (`mfa_policy`)
    grace_days       how long a user without a second factor may still sign in after the policy was switched on (or the account was made)
    idle_minutes     sign out after this long without a request (0 = off)                       Enterprise (`privileged`)
    absolute_hours   sign out this long after signing in, whatever happens (0 = off)            Enterprise
    max_sessions     the newest N sessions of a user stay, older ones end (0 = no limit)        Enterprise

Rules that keep it safe:
  * a setting that was made stays enforced when a licence ends (a lapsing licence never weakens security); only *changing* it needs the licence;
  * single-sign-on users are not asked for a second factor by Netlens (their identity provider does that);
  * after the grace period a user without a second factor can only reach the pages that set one up (the "restricted" state), never anything else.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from app.db import get_setting, set_setting, utcnow

KEY = "security.policy"
STAMP = "%Y-%m-%dT%H:%M:%SZ"
REQUIRE_VALUES = ("off", "admins", "operators", "everyone")
DEFAULTS: dict[str, Any] = {"require_totp": "off", "grace_days": 14, "require_since": None, "idle_minutes": 0, "absolute_hours": 0, "max_sessions": 0,
                            "step_up": False, "step_up_minutes": 10, "static_token": "allowed", "local_login": "allowed", "api_token_max_days": 0, "min_password": 8}
RANGES = {"grace_days": (0, 365), "idle_minutes": (0, 1440), "absolute_hours": (0, 720), "max_sessions": (0, 50), "step_up_minutes": (1, 120), "api_token_max_days": (0, 3650), "min_password": (8, 64)}
ENUMS = {"static_token": ("allowed", "lan", "off"), "local_login": ("allowed", "break_glass_only")}
ENTERPRISE_FIELDS = ("idle_minutes", "absolute_hours", "max_sessions", "step_up", "step_up_minutes", "static_token", "local_login", "api_token_max_days", "min_password")
# a restricted session (no second factor after the grace period) may use only these
ENROL_PATHS = ("/api/session", "/api/logout", "/api/me/totp", "/api/me/totp/begin", "/api/me/totp/confirm", "/api/me/password", "/api/me/sessions", "/api/me/stepup")

_cache: dict[str, tuple[float, dict[str, Any]]] = {}
CACHE_SECONDS = 30.0           # only this process writes the policy (and `save` and a restore forget it at once), so a long time is safe and keeps the per-request check free


class PolicyError(ValueError):
    """A sentence the administrator can act on."""


def _key(conn) -> str:
    return getattr(conn, "file", "") or str(id(conn))


def get_by_path(db_path) -> dict[str, Any]:
    """The policy by database file: the cache first, so the per-request checks (the access token, step-up) open no connection when it is warm."""
    import os

    if not db_path:
        return dict(DEFAULTS)
    k = os.path.realpath(str(db_path))
    hit = _cache.get(k)
    if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
        return dict(hit[1])
    from app.db import connect

    try:
        conn = connect(db_path)
    except (OSError, ValueError):             # no database to read (a bare application object in a test): the defaults; everything else fails on its own
        return dict(DEFAULTS)
    try:
        return get(conn)
    finally:
        conn.close()


def _parse(ts: str | None) -> datetime | None:
    try:
        return datetime.strptime(ts, STAMP).replace(tzinfo=timezone.utc) if ts else None
    except ValueError:
        return None


def get(conn) -> dict[str, Any]:
    """The policy (cached for a few seconds: it is read on every request)."""
    k = _key(conn)
    hit = _cache.get(k)
    now = time.monotonic()
    if hit and now - hit[0] < CACHE_SECONDS:
        return dict(hit[1])
    out = dict(DEFAULTS)
    try:
        saved = json.loads(get_setting(conn, KEY) or "{}")
    except ValueError:
        saved = {}
    if isinstance(saved, dict):
        out.update({k2: saved[k2] for k2 in DEFAULTS if k2 in saved})
    _cache[k] = (now, out)
    return dict(out)


def forget(conn=None) -> None:
    if conn is None:
        _cache.clear()
    else:
        _cache.pop(_key(conn), None)


def save(conn, data: dict[str, Any], *, may_mfa: bool, may_privileged: bool) -> dict[str, Any]:
    """Validate and store changes. `may_mfa` / `may_privileged`: the licence allows changing the Small business and the Enterprise fields."""
    cur = get(conn)
    new = dict(cur)
    if "require_totp" in data:
        v = data["require_totp"]
        if v not in REQUIRE_VALUES:
            raise PolicyError("require_totp must be off, admins, operators or everyone")
        if v != cur["require_totp"] and not may_mfa:
            raise PolicyError("requiring a second factor is part of the Small business and Enterprise editions (or the free trial)")
        new["require_totp"] = v
        if v != "off" and cur["require_totp"] == "off":
            new["require_since"] = utcnow()                    # the grace period starts when the policy is switched on
        if v == "off":
            new["require_since"] = None
    for field in ("grace_days",) + ENTERPRISE_FIELDS:
        if field not in data:
            continue
        v = data[field]
        if field == "step_up":
            if not isinstance(v, bool):
                raise PolicyError("step_up must be true or false")
        elif field in ENUMS:
            if v not in ENUMS[field]:
                raise PolicyError(f"{field} must be one of {', '.join(ENUMS[field])}")
        else:
            low, high = RANGES[field]
            if isinstance(v, bool) or not isinstance(v, int) or not low <= v <= high:
                raise PolicyError(f"{field} must be a whole number from {low} to {high}")
        if v != cur[field]:
            if field in ENTERPRISE_FIELDS and not may_privileged:
                raise PolicyError("this setting is part of the Enterprise edition (or the free trial)")
            if field == "grace_days" and not may_mfa:
                raise PolicyError("requiring a second factor is part of the Small business and Enterprise editions (or the free trial)")
        new[field] = v
    _check_safe(conn, new, cur)
    set_setting(conn, KEY, json.dumps({k: new[k] for k in DEFAULTS}))
    conn.commit()
    forget(conn)
    return get(conn)


def _check_safe(conn, new: dict[str, Any], cur: dict[str, Any]) -> None:
    """Refuse a setting that would lock everybody out. Only when it is being switched on or moved now (a setting already in force is left alone)."""
    admins = conn.execute("SELECT COUNT(*) FROM users WHERE disabled = 0 AND role = 'admin'").fetchone()[0]
    if new["step_up"] and not cur["step_up"] and admins < 1:
        raise PolicyError("create at least one administrator account first: the access token cannot confirm a privileged action")
    if new["static_token"] != "allowed" and cur["static_token"] == "allowed" and admins < 1:
        raise PolicyError("create at least one administrator account before the access token is limited or switched off")
    if new["local_login"] == "break_glass_only" and cur["local_login"] != "break_glass_only":
        from app import licence, oidc

        if not oidc.settings(conn)["enabled"] or not licence.allows(conn, "sso"):
            raise PolicyError("password sign-in can only be limited when single sign-on is set up and on")
        if conn.execute("SELECT COUNT(*) FROM users WHERE disabled = 0 AND role = 'admin' AND break_glass = 1 AND totp_enabled = 1").fetchone()[0] < 1:
            raise PolicyError("make at least one administrator a break-glass account with a second factor first (Users & tokens): it is the way in when single sign-on fails")


# ----------------------------------------------------------------------------- who must have a second factor
def _in_scope(role: str, mode: str) -> bool:
    return (mode == "everyone") or (mode == "operators" and role in ("admin", "operator")) or (mode == "admins" and role == "admin")


def mfa_state(conn, row, now: datetime | None = None) -> dict[str, Any]:
    """{"required", "enrolled", "deadline", "restricted"} for a user row (needs role, created, oidc_sub, totp_enabled)."""
    pol = get(conn)
    enrolled = bool(row["totp_enabled"])
    sso = bool(row["oidc_sub"])
    required = pol["require_totp"] != "off" and not sso and _in_scope(row["role"], pol["require_totp"])
    deadline = None
    restricted = False
    if required and not enrolled:
        start = max(filter(None, (_parse(pol["require_since"]), _parse(row["created"]))), default=datetime.now(timezone.utc))
        end = start + timedelta(days=pol["grace_days"])
        deadline = end.strftime(STAMP)
        restricted = (now or datetime.now(timezone.utc)) >= end
    return {"required": required, "enrolled": enrolled, "deadline": deadline, "restricted": restricted}


def users_without_factor(conn) -> list[str]:
    """The users the policy applies to who have not set a second factor up yet (for the settings page)."""
    out = []
    for r in conn.execute("SELECT username, role, created, oidc_sub, totp_enabled, disabled FROM users WHERE disabled = 0 ORDER BY LOWER(username)"):
        st = mfa_state(conn, r)
        if st["required"] and not st["enrolled"]:
            out.append(r["username"])
    return out
