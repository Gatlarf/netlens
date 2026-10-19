"""The licence: what an installation may do beyond the free Community edition.

Community is free and complete except for one thing: the central Netlens takes in **one** remote site. More sites need a licence key
(Small business: 10 sites, Enterprise: unlimited, Supporter: 3 for a yearly coffee for the author). The business editions also have the features that mostly
help organisations (single sign-on, log forwarding, operators and customer views, on-call schedules, share links for some groups only and white label); Supporter has every other business feature.
Monitoring itself is never limited, nothing is deleted when a licence ends, and sites beyond the limit are only frozen.

A key is `NLK1.<payload>.<signature>`: JSON payload, Ed25519 signature, checked here with the public key below, offline. The signing key
lives outside this repository. The source stays readable and a determined person can change it; the key is the way to buy a supported,
signed licence, not a lock. A free 30-day trial of the full version can be started once per installation: its start is stored in the
database and in a marker file next to it, and the clock cannot be turned back (the newest time ever seen is kept), so restoring a backup
or setting the clock back does not renew it. Wiping the data folder does: Netlens has no online service that could prevent that.
"""

from __future__ import annotations

import base64
import json
import sqlite3
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PUBLIC_KEY = "zy4IfCAsy2K7_Ev5ni9HgAFw1P4JOEKpBjWcCbXvKKM"
PREFIX = "NLK1"
KEY_SETTING = "licence.key"
TRIAL_SETTING = "licence.trial_started"
SEEN_SETTING = "licence.seen"
MARKER = ".licence-trial"
TRIAL_DAYS = 30
GRACE_DAYS = 30
WARN_DAYS = (30, 14, 7)
FREE_SITES = 1
SUPPORTER_SITES = 3
EDITIONS = {
    "free": {"name": "Community", "sites": FREE_SITES},
    "supporter": {"name": "Supporter", "sites": SUPPORTER_SITES},
    "business": {"name": "Small business", "sites": 10},
    "enterprise": {"name": "Enterprise", "sites": None},
}
STAMP = "%Y-%m-%dT%H:%M:%SZ"


class LicenceError(ValueError):
    pass


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def parse(token: str, public_key: str | None = None) -> dict[str, Any]:
    """The payload of a genuine key; LicenceError when it is not one."""
    try:
        prefix, body, sig = str(token or "").strip().split(".")
        if prefix != PREFIX:
            raise ValueError
        Ed25519PublicKey.from_public_bytes(_unb64(public_key or PUBLIC_KEY)).verify(_unb64(sig), body.encode())
        payload = json.loads(_unb64(body))
    except (ValueError, InvalidSignature, TypeError):
        raise LicenceError("this is not a valid Netlens licence key") from None
    if not isinstance(payload, dict) or payload.get("edition") not in EDITIONS or payload.get("edition") == "free":
        raise LicenceError("this is not a valid Netlens licence key")
    return payload


# ----------------------------------------------------------------------------- clock and storage
def _data_dir(conn: sqlite3.Connection) -> Path | None:
    for row in conn.execute("PRAGMA database_list"):
        if row[1] == "main" and row[2]:
            return Path(row[2]).resolve().parent
    return None


def _setting(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def _store(conn: sqlite3.Connection, key: str, value: str | None) -> None:
    if value is None:
        conn.execute("DELETE FROM settings WHERE key = ?", (key,))
    else:
        conn.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))
    conn.commit()


def _parse_ts(value: str | None) -> datetime | None:
    try:
        return datetime.strptime(value, STAMP).replace(tzinfo=timezone.utc) if value else None
    except ValueError:
        return None


def clock(conn: sqlite3.Connection, now: datetime | None = None) -> tuple[datetime, bool]:
    """(the time to rely on, whether the system clock was set back). The newest time ever seen is kept; time never runs backwards here."""
    real = now or datetime.now(timezone.utc)
    seen = _parse_ts(_setting(conn, SEEN_SETTING))
    if seen is not None and seen > real:
        return seen, seen - real > timedelta(days=1)
    if seen is None or real - seen > timedelta(hours=1):
        _store(conn, SEEN_SETTING, real.strftime(STAMP))
    return real, False


def _trial_start(conn: sqlite3.Connection) -> datetime | None:
    """When the trial began: the earlier of the database record and the marker file (a restored database cannot make it later)."""
    found = [t for t in (_parse_ts(_setting(conn, TRIAL_SETTING)),) if t]
    folder = _data_dir(conn)
    if folder is not None:
        try:
            marker = _parse_ts((folder / MARKER).read_text().strip())
        except OSError:
            marker = None
        if marker:
            found.append(marker)
    return min(found) if found else None


def start_trial(conn: sqlite3.Connection, now: datetime | None = None) -> dict[str, Any]:
    when, _ = clock(conn, now)
    if _trial_start(conn) is not None:
        raise LicenceError("the free trial of this installation has been used already")
    stamp = when.strftime(STAMP)
    _store(conn, TRIAL_SETTING, stamp)
    folder = _data_dir(conn)
    if folder is not None:
        try:
            (folder / MARKER).write_text(stamp + "\n")
        except OSError:
            pass
    return status(conn, now)


# ----------------------------------------------------------------------------- the state
def status(conn: sqlite3.Connection, now: datetime | None = None) -> dict[str, Any]:
    when, rolled_back = clock(conn, now)
    today = when.date()
    out: dict[str, Any] = {"edition": "free", "name": EDITIONS["free"]["name"], "state": "free", "sites": FREE_SITES, "expires": None, "days_left": None,
                           "holder": None, "email": None, "id": None, "trial_available": False, "trial_ends": None, "clock_warning": rolled_back,
                           "message": None}
    started = _trial_start(conn)
    token = _setting(conn, KEY_SETTING)
    if token:
        try:
            payload = parse(token)
        except LicenceError:
            out["state"], out["message"] = "invalid", "The stored licence key is not valid."
        else:
            edition = payload["edition"]
            sites = payload.get("sites") if "sites" in payload else EDITIONS[edition]["sites"]
            out.update(edition=edition, name=EDITIONS[edition]["name"], holder=payload.get("holder"), email=payload.get("email"), id=payload.get("id"))
            expires = payload.get("expires")
            try:
                end = date.fromisoformat(expires) if expires else None
            except ValueError:
                end = today - timedelta(days=GRACE_DAYS + 1)
            out["expires"] = end.isoformat() if end else None
            if end is None:
                out.update(state="active", sites=sites)
            else:
                left = (end - today).days
                out["days_left"] = left
                if left >= 0:
                    out.update(state="active", sites=sites)
                    if left <= max(WARN_DAYS):
                        out["message"] = f"This licence ends in {left} day{'s' if left != 1 else ''}."
                elif -left <= GRACE_DAYS:
                    out.update(state="grace", sites=sites, message=f"This licence ended {-left} day{'s' if -left != 1 else ''} ago; the extra sites stay on for {GRACE_DAYS + left} more days.")
                else:
                    out.update(state="expired", edition="free", name=EDITIONS["free"]["name"], sites=FREE_SITES,
                               message="This licence has ended: sites beyond the first one are frozen. Renew the key to bring them back.")
            if out["state"] in ("active", "grace"):
                return out
    if started is not None and out["state"] != "invalid":
        end_trial = started + timedelta(days=TRIAL_DAYS)
        out["trial_ends"] = end_trial.strftime(STAMP)
        if when < end_trial:
            left = (end_trial - when).days
            out.update(edition="trial", name="Free trial", state="trial", sites=None, days_left=left, expires=end_trial.date().isoformat(),
                       message=f"The free trial of the full version ends in {left} day{'s' if left != 1 else ''}.")
        elif out["state"] != "expired":
            out.update(state="trial_over", message="The free 30-day trial has ended: sites beyond the first one are frozen.")
    elif started is None and out["state"] != "invalid":
        out["trial_available"] = True
    return out


PAID_FEATURES = ("remediation", "engineer", "oncall", "sso", "siem", "insights", "vulnerabilities", "teams", "schedules", "sharing", "assistant")      # beyond the free Community edition (trial and every licence include them)
BUSINESS_ONLY = ("sso", "siem", "teams", "schedules", "sharing")      # of those, the ones the Supporter edition does not have: they mostly help organisations (the trial has them)


def allows(conn: sqlite3.Connection, feature: str, now: datetime | None = None) -> bool:
    """Whether a feature that needs a licence may be used. Everything that was free stays free; only new business features are asked about."""
    if feature not in PAID_FEATURES:
        return True
    edition = status(conn, now)["edition"]
    if edition == "free":
        return False
    return not (feature in BUSINESS_ONLY and edition == "supporter")


def site_limit(conn: sqlite3.Connection) -> int | None:
    """How many remote sites this installation takes in (None = no limit)."""
    return status(conn)["sites"]


def install(conn: sqlite3.Connection, token: str, now: datetime | None = None) -> dict[str, Any]:
    token = str(token or "").strip()
    payload = parse(token)
    when, _ = clock(conn, now)
    if payload.get("expires"):
        try:
            if (when.date() - date.fromisoformat(payload["expires"])).days > GRACE_DAYS:
                raise LicenceError("this licence key has expired")
        except ValueError:
            raise LicenceError("this is not a valid Netlens licence key") from None
    _store(conn, KEY_SETTING, token)
    return status(conn, now)


def remove(conn: sqlite3.Connection) -> dict[str, Any]:
    _store(conn, KEY_SETTING, None)
    return status(conn)


def notify(conn: sqlite3.Connection, now: datetime | None = None) -> str | None:
    """Once an hour: one `licence_expiring` event at 30, 14 and 7 days before the end, when the grace period starts and when it ends."""
    from app.db import add_event

    st = status(conn, now)
    left = st["days_left"]
    if st["state"] == "active" and left is not None and left <= max(WARN_DAYS):
        level = min(w for w in WARN_DAYS if left <= w)
    elif st["state"] == "grace":
        level = "grace"
    elif st["state"] == "expired":
        level = "ended"
    else:
        level = None
    key = f"{st['id']}:{level}"
    if level is None or _setting(conn, "licence.notified") == key:
        return None
    _store(conn, "licence.notified", key)
    add_event(conn, "licence_expiring", st["message"] or "The licence ends soon.")
    return key
