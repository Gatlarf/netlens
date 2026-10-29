"""Access review and the evidence pack (Enterprise).

Auditors ask the same questions every time: who has access, with which role, protected by what, since when, and is anybody still here who should not be? `report()` answers
from the live data: every account with its role, how it signs in, its second factor, its API tokens, when it was last used; the security posture of the installation; and a list of
findings written in plain words (an administrator without a second factor, an account nobody has used for 90 days, a token that never ends ...).

`pack()` makes that report a **signed evidence pack**: the report in canonical JSON plus an HMAC (a key derived from the master key). Its SHA-256 is written to the audit log, which is
itself tamper-evident, so the pack can later be shown to be the one that was made then and unchanged since; `verify()` checks a pack that is handed back. The pack holds no secret
(no password hashes, no tokens, no keys).
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from app import vault
from app.db import get_setting, set_setting, utcnow

DORMANT_DAYS = 90
LAST_REVIEW_KEY = "access.last_review"
STAMP = "%Y-%m-%dT%H:%M:%SZ"


def _days_since(ts: str | None, now: datetime) -> int | None:
    try:
        return (now - datetime.strptime(ts, STAMP).replace(tzinfo=timezone.utc)).days if ts else None
    except ValueError:
        return None


def last_review(conn: sqlite3.Connection) -> dict | None:
    try:
        return json.loads(get_setting(conn, LAST_REVIEW_KEY) or "null")
    except ValueError:
        return None


def complete(conn: sqlite3.Connection, reviewer: str, comment: str) -> dict:
    done = {"at": utcnow(), "by": reviewer, "comment": " ".join(str(comment or "").split())[:300]}
    set_setting(conn, LAST_REVIEW_KEY, json.dumps(done))
    conn.commit()
    return done


def report(conn: sqlite3.Connection, now: datetime | None = None) -> dict[str, Any]:
    from app import licence, oidc, secpolicy

    now = now or datetime.now(timezone.utc)
    pol = secpolicy.get(conn)
    people, findings = [], []
    for u in conn.execute("SELECT id, username, role, custom_role, cert_identity, disabled, created, last_login, scope, site_scope, totp_enabled, webauthn_enabled, break_glass, oidc_sub FROM users ORDER BY LOWER(username)"):
        tokens = conn.execute("SELECT name, created, last_used, readonly, assistant, expires, allowed_ips FROM api_tokens WHERE user_id = ? ORDER BY id", (u["id"],)).fetchall()
        keys = conn.execute("SELECT COUNT(*) FROM user_webauthn WHERE user_id = ?", (u["id"],)).fetchone()[0]
        sessions = conn.execute("SELECT COUNT(*) FROM sessions WHERE user_id = ? AND expires > ?", (u["id"], utcnow())).fetchone()[0]
        sso = bool(u["oidc_sub"])
        factor = "single sign-on (the identity provider's)" if sso else ", ".join(x for x in ("authenticator app" if u["totp_enabled"] else "", f"{keys} security key{'s' if keys != 1 else ''}" if keys else "") if x) or "none"
        idle = _days_since(u["last_login"], now)
        person = {"username": u["username"], "role": u["role"], "custom_role": u["custom_role"], "disabled": bool(u["disabled"]), "source": "single sign-on" if sso else "local", "second_factor": factor,
                  "has_second_factor": sso or bool(u["totp_enabled"] or keys), "break_glass": bool(u["break_glass"]), "certificate_linked": bool(u["cert_identity"]), "customer_view": bool(u["scope"] or u["site_scope"]),
                  "created": u["created"], "last_login": u["last_login"], "days_since_login": idle, "sessions_open": sessions,
                  "tokens": [{"name": t["name"], "read_only": bool(t["readonly"]), "assistant": t["assistant"], "expires": t["expires"], "restricted_to_addresses": bool(t["allowed_ips"]), "last_used": t["last_used"]} for t in tokens]}
        people.append(person)
        if u["disabled"]:
            continue
        who = u["username"]
        if u["role"] == "admin" and not person["has_second_factor"]:
            findings.append({"level": "bad", "who": who, "text": f"{who} is an administrator without a second factor"})
        if u["role"] != "viewer" and idle is not None and idle >= DORMANT_DAYS:
            findings.append({"level": "warn", "who": who, "text": f"{who} ({u['role']}) has not signed in for {idle} days: still needed?"})
        if u["role"] != "viewer" and u["last_login"] is None and (_days_since(u["created"], now) or 0) >= 30:
            findings.append({"level": "warn", "who": who, "text": f"{who} ({u['role']}) was created more than 30 days ago and has never signed in"})
        for t in tokens:
            if not t["expires"] and not t["readonly"] and u["role"] in ("admin", "operator"):
                findings.append({"level": "warn", "who": who, "text": f"{who}: the API token {t['name']!r} can change things and never expires"})
            if not t["last_used"] and (_days_since(t["created"], now) or 0) >= 30:
                findings.append({"level": "info", "who": who, "text": f"{who}: the API token {t['name']!r} has never been used (made {_days_since(t['created'], now)} days ago)"})
    admins = [p for p in people if p["role"] == "admin" and not p["disabled"]]
    if len(admins) > 5:
        findings.append({"level": "info", "who": "", "text": f"{len(admins)} administrators: is that many needed? (least privilege)"})
    key_source = vault.key_source(conn)
    posture = {
        "second_factor_required": pol["require_totp"], "step_up": pol["step_up"], "four_eyes": pol["four_eyes"], "session_recording": pol["record_sessions"], "admin_networks": pol["admin_networks"],
        "access_token": pol["static_token"], "password_sign_in": pol["local_login"], "idle_minutes": pol["idle_minutes"], "api_token_max_days": pol["api_token_max_days"], "min_password": pol["min_password"],
        "single_sign_on": bool(oidc.settings(conn)["enabled"]), "master_key": key_source, "licence": licence.status(conn)["edition"],
    }
    if pol["require_totp"] == "off":
        findings.append({"level": "warn", "who": "", "text": "a second factor is not required of anybody (Settings → Sign-in security)"})
    if not pol["step_up"]:
        findings.append({"level": "info", "who": "", "text": "privileged actions do not ask for a fresh confirmation (step-up is off)"})
    if key_source == "file":
        findings.append({"level": "info", "who": "", "text": "the master key is in a file next to the data (an external key service or a secret keeps it apart)"})
    from app import auditchain

    check = auditchain.last_result(conn)
    if check and not check.get("ok"):
        findings.append({"level": "bad", "who": "", "text": "the audit log failed its last integrity check"})
    rank = {"bad": 0, "warn": 1, "info": 2}
    findings.sort(key=lambda f: (rank[f["level"]], f["text"]))
    return {"generated": now.strftime(STAMP), "dormant_days": DORMANT_DAYS, "people": people, "posture": posture, "findings": findings, "last_review": last_review(conn),
            "totals": {"accounts": len(people), "active": sum(1 for p in people if not p["disabled"]), "administrators": len(admins), "without_second_factor": sum(1 for p in people if not p["disabled"] and not p["has_second_factor"]),
                       "tokens": sum(len(p["tokens"]) for p in people)}}


def csv_text(rep: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["user", "role", "custom role", "source", "second factor", "disabled", "break-glass", "customer view", "last sign-in", "days since", "open sessions", "API tokens"])
    for p in rep["people"]:
        cells = [p["username"], p["role"], p["custom_role"] or "", p["source"], p["second_factor"], "yes" if p["disabled"] else "no", "yes" if p["break_glass"] else "no", "yes" if p["customer_view"] else "no",
                 p["last_login"] or "never", p["days_since_login"] if p["days_since_login"] is not None else "", p["sessions_open"], len(p["tokens"])]
        writer.writerow([("'" + c if isinstance(c, str) and c[:1] in "=+-@" else c) for c in cells])
    return out.getvalue()


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def pack(conn: sqlite3.Connection, now: datetime | None = None) -> dict[str, Any]:
    """The report, signed: {"report": ..., "sha256": ..., "signature": ...}. The caller writes the digest to the audit log."""
    rep = report(conn, now)
    body = _canonical(rep)
    key = vault.derive_key(conn, "access-review-pack-v1")
    return {"format": "netlens-access-review-v1", "report": rep, "sha256": hashlib.sha256(body).hexdigest(), "signature": hmac.new(key, body, hashlib.sha256).hexdigest()}


def verify(conn: sqlite3.Connection, doc: Any) -> dict[str, Any]:
    """Is this pack one that this installation made, unchanged? (The key that signed it is derived from this installation's master key.)"""
    if not isinstance(doc, dict) or doc.get("format") != "netlens-access-review-v1" or not isinstance(doc.get("report"), dict):
        return {"ok": False, "why": "this is not a Netlens access review pack"}
    body = _canonical(doc["report"])
    if hashlib.sha256(body).hexdigest() != doc.get("sha256"):
        return {"ok": False, "why": "the content does not match its hash: it was changed"}
    key = vault.derive_key(conn, "access-review-pack-v1")
    if not hmac.compare_digest(hmac.new(key, body, hashlib.sha256).hexdigest(), str(doc.get("signature") or "")):
        return {"ok": False, "why": "the signature is not from this installation (or the pack was changed)"}
    known = conn.execute("SELECT 1 FROM audit_log WHERE action LIKE ? LIMIT 1", (f"%{doc['sha256'][:24]}%",)).fetchone() is not None
    return {"ok": True, "generated": doc["report"].get("generated"), "in_audit_log": known}
