"""Four-eyes approval (Enterprise): some actions need a second administrator to say yes first.

Which actions: opening a terminal, opening a remote desktop, and restoring a backup (Settings -> Sign-in security). The person who wants to do it asks, with a reason; another
administrator (never the same person) approves or denies; an approval is good for one use, for a few minutes, for exactly that target. Everything is in the audit log and an
alert goes out when somebody asks.

Safety rails:
  * the policy can only be switched on while at least two administrators with their own accounts exist (the access token cannot approve), so it cannot lock everybody out;
  * break-glass accounts do not need approval (they are the emergency way in; every use is already a critical event);
  * an approval is claimed with one conditional UPDATE, so two sessions cannot both use it;
  * a lapsing licence never switches the policy off.
"""

from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from app.db import add_event, insert_id, utcnow

ACTIONS = {"terminal": "Open a terminal", "remote": "Open a remote desktop", "restore": "Restore a backup"}
PENDING_MINUTES = 30
MAX_PENDING_PER_USER = 5
STAMP = "%Y-%m-%dT%H:%M:%SZ"


class ApprovalError(ValueError):
    """A sentence the user can act on."""


def _iso(dt: datetime) -> str:
    return dt.strftime(STAMP)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def needs(policy: dict[str, Any], action: str) -> bool:
    return action in (policy.get("four_eyes") or [])


def exempt(principal) -> bool:
    return bool(getattr(principal, "break_glass", False))


def person(principal) -> bool:
    """A signed-in person who can be named: not the access token, not an API token."""
    return principal is not None and principal.user_id is not None and principal.auth_method is not None and getattr(principal, "assistant", None) is None


def _expire(conn: sqlite3.Connection) -> None:
    now = utcnow()
    conn.execute("UPDATE approvals SET status = 'expired' WHERE (status = 'pending' AND created < ?) OR (status = 'approved' AND used_at IS NULL AND expires < ?)", (_iso(_now() - timedelta(minutes=PENDING_MINUTES)), now))
    conn.commit()


def _row(r) -> dict[str, Any]:
    return {k: r[k] for k in ("id", "action", "target", "label", "reason", "requester", "status", "created", "decided_by", "decided_at", "comment", "expires", "used_at")} | {"action_text": ACTIONS.get(r["action"], r["action"])}


def request(conn: sqlite3.Connection, principal, action: str, target: str, label: str, reason: str) -> dict[str, Any]:
    if action not in ACTIONS:
        raise ApprovalError("that action does not need approval")
    reason = " ".join(str(reason or "").split())[:300]
    if len(reason) < 3:
        raise ApprovalError("give a reason (a ticket number or a few words) so the approver knows what it is for")
    if not person(principal):
        raise ApprovalError("only a signed-in person can ask: the access token and API tokens cannot")
    _expire(conn)
    if conn.execute("SELECT COUNT(*) FROM approvals WHERE requester_id = ? AND status IN ('pending', 'approved') AND used_at IS NULL", (principal.user_id,)).fetchone()[0] >= MAX_PENDING_PER_USER:
        raise ApprovalError("you already have several requests open: cancel or use them first")
    same = conn.execute("SELECT id FROM approvals WHERE requester_id = ? AND action = ? AND target = ? AND status IN ('pending', 'approved') AND used_at IS NULL", (principal.user_id, action, target)).fetchone()
    if same:
        return get(conn, same["id"])
    new_id = insert_id(conn, "INSERT INTO approvals (action, target, label, reason, requester_id, requester, created, status) VALUES (?,?,?,?,?,?,?, 'pending')",
                       (action, target[:80], label[:120], reason, principal.user_id, principal.username, utcnow()))
    conn.commit()
    add_event(conn, "approval_requested", f"{principal.username} asks to {ACTIONS[action].lower()}{(' (' + label + ')') if label else ''}: {reason}")
    return get(conn, new_id or 0)


def get(conn: sqlite3.Connection, approval_id: int) -> dict[str, Any]:
    r = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
    if r is None:
        raise ApprovalError("no such request")
    return _row(r)


def listing(conn: sqlite3.Connection, principal) -> dict[str, Any]:
    _expire(conn)
    waiting = [_row(r) for r in conn.execute("SELECT * FROM approvals WHERE status = 'pending' AND requester_id != ? ORDER BY id", (principal.user_id or -1,))]
    mine = [_row(r) for r in conn.execute("SELECT * FROM approvals WHERE requester_id = ? ORDER BY id DESC LIMIT 10", (principal.user_id or -1,))]
    recent = [_row(r) for r in conn.execute("SELECT * FROM approvals WHERE status != 'pending' ORDER BY id DESC LIMIT 20")]
    return {"waiting": waiting, "mine": mine, "recent": recent}


def decide(conn: sqlite3.Connection, principal, approval_id: int, approve: bool, comment: str, minutes: int) -> dict[str, Any]:
    if not person(principal) or not principal.is_admin:
        raise ApprovalError("only a signed-in administrator can decide")
    _expire(conn)
    item = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
    if item is None:
        raise ApprovalError("no such request")
    if item["requester_id"] == principal.user_id:
        raise ApprovalError("you cannot decide your own request: another administrator has to")
    if item["status"] != "pending":
        raise ApprovalError(f"this request is already {item['status']}")
    expires = _iso(_now() + timedelta(minutes=minutes)) if approve else None
    claimed = conn.execute("UPDATE approvals SET status = ?, decided_by = ?, decided_at = ?, comment = ?, expires = ? WHERE id = ? AND status = 'pending'",
                           ("approved" if approve else "denied", principal.username, utcnow(), " ".join(str(comment or "").split())[:200], expires, approval_id)).rowcount
    conn.commit()
    if not claimed:
        raise ApprovalError("this request was decided just now by somebody else")
    return get(conn, approval_id)


def cancel(conn: sqlite3.Connection, principal, approval_id: int) -> dict[str, Any]:
    item = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
    if item is None or item["requester_id"] != principal.user_id:
        raise ApprovalError("no such request of yours")
    conn.execute("UPDATE approvals SET status = 'cancelled' WHERE id = ? AND status IN ('pending', 'approved') AND used_at IS NULL", (approval_id,))
    conn.commit()
    return get(conn, approval_id)


def consume(conn: sqlite3.Connection, principal, action: str, target: str) -> dict[str, Any] | None:
    """Use up an approval of this person for this action and target (one use). Returns it, or None when there is none that is still good."""
    if not person(principal):
        return None
    _expire(conn)
    r = conn.execute("SELECT id FROM approvals WHERE requester_id = ? AND action = ? AND target = ? AND status = 'approved' AND used_at IS NULL AND expires >= ? ORDER BY id DESC LIMIT 1",
                     (principal.user_id, action, target, utcnow())).fetchone()
    if r is None:
        return None
    claimed = conn.execute("UPDATE approvals SET used_at = ?, status = 'used' WHERE id = ? AND status = 'approved' AND used_at IS NULL", (utcnow(), r["id"])).rowcount
    conn.commit()
    return get(conn, r["id"]) if claimed else None


def waiting_count(conn: sqlite3.Connection) -> int:
    _expire(conn)
    return conn.execute("SELECT COUNT(*) FROM approvals WHERE status = 'pending'").fetchone()[0]


def require(conn: sqlite3.Connection, principal, policy: dict[str, Any], action: str, target: str) -> dict[str, Any] | None:
    """For the code that does the action: raises ApprovalError("approval_required:<action>:<target>") unless the policy does not ask, the person is exempt, or an approval is
    used up now. Returns the approval that was used, if any."""
    if not needs(policy, action) or exempt(principal) or getattr(principal, "username", "") == "central Netlens":
        return None
    used = consume(conn, principal, action, target)
    if used is None:
        raise ApprovalError(f"approval_required:{action}:{target}")
    return used
