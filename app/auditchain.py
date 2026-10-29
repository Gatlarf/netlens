"""A tamper-evident audit log.

Every line of the audit log carries a **chain** value: an HMAC-SHA256 (keyed with a key derived from the master key of the installation) over the line and the chain value
of the line before it. Changing a line, inserting one, or removing one from the middle breaks the chain from that point on, and nobody can repair it without the key.

What this does **not** do, said plainly: somebody who can write to the database *and* has the key can rebuild the whole chain, and a line removed from the very end leaves a
valid chain. That is what the **anchors** are for: once an hour, if there is anything new, Netlens writes a line that holds the newest chain value. Log forwarding
(Settings → Log forwarding) sends audit lines to your SIEM like any other, so the SIEM holds a copy of the chain that Netlens cannot reach. `verify()` also checks the
anchors it still has.

Pruning (retention) removes the oldest lines; it keeps the chain value of the last line removed, so what is left can still be verified.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from typing import Any

from app import vault
from app.db import get_setting, insert_id, set_setting, utcnow

BASE_KEY = "audit.chain_base"            # {"id": n, "chain": hex}: the last line that was pruned
LAST_KEY = "audit.verify_last"           # the latest verification result (so the interface and the problem list need not recompute)
ANCHOR_MARK = "Audit chain anchor:"
_lock = threading.Lock()                 # one writer links to the line before it at a time


def _mac(conn: sqlite3.Connection, prev: str, fields: list) -> str:
    key = vault.derive_key(conn, "audit-chain-v1")
    body = json.dumps([prev, *fields], separators=(",", ":"), ensure_ascii=True).encode()
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def _fields(row: Any) -> list:
    return [row["id"], row["ts"], row["user"], row["role"], row["ip"], row["method"], row["path"], row["status"], row["action"]]


def append(conn: sqlite3.Connection, ts: str, user: str, role: str, ip: str, method: str, path: str, status: int, action: str) -> None:
    """Insert one audit line and link it. The write must never fail because of the chain: a line that could not be linked is written without one and shows in `verify()`."""
    with _lock:
        last = conn.execute("SELECT chain FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev = (last["chain"] if last is not None else None) or ""
        row_id = insert_id(conn, "INSERT INTO audit_log (ts, user, role, ip, method, path, status, action) VALUES (?,?,?,?,?,?,?,?)", (ts, user, role, ip, method, path, status, action))
        try:
            chain = _mac(conn, prev, [row_id, ts, user, role, ip, method, path, status, action])
            conn.execute("UPDATE audit_log SET chain = ? WHERE id = ?", (chain, row_id))
        except Exception:          # noqa: BLE001 - the audit line itself matters more than its link
            pass
        conn.commit()


def prune(conn: sqlite3.Connection, cutoff_ts: str | None = None, max_rows: int | None = None, dry_run: bool = False) -> int:
    """Remove the oldest lines (older than `cutoff_ts`, or beyond the newest `max_rows`) and remember where the chain now starts. Returns how many lines went."""
    with _lock:
        newest = conn.execute("SELECT COALESCE(MAX(id), 0) FROM audit_log").fetchone()[0]
        cut = 0
        if cutoff_ts:
            cut = max(cut, conn.execute("SELECT COALESCE(MAX(id), 0) FROM audit_log WHERE ts < ?", (cutoff_ts,)).fetchone()[0])
        if max_rows is not None:
            cut = max(cut, newest - max_rows)
        if cut <= 0:
            return 0
        if dry_run:
            return conn.execute("SELECT COUNT(*) FROM audit_log WHERE id <= ?", (cut,)).fetchone()[0]
        last = conn.execute("SELECT id, chain FROM audit_log WHERE id <= ? ORDER BY id DESC LIMIT 1", (cut,)).fetchone()
        if last is not None and last["chain"]:
            set_setting(conn, BASE_KEY, json.dumps({"id": last["id"], "chain": last["chain"]}))
        removed = conn.execute("DELETE FROM audit_log WHERE id <= ?", (cut,)).rowcount
        conn.commit()
        return removed


def _base(conn: sqlite3.Connection) -> tuple[int, str]:
    try:
        data = json.loads(get_setting(conn, BASE_KEY) or "{}")
        return int(data.get("id") or 0), str(data.get("chain") or "")
    except (ValueError, TypeError):
        return 0, ""


def verify(conn: sqlite3.Connection, save: bool = True) -> dict:
    """Walk the log from where the chain starts and recompute every link.

    Returns {"ok", "checked", "head": {"id", "chain"}, "unchained": n (older lines from before the chain existed), "problem": None or {"id", "kind", "text"}, "anchors_checked", "at"}.
    The first problem found is reported; later lines cannot be trusted after it."""
    base_id, base_chain = _base(conn)
    prev, started, checked, unchained, head = base_chain, bool(base_chain), 0, 0, {"id": base_id, "chain": base_chain}
    problem = None
    anchors: list[tuple[int, str, int]] = []                  # (anchor line id, chain it names, id it names)
    for row in conn.execute("SELECT id, ts, user, role, ip, method, path, status, action, chain FROM audit_log WHERE id > ? ORDER BY id", (base_id,)):
        if not row["chain"]:
            if started:
                problem = {"id": row["id"], "kind": "unchained", "text": "a line without a chain value after the chain began: it was inserted or its chain was removed"}
                break
            unchained += 1
            continue
        expected = _mac(conn, prev, _fields(row))
        if not hmac.compare_digest(expected, row["chain"]):
            problem = {"id": row["id"], "kind": "broken", "text": "this line, or one before it, was changed, inserted or removed (if the encryption key was replaced, every line shows this)"}
            break
        started, prev, checked, head = True, row["chain"], checked + 1, {"id": row["id"], "chain": row["chain"]}
        if row["action"].startswith(ANCHOR_MARK):
            anchors.append((row["id"], row["action"], 0))
    anchors_checked = 0
    if problem is None:
        for _id, text, _x in anchors[-50:]:
            named = text[len(ANCHOR_MARK):].split()
            if len(named) >= 4 and named[0] == "row" and named[2] == "chain":
                at = int(named[1].rstrip(",")) if named[1].rstrip(",").isdigit() else 0
                found = conn.execute("SELECT chain FROM audit_log WHERE id = ?", (at,)).fetchone()
                if found is None and at > base_id:
                    problem = {"id": at, "kind": "missing", "text": f"line {at}, which an anchor names, is not in the log any more"}
                    break
                if found is not None and found["chain"] != named[3]:
                    problem = {"id": at, "kind": "anchor", "text": f"line {at} does not match the chain value that an anchor recorded for it"}
                    break
                anchors_checked += 1
    result = {"ok": problem is None, "checked": checked, "head": head, "unchained": unchained, "problem": problem, "anchors_checked": anchors_checked, "at": utcnow()}
    if save:
        set_setting(conn, LAST_KEY, json.dumps(result))
        conn.commit()
    return result


def last_result(conn: sqlite3.Connection) -> dict | None:
    try:
        return json.loads(get_setting(conn, LAST_KEY) or "null")
    except ValueError:
        return None


def anchor(conn: sqlite3.Connection) -> bool:
    """Write the anchor line (the newest chain value) if there is something new since the last one. Returns whether a line was written."""
    from app import audit

    last = conn.execute("SELECT id, chain, action FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    if last is None or not last["chain"] or last["action"].startswith(ANCHOR_MARK):
        return False
    audit.record_system(conn, f"{ANCHOR_MARK} row {last['id']}, chain {last['chain']}", "/audit/anchor")
    return True


def check(conn: sqlite3.Connection) -> dict:
    """Verify, and raise a critical event once when the log fails (and again only if it fails at a different place)."""
    from app.db import add_event

    before = last_result(conn)
    result = verify(conn)
    if not result["ok"]:
        same = before and not before.get("ok") and (before.get("problem") or {}).get("id") == result["problem"]["id"]
        if not same:
            add_event(conn, "audit_tampered", f"Audit log integrity check failed at line {result['problem']['id']}: {result['problem']['text']}")
    return result


async def loop(db_path: str) -> None:
    """Hourly: an anchor line when there is something new; every six hours: a full check."""
    import asyncio

    from app.db import connect

    def work(n: int) -> None:
        conn = connect(db_path)
        try:
            anchor(conn)
            if n % 6 == 0:
                check(conn)
        finally:
            conn.close()

    await asyncio.sleep(90)
    n = 0
    while True:
        try:
            await asyncio.to_thread(work, n)
        except Exception:      # noqa: BLE001 - a failed round must not stop the next one
            pass
        n += 1
        await asyncio.sleep(3600)
