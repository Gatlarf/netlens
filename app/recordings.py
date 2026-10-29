"""Terminal session recording (Enterprise).

When switched on (Settings -> Sign-in security), every web-terminal session (SSH and Telnet) is recorded: what the host sent to the screen, with its timing. What the person **types
is not recorded**: it would capture the passwords typed at prompts. (What a shell echoes of a command is part of the screen, so the commands are there.) Remote desktop
sessions are not recorded by Netlens (the remote desktop helper, guacd, can record them; see README).

How a recording is kept:
  * each piece of output is one **encrypted** record (AES-256-GCM, a key derived from the master key); the authenticated data names the recording and the position, so
    pieces cannot be removed from the middle, reordered or moved between recordings; an end record holds the count, so cutting off the end is seen;
  * the file's SHA-256 is written into the audit log when the session ends, so the tamper-evident audit chain vouches for it;
  * a recording stops growing at 20 MiB of output (the session goes on; the recording says it was cut);
  * recordings are deleted after the number of days in the policy; watching or downloading one is an audit line and, with step-up on, needs a fresh confirmation.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import struct
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import vault
from app.db import insert_id, utcnow

DIR_NAME = "recordings"
MAX_PLAIN_BYTES = 20 * 1024 * 1024
_MAGIC = b"NLREC1\n"


class RecordingError(ValueError):
    """A sentence the user can act on."""


def _dir(data_dir: Path) -> Path:
    path = Path(data_dir) / DIR_NAME
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def _aad(rec_id: int, index: int) -> bytes:
    return f"netlens-recording:{rec_id}:{index}".encode()


class Recorder:
    """One open recording. `write` never raises: a problem with the recording must not end the session."""

    def __init__(self, conn: sqlite3.Connection, data_dir: Path, user: str, device_id: int, device: str, proto: str) -> None:
        self.conn = conn
        self.started = time.monotonic()
        self.index = 0
        self.plain = 0
        self.truncated = False
        self.failed = False
        self.id = insert_id(conn, "INSERT INTO session_recordings (user, device_id, device, proto, started, status, file) VALUES (?,?,?,?,?, 'recording', '')", (user[:60], device_id, device[:120], proto, utcnow())) or 0
        conn.commit()
        self.name = f"{self.id}-{secrets.token_hex(6)}.rec"
        self.path = _dir(data_dir) / self.name
        self.key = vault.derive_key(conn, "session-recording-v1")
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.file = os.fdopen(fd, "wb")
        self.file.write(_MAGIC)
        conn.execute("UPDATE session_recordings SET file = ? WHERE id = ?", (self.name, self.id))
        conn.commit()

    def _record(self, payload: list) -> None:
        raw = json.dumps(payload, separators=(",", ":")).encode()
        nonce = secrets.token_bytes(12)
        sealed = nonce + AESGCM(self.key).encrypt(nonce, raw, _aad(self.id, self.index))
        self.file.write(struct.pack(">I", len(sealed)) + sealed)
        self.index += 1

    def write(self, data: bytes) -> None:
        if self.failed or self.truncated or not data:
            return
        try:
            if self.plain + len(data) > MAX_PLAIN_BYTES:
                self.truncated = True
                self._record([round(time.monotonic() - self.started, 3), "x", "the recording stopped here: it reached its size limit"])
                return
            self.plain += len(data)
            self._record([round(time.monotonic() - self.started, 3), "o", data.decode("utf-8", "replace")])
        except Exception:      # noqa: BLE001 - the session matters more than its recording
            self.failed = True

    def close(self, audit_user: Any = None, ip: str = "") -> None:
        """Finish: the end record, the file's hash into the database and the audit log."""
        try:
            self._record([round(time.monotonic() - self.started, 3), "end", self.index])
            self.file.flush()
            os.fsync(self.file.fileno())
        except Exception:      # noqa: BLE001
            self.failed = True
        finally:
            try:
                self.file.close()
            except Exception:      # noqa: BLE001
                pass
        digest = hashlib.sha256(self.path.read_bytes()).hexdigest() if self.path.exists() else ""
        self.conn.execute("UPDATE session_recordings SET ended = ?, bytes = ?, chunks = ?, truncated = ?, sha256 = ?, status = ? WHERE id = ?",
                          (utcnow(), self.plain, self.index, 1 if self.truncated else 0, digest, "incomplete" if self.failed else "done", self.id))
        self.conn.commit()
        from app import audit

        row = self.conn.execute("SELECT * FROM session_recordings WHERE id = ?", (self.id,)).fetchone()
        audit.record_by(self.conn, audit_user, ip, "WS", f"/api/recordings/{self.id}", 200,
                        f"Recorded the terminal session #{self.id} of {row['user']} on {row['device']} ({row['proto'].upper()}, {row['bytes']} bytes of output{', cut at the size limit' if self.truncated else ''}); file sha256 {digest[:24]}…")


def _read_frames(conn: sqlite3.Connection, data_dir: Path, row) -> tuple[list[list], bool, str]:
    """(frames, verified, why not). Every piece is authenticated; the count in the end record and the hash in the database are checked."""
    path = _dir(data_dir) / str(row["file"])
    try:
        blob = path.read_bytes()
    except OSError:
        raise RecordingError("the recording file is missing") from None
    if not blob.startswith(_MAGIC):
        raise RecordingError("this is not a Netlens recording")
    key = vault.derive_key(conn, "session-recording-v1")
    frames, pos, index, ended = [], len(_MAGIC), 0, False
    problem = ""
    while pos + 4 <= len(blob):
        (size,) = struct.unpack(">I", blob[pos:pos + 4])
        sealed = blob[pos + 4:pos + 4 + size]
        if len(sealed) != size or size < 13:
            problem = "the file is cut off in the middle of a piece"
            break
        try:
            item = json.loads(AESGCM(key).decrypt(sealed[:12], sealed[12:], _aad(row["id"], index)))
        except (InvalidTag, ValueError):
            problem = "a piece of the recording does not verify: it was changed, removed or moved"
            break
        pos += 4 + size
        index += 1
        if item[1] == "end":
            ended = item[2] == index - 1
            if not ended:
                problem = "the end record does not match the number of pieces"
            break
        frames.append(item)
    if not problem and not ended:
        problem = "the recording has no end (the session was cut off, or the end was removed)"
    if not problem and row["sha256"] and hashlib.sha256(blob).hexdigest() != row["sha256"]:
        problem = "the file does not match the hash that was written to the audit log when the session ended"
    return frames, not problem, problem


def listing(conn: sqlite3.Connection, limit: int = 100) -> list[dict[str, Any]]:
    return [dict(r) | {"truncated": bool(r["truncated"])} for r in conn.execute(
        "SELECT id, user, device_id, device, proto, started, ended, bytes, truncated, status, sha256 FROM session_recordings ORDER BY id DESC LIMIT ?", (max(1, min(limit, 500)),))]


def get(conn: sqlite3.Connection, data_dir: Path, rec_id: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM session_recordings WHERE id = ?", (rec_id,)).fetchone()
    if row is None:
        raise RecordingError("no such recording")
    frames, ok, why = _read_frames(conn, data_dir, row)
    return {"id": row["id"], "user": row["user"], "device": row["device"], "proto": row["proto"], "started": row["started"], "ended": row["ended"], "truncated": bool(row["truncated"]),
            "frames": frames, "verified": ok, "problem": why}


def asciicast(conn: sqlite3.Connection, data_dir: Path, rec_id: int) -> str:
    """The recording as asciinema v2 text (one header line, then [time, "o", text] lines), for tools that play it."""
    rec = get(conn, data_dir, rec_id)
    started = int(time.mktime(time.strptime(rec["started"], "%Y-%m-%dT%H:%M:%SZ")))
    lines = [json.dumps({"version": 2, "width": 120, "height": 30, "timestamp": started, "title": f"{rec['user']} on {rec['device']}"})]
    lines += [json.dumps([f[0], "o", f[2]]) for f in rec["frames"] if f[1] == "o"]
    return "\n".join(lines) + "\n"


def delete(conn: sqlite3.Connection, data_dir: Path, rec_id: int) -> bool:
    row = conn.execute("SELECT file FROM session_recordings WHERE id = ?", (rec_id,)).fetchone()
    if row is None:
        return False
    try:
        (_dir(data_dir) / str(row["file"])).unlink(missing_ok=True)
    except OSError:
        pass
    conn.execute("DELETE FROM session_recordings WHERE id = ?", (rec_id,))
    conn.commit()
    return True


def prune(conn: sqlite3.Connection, data_dir: Path, days: int) -> int:
    """Delete recordings older than `days` (and files that no row knows)."""
    from datetime import datetime, timedelta, timezone

    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    gone = 0
    for row in conn.execute("SELECT id FROM session_recordings WHERE started < ? AND status != 'recording'", (cutoff,)).fetchall():
        gone += 1 if delete(conn, data_dir, row["id"]) else 0
    known = {r[0] for r in conn.execute("SELECT file FROM session_recordings")}
    for path in _dir(data_dir).glob("*.rec"):
        if path.name not in known and time.time() - path.stat().st_mtime > 86400:
            path.unlink(missing_ok=True)
    return gone
