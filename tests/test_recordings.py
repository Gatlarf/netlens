"""Terminal session recording: encrypted, ordered, verifiable, never holding what was typed."""

import hashlib
import json
import struct

import pytest
from fastapi.testclient import TestClient

from app import licence, recordings, secpolicy, vault
from app.db import connect, init_db
from tests.fake_terminal import FakeBackend
from tests.test_api_terminal_session import FIXTURE

ADMIN = {"Authorization": "Bearer t"}


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    yield c
    c.close()


def record(conn, tmp_path, chunks=("hello\r\n", "world")):
    r = recordings.Recorder(conn, tmp_path, "alice", 1, "web01", "ssh")
    for chunk in chunks:
        r.write(chunk.encode())
    r.close(None, "10.0.0.1")
    return r


def test_a_recording_is_encrypted_and_plays_back_with_its_timing(conn, tmp_path):
    r = record(conn, tmp_path, ("secret-output-1\r\n", "more\r\n"))
    raw = r.path.read_bytes()
    assert b"secret-output" not in raw and raw.startswith(b"NLREC1")
    assert r.path.stat().st_mode & 0o777 == 0o600 and (tmp_path / "recordings").stat().st_mode & 0o777 == 0o700
    rec = recordings.get(conn, tmp_path, r.id)
    assert rec["verified"] and [f[2] for f in rec["frames"]] == ["secret-output-1\r\n", "more\r\n"] and rec["frames"][0][0] <= rec["frames"][1][0]
    row = conn.execute("SELECT * FROM session_recordings WHERE id = ?", (r.id,)).fetchone()
    assert row["status"] == "done" and row["sha256"] == hashlib.sha256(raw).hexdigest() and row["chunks"] == 3
    audit = conn.execute("SELECT action FROM audit_log WHERE path = ?", (f"/api/recordings/{r.id}",)).fetchone()[0]
    assert row["sha256"][:24] in audit and "secret-output" not in audit
    cast = recordings.asciicast(conn, tmp_path, r.id)
    assert cast.splitlines()[0].startswith('{"version": 2') and json.loads(cast.splitlines()[1])[2] == "secret-output-1\r\n"


def test_every_kind_of_tampering_is_found(conn, tmp_path):
    r = record(conn, tmp_path, ("one\r\n", "two\r\n", "three\r\n"))
    good = r.path.read_bytes()

    def pieces(blob):
        pos, out = len(recordings._MAGIC), []
        while pos < len(blob):
            (n,) = struct.unpack(">I", blob[pos:pos + 4])
            out.append(blob[pos:pos + 4 + n])
            pos += 4 + n
        return out

    parts = pieces(good)
    cases = {"changed": good[:-3] + bytes([good[-3] ^ 1]) + good[-2:], "removed middle": recordings._MAGIC + parts[0] + parts[2] + parts[3],
             "reordered": recordings._MAGIC + parts[1] + parts[0] + parts[2] + parts[3], "cut off the end": recordings._MAGIC + b"".join(parts[:-1]), "cut in a piece": good[:-5]}
    for name, blob in cases.items():
        r.path.write_bytes(blob)
        rec = recordings.get(conn, tmp_path, r.id)
        assert not rec["verified"] and rec["problem"], name
    r.path.write_bytes(good)
    assert recordings.get(conn, tmp_path, r.id)["verified"]
    other = record(conn, tmp_path, ("one\r\n", "two\r\n", "three\r\n"))
    r.path.write_bytes(other.path.read_bytes())                                              # a recording moved to another id does not verify
    assert not recordings.get(conn, tmp_path, r.id)["verified"]


def test_the_size_limit_cuts_the_recording_not_the_session(conn, tmp_path, monkeypatch):
    monkeypatch.setattr(recordings, "MAX_PLAIN_BYTES", 100)
    r = record(conn, tmp_path, ("x" * 60, "y" * 60, "z" * 10))
    rec = recordings.get(conn, tmp_path, r.id)
    assert rec["verified"] and rec["truncated"] and [f[1] for f in rec["frames"]] == ["o", "x"]
    assert conn.execute("SELECT truncated FROM session_recordings").fetchone()[0] == 1


def test_a_failing_recording_never_raises_into_the_session(conn, tmp_path):
    r = recordings.Recorder(conn, tmp_path, "alice", 1, "web01", "ssh")
    r.file.close()                                                                            # the disk went away
    r.write(b"still fine")                                                                    # no exception
    r.close(None, "")
    assert conn.execute("SELECT status FROM session_recordings").fetchone()[0] == "incomplete"


def test_retention_deletes_old_recordings_and_their_files(conn, tmp_path):
    old, new = record(conn, tmp_path), record(conn, tmp_path)
    conn.execute("UPDATE session_recordings SET started = '2020-01-01T00:00:00Z' WHERE id = ?", (old.id,))
    conn.commit()
    assert recordings.prune(conn, tmp_path, 90) == 1
    assert not old.path.exists() and new.path.exists()
    assert recordings.delete(conn, tmp_path, new.id) and not new.path.exists() and not recordings.delete(conn, tmp_path, new.id)


# ------------------------------------------------------------------ through the terminal
def test_a_terminal_session_is_recorded_when_the_policy_says_so_and_what_is_typed_is_not(tmp_path, monkeypatch):
    monkeypatch.setattr(licence, "allows", lambda c, feature, now=None: True)
    secpolicy.forget()
    FakeBackend.reset()
    from app.config import load_settings
    from app.main import create_app
    from app.scanner.nmap_parser import parse_nmap_xml
    from app.scanner.store import save_scan_results

    boot = connect(tmp_path / "t.db")
    init_db(boot)
    save_scan_results(boot, parse_nmap_xml(FIXTURE.read_text(encoding="utf-8")), "deep")
    boot.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "t", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=tmp_path / "t.db")
    app.state.terminal_backends = {"ssh": FakeBackend, "telnet": FakeBackend}
    with TestClient(app, headers=ADMIN) as c:
        url = "/api/terminal/1/ws?proto=ssh"
        with c.websocket_connect(url, headers=ADMIN) as ws:
            ws.send_json({"type": "auth", "username": "bob", "password": "pw", "cols": 80, "rows": 24})
            assert ws.receive_json()["state"] == "connected"
        assert c.get("/api/recordings").json()["recordings"] == []                              # off by default
        assert c.put("/api/security-policy", json={"record_sessions": True, "recording_days": 30}).status_code == 200
        with c.websocket_connect(url, headers=ADMIN) as ws:
            ws.send_json({"type": "auth", "username": "bob", "password": "AuthSecret9", "cols": 80, "rows": 24})
            assert ws.receive_json()["state"] == "connected"
            ws.send_bytes(b"ls -l\r")
            ws.receive_bytes()
        items = c.get("/api/recordings").json()
        assert items["enabled"] and items["days"] == 30 and len(items["recordings"]) == 1
        rec = c.get(f"/api/recordings/{items['recordings'][0]['id']}").json()
        assert rec["verified"] and any("welcome" in f[2] for f in rec["frames"]) and "AuthSecret9" not in json.dumps(rec) and any("ls -l" in f[2] for f in rec["frames"])          # the login password is never in it; what the host echoed back (the command) is
        blob = (tmp_path / "recordings").glob("*.rec").__next__().read_bytes()
        assert b"welcome" not in blob and b"AuthSecret9" not in blob
        audit = " ".join(r["action"] for r in c.get("/api/audit").json()["entries"])
        assert "Recorded the terminal session" in audit and "Watched the recording" in audit and "AuthSecret9" not in audit
        assert c.get(f"/api/recordings/{items['recordings'][0]['id']}/download").text.startswith('{"version": 2')
        assert c.delete(f"/api/recordings/{items['recordings'][0]['id']}").json() == {"deleted": True}
        assert c.get("/api/recordings/999").status_code == 404
        c.post("/api/users", json={"username": "vera", "password": "longenough1", "role": "viewer"})
        v = TestClient(app)
        v.headers.pop("authorization", None)
        v.post("/api/login", json={"username": "vera", "password": "longenough1"})
        assert v.get("/api/recordings").status_code == 403
    secpolicy.forget()
