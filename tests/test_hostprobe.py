"""Host probes: the answers of the scripts, what grew between two snapshots, short-lived credentials, and a run against a real SSH server."""

import asyncio
import json
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import asyncssh
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from app import tsdb
from app.config import load_settings
from app.db import connect, init_db
from app.hostmetrics import service as hm
from app.hostprobe import credentials, parse, scripts, service
from app.main import create_app

GB = 1024 ** 3
MB = 1024 ** 2
AUTH = {"Authorization": "Bearer secret"}

OUTPUT = """##host
Linux 6.1
0
##df
Filesystem Type 1024-blocks Used Available Capacity Mounted on
/dev/sda1 ext4 102400000 96000000 4000000 96% /
//nas/media cifs 9999999 100 9999899 1% /media/plexmedia
##du /
96000000\t/
58720256\t/media
58720256\t/media/torrents
26214400\t/media/torrents/transmission/incomplete
##big /
16106127360\t1793000000.5\t/media/torrents/transmission/incomplete/Big.File.mkv.part
##dockerdf
Images|32|31|30.67GB|441kB (0%)
Containers|32|32|1.204GB|0B (0%)
##dockerps
sonarr|Up 10 days|120MB (virtual 300MB)
##dockerlogs
/sonarr|968884224|0
/uptime-kuma|2400000000|3
##deleted
2147483648|java|/tmp/x.log (deleted)
##end
"""


def snapshot(incomplete_gb: float, with_big=False, log_bytes=0):
    return {"platform": "linux", "partial": False, "mounts": [{"mount": "/", "fs": "ext4", "size": 100 * GB, "used": 90 * GB, "dirs": [
        {"path": "/", "bytes": 90 * GB}, {"path": "/media", "bytes": int((40 + incomplete_gb) * GB)}, {"path": "/media/torrents", "bytes": int((40 + incomplete_gb) * GB)},
        {"path": "/media/torrents/transmission", "bytes": int((40 + incomplete_gb) * GB)}, {"path": "/media/torrents/transmission/incomplete", "bytes": int((9 + incomplete_gb) * GB)},
        {"path": "/var", "bytes": 35 * GB}], "files": [{"path": "/media/torrents/transmission/incomplete/Big.mkv.part", "bytes": int(15 * GB), "mtime": 1}] if with_big else []}],
        "docker": {"usage": [], "containers": [{"name": "sonarr", "status": "Up", "layer_bytes": 0, "log_bytes": log_bytes, "restarts": 0}]}, "deleted": []}


# ----------------------------------------------------------------------------- reading the answers
def test_the_linux_answer_is_read():
    s = parse.parse_linux(OUTPUT)
    root = next(m for m in s["mounts"] if m["mount"] == "/")
    assert root["used"] == 96000000 * 1024 and root["dirs"][0]["path"] == "/" and root["files"][0]["bytes"] == 16106127360
    assert [m["mount"] for m in s["mounts"]] == ["/"]                           # the network share was not walked
    assert {c["name"]: c["log_bytes"] for c in s["docker"]["containers"]} == {"sonarr": 968884224, "uptime-kuma": 2400000000}
    assert s["docker"]["containers"][1]["restarts"] == 3 and s["deleted"][0]["process"] == "java" and s["deleted"][0]["path"] == "/tmp/x.log"
    assert s["docker"]["usage"][0]["bytes"] == 30670000000
    with pytest.raises(parse.ProbeError):
        parse.parse_linux(OUTPUT.replace("##end", ""))


def test_the_windows_answer_is_read():
    text = "noise\n##netlens-probe\n" + json.dumps({"vols": [{"id": "C:", "size": 500 * GB, "free": 100 * GB}], "partial": True,
                                                    "dirs": [{"p": "C:\\", "s": 400 * GB}, {"p": "C:\\Users\\bert\\Videos", "s": 90 * GB}],
                                                    "big": {"p": "C:\\Users\\bert\\Videos\\a.mkv", "s": 5 * GB, "m": "2026-10-24T16:07:06.0000000Z"}})
    s = parse.parse_windows(text)
    m = s["mounts"][0]
    assert s["platform"] == "windows" and s["partial"] and m["used"] == 400 * GB and m["dirs"][0]["path"] == "C:\\" and m["files"][0]["bytes"] == 5 * GB
    with pytest.raises(parse.ProbeError):
        parse.parse_windows("nothing")


def test_docker_sizes():
    assert parse.docker_size("30.67GB") == 30670000000 and parse.docker_size("441kB (0%)") == 441000 and parse.docker_size("1.2GB (virtual 3GB)") == 1200000000 and parse.docker_size("") == 0


# ----------------------------------------------------------------------------- what grew
def test_the_directory_that_explains_the_growth_is_named_not_its_parents():
    g = parse.compare(snapshot(0), snapshot(16, with_big=True, log_bytes=300 * MB))
    top = g["growth"][0]
    assert top["path"] == "/media/torrents/transmission/incomplete" and 15.9 * GB < top["bytes"] < 16.1 * GB
    assert not any(x["path"] in ("/media", "/media/torrents") for x in g["growth"])                      # the parents only repeat it
    assert any(x["kind"] == "file" and x["new"] for x in g["growth"]) and any(x["kind"] == "container log" for x in g["growth"])
    assert parse.compare(snapshot(0), snapshot(0))["growth"] == []


def test_a_small_change_is_not_news():
    assert parse.compare(snapshot(0), snapshot(0.05))["growth"] == []


# ----------------------------------------------------------------------------- the host side
def test_the_probe_script_is_valid_sh_and_only_reads():
    assert subprocess.run(["sh", "-n"], input=scripts.LINUX_SCRIPT.encode(), capture_output=True).returncode == 0
    for word in ("rm ", "mv ", "chmod", "chown", "kill", "tee ", "> /", "mkfs", "systemctl", "docker rm", "docker stop", "docker exec", "docker run", "truncate"):
        assert word not in scripts.LINUX_SCRIPT, word
    for word in ("Remove-Item", "Set-", "New-Item", "Stop-", "Start-", "Invoke-", "Write-", "Out-File"):
        assert word not in scripts.WINDOWS_SCRIPT, word


def test_the_lockdown_files():
    setup = scripts.linux_setup("netlens-ro", "ssh-ed25519 AAAAkey me", "ssh-ed25519 AAAAca netlens-ca")
    assert setup["authorized_keys"].startswith('command="sudo -n /usr/local/sbin/netlens-probe",restrict ssh-ed25519 AAAAkey')
    assert "NOPASSWD: /usr/local/sbin/netlens-probe" in setup["sudoers"] and "ForceCommand sudo -n /usr/local/sbin/netlens-probe" in setup["sshd_config"]
    assert "TrustedUserCAKeys" in setup["sshd_config"] and setup["script"].startswith("#!/bin/sh")
    win = scripts.windows_setup("netlens-ro", None, "ssh-ed25519 AAAAca netlens-ca")
    assert "authorized_keys" not in win and "ForceCommand" in win["sshd_config"] and "New-LocalUser" in win["install"]


# ----------------------------------------------------------------------------- short-lived credentials
@pytest.fixture
def conn(tmp_path):
    tsdb.forget_all()
    c = connect(tmp_path / "p.db")
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '127.0.0.1', 'docker1', 1, 'x', 'x')")
    c.commit()
    yield c
    c.close()
    tsdb.forget_all()


def test_the_netlens_ca_signs_certificates_that_last_minutes(conn):
    with pytest.raises(credentials.CredentialError):
        asyncio.run(credentials.issue(conn, "netlens_ca", {}, {}))
    pub = credentials.ca_create(conn)
    assert pub.startswith("ssh-ed25519 ") and credentials.ca_public(conn) == pub
    assert "BEGIN" not in json.dumps(service.public_settings(conn))                                   # the private key never leaves
    cred = asyncio.run(credentials.issue(conn, "netlens_ca", {"ttl_s": 120, "username": "ro"}, {}))
    cert = asyncssh.import_certificate(cred.certificate)
    assert cert.principals == ["ro"] and 100 < cred.expires - time.time() <= 121 and cred.source == "netlens_ca"
    assert 100 < cert._valid_before - time.time() <= 121 and cert._valid_after < time.time()                   # valid now, for two minutes
    other = asyncio.run(credentials.issue(conn, "netlens_ca", {}, {}))
    assert other.private_key != cred.private_key                                                      # a new key pair every time


def test_the_ttl_is_kept_within_bounds():
    assert credentials._ttl({"ttl_s": 5}) == credentials.MIN_TTL_S and credentials._ttl({"ttl_s": 10 ** 6}) == credentials.MAX_TTL_S and credentials._ttl({}) == credentials.DEFAULT_TTL_S


def test_a_vault_or_openbao_server_can_sign_instead(conn):
    ca = asyncssh.generate_private_key("ssh-ed25519")
    seen = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen["path"], seen["token"], seen["body"] = self.path, self.headers.get("X-Vault-Token"), body
            if self.path.endswith("/login"):
                out = {"auth": {"client_token": "tok-from-approle"}}
            else:
                cert = ca.generate_user_certificate(asyncssh.import_public_key(body["public_key"]), "vault", principals=[body["valid_principals"]], valid_after=int(time.time()) - 60, valid_before=int(time.time()) + 300)
                out = {"data": {"signed_key": cert.export_certificate("openssh").decode()}}
            data = json.dumps(out).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}"
        cred = asyncio.run(credentials.issue(conn, "vault_ssh", {"url": url, "mount": "ssh-client", "role": "netlens", "token": "root-token", "username": "ro", "ttl_s": 120}, {}))
        assert seen["path"] == "/v1/ssh-client/sign/netlens" and seen["token"] == "root-token" and seen["body"]["valid_principals"] == "ro" and seen["body"]["ttl"] == "120s"
        assert asyncssh.import_certificate(cred.certificate).principals == ["ro"] and cred.source == "vault_ssh"
        asyncio.run(credentials.issue(conn, "vault_ssh", {"url": url, "role_id": "r", "secret_id": "s"}, {"username": "ro"}))
        assert seen["token"] == "tok-from-approle"
    finally:
        server.shutdown()
    with pytest.raises(credentials.CredentialError):
        asyncio.run(credentials.issue(conn, "vault_ssh", {"url": "http://127.0.0.1:9", "token": "x"}, {}))
    with pytest.raises(credentials.CredentialError):
        asyncio.run(credentials.issue(conn, "vault_ssh", {}, {}))


def test_another_system_can_be_plugged_in(conn):
    async def teleport(conn, config, secret):
        return credentials.Credential("ro", password="short-lived", expires=time.time() + 60, source="teleport")

    credentials.register("teleport", teleport)
    try:
        assert asyncio.run(credentials.issue(conn, "teleport", {}, {})).password == "short-lived"
    finally:
        credentials.PROVIDERS.pop("teleport")


# ----------------------------------------------------------------------------- a real SSH server that trusts only the Netlens CA
@pytest_asyncio.fixture
async def host(conn):
    """Returns a function start(locked) -> port. The server accepts only certificates signed by the Netlens CA, for the user ro."""
    ca_pub = credentials.ca_create(conn)
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    commands: list[str] = []
    servers = []

    async def start(locked: bool) -> int:
        async def handle(process):
            commands.append(process.command)
            if locked or "netlens-probe" not in (process.command or ""):
                process.stdout.write(OUTPUT)
                process.exit(0)
            else:
                process.stderr.write("sh: netlens-probe: not found\n")
                process.exit(127)

        server = await asyncssh.create_server(asyncssh.SSHServer, "127.0.0.1", 0, server_host_keys=[host_key], process_factory=handle,
                                              authorized_client_keys=asyncssh.import_authorized_keys(f'cert-authority,principals="ro" {ca_pub}\n'), password_auth=False)
        servers.append(server)
        return server.sockets[0].getsockname()[1]

    yield start, commands
    for s in servers:
        s.close()
        await s.wait_closed()


@pytest.mark.asyncio
async def test_a_probe_with_a_short_lived_certificate_on_a_locked_host(conn, host):
    start, commands = host
    port = await start(locked=True)
    hm.save_monitor(conn, 1, {"method": "ssh", "address": "127.0.0.1", "port": port, "username": "ro", "password": "unused"})
    service.save_settings(conn, {"devices": {"1": {"enabled": True, "provider": "netlens_ca", "username": "ro"}}})
    result = await service.run(conn, 1)
    assert result["ok"], result["error"]
    assert result["mode"] == "locked" and commands == ["netlens-probe storage"]
    assert result["data"]["credential"]["source"] == "netlens_ca" and result["data"]["credential"]["certificate"] is True
    assert service.snapshots(conn, 1)[0]["ok"] is True and service.latest_ok(conn, 1)["data"]["mounts"][0]["mount"] == "/"


@pytest.mark.asyncio
async def test_a_host_without_the_script_gets_the_same_probe_directly(conn, host):
    start, commands = host
    port = await start(locked=False)
    hm.save_monitor(conn, 1, {"method": "ssh", "address": "127.0.0.1", "port": port, "username": "ro", "password": "unused"})
    service.save_settings(conn, {"devices": {"1": {"enabled": True, "provider": "netlens_ca", "username": "ro"}}})
    result = await service.run(conn, 1)
    assert result["ok"], result["error"]
    assert result["mode"] == "direct" and commands[0] == "netlens-probe storage" and commands[1].startswith("sh -c ")


@pytest.mark.asyncio
async def test_a_refused_login_is_stored_as_a_failed_snapshot(conn, host):
    start, _ = host
    port = await start(locked=True)
    hm.save_monitor(conn, 1, {"method": "ssh", "address": "127.0.0.1", "port": port, "username": "someone-else", "password": "x"})
    service.save_settings(conn, {"devices": {"1": {"enabled": True, "provider": "netlens_ca", "username": "someone-else"}}})
    result = await service.run_one(conn.execute("PRAGMA database_list").fetchone()[2], 1)
    assert not result["ok"] and "refused" in result["error"]
    assert service.snapshots(conn, 1)[0]["ok"] is False


@pytest.mark.asyncio
async def test_a_device_without_a_monitor_is_explained(conn):
    with pytest.raises(service.ProbeFailed, match="host monitor"):
        await service.run(conn, 1)


# ----------------------------------------------------------------------------- snapshots over time
def test_explain_compares_the_snapshot_before_with_the_one_after(conn):
    service.store(conn, 1, True, "locked", None, snapshot(0), now=time.mktime((2026, 10, 24, 12, 0, 0, 0, 0, 0)) - time.timezone)
    service.store(conn, 1, True, "locked", None, snapshot(16, with_big=True), now=time.mktime((2026, 10, 24, 18, 0, 0, 0, 0, 0)) - time.timezone)
    got = service.explain(conn, 1, "2026-10-24T16:05:00Z", "2026-10-24T16:24:00Z")
    assert got["growth"][0]["path"].endswith("/incomplete") and got["from"] == "2026-10-24T12:00:00Z" and got["to"] == "2026-10-24T18:00:00Z"
    assert "grew by 16.0 GB" in service.describe(got)[0]
    conn.execute("DELETE FROM probe_snapshots WHERE taken > '2026-10-24T13:00:00Z'")
    assert service.explain(conn, 1, "2026-10-24T16:05:00Z") is None                                    # one snapshot is nothing to compare


def test_old_snapshots_are_pruned(conn):
    for n in range(service.KEEP_MAX + 10):
        service.store(conn, 1, True, "direct", None, snapshot(0), now=time.time() - n)
    assert len(service.snapshots(conn, 1, 500)) == service.KEEP_MAX
    service.store(conn, 1, True, "direct", None, snapshot(0), now=time.time() - 40 * 86400)
    assert all(s["taken"] > "2000" for s in service.snapshots(conn, 1, 500))


def test_the_schedule(conn):
    service.save_settings(conn, {"devices": {"1": {"enabled": True, "interval_h": 6}}})
    now = time.time()
    assert service.due(conn, now) == [1]                                                              # never looked at
    service.store(conn, 1, True, "direct", None, snapshot(0), now=now - 3600)
    assert service.due(conn, now) == []
    assert service.due(conn, now + 6 * 3600) == [1]
    conn.execute("INSERT INTO host_monitors (id, device_id, method, address, port, created) VALUES (7, 1, 'ssh', 'a', 22, 'x')")
    conn.execute("INSERT INTO metric_state (monitor_id, metric, label, level, since, value) VALUES (7, 'disk_pct', '/', 'critical', 'x', 100)")
    conn.commit()
    assert service.due(conn, now) == [1]                                                              # a full disk: look again after half an hour, not six hours
    service.save_settings(conn, {"devices": {"1": {"enabled": False}}})
    assert service.due(conn, now) == []


def test_settings_are_checked_and_secrets_stay_secret(conn):
    saved = service.save_settings(conn, {"providers": {"vault_ssh": {"url": "https://vault:8200", "role": "netlens", "token": "s.verysecret"}}, "devices": {"1": {"enabled": True, "interval_h": 999, "provider": "netlens_ca"}}})
    assert saved["providers"]["vault_ssh"]["has_token"] is True and "verysecret" not in json.dumps(saved) and saved["devices"]["1"]["interval_h"] == 168
    for bad in ({"providers": {"x": {}}}, {"providers": {"vault_ssh": {"url": "ftp://x"}}}, {"devices": {"abc": {}}}, {"devices": {"1": {"provider": "magic"}}}):
        with pytest.raises(ValueError):
            service.save_settings(conn, bad)
    from app.db import get_setting

    assert "verysecret" not in conn.execute("SELECT value FROM settings WHERE key = 'hostprobe.settings'").fetchone()["value"]            # stored encrypted


# ----------------------------------------------------------------------------- the API
@pytest.fixture
def client(tmp_path):
    tsdb.forget_all()
    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'nas', 1, 'x', 'x')")
    c.commit()
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app, headers=AUTH) as tc:
        yield tc
    tsdb.forget_all()


def test_the_api(client):
    assert client.get("/api/hostprobe/settings").json()["ca_public_key"] is None
    ca = client.post("/api/hostprobe/ca").json()["ca_public_key"]
    assert ca.startswith("ssh-ed25519")
    setup = client.get("/api/hostprobe/setup", params={"platform": "linux", "user": "netlens-ro", "public_key": "ssh-ed25519 AAAA k"}).json()
    assert setup["has_ca"] and "ForceCommand" in setup["files"]["sshd_config"] and ca in setup["files"]["ca_public_key"] and setup["files"]["authorized_keys"].startswith("command=")
    assert client.get("/api/hostprobe/setup", params={"platform": "windows"}).json()["files"]["install"]
    assert client.get("/api/hostprobe/setup", params={"platform": "amiga"}).status_code == 422
    assert client.get("/api/hostprobe/setup", params={"user": "a b;rm"}).status_code == 422
    assert client.put("/api/hostprobe/settings", json={"providers": {"nope": {}}}).status_code == 422
    view = client.put("/api/devices/1/hostprobe", json={"enabled": True, "provider": "netlens_ca"}).json()
    assert view["config"]["enabled"] and view["monitor"] is None and view["latest"] is None
    assert client.get("/api/devices/99/hostprobe").status_code == 404
    run = client.post("/api/devices/1/hostprobe/run").json()
    assert run["ok"] is False and "host monitor" in run["error"]


# ----------------------------------------------------------------------------- records for compliance
def audit_rows(conn):
    return [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id")]


@pytest.mark.asyncio
async def test_a_scheduled_look_is_in_the_audit_log_with_the_certificate_id_and_no_secret(conn, host):
    start, _ = host
    port = await start(locked=True)
    hm.save_monitor(conn, 1, {"method": "ssh", "address": "127.0.0.1", "port": port, "username": "ro", "password": "hunter2-secret"})
    service.save_settings(conn, {"devices": {"1": {"enabled": True, "provider": "netlens_ca", "username": "ro"}}})
    result = await service.run_one(conn.execute("PRAGMA database_list").fetchone()[2], 1)
    assert result["ok"]
    rows = audit_rows(conn)
    assert len(rows) == 1 and rows[0]["user"] == "netlens" and rows[0]["role"] == "system" and rows[0]["method"] == "SYSTEM"
    text = rows[0]["action"]
    assert "Storage inspection of docker1 (scheduled)" in text and "certificate from the Netlens CA" in text and "id netlens-probe-" in text and "user ro" in text and "valid until" in text and "ok, locked script" in text
    everything = json.dumps(rows) + json.dumps(service.snapshots(conn, 1, 5, with_data=True))
    for secret in ("hunter2-secret", "BEGIN OPENSSH PRIVATE KEY", "AAAAC3Nza"):
        assert secret not in everything.replace(credentials.ca_public(conn), "")


@pytest.mark.asyncio
async def test_a_failed_look_and_a_look_by_a_person_are_recorded_too(conn, host):
    from types import SimpleNamespace

    start, _ = host
    port = await start(locked=True)
    hm.save_monitor(conn, 1, {"method": "ssh", "address": "127.0.0.1", "port": port, "username": "intruder", "password": "x"})
    service.save_settings(conn, {"devices": {"1": {"enabled": True, "provider": "netlens_ca", "username": "intruder"}}})
    await service.run_one(conn.execute("PRAGMA database_list").fetchone()[2], 1, actor=(SimpleNamespace(username="bert", role="admin"), "192.168.0.5"))
    row = audit_rows(conn)[0]
    assert row["user"] == "bert" and row["ip"] == "192.168.0.5" and row["status"] == 502 and "started by a person" in row["action"] and "failed:" in row["action"]


def test_changes_and_views_are_recorded_without_secret_values(client):
    from app.db import connect

    client.post("/api/hostprobe/ca")
    client.post("/api/hostprobe/ca")
    client.put("/api/hostprobe/settings", json={"providers": {"vault_ssh": {"url": "https://vault:8200", "token": "s.TOPSECRET"}}, "keep_days": 14})
    client.put("/api/devices/1/hostprobe", json={"enabled": True})
    client.get("/api/hostprobe/setup", params={"platform": "linux"})
    client.get("/api/hostprobe/setup", params={"platform": "linux"})                     # the same view again is not a second line
    db = connect(client.app.state.db_path)
    try:
        actions = [r["action"] for r in db.execute("SELECT action FROM audit_log ORDER BY id")]
        everything = json.dumps(actions)
    finally:
        db.close()
    assert actions[0].startswith("Created the Netlens SSH certificate authority (public key SHA256:") and actions[1].startswith("Replaced the Netlens SSH certificate authority") and "refuse new certificates" in actions[1]
    assert any(a.startswith("Changed the host probe settings: keep_days, vault_ssh.token, vault_ssh.url") for a in actions)
    assert any(a.startswith("Changed the storage inspection of nas") for a in actions)
    assert sum(1 for a in actions if a.startswith("Viewed the files that prepare a linux host")) == 1
    assert "TOPSECRET" not in everything and "BEGIN" not in everything


def test_viewing_the_names_is_recorded_once_in_a_while(client):
    from app.db import connect
    from app.hostprobe import service as probes

    db = connect(client.app.state.db_path)
    probes.store(db, 1, True, "locked", None, snapshot(1), now=time.time())
    db.close()
    for _ in range(3):
        assert client.get("/api/devices/1/hostprobe").status_code == 200
    db = connect(client.app.state.db_path)
    try:
        lines = [r for r in db.execute("SELECT * FROM audit_log WHERE method = 'GET'")]
    finally:
        db.close()
    assert len(lines) == 1 and "Viewed the storage inspection of nas" in lines[0]["action"]


def test_the_snapshots_are_kept_for_the_chosen_number_of_days(conn):
    service.save_settings(conn, {"keep_days": 2})
    service.store(conn, 1, True, "direct", None, snapshot(0), now=time.time() - 3 * 86400)
    service.store(conn, 1, True, "direct", None, snapshot(0), now=time.time() - 3600)
    assert len(service.snapshots(conn, 1)) == 1
