"""SSH through a bastion (jump) or a PAM session proxy, against real asyncssh servers: the target's host key is still checked through a bastion, the bastion's can be
pinned, a proxy gets the user name from a template, the login for the bastion can come from the PAM, and nothing secret is shown."""

import asyncio
import json

import asyncssh
import pytest
import pytest_asyncio

from app import credstore, sshroute
from app.db import connect, init_db
from app.hostmetrics import ssh
from app.terminal.base import ConnectFailed, HostKeyMismatch
from app.terminal.ssh import SSHBackend


class Seen:
    users: list[str] = []
    forwards: list[tuple] = []


def make_server(passwords, allow_forward=False, banner="target"):
    class S(asyncssh.SSHServer):
        def connection_made(self, conn):
            self.conn = conn

        def begin_auth(self, username):
            return True

        def password_auth_supported(self):
            return True

        def validate_password(self, username, password):
            Seen.users.append(username)
            return passwords.get(username) == password

        def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
            Seen.forwards.append((dest_host, dest_port))
            return allow_forward

    async def handle(process):
        if process.command:
            process.stdout.write(f"{banner}:{process.command}")
            process.exit(0)
            return
        process.stdout.write(f"{banner} shell\r\n".encode() if False else f"{banner} shell\r\n")
        process.exit(0)

    return S, handle


async def start(passwords, allow_forward=False, banner="target"):
    key = asyncssh.generate_private_key("ssh-ed25519")
    S, handle = make_server(passwords, allow_forward, banner)
    server = await asyncssh.create_server(S, "127.0.0.1", 0, server_host_keys=[key], process_factory=handle, encoding="utf-8")
    return server, server.sockets[0].getsockname()[1], key.get_fingerprint("sha256")


@pytest_asyncio.fixture
async def lab():
    Seen.users, Seen.forwards = [], []
    bastion, bport, bfp = await start({"jumper": "jp-pw"}, allow_forward=True, banner="bastion")
    target, tport, tfp = await start({"svc": "target-pw"})
    proxy, pport, pfp = await start({"svc@web01": "proxy-pw", "svc@127.0.0.1": "proxy-pw"}, banner="proxy")
    yield {"bport": bport, "bfp": bfp, "tport": tport, "tfp": tfp, "pport": pport, "pfp": pfp}
    for s in (bastion, target, proxy):
        s.close()
        await s.wait_closed()


def jump(lab, **over):
    return {"mode": "jump", "host": "127.0.0.1", "port": lab["bport"], "fingerprint": lab["bfp"], "login": {"username": "jumper", "password": "jp-pw"}, **over}


# ------------------------------------------------------------------ the route itself
@pytest.mark.asyncio
async def test_a_command_goes_through_the_bastion_and_the_target_key_is_still_checked(lab):
    out, status, fp = await ssh.run_command("127.0.0.1", lab["tport"], "svc", "target-pw", None, None, "uptime", None, route=jump(lab))
    assert out == "target:uptime" and status == 0 and fp == lab["tfp"]                      # the key seen is the TARGET's, not the bastion's
    assert Seen.forwards and Seen.forwards[-1][1] == lab["tport"]
    with pytest.raises(ssh.SshError, match="host key"):
        await ssh.run_command("127.0.0.1", lab["tport"], "svc", "target-pw", None, None, "uptime", "SHA256:" + "A" * 43, route=jump(lab))


@pytest.mark.asyncio
async def test_the_bastion_key_can_be_pinned_and_its_login_must_work(lab):
    with pytest.raises(ssh.SshError, match="not the one that was pinned"):
        await ssh.run_command("127.0.0.1", lab["tport"], "svc", "target-pw", None, None, "x", None, route=jump(lab, fingerprint="SHA256:" + "B" * 43))
    with pytest.raises(ssh.SshError, match="bastion refused"):
        await ssh.run_command("127.0.0.1", lab["tport"], "svc", "target-pw", None, None, "x", None, route=jump(lab, login={"username": "jumper", "password": "wrong"}))
    with pytest.raises(ssh.SshError, match="cannot reach the bastion"):
        await ssh.run_command("127.0.0.1", lab["tport"], "svc", "target-pw", None, None, "x", None, route=jump(lab, port=1), timeout=3)


@pytest.mark.asyncio
async def test_a_bastion_that_refuses_to_forward_gives_no_session(lab):
    Seen.forwards.clear()
    nofwd, nport, nfp = await start({"jumper": "jp-pw"}, allow_forward=False)
    try:
        with pytest.raises(ssh.SshError):
            await ssh.run_command("127.0.0.1", lab["tport"], "svc", "target-pw", None, None, "x", None, route=jump(lab, port=nport, fingerprint=nfp))
    finally:
        nofwd.close()


@pytest.mark.asyncio
async def test_a_proxy_gets_the_user_name_from_the_template_and_is_the_only_hop(lab):
    route = {"mode": "proxy", "host": "127.0.0.1", "port": lab["pport"], "template": "{user}@{target}", "fingerprint": lab["pfp"]}
    out, status, fp = await ssh.run_command("127.0.0.1", lab["tport"], "svc", "proxy-pw", None, None, "id", None, route=route)
    assert out == "proxy:id" and "svc@127.0.0.1" in Seen.users and fp == lab["pfp"] and not Seen.forwards
    with pytest.raises(ssh.SshError, match="host key"):
        await ssh.run_command("127.0.0.1", lab["tport"], "svc", "proxy-pw", None, None, "id", None, route={**route, "fingerprint": "SHA256:" + "C" * 43})


@pytest.mark.asyncio
async def test_the_terminal_uses_the_route_and_still_reports_a_changed_target_key(lab):
    backend = SSHBackend(host="127.0.0.1", port=lab["tport"], username="svc", password="target-pw", route=jump(lab))
    await backend.connect()
    assert backend.fingerprint == lab["tfp"]
    await backend.close()
    bad = SSHBackend(host="127.0.0.1", port=lab["tport"], username="svc", password="target-pw", route=jump(lab), known_fingerprint="SHA256:" + "D" * 43)
    with pytest.raises(HostKeyMismatch):
        await bad.connect()
    broken = SSHBackend(host="127.0.0.1", port=lab["tport"], username="svc", password="target-pw", route=jump(lab, login={"username": "jumper", "password": "no"}))
    with pytest.raises(ConnectFailed, match="bastion refused"):
        await broken.connect()


# ------------------------------------------------------------------ the rules for a route
def test_template_and_route_validation():
    ok = {"route_mode": "proxy", "route_host": "psm.example.com", "route_port": "22", "route_template": "{user}@{target}"}
    sshroute.validate(ok)
    for bad in ({"route_mode": "teleport"}, {**ok, "route_host": "a b"}, {**ok, "route_host": ""}, {**ok, "route_port": "0"}, {**ok, "route_port": "x"}, {**ok, "route_template": ""},
                {**ok, "route_template": "{user}@{pwd}"}, {**ok, "route_template": "{user}@{target}\n"}, {**ok, "route_template": "{user} {target}"}, {**ok, "route_template": "{user}@{target"},
                {**ok, "route_fingerprint": "nope"}, {"route_mode": "jump", "route_host": "b", "route_port": "22"}):
        with pytest.raises(sshroute.RouteError):
            sshroute.validate(bad)
    assert sshroute.username_for("{user}@{target}:{port}", "svc", "10.0.0.5", 22) == "svc@10.0.0.5:22"
    for hostile in ("a b", "a\nb", "a\x00"):
        with pytest.raises(sshroute.RouteError):
            sshroute.username_for("{user}@{target}", hostile, "10.0.0.5", 22)
        with pytest.raises(sshroute.RouteError):
            sshroute.username_for("{user}@{target}", "svc", hostile, 22)


# ------------------------------------------------------------------ through the credential store
@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "c.db")
    init_db(c)
    yield c
    c.close()


def test_the_store_checks_a_route_and_hands_it_to_the_code_that_connects(conn):
    bastion = credstore.create(conn, "anna", "Bastion login", "login", {"username": "jumper", "password": "jp-pw"}, shared=True)
    made = credstore.create(conn, "anna", "Web via bastion", "login", {"username": "svc", "password": "target-pw", "route_mode": "jump", "route_host": "bastion.example.com",
                                                                       "route_port": "2222", "route_login": bastion["id"], "route_fingerprint": "SHA256:" + "E" * 43}, shared=True)
    assert made["route"] == {"mode": "jump", "host": "bastion.example.com", "port": "2222", "template": "", "login": bastion["id"], "pinned": True, "fingerprint": "SHA256:" + "E" * 43}
    assert "jp-pw" not in json.dumps(credstore.listing(conn, "anna"))
    got = credstore.resolve(conn, "anna", made["id"], "SSH terminal")
    assert got["route"]["login"] == {"username": "jumper", "password": "jp-pw"} and got["route"]["port"] == 2222 and got["password"] == "target-pw"
    again = credstore.use_bound(conn, made["id"], "monitoring SSH")
    assert again["route"]["mode"] == "jump"
    for bad in ({"route_login": "nope"}, {"route_login": made["id"]}, {"route_host": "a b"}):
        with pytest.raises(credstore.CredentialError):
            credstore.create(conn, "anna", "bad" + str(bad), "login", {"username": "u", "password": "p", "route_mode": "jump", "route_host": "b.example.com", "route_login": bastion["id"], **bad})
    with pytest.raises(credstore.CredentialError, match="cannot itself use a route"):
        credstore.create(conn, "anna", "chain", "login", {"username": "u", "password": "p", "route_mode": "jump", "route_host": "b.example.com", "route_login": made["id"]})
    with pytest.raises(credstore.CredentialError, match="not yours"):
        credstore.create(conn, "bob", "steal", "login", {"username": "u", "password": "p", "route_mode": "jump", "route_host": "b.example.com", "route_login": credstore.create(conn, "anna", "private", "login", {"username": "j", "password": "x"})["id"]})


def test_the_login_for_the_bastion_can_come_from_the_pam(conn, tmp_path):
    from tests.fake_vault import ROLE, SECRET, Fake

    bao = Fake().start()
    try:
        bao.kv2["netlens/bastion"] = {"username": "jumper", "password": "jp-from-vault"}
        hop = credstore.create(conn, "anna", "Bastion in vault", "pam", {"provider": "vault_kv", "url": bao.url, "path": "netlens/bastion", "role_id": ROLE, "secret_id": SECRET}, shared=True)
        made = credstore.create(conn, "anna", "Web via vaulted bastion", "login", {"username": "svc", "password": "target-pw", "route_mode": "proxy", "route_host": "psm.example.com",
                                                                                    "route_template": "{user}@{target}"}, shared=True)
        assert credstore.resolve(conn, "anna", made["id"], "SSH terminal")["route"]["template"] == "{user}@{target}"
        jumped = credstore.create(conn, "anna", "Web via jump", "login", {"username": "svc", "password": "x", "route_mode": "jump", "route_host": "b.example.com", "route_login": hop["id"]}, shared=True)
        got = credstore.resolve(conn, "anna", jumped["id"], "SSH terminal", "", "web01")
        assert got["route"]["login"]["password"] == "jp-from-vault"
        rows = " ".join(r["action"] for r in conn.execute("SELECT action FROM audit_log WHERE method = 'PAM'"))
        assert "bastion for SSH terminal" in rows and "jp-from-vault" not in rows
    finally:
        bao.stop()
