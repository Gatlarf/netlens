"""Install, update, check and remove the probe on a host from within Netlens.

The real install script is run here against a fake tree (/etc/ssh, /usr/local/sbin, /etc/sudoers.d are redirected to a temporary folder and the system commands
are stubs), so what it does to sshd_config is tested for real: where the blocks go, that a second run changes nothing, that an old block is replaced, that another
trusted CA is respected, and that a configuration that fails its test is put back.
"""

import asyncio
import os
import stat
import subprocess
from pathlib import Path

import pytest

from app import tsdb
from app.db import connect, init_db
from app.hostmetrics import service as hm, ssh
from app.hostprobe import credentials, installer, scripts, service

CA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItestcakey netlens-ca"
ORIGINAL = "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nPermitRootLogin no\nUsePAM yes\n\nMatch Address 10.0.0.0/8\n    PasswordAuthentication yes\n"
LEGACY = ("\n# Netlens read-only probe (added by Netlens; remove these lines and /etc/ssh/netlens_ca.pub to undo)\nTrustedUserCAKeys /etc/ssh/netlens_ca.pub\nMatch User netlens-ro\n"
          "    ForceCommand sudo -n /usr/local/sbin/netlens-probe\n    PermitTTY no\n    X11Forwarding no\n    AllowTcpForwarding no\n    AllowAgentForwarding no\n")


class Sandbox:
    def __init__(self, root: Path):
        self.root = root
        self.sbin, self.ssh, self.sudoers, self.bin = root / "sbin", root / "ssh", root / "sudoers.d", root / "bin"
        for d in (self.sbin, self.ssh, self.sudoers, self.bin, self.ssh / "sshd_config.d"):
            d.mkdir(parents=True, exist_ok=True)
        self.log = root / "calls.log"
        self.log.write_text("")
        (self.ssh / "sshd_config").write_text(ORIGINAL)
        self._stub("sudo", 'while [ "$1" = "-S" ] || [ "$1" = "-n" ] || [ "$1" = "-p" ]; do [ "$1" = "-p" ] && shift; shift; done; exec "$@"')
        self._stub("useradd", f'echo "useradd $*" >> {self.log}; touch {root}/account-created')
        self._stub("visudo", f'echo "visudo $*" >> {self.log}; grep -q BADSUDOERS "$2" && exit 1; exit 0')
        self._stub("sshd", f'echo "sshd $*" >> {self.log}; if [ -n "$SSHD_FAIL" ] && grep -q "Match User netlens-ro" {self.ssh}/sshd_config; then echo "bad config" >&2; exit 1; fi; exit 0')
        self._stub("systemctl", f'echo "systemctl $*" >> {self.log}')
        self._stub("install", 'A=""; while [ $# -gt 0 ]; do case "$1" in -o|-g) shift 2;; *) A="$A $1"; shift;; esac; done; exec /usr/bin/install $A')
        self._stub("userdel", f'echo "userdel $*" >> {self.log}; rm -f {root}/account-created')
        self._stub("id", f'if [ "$1" = "-u" ] && [ -n "$FAKE_ROOT" ]; then echo 0; exit 0; fi; if [ "$1" = "netlens-ro" ]; then [ -e {root}/account-created ] && exit 0 || exit 1; fi; exec /usr/bin/id "$@"')

    def _stub(self, name: str, body: str) -> None:
        f = self.bin / name
        f.write_text("#!/bin/sh\n" + body + "\n")
        f.chmod(f.stat().st_mode | stat.S_IEXEC)

    def run(self, action: str, **env) -> subprocess.CompletedProcess:
        script = installer.linux_script(action, "netlens-ro", CA, "pw", None, False)
        script = script.replace("/usr/local/sbin", str(self.sbin)).replace("/etc/ssh", str(self.ssh)).replace("/etc/sudoers.d", str(self.sudoers))
        return subprocess.run(["bash", "-s"], input=script, capture_output=True, text=True, env={"PATH": f"{self.bin}:/usr/bin:/bin", "HOME": str(self.root), **env}, timeout=60)

    def config(self) -> str:
        return (self.ssh / "sshd_config").read_text()

    def tree(self) -> dict[str, str]:
        return {str(p.relative_to(self.root)): p.read_text() for p in sorted(self.root.rglob("*")) if p.is_file() and p.name != "calls.log" and "bin/" not in str(p.relative_to(self.root))}


@pytest.fixture
def box(tmp_path):
    return Sandbox(tmp_path)


def test_check_changes_nothing_and_says_what_it_sees(box):
    before = box.tree()
    r = box.run("check")
    assert r.returncode == 0, r.stdout + r.stderr
    got = installer.parse_output(r.stdout)
    assert got["result"]["installed_version"] == "none" and got["result"]["account"] == "no" and got["result"]["sshd_block"] == "no" and got["done"].startswith("check")
    assert box.tree() == before


def test_install_puts_everything_in_place_and_the_blocks_in_the_right_places(box):
    r = box.run("install")
    assert r.returncode == 0, r.stdout + r.stderr
    got = installer.parse_output(r.stdout)
    assert got["error"] is None and got["done"] == "install" and got["result"]["installed_version"] == str(scripts.SCRIPT_VERSION)
    assert (box.sbin / "netlens-probe").stat().st_mode & 0o777 == 0o755 and (box.sbin / "netlens-probe-entry").stat().st_mode & 0o777 == 0o755
    assert (box.sudoers / "netlens-probe").stat().st_mode & 0o777 == 0o440 and (box.ssh / "netlens_ca.pub").read_text().strip() == CA
    cfg = box.config()
    assert cfg.index("TrustedUserCAKeys") < cfg.index("Match Address") < cfg.index("Match User netlens-ro")          # the CA line is global (before every Match), our Match block comes last
    assert cfg.count("Match User netlens-ro") == 1 and "ForceCommand " + str(box.sbin) + "/netlens-probe-entry" in cfg
    assert any(p.name.startswith("sshd_config.netlens-backup-") for p in box.ssh.iterdir()) and "reload ssh" in box.log.read_text()
    assert cfg.startswith(ORIGINAL.split("\n\nMatch")[0])                                                      # the administrator's lines come first, unchanged


def test_a_second_run_changes_nothing(box):
    box.run("install")
    first = box.tree()
    r = box.run("update")
    assert r.returncode == 0 and "already right" in r.stdout
    assert box.tree() == first and box.config().count("TrustedUserCAKeys") == 1


def test_an_older_install_is_replaced_not_doubled(box):
    (box.ssh / "sshd_config").write_text(ORIGINAL + LEGACY.replace("/etc/ssh", str(box.ssh)).replace("/usr/local/sbin", str(box.sbin)))
    r = box.run("update")
    assert r.returncode == 0, r.stdout
    cfg = box.config()
    assert "added by Netlens" not in cfg and cfg.count("Match User netlens-ro") == 1 and cfg.count("TrustedUserCAKeys") == 1 and "netlens-probe-entry" in cfg
    assert "PermitRootLogin no" in cfg and "Match Address 10.0.0.0/8" in cfg                       # the administrator's own lines are untouched


def test_another_trusted_ca_is_respected_and_nothing_is_changed(box):
    (box.ssh / "sshd_config").write_text(ORIGINAL.replace("Port 22", "Port 22\nTrustedUserCAKeys /etc/ssh/company_ca.pub"))
    before = box.tree()
    r = box.run("install")
    got = installer.parse_output(r.stdout)
    assert r.returncode == 4 and "already trusts another certificate authority" in got["error"] and "company_ca.pub" in got["error"]
    assert box.tree() == before and not (box.sbin / "netlens-probe").exists()


def test_a_configuration_that_fails_its_test_is_put_back(box):
    before = box.config()
    r = box.run("install", SSHD_FAIL="1")
    got = installer.parse_output(r.stdout)
    assert r.returncode == 6 and "old configuration was put back" in got["error"]
    assert box.config() == before


def test_a_refused_sudoers_file_is_removed(box):
    (box.bin / "visudo").write_text("#!/bin/sh\nexit 1\n")
    r = box.run("install")
    assert r.returncode == 5 and "refused by visudo" in installer.parse_output(r.stdout)["error"] and not (box.sudoers / "netlens-probe").exists()
    assert box.config() == ORIGINAL


def test_remove_takes_it_all_out_again(box):
    box.run("install")
    r = box.run("remove")
    got = installer.parse_output(r.stdout)
    assert r.returncode == 0 and got["done"] == "remove"
    assert box.config() == ORIGINAL                                                             # exactly what it was before
    for f in (box.sbin / "netlens-probe", box.sbin / "netlens-probe-entry", box.sudoers / "netlens-probe", box.ssh / "netlens_ca.pub"):
        assert not f.exists(), f
    assert any("account netlens-ro" in line and "left" in line for line in got["log"])


def test_the_password_is_not_in_the_script_arguments_or_the_log(box):
    script = installer.linux_script("install", "netlens-ro", CA, "hunter2 'quoted'", None, False)
    assert script.startswith("PW='hunter2 '\"'\"'quoted'\"'\"''") and "export PW" not in script
    r = box.run("check")
    assert "hunter2" not in r.stdout + r.stderr
    assert "sudo" not in installer.linux_script("check", "x", CA, "p", None, True).split("S() {")[1].split("}")[0]                # as root there is no sudo at all


# ----------------------------------------------------------------------------- from Netlens
@pytest.fixture
def conn(tmp_path):
    tsdb.forget_all()
    c = connect(tmp_path / "i.db")
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'web1', 1, 'x', 'x')")
    c.commit()
    hm.save_monitor(c, 1, {"method": "ssh", "address": "10.0.0.5", "port": 22, "username": "bert", "password": "pw"})
    yield c
    c.close()
    tsdb.forget_all()


def test_the_checks_before_anything_is_sent(conn):
    with pytest.raises(installer.InstallError, match="administrator login"):
        asyncio.run(installer.administer(conn, 1, "install", {}))
    with pytest.raises(installer.InstallError, match="action must be"):
        asyncio.run(installer.administer(conn, 1, "format", {"username": "a", "password": "b"}))
    with pytest.raises(installer.InstallError, match="account name"):
        asyncio.run(installer.administer(conn, 1, "install", {"username": "a", "password": "b"}, "x;y"))
    hm.save_monitor(conn, 1, {"method": "winrm", "address": "10.0.0.5", "username": "a", "password": "b"})
    with pytest.raises(installer.InstallError, match="needs a password"):
        asyncio.run(installer.administer(conn, 1, "install", {"username": "a", "private_key": "KEY"}))                 # over WinRM there is no key login


def test_install_creates_the_ca_sends_the_script_once_and_checks_the_result(conn, monkeypatch):
    sent = []

    async def fake(host, port, user, password, key, passphrase, command, known=None, timeout=15.0, certificate=None, input=None):
        sent.append({"user": user, "command": command, "input": input, "certificate": certificate})
        if command == "bash -s":
            return "NETLENS: step connected as bert on web1\nNETLENS: result installed_version=none\nNETLENS: step installed the probe\nNETLENS: result installed_version=%d\nNETLENS: done install\n" % scripts.SCRIPT_VERSION, 0, None
        assert certificate and user == "netlens-ro" and command == scripts.locked_command("changes")             # the check logs in as the probe account with a fresh certificate
        return "##version 5\n##tz\n+0000\n##time\n1\n##boots\n##packages\n##etc\n##docker\n##users\n##keys\n##end\n", 0, None

    monkeypatch.setattr(ssh, "run_command", fake)
    assert credentials.ca_public(conn) is None
    r = asyncio.run(installer.administer(conn, 1, "install", {"username": "bert", "password": "s3cret"}))
    assert r["ok"] and r["created_ca"] and r["installed_version"] == str(scripts.SCRIPT_VERSION) and r["verified"]["ok"] and credentials.ca_public(conn)
    assert sent[0]["user"] == "bert" and "s3cret" in sent[0]["input"].splitlines()[0] and sent[0]["command"] == "bash -s"
    assert "s3cret" not in str(r) and "s3cret" not in sent[1]["command"]


def test_a_host_that_does_not_answer_like_the_script_is_explained(conn, monkeypatch):
    async def fake(*a, **k):
        return "bash: not found\n", 127, None

    monkeypatch.setattr(ssh, "run_command", fake)
    credentials.ca_create(conn)
    r = asyncio.run(installer.administer(conn, 1, "check", {"username": "bert", "password": "x"}))
    assert not r["ok"] and "did not answer the way the install script does" in r["error"]


def test_the_windows_script_parses_in_powershell_when_it_is_available(tmp_path):
    import shutil

    if not shutil.which("pwsh"):
        pytest.skip("PowerShell is not installed here")
    f = tmp_path / "install.ps1"
    f.write_text(installer.windows_script("install", "netlens-ro", CA))
    r = subprocess.run(["pwsh", "-NoProfile", "-Command", "$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('" + str(f) + "',[ref]$t,[ref]$e);if($e.Count){$e|%{$_.Message};exit 1}"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


# ----------------------------------------------------------------------------- the standalone uninstallers
def run_uninstall(box, *args, **env):
    script = scripts.linux_uninstall("netlens-ro").replace("/usr/local/sbin", str(box.sbin)).replace("/etc/ssh", str(box.ssh)).replace("/etc/sudoers.d", str(box.sudoers))
    path = box.root / "uninstall.sh"
    path.write_text(script)
    return subprocess.run(["sh", str(path), *args], capture_output=True, text=True, env={"PATH": f"{box.bin}:/usr/bin:/bin", "HOME": str(box.root), "FAKE_ROOT": "1", **env}, timeout=60)


def test_the_linux_uninstaller_undoes_an_install_without_netlens(box):
    box.run("install")
    r = run_uninstall(box)
    assert r.returncode == 0, r.stdout + r.stderr
    assert box.config() == ORIGINAL and "Removed the scripts" in r.stdout and "was left" in r.stdout
    for f in (box.sbin / "netlens-probe", box.sbin / "netlens-probe-entry", box.sudoers / "netlens-probe", box.ssh / "netlens_ca.pub"):
        assert not f.exists(), f
    assert "reload ssh" in box.log.read_text() and "userdel" not in box.log.read_text()
    again = run_uninstall(box)
    assert again.returncode == 0 and "holds nothing from Netlens" in again.stdout                                      # safe to run twice


def test_the_linux_uninstaller_removes_the_account_only_when_asked(box):
    box.run("install")
    r = run_uninstall(box, "--remove-account")
    assert "Removed the account netlens-ro" in r.stdout and "userdel -r netlens-ro" in box.log.read_text()


def test_the_linux_uninstaller_replaces_an_older_install_and_needs_root(box):
    (box.ssh / "sshd_config").write_text(ORIGINAL + LEGACY.replace("/etc/ssh", str(box.ssh)).replace("/usr/local/sbin", str(box.sbin)))
    assert run_uninstall(box).returncode == 0 and box.config().rstrip() == ORIGINAL.rstrip()
    r = subprocess.run(["sh", "-c", scripts.linux_uninstall()], capture_output=True, text=True, env={"PATH": f"{box.bin}:/usr/bin:/bin"})
    assert r.returncode == 3 and "Run this as root" in r.stdout


def test_a_configuration_that_fails_its_test_is_put_back_by_the_uninstaller_too(box):
    box.run("install")
    installed = box.config()
    (box.bin / "sshd").write_text("#!/bin/sh\nexit 1\n")
    r = run_uninstall(box)
    assert r.returncode == 6 and "put back" in r.stdout and box.config() == installed and (box.sbin / "netlens-probe").exists()           # nothing else was removed


def test_both_uninstallers_are_offered_and_the_windows_one_parses(tmp_path):
    import shutil

    setup = scripts.linux_setup("netlens-ro", None, CA)
    assert setup["uninstall"].startswith("#!/bin/sh") and scripts.windows_setup("netlens-ro", None, CA)["uninstall"].startswith("# Removes the Netlens host probe")
    if not shutil.which("pwsh"):
        pytest.skip("PowerShell is not installed here")
    f = tmp_path / "u.ps1"
    f.write_text(scripts.windows_uninstall("netlens-ro"))
    r = subprocess.run(["pwsh", "-NoProfile", "-Command", "$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('" + str(f) + "',[ref]$t,[ref]$e);if($e.Count){$e|%{$_.Message};exit 1}"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


# ----------------------------------------------------------------------------- Windows over WinRM
def test_the_windows_script_carries_its_settings_and_the_ssh_server_is_opt_in():
    t = installer.windows_script("install", "netlens-ro", CA, enable_sshd=False)
    assert "$enableSshd = $false" in t and "@@" not in t and "error the OpenSSH server is not installed" in t and f"@@VERSION@@" not in t and f"installed_version={scripts.SCRIPT_VERSION}" in t
    on = installer.windows_script("install", "netlens-ro", CA, enable_sshd=True, allow_from="192.168.0.189")
    assert "$enableSshd = $true" in on and "$allowFrom = '192.168.0.189'" in on and "AllowUsers" in on and "PasswordAuthentication no" in on and "Add-WindowsCapability" in on
    assert "$deferRestart = $true" in installer.windows_script("check", "x", CA, defer_restart=True)


def test_the_windows_script_is_sent_over_winrm_in_small_pieces_and_arrives_whole():
    import base64
    import gzip
    import re

    script = installer.windows_script("install", "netlens-ro", CA, enable_sshd=True)
    commands = []

    class FakeSession:
        def run_powershell(self, command, total=None):
            commands.append(command)
            return "NETLENS: done install\n", "", 0

    out, err, code = installer.winrm_upload_and_run(script, FakeSession, 10.0)
    assert code == 0 and len(commands) > 3
    assert all(len(base64.b64encode(c.encode("utf-16-le"))) < 7500 for c in commands), "every command line has to fit in what WinRM takes"
    pieces = [re.search(r"-Value '([A-Za-z0-9+/=]*)'", c).group(1) for c in commands[:-1]]
    assert gzip.decompress(base64.b64decode("".join(pieces))).decode() == script
    assert commands[0].startswith("$f = Join-Path $env:TEMP") and "Set-Content" in commands[0] and "Add-Content" in commands[1] and "Invoke-Expression" in commands[-1]
    assert "password" not in " ".join(commands).lower().replace("passwordauthentication", "").replace("securestring", "").replace("-password", "").replace("random password", "")


def test_a_windows_host_over_winrm_is_installed_through_winrm_and_then_switched_to_the_locked_login(conn, monkeypatch):
    from app.hostmetrics import winrm

    hm.save_monitor(conn, 1, {"method": "winrm", "address": "10.0.0.5", "port": 5986, "username": "netlens", "password": "mon-pw"})
    seen = {"users": [], "scripts": []}

    class FakeSession:
        def __init__(self, host, port, https, user, password, auth="ntlm", verify_tls=False, timeout=30):
            seen["users"].append((user, password, port, https))

        def run_powershell(self, command, total=None):
            seen["scripts"].append(command)
            if "Invoke-Expression" in command:
                return ("NETLENS: step connected as admin on PC\nNETLENS: result installed_version=none\nNETLENS: result sshd_installed=False\nNETLENS: step installed the Windows OpenSSH Server\n"
                        "NETLENS: step installed probe.ps1\nNETLENS: result installed_version=%d\nNETLENS: done install\n" % scripts.SCRIPT_VERSION), "", 0
            return "", "", 0

    async def fake_ssh(host, port, user, password, key, passphrase, command, known=None, timeout=15.0, certificate=None, input=None):
        assert port == 22 and user == "netlens-ro" and certificate and command == scripts.locked_command("changes")
        return '##netlens-probe\n{"version": 5, "boots": [], "hotfixes": [], "installs": [], "services": [], "users": []}', 0, None

    monkeypatch.setattr(winrm, "Session", FakeSession)
    monkeypatch.setattr(ssh, "run_command", fake_ssh)
    r = asyncio.run(installer.administer(conn, 1, "install", {"username": "admin@example.com", "password": "adminpw"}, enable_sshd=True))
    assert r["ok"] and r["verified"]["ok"] and r["verified"]["platform"] == "windows" and r["switched"] is True
    assert {u[0] for u in seen["users"]} == {"admin@example.com"} and all(u[1] == "adminpw" and u[2] == 5986 and u[3] for u in seen["users"])      # the admin login, not the monitor's
    assert service.device_config(conn, 1)["provider"] == "netlens_ca" and service.device_config(conn, 1)["username"] == "netlens-ro"
    assert "adminpw" not in str(r) and not any("adminpw" in c for c in seen["scripts"])
