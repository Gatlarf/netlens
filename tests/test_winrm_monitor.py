"""Health readings of a Windows computer over WinRM, against the simulated WinRM service of the Hyper-V tests."""

import asyncio
import json
import shutil

import pytest

from app import tsdb
from app.db import connect, init_db
from app.hostmetrics import service as hm
from app.hostmetrics import ssh, winrm
from tests.fake_winrm import FakeWinRM
from tests.test_hostmetrics import win_output

needs_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is needed to make a test certificate")


def secret(server, **extra):
    return {"username": server.user, "password": server.password, "auth": "ntlm", "verify_tls": False, **extra}


def read(server, state=None, now=1_773_144_000, **extra):
    return asyncio.run(hm.read("winrm", "127.0.0.1", server.port, secret(server, **extra), None, state if state is not None else {}, None, now))


@needs_openssl
def test_readings_over_winrm(tmp_path):
    with FakeWinRM(tmp_path, output=win_output()) as server:
        state = {}
        pts, found, fingerprint = read(server, state)
        assert fingerprint is None and {"cpu", "memory", "disk", "uptime"} <= set(found)
        got = {(m, label): v for m, label, v, _u in pts}
        assert got[("cpu_pct", "")] == 23 and got[("disk_pct", "C:\\")] == pytest.approx(75.0)
        assert server.actions == ["Create", "Command", "Receive", "Delete"] and server.shells_open == 0
        assert server.scripts == [ssh.WIN_SCRIPT]                                  # one fixed, read-only script
        pts, _, _ = read(server, state, now=1_773_144_010)                          # traffic needs a second round
        assert [v for m, _l, v, _u in pts if m == "net_rx_bps"] == [0.0]       # the fake reports the same counters twice: no traffic
    script = ssh.WIN_SCRIPT
    assert "Get-CimInstance" in script and not any(w in script for w in ("Set-", "Remove-", "Start-", "Stop-", "Restart", "Invoke-", "New-"))


@needs_openssl
def test_a_wrong_password_is_a_sentence(tmp_path):
    with FakeWinRM(tmp_path, output=win_output()) as server:
        with pytest.raises(hm.MonitorError, match="refused the login"):
            asyncio.run(hm.read("winrm", "127.0.0.1", server.port, secret(server, password="nope"), None, {}, None, 1))


@needs_openssl
def test_basic_login(tmp_path):
    with FakeWinRM(tmp_path, auth="basic", output=win_output()) as server:
        pts, found, _ = read(server, auth="basic")
        assert "cpu" in found


@needs_openssl
def test_a_script_error_is_shown(tmp_path):
    with FakeWinRM(tmp_path, output="", stderr="#< CLIXML\n<Objs><S S=\"Error\">Get-CimInstance : Access denied_x000D__x000A_</S></Objs>", exit_code=1) as server:
        with pytest.raises(hm.MonitorError, match="Access denied"):
            read(server)


def test_definition_rules():
    d = hm.validate({"method": "winrm", "address": "10.0.0.7", "username": "netlens", "password": "pw-long-enough"})
    assert d["port"] == 5986 and d["secret"]["auth"] == "ntlm" and d["secret"]["verify_tls"] is False
    with pytest.raises(hm.MonitorError):
        hm.validate({"method": "winrm", "address": "10.0.0.7", "username": "u"})
    with pytest.raises(hm.MonitorError):
        hm.validate({"method": "winrm", "address": "10.0.0.7", "username": "u", "password": "p", "auth": "kerberos"})
    with pytest.raises(hm.MonitorError, match="own network"):
        hm.validate({"method": "winrm", "address": "8.8.8.8", "port": 5985, "username": "u", "password": "p"})
    assert hm.validate({"method": "winrm", "address": "192.168.0.7", "port": 5985, "username": "u", "password": "p"})["port"] == 5985
    kept = hm.validate({"method": "winrm", "address": "10.0.0.7", "username": "u2"}, {"method": "winrm", "secret": d["secret"]})
    assert kept["secret"]["password"] == "pw-long-enough" and kept["secret"]["username"] == "u2"


@needs_openssl
def test_saved_monitor_runs_and_hides_the_password(tmp_path):
    tsdb.forget_all()
    with FakeWinRM(tmp_path, output=win_output()) as server:
        path = tmp_path / "t.db"
        c = connect(path)
        init_db(c)
        c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '127.0.0.1', 'pc', 1, 'x', 'x')")
        c.commit()
        saved = hm.save_monitor(c, 1, {"method": "winrm", "address": "127.0.0.1", "port": server.port, "username": server.user, "password": server.password})
        assert saved["has_password"] is True and saved["auth"] == "ntlm" and server.password not in json.dumps(saved)
        monitor_id = saved["id"]
        c.close()
        result = asyncio.run(hm.run_monitor(str(path), monitor_id, 1_773_144_000))
        assert result["ok"] and result["points"] > 3
    tsdb.forget_all()


@needs_openssl
def test_process_check_over_winrm(tmp_path):
    tsdb.forget_all()
    for code, expect in ((0, True), (1, False)):
        with FakeWinRM(tmp_path, output="", exit_code=code) as server:
            path = tmp_path / f"t{code}.db"
            c = connect(path)
            init_db(c)
            c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '127.0.0.1', 'pc', 1, 'x', 'x')")
            c.commit()
            hm.save_monitor(c, 1, {"method": "winrm", "address": "127.0.0.1", "port": server.port, "username": server.user, "password": server.password})
            c.close()
            running, detail, ms = asyncio.run(hm.check_process(str(path), 1, "spooler.exe"))
            assert running is expect and "Get-Service -Name 'spooler'" in server.scripts[0]
    tsdb.forget_all()
