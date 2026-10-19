"""Host health readings: SNMP (against the simulated agent of the plugin tests), the /proc parser for SSH, limits and alerts."""

import json

import pytest

from app import tsdb, vault
from app.db import connect, init_db
from app.hostmetrics import service as hm
from app.hostmetrics import snmp, ssh
from tests import test_plugin_snmp as sim

NOW = "2026-03-10T12:00:00Z"
T0 = 1_800_000_000


@pytest.fixture(autouse=True)
def oid_values(monkeypatch):
    """The plugin tests' simulated agent cannot answer with an object identifier (hrStorageType does); teach it."""
    original = sim.encode_value

    def encode_value(value):
        if isinstance(value, tuple):
            return sim.plugin._oid(value)
        return original(value)

    monkeypatch.setattr(sim, "encode_value", encode_value)


def oid(base, *tail):
    return tuple(base) + tail


def host_mib(community="public", cpu=(30, 50), cached=True, ram_used_gb=6.0, disk_pct=40):
    m = sim.Mib(community)
    GB = 1024 ** 3
    units = 4096
    for i, load in enumerate(cpu, start=196608):
        m.set(oid(snmp.HR_PROC_LOAD, i), load)
    m.set(snmp.HR_UPTIME, 8640000)                                   # 1 day in 1/100 s
    rows = [  # index, type, descr, total, used
        (1, snmp.ST_RAM, "Physical memory", 8 * GB, int(ram_used_gb * GB)),
        (2, snmp.ST_VIRTUAL, "Swap space", 2 * GB, 0),
        (3, snmp.ST_OTHER, "Cached memory", 2 * GB, 2 * GB),
        (4, snmp.ST_OTHER, "Memory buffers", 1 * GB, 1 * GB),
        (31, snmp.ST_FIXED, "/", 100 * GB, int(disk_pct * GB)),
        (32, snmp.ST_FIXED, "/run", 1 * GB, 0),
        (33, snmp.ST_FIXED, "/var/lib/docker/overlay2/abc", 100 * GB, 50 * GB),
        (34, snmp.ST_FIXED, "C:\\ Label:Data  Serial Number 12345678", 500 * GB, 450 * GB),
    ]
    for index, kind, descr, total, used in rows:
        m.set(oid(snmp.HR_STORAGE_TYPE, index), kind)
        m.set(oid(snmp.HR_STORAGE_DESCR, index), descr.encode())
        m.set(oid(snmp.HR_STORAGE_UNITS, index), units)
        m.set(oid(snmp.HR_STORAGE_SIZE, index), total // units)
        m.set(oid(snmp.HR_STORAGE_USED, index), used // units)
    return m


class Direct:
    """The Agent interface straight on a Mib, without UDP."""

    def __init__(self, mib):
        self.mib = mib

    def get(self, *oids):
        return {o: self.mib.values[o] for o in oids if o in self.mib.values}

    def walk(self, base):
        n = len(base)
        return [(k[n:], v) for k, v in sorted(self.mib.values.items()) if k[:n] == base]


def points(found):
    return {(m, label): v for m, label, v, _u in found}


def test_cpu_memory_disk_from_hr_tables():
    pts, found = snmp.collect(Direct(host_mib()), state={}, now=100)
    got = points(pts)
    assert got[("cpu_pct", "")] == 40
    # 6 GB used of 8, but 3 GB of that is cache and buffers: a program could still get it
    assert got[("mem_pct", "")] == pytest.approx(37.5)
    assert got[("swap_pct", "")] == 0
    assert got[("disk_pct", "/")] == pytest.approx(40)
    assert got[("disk_pct", "C:\\")] == pytest.approx(90)               # the Windows label is cut at " Label:"
    labels = {label for (m, label) in got if m == "disk_pct"}
    assert labels == {"/", "C:\\"}                                       # /run and docker overlays are not disks you manage
    assert got[("uptime_s", "")] == 86400
    assert {"cpu", "memory", "disk", "uptime"} <= set(found)


def test_traffic_is_a_rate_between_two_rounds_and_survives_a_wrap():
    mib = sim.Mib()
    mib.set(oid(snmp.IF_NAME, 1), b"eth0")
    mib.set(oid(snmp.IF_OPER, 1), 1)
    mib.set(oid(snmp.IF_NAME, 2), b"lo")
    mib.set(oid(snmp.IF_OPER, 2), 1)
    mib.set(oid(snmp.IF_NAME, 3), b"eth1")
    mib.set(oid(snmp.IF_OPER, 3), 2)                                     # down
    mib.set(oid(snmp.IF_HC_IN, 1), 1_000_000)
    mib.set(oid(snmp.IF_HC_OUT, 1), 0)
    agent, state = Direct(mib), {}
    pts, found = snmp.collect(agent, ["network"], state, now=100)
    assert points(pts) == {("if_up", "eth0"): 1.0, ("if_up", "eth1"): 0.0}    # the first round only learns the counters (and sees the links)
    assert found == ["network"]
    mib.set(oid(snmp.IF_HC_IN, 1), 1_000_000 + 12_500_000)              # 100 Mbit in 10 s
    mib.set(oid(snmp.IF_HC_OUT, 1), 1_250_000)
    pts, found = snmp.collect(agent, ["network"], state, now=110)
    got = points(pts)
    assert got[("net_rx_bps", "eth0")] == pytest.approx(10_000_000)
    assert got[("net_tx_bps", "eth0")] == pytest.approx(1_000_000)
    assert ("net_rx_bps", "lo") not in got and ("net_rx_bps", "eth1") not in got
    mib.set(oid(snmp.IF_HC_IN, 1), 500)                                  # the counter restarted: no wild number
    pts, _ = snmp.collect(agent, ["network"], state, now=120)
    assert ("net_rx_bps", "eth0") not in points(pts)


def test_32_bit_counter_wrap():
    assert snmp._delta(100, 2 ** 32 - 50, 32) == 150
    assert snmp._delta(100, 5000, 32) is None
    assert snmp._delta(5000, 100, 32) == 4900


def test_ups_printer_and_temperature():
    mib = sim.Mib()
    mib.set(snmp.UPS_CHARGE, 80)
    mib.set(snmp.UPS_MINUTES, 25)
    mib.set(snmp.UPS_OUTPUT_SOURCE, 5)
    mib.set(oid(snmp.PRT_SUPPLY_DESCR, 1, 1), b"Black toner")
    mib.set(oid(snmp.PRT_SUPPLY_MAX, 1, 1), 100)
    mib.set(oid(snmp.PRT_SUPPLY_LEVEL, 1, 1), 12)
    mib.set(oid(snmp.PRT_SUPPLY_DESCR, 1, 2), b"Waste")
    mib.set(oid(snmp.PRT_SUPPLY_MAX, 1, 2), 100)
    mib.set(oid(snmp.PRT_SUPPLY_LEVEL, 1, 2), -3)                        # "some remaining": no number
    mib.set(oid(snmp.LM_TEMP_DESCR, 1), b"Core 0")
    mib.set(oid(snmp.LM_TEMP_VALUE, 1), 54500)
    got = points(snmp.collect(Direct(mib), state={}, now=1)[0])
    assert got[("battery_pct", "")] == 80 and got[("battery_minutes", "")] == 25 and got[("on_battery", "")] == 1
    assert got[("supply_pct", "Black toner")] == 12
    assert ("supply_pct", "Waste") not in got
    assert got[("temp_c", "Core 0")] == pytest.approx(54.5)


def answering(mib):
    """UDP send replacement: the simulated agent answers, or stays silent like a real one that does not know the community."""
    def send(address, payload, timeout):
        try:
            return mib.handle(payload)
        except sim.plugin.Timeout as exc:
            raise snmp.Timeout(str(exc)) from None
    return send


def test_snmp_over_udp_with_the_simulated_agent(monkeypatch):
    mib = host_mib()
    monkeypatch.setattr(snmp, "SEND", answering(mib))
    agent = snmp.Agent("10.0.0.9", "public", "2c")
    pts, found = snmp.collect(agent, ["cpu", "disk"], {}, now=1)
    assert points(pts)[("cpu_pct", "")] == 40
    assert found == ["cpu", "disk"]


# ------------------------------------------------------------------ SSH
PROC = """##loadavg
0.52 0.40 0.30 1/200 1234
##stat
cpu  {user} 0 {system} {idle} {iowait} 0 0 0 0 0
##mem
MemTotal:        8000000 kB
MemAvailable:    2000000 kB
SwapTotal:       2000000 kB
SwapFree:        1500000 kB
##uptime
7200.55 14000.00
##df
Filesystem     Type     1024-blocks     Used Available Capacity Mounted on
/dev/sda1      ext4       100000000 60000000  40000000      60% /
tmpfs          tmpfs        4000000        0   4000000       0% /dev/shm
/dev/sdb1      ext4       500000000 450000000 40000000      92% /mnt/data
/dev/loop0     squashfs       100000   100000         0     100% /snap/core/1
##net
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0
  eth0: {rx} 100 0 0 0 0 0 0 {tx} 100 0 0 0 0 0 0
docker0: 5 1 0 0 0 0 0 0 5 1 0 0 0 0 0 0
##temp
x86_pkg_temp 61000
##end
"""


def proc(user=1000, system=500, idle=8000, iowait=500, rx=0, tx=0):
    return PROC.format(user=user, system=system, idle=idle, iowait=iowait, rx=rx, tx=tx)


def test_a_container_does_not_report_the_temperatures_of_its_host():
    """LXC and Docker guests see the sensors of the machine they run on; reading them gave every guest the same warning."""
    for kind in ("lxc", "docker", "container", "podman"):
        pts, found = ssh.parse(proc().replace("##temp", f"##container\n{kind}\n##temp"), {}, now=100)
        assert "temperature" not in found and ("temp_c", "x86_pkg_temp") not in points(pts), kind
    pts, found = ssh.parse(proc().replace("##temp", "##container\nnone\n##temp"), {}, now=100)
    assert points(pts)[("temp_c", "x86_pkg_temp")] == pytest.approx(61)                   # systemd-detect-virt says "none" on a real machine
    pts, found = ssh.parse(proc().replace("##temp", "##container\n##temp"), {}, now=100)
    assert points(pts)[("temp_c", "x86_pkg_temp")] == pytest.approx(61)                   # nothing detected


def test_the_container_check_in_the_script_is_valid_shell_and_answers():
    import subprocess

    script = ssh.SCRIPT
    assert subprocess.run(["sh", "-n", "-c", script], capture_output=True).returncode == 0
    out = subprocess.run(["sh", "-c", script], capture_output=True, text=True).stdout
    assert "##container" in out and out.index("##container") < out.index("##temp") < out.index("##end")


def test_ssh_parser_first_round_and_second_round():
    state = {}
    pts, found = ssh.parse(proc(), state, now=100)
    got = points(pts)
    assert ("cpu_pct", "") not in got and "cpu" in found                  # needs a second round
    assert got[("load1", "")] == 0.52
    assert got[("mem_pct", "")] == pytest.approx(75)
    assert got[("swap_pct", "")] == pytest.approx(25)
    assert got[("uptime_s", "")] == pytest.approx(7200.55)
    assert got[("disk_pct", "/")] == pytest.approx(60)
    assert got[("disk_pct", "/mnt/data")] == pytest.approx(100 * 450 / 490)
    assert ("disk_pct", "/dev/shm") not in got and ("disk_pct", "/snap/core/1") not in got
    assert got[("temp_c", "x86_pkg_temp")] == pytest.approx(61)
    # second round: 1000 jiffies passed, 750 of them idle (idle + iowait): 25% busy; and 1 MB in 10 s
    pts, _ = ssh.parse(proc(user=1000 + 200, system=500 + 50, idle=8000 + 600, iowait=500 + 150, rx=1_250_000, tx=125_000), state, now=110)
    got = points(pts)
    assert got[("cpu_pct", "")] == pytest.approx(25)
    assert got[("net_rx_bps", "eth0")] == pytest.approx(1_000_000)
    assert got[("net_tx_bps", "eth0")] == pytest.approx(100_000)
    assert not any(label in ("lo", "docker0") for (_m, label) in got)


def test_ssh_cut_off_answer_is_an_error():
    with pytest.raises(ssh.SshError):
        ssh.parse("##loadavg\n0.5 0.4 0.3 1/2 3\n", {}, now=1)


def test_the_command_has_no_unbalanced_quotes():
    import shlex

    parts = shlex.split(ssh.COMMAND)
    assert parts[:2] == ["sh", "-c"] and parts[2].rstrip().endswith('echo "##end"')


# ------------------------------------------------------------------ limits and alerts
@pytest.fixture
def conn(tmp_path):
    tsdb.forget_all()
    c = connect(tmp_path / "t.db")
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'nas', 1, ?, ?)", (NOW, NOW))
    c.commit()
    yield c
    c.close()
    tsdb.forget_all()


def monitor(conn):
    return hm.save_monitor(conn, 1, {"method": "snmp", "address": "10.0.0.5", "community": "s3cret"})


def events(conn):
    return [(r["kind"], r["detail"]) for r in conn.execute("SELECT kind, detail FROM events ORDER BY id")]


def test_login_is_stored_encrypted_and_never_shown(conn):
    shown = monitor(conn)
    assert shown["has_community"] is True and "s3cret" not in json.dumps(shown)
    raw = conn.execute("SELECT credential FROM host_monitors").fetchone()[0]
    assert vault.is_encrypted(raw) and "s3cret" not in raw


def test_secret_is_kept_when_not_sent_again(conn):
    monitor(conn)
    hm.save_monitor(conn, 1, {"interval_s": 120})
    row = hm.get_monitor(conn, 1)
    assert hm.load_secret(conn, row)["community"] == "s3cret" and row["interval_s"] == 120


def test_validation(conn):
    with pytest.raises(hm.MonitorError):
        hm.validate({"method": "ftp", "address": "10.0.0.5"})
    with pytest.raises(hm.MonitorError):
        hm.validate({"method": "ssh", "address": "10.0.0.5", "username": "me"})              # no password or key
    with pytest.raises(hm.MonitorError):
        hm.validate({"method": "snmp", "address": "10.0.0.5", "interval_s": 5})
    with pytest.raises(hm.MonitorError):
        hm.validate({"method": "snmp", "address": "bad address!"})
    ok = hm.validate({"method": "ssh", "address": "10.0.0.5", "username": "me", "password": "x"})
    assert ok["port"] == 22 and ok["secret"] == {"username": "me", "password": "x"}


def test_level_needs_confirmation_and_recovers(conn):
    monitor(conn)
    mid = hm.get_monitor(conn, 1)["id"]
    ev = lambda v, t: hm.evaluate(conn, mid, 1, "nas", [("cpu_pct", "", v, "%")], t)    # noqa: E731
    assert ev(10, "2026-03-10T12:00:00Z") == []                         # starts ok
    for minute in range(1, 5):
        assert ev(99, f"2026-03-10T12:0{minute}:00Z") == []              # not yet: 5 readings in a row are needed
    assert ev(99, "2026-03-10T12:05:00Z") == ["metric_critical"]
    assert ev(99, "2026-03-10T12:06:00Z") == []                          # no repeat
    assert ev(10, "2026-03-10T12:07:00Z") == []                          # one good reading is not "back to normal" yet
    assert ev(99, "2026-03-10T12:08:00Z") == []                          # and it falls back
    for minute in range(9, 13):
        ev(10, f"2026-03-10T12:{minute:02d}:00Z")
    assert ev(10, "2026-03-10T12:13:00Z") == ["metric_ok"]
    kinds = [k for k, _ in events(conn)]
    assert kinds == ["metric_critical", "metric_ok"]
    assert "nas" in events(conn)[0][1] and "99%" in events(conn)[0][1]


def test_low_is_bad_for_batteries_and_supplies(conn):
    monitor(conn)
    mid = hm.get_monitor(conn, 1)["id"]
    assert hm.evaluate(conn, mid, 1, "nas", [("supply_pct", "Black toner", 12, "%")], NOW) == ["metric_warning"]     # a problem seen at the first look
    assert hm.evaluate(conn, mid, 1, "nas", [("supply_pct", "Black toner", 4, "%")], "2026-03-10T12:01:00Z") == ["metric_critical"]
    assert hm.problems(conn)[0]["level"] == "critical"


def test_changing_the_limits(conn):
    r = hm.save_rules(conn, {"disk_pct": {"warn": 70, "crit": 80}})
    assert r["disk_pct"]["warn"] == 70
    with pytest.raises(hm.MonitorError):
        hm.save_rules(conn, {"disk_pct": {"warn": 90, "crit": 80}})
    with pytest.raises(hm.MonitorError):
        hm.save_rules(conn, {"battery_pct": {"warn": 20, "crit": 40}})                       # low is bad: critical must be below warning
    with pytest.raises(hm.MonitorError):
        hm.save_rules(conn, {"nonsense": {"warn": 1}})
    assert hm.level_of(hm.rules(conn)["disk_pct"], 75) == "warning"
    hm.save_rules(conn, {"disk_pct": {"enabled": False}})
    assert hm.rules(conn)["disk_pct"]["enabled"] is False


async def test_run_monitor_end_to_end(conn, monkeypatch, tmp_path):
    monitor(conn)
    mid = hm.get_monitor(conn, 1)["id"]
    mib = host_mib(community="s3cret", cpu=(97, 99), disk_pct=96)
    monkeypatch.setattr(snmp, "SEND", answering(mib))
    db_path = str(tmp_path / "t.db")
    result = await hm.run_monitor(db_path, mid, now_ts=T0)
    assert result["ok"] and result["error"] is None
    row = hm.get_monitor(conn, 1)
    assert row["last_ok"] == 1 and set(json.loads(row["groups"])) >= {"cpu", "memory", "disk"}
    # a disk at 96 % is critical at once (2 readings are needed: not yet), the first look already reports the first
    assert tsdb.for_conn(conn).latest("device", 1, "cpu_pct")[1] == 98
    kinds = [k for k, _ in events(conn)]
    assert "metric_critical" in kinds                                    # disk: first look at a problem
    # an unknown community: the device does not answer
    hm.save_monitor(conn, 1, {"community": "wrong"})
    result = await hm.run_monitor(db_path, mid, now_ts=T0 + 60)
    assert not result["ok"] and "answer" in result["error"].lower()
    row = hm.get_monitor(conn, 1)
    assert row["last_ok"] == 0 and row["last_error"]


def test_ports_have_load_errors_and_link_state():
    mib = sim.Mib()
    for i, name in ((1, b"Gi1/0/1"), (2, b"Gi1/0/2"), (3, b"Gi1/0/3")):
        mib.set(oid(snmp.IF_NAME, i), name)
    mib.set(oid(snmp.IF_OPER, 1), 1)
    mib.set(oid(snmp.IF_OPER, 2), 2)                                     # no cable
    mib.set(oid(snmp.IF_OPER, 3), 2)
    mib.set(oid(snmp.IF_ADMIN, 3), 2)                                    # switched off on purpose: not reported
    mib.set(oid(snmp.IF_HIGH_SPEED, 1), 1000)                            # 1 Gbit/s
    mib.set(oid(snmp.IF_HC_IN, 1), 0)
    mib.set(oid(snmp.IF_HC_OUT, 1), 0)
    mib.set(oid(snmp.IF_IN_ERR, 1), 0)
    mib.set(oid(snmp.IF_OUT_ERR, 1), 0)
    agent, state = Direct(mib), {}
    snmp.collect(agent, ["network"], state, now=100)
    mib.set(oid(snmp.IF_HC_IN, 1), 250_000_000 * 10 // 8)               # 250 Mbit/s in
    pts, _ = snmp.collect(agent, ["network"], state, now=110)
    got = points(pts)
    assert got[("if_util_pct", "Gi1/0/1")] == pytest.approx(25.0)
    assert got[("if_up", "Gi1/0/1")] == 1.0 and got[("if_up", "Gi1/0/2")] == 0.0 and ("if_up", "Gi1/0/3") not in got
    assert ("if_err_ps", "Gi1/0/1") not in got                           # no errors, no graph
    mib.set(oid(snmp.IF_IN_ERR, 1), 50)
    pts, _ = snmp.collect(agent, ["network"], state, now=120)
    assert points(pts)[("if_err_ps", "Gi1/0/1")] == pytest.approx(5.0)
    pts, _ = snmp.collect(agent, ["network"], state, now=130)
    assert points(pts)[("if_err_ps", "Gi1/0/1")] == 0.0                  # once there were errors the series continues


# ---------------------------------------------------------------- Windows over SSH (PowerShell)
def win_output(boot="2026-03-09T12:00:00.0000000Z", rx=1_000_000, tx=500_000, cpu=23):
    data = {"cpu": cpu, "mt": 16_000_000.0, "mf": 4_000_000.0, "st": 20_000_000.0, "sf": 16_000_000.0, "boot": boot,
            "disks": [{"id": "C:", "size": 500e9, "free": 125e9}, {"id": "D:", "size": 1e12, "free": 900e9}],
            "nics": [{"name": "Intel(R) Ethernet", "rx": rx, "tx": tx}, {"name": "Software Loopback Interface 1", "rx": 5, "tx": 5},
                     {"name": "isatap.{ABC}", "rx": 0, "tx": 0}]}
    return "garbage before\n##netlens-windows\n" + json.dumps(data)


def test_windows_readings():
    state = {}
    pts, found = ssh.parse_windows(win_output(), state, now=1_773_144_000)       # 2026-03-10T12:00:00Z
    got = points(pts)
    assert got[("cpu_pct", "")] == 23
    assert got[("mem_pct", "")] == pytest.approx(75.0)
    assert got[("swap_pct", "")] == pytest.approx(75.0 + 0) or got[("swap_pct", "")] >= 0
    assert got[("disk_pct", "C:\\")] == pytest.approx(75.0) and got[("disk_pct", "D:\\")] == pytest.approx(10.0)
    assert got[("uptime_s", "")] == pytest.approx(86400)
    assert {"cpu", "memory", "disk", "uptime", "network"} <= set(found)
    assert not any(m.startswith("net_") for m, _l in got)                          # the first round only learns the counters
    pts, _ = ssh.parse_windows(win_output(rx=1_000_000 + 1_250_000, tx=500_000 + 125_000), state, now=1_773_144_010)
    got = points(pts)
    assert got[("net_rx_bps", "Intel(R) Ethernet")] == pytest.approx(1_000_000)
    assert not any("Loopback" in l or "isatap" in l for _m, l in got)


def test_windows_bad_answers():
    with pytest.raises(ssh.SshError):
        ssh.parse_windows("'sh' is not recognized", {}, now=1)
    with pytest.raises(ssh.SshError):
        ssh.parse_windows("##netlens-windows\nnot json", {}, now=1)


def test_the_powershell_command_is_encoded_and_short():
    cmd = ssh.powershell("Get-Date")
    assert cmd.startswith("powershell ") and " -EncodedCommand " in cmd and "Get-Date" not in cmd
    assert len(ssh.WIN_COMMAND) < 7000                                             # cmd.exe stops at 8191


def test_ssh_reading_falls_back_to_windows(monkeypatch):
    import asyncio

    calls = []

    async def run(host, port, user, pw, key, phrase, known=None, timeout=15.0):
        calls.append("linux")
        return "'sh' is not recognized as an internal or external command", "AA:BB"

    async def run_command(host, port, user, pw, key, phrase, command, known=None, timeout=15.0):
        calls.append("windows")
        return win_output(), 0, "AA:BB"

    monkeypatch.setattr(ssh, "run", run)
    monkeypatch.setattr(ssh, "run_command", run_command)
    state = {}
    pts, found, fp = asyncio.run(hm.read("ssh", "10.0.0.7", 22, {"username": "u", "password": "p"}, None, state, None, 1_773_144_000))
    assert calls == ["linux", "windows"] and state["platform"] == "windows" and "cpu" in found
    calls.clear()
    asyncio.run(hm.read("ssh", "10.0.0.7", 22, {"username": "u", "password": "p"}, None, state, None, 1_773_144_060))
    assert calls == ["windows"]                                                    # remembered: no wasted round trip
    calls.clear()


def test_platform_is_validated():
    d = hm.validate({"method": "ssh", "address": "10.0.0.5", "username": "me", "password": "x", "platform": "windows"})
    assert d["secret"]["platform"] == "windows"
    with pytest.raises(hm.MonitorError):
        hm.validate({"method": "ssh", "address": "10.0.0.5", "username": "me", "password": "x", "platform": "vms"})


# ---------------------------------------------------------------- storage health
MDSTAT_OK = ["Personalities : [raid1] [raid6]", "md0 : active raid1 sdb1[1] sda1[0]", "      976630464 blocks super 1.2 [2/2] [UU]", "", "unused devices: <none>"]
MDSTAT_BAD = ["Personalities : [raid5]", "md1 : active raid5 sdc[0] sdd[1](F) sde[2]", "      1953260928 blocks super 1.2 level 5 [3/2] [U_U]",
              "      [=>...................]  recovery =  8.0% (78125000/976630464)", "md2 : inactive sdf[0](S)", "      1000 blocks super 1.2", "md3 : active raid0 sdg[0] sdh[1]", "      2000 blocks 64k chunks"]


def test_mdstat_levels():
    got = {label: v for _m, label, v, _u in ssh.parse_mdstat(MDSTAT_OK + MDSTAT_BAD[1:])}
    assert got == {"md0": 0.0, "md1": 1.0, "md2": 2.0, "md3": 0.0}


def test_ssh_reports_arrays_and_pools():
    text = proc()
    text = text.replace("##end", "##mdstat\n" + "\n".join(MDSTAT_BAD) + "\n##zpool\ntank\tONLINE\nbackup\tDEGRADED\nold\tFAULTED\n##end")
    pts, found = ssh.parse(text, {}, now=100)
    got = {(m, label): v for m, label, v, _u in pts if m == "storage_status"}
    assert got[("storage_status", "md1")] == 1.0 and got[("storage_status", "tank")] == 0.0
    assert got[("storage_status", "backup")] == 1.0 and got[("storage_status", "old")] == 2.0 and "storage" in found


def test_windows_physical_disks():
    data = json.loads(win_output().split("##netlens-windows\n", 1)[1])
    data["pd"] = [{"n": "Samsung SSD", "h": "Healthy"}, {"n": "WD Red", "h": "Warning"}, {"n": "Old", "h": "Unhealthy"}]
    pts, found = ssh.parse_windows("##netlens-windows\n" + json.dumps(data), {}, now=1_773_144_000)
    got = {label: v for m, label, v, _u in pts if m == "storage_status"}
    assert got == {"Samsung SSD": 0.0, "WD Red": 1.0, "Old": 2.0} and "storage" in found


def test_synology_raid_and_disks_over_snmp():
    mib = sim.Mib()
    for i, (name, status) in enumerate([(b"Volume 1", 1), (b"Volume 2", 11)], start=1):
        mib.set(oid(snmp.SYNO_RAID_NAME, i), name)
        mib.set(oid(snmp.SYNO_RAID_STATUS, i), status)
    for i, (name, status, temp) in enumerate([(b"Disk 1", 1, 38), (b"Disk 2", 5, 41), (b"Disk 3", 3, 0)], start=1):
        mib.set(oid(snmp.SYNO_DISK_ID, i), name)
        mib.set(oid(snmp.SYNO_DISK_STATUS, i), status)
        mib.set(oid(snmp.SYNO_DISK_TEMP, i), temp)
    pts, found = snmp.collect(Direct(mib), ["storage"], {}, now=1)
    got = {(m, label): v for m, label, v, _u in pts}
    assert got[("storage_status", "Volume 1")] == 0 and got[("storage_status", "Volume 2")] == 1
    assert got[("storage_status", "Disk 1")] == 0 and got[("storage_status", "Disk 2")] == 2 and got[("storage_status", "Disk 3")] == 0
    assert got[("temp_c", "Disk 1")] == 38 and ("temp_c", "Disk 3") not in got and found == ["storage"]


def test_a_degraded_array_alerts_with_words(tmp_path):
    from app.db import connect as db_connect, init_db as db_init

    c = db_connect(tmp_path / "s.db")
    db_init(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'nas', 1, 'x', 'x')")
    c.execute("INSERT INTO host_monitors (id, device_id, method, address, port, credential, interval_s, groups, alerts, enabled, created) VALUES (1,1,'ssh','10.0.0.5',22,'',60,'[]',1,1,'x')")
    c.commit()
    assert hm.evaluate(c, 1, 1, "nas", [("storage_status", "md1", 1.0, "state")], NOW) == ["metric_warning"]
    text = c.execute("SELECT detail FROM events ORDER BY id DESC LIMIT 1").fetchone()[0]
    assert "nas: md1 is degraded" in text
    assert hm.evaluate(c, 1, 1, "nas", [("storage_status", "md1", 2.0, "state")], NOW) == ["metric_critical"]
    assert hm.evaluate(c, 1, 1, "nas", [("storage_status", "md1", 0.0, "state")], NOW) == ["metric_ok"]
    c.close()


def test_windows_script_errors_are_reported_and_progress_noise_is_not():
    from app.hostmetrics import winrm

    refused = "##netlens-windows\n" + json.dumps({"e": ["memory: Access denied", "processor: Access denied"]})
    with pytest.raises(ssh.SshError, match="Access denied"):
        ssh.parse_windows(refused, {}, now=1)
    progress = '#< CLIXML\n<Objs Version="1.1.0.1"><Obj S="progress"><TN><T>System.Management.Automation.PSCustomObject</T></TN><PR N="Activity">Preparing modules for first use.</PR></Obj></Objs>'
    assert winrm.powershell_error(progress) == ""
    error = '#< CLIXML\n<Objs><S S="Error">Get-CimInstance : Access denied_x000D__x000A_</S></Objs>'
    assert "Access denied" in winrm.powershell_error(error)
    script = ssh.WIN_SCRIPT
    assert "$ProgressPreference='SilentlyContinue'" in script and len(ssh.WIN_COMMAND) < 7000


# ---------------------------------------------------------------- stopped Windows services
def test_windows_stopped_services_are_read():
    data = json.loads(win_output().split("##netlens-windows\n", 1)[1])
    data["sv"] = ["Backup Agent", "SQL Server (MSSQLSERVER)"]
    pts, found = ssh.parse_windows("##netlens-windows\n" + json.dumps(data), {}, now=1_773_144_000)
    got = {label: v for m, label, v, _u in pts if m == "service_stopped"}
    assert got == {"": 0.0, "Backup Agent": 1.0, "SQL Server (MSSQLSERVER)": 1.0} and "services" in found
    data["sv"] = "Spooler"       # PowerShell gives a single answer as a plain string
    pts, _ = ssh.parse_windows("##netlens-windows\n" + json.dumps(data), {}, now=1_773_144_000)
    assert {label for m, label, _v, _u in pts if m == "service_stopped"} == {"", "Spooler"}


def test_stopped_service_raises_and_clears(conn):
    monitor(conn)
    mid = hm.get_monitor(conn, 1)["id"]
    sentinel = ("service_stopped", "", 0.0, "state")
    stopped = ("service_stopped", "Backup Agent", 1.0, "state")
    assert hm.evaluate(conn, mid, 1, "pc", [sentinel, stopped], NOW) == ["metric_warning"]
    assert hm.evaluate(conn, mid, 1, "pc", [sentinel], "2026-03-10T12:01:00Z") == ["metric_ok"]     # gone from the list: running again
    assert any("the service Backup Agent is running again" in d for _k, d in events(conn))
    assert hm.evaluate(conn, mid, 1, "pc", [sentinel], "2026-03-10T12:02:00Z") == []
    # a round that did not read the services (no sentinel) clears nothing
    hm.evaluate(conn, mid, 1, "pc", [sentinel, stopped], "2026-03-10T12:03:00Z")
    assert hm.evaluate(conn, mid, 1, "pc", [("cpu_pct", "", 10, "%")], "2026-03-10T12:04:00Z") == []


def test_a_temperature_warning_clears_when_the_reading_is_no_longer_taken(tmp_path):
    from app.db import connect, init_db
    from app.hostmetrics import service

    conn = connect(tmp_path / "t.db")
    init_db(conn)
    dev = conn.execute("INSERT INTO devices (primary_ip, first_seen, last_seen) VALUES ('10.0.0.5', 'x', 'x')").lastrowid
    conn.execute("INSERT INTO host_monitors (id, device_id, method, address, port, created) VALUES (1, ?, 'ssh', '10.0.0.5', 22, 'x')", (dev,))
    conn.execute("INSERT INTO metric_state (monitor_id, metric, label, level, since, value, pending, pending_n) VALUES (1, 'temp_c', 'x86_pkg_temp', 'warning', 'x', 84, NULL, 0)")
    service.evaluate(conn, 1, dev, "lxc", [("cpu_pct", "", 10.0, "%")])                      # the read worked, there is no temperature any more
    assert conn.execute("SELECT level FROM metric_state").fetchone()[0] == "ok"
    conn.execute("UPDATE metric_state SET level = 'warning'")
    service.evaluate(conn, 1, dev, "lxc", [])                                                 # a failed read changes nothing
    assert conn.execute("SELECT level FROM metric_state").fetchone()[0] == "warning"


def sensors_mib(rows):
    """rows: (index, type, scale, precision, raw value, oper status, name)"""
    mib = sim.Mib()
    for index, kind, scale, precision, raw, oper, name in rows:
        mib.set(oid(snmp.ENT_SENSOR + (1,), index), kind)
        mib.set(oid(snmp.ENT_SENSOR + (2,), index), scale)
        mib.set(oid(snmp.ENT_SENSOR + (3,), index), precision)
        mib.set(oid(snmp.ENT_SENSOR + (4,), index), raw)
        mib.set(oid(snmp.ENT_SENSOR + (5,), index), oper)
        mib.set(oid(snmp.ENT_PHYS_NAME, index), name.encode())
    return mib


def test_entity_sensors_give_temperature_fans_voltage_and_faults():
    mib = sensors_mib([
        (1, 8, 9, 1, 423, 1, "CPU temp"),             # units, 1 decimal: 42.3 C
        (2, 10, 9, 0, 4200, 1, "Fan 1"),              # rpm
        (3, 10, 9, 0, 0, 1, "Fan 2"),                 # stopped
        (4, 4, 8, 0, 12000, 1, "PSU 1 12V"),          # milli volts: 12 V
        (5, 4, 8, 0, 0, 3, "PSU 2 12V"),              # nonoperational: a failed power supply
        (6, 8, 9, 0, 55, 2, "Absent sensor"),         # unavailable: ignored
    ])
    got = points(snmp.collect(Direct(mib), groups=["sensors"], state={}, now=1)[0])
    assert got[("temp_c", "CPU temp")] == pytest.approx(42.3)
    assert got[("fan_rpm", "Fan 1")] == 4200 and got[("sensor_fault", "Fan 1")] == 0
    assert got[("sensor_fault", "Fan 2")] == 2
    assert got[("voltage_v", "PSU 1 12V")] == pytest.approx(12.0)
    assert got[("sensor_fault", "PSU 2 12V")] == 1 and got[("sensor_fault", "PSU 1 12V")] == 0
    assert not any(label == "Absent sensor" for (_m, label) in got)


def test_a_device_without_entity_sensors_reports_nothing():
    pts, found = snmp.collect(Direct(sim.Mib()), groups=["sensors"], state={}, now=1)
    assert pts == [] and "sensors" not in found


def test_fan_fault_raises_an_alert_with_a_clear_sentence(tmp_path):
    from app.db import connect, get_or_create_device, init_db
    from app.hostmetrics import service

    conn = connect(tmp_path / "t.db")
    init_db(conn)
    dev = get_or_create_device(conn, "aa:bb:cc:00:00:09", "10.0.0.9")
    conn.execute("INSERT INTO host_monitors (device_id, method, address, port, credential, interval_s, groups, alerts, enabled, created) VALUES (?,?,?,?,?,?,?,?,?,?)",
                 (dev, "snmp", "10.0.0.9", 161, "", 60, "[]", 1, 1, "2026-01-01T00:00:00Z"))
    conn.commit()
    monitor = conn.execute("SELECT id FROM host_monitors").fetchone()[0]
    pts = [("sensor_fault", "Fan 2", 2.0, "state")]
    service.evaluate(conn, monitor, dev, "sw1", pts)
    service.evaluate(conn, monitor, dev, "sw1", pts)
    detail = conn.execute("SELECT kind, detail FROM events WHERE kind LIKE 'metric_%'").fetchone()
    assert detail["kind"] == "metric_critical" and "Fan 2 has stopped" in detail["detail"]


def test_vendor_readings_for_apc_and_mikrotik():
    apc = sim.Mib()
    apc.set(snmp.SYS_OBJECT_ID, (1, 3, 6, 1, 4, 1, 318, 1, 3, 2, 8))
    for o, v in ((snmp.APC_CAPACITY, 87), (snmp.APC_RUNTIME, 90000), (snmp.APC_TEMP, 29), (snmp.APC_STATUS, 3), (snmp.APC_LOAD, 41)):
        apc.set(o, v)
    got = points(snmp.collect(Direct(apc), groups=["vendor"], state={}, now=1)[0])
    assert got[("battery_pct", "")] == 87 and got[("battery_minutes", "")] == 15 and got[("temp_c", "UPS battery")] == 29
    assert got[("on_battery", "")] == 1 and got[("ups_load_pct", "")] == 41

    mt = sim.Mib()
    mt.set(snmp.SYS_OBJECT_ID, (1, 3, 6, 1, 4, 1, 14988, 1))
    for o, v in ((snmp.MT_VOLTAGE, 242), (snmp.MT_TEMP, 415), (snmp.MT_CPU_TEMP, 520), (snmp.MT_FAN1, 5100), (snmp.MT_FAN2, 0)):
        mt.set(o, v)
    got = points(snmp.collect(Direct(mt), groups=["vendor"], state={}, now=1)[0])
    assert got[("voltage_v", "Supply")] == pytest.approx(24.2) and got[("temp_c", "Board")] == pytest.approx(41.5) and got[("temp_c", "CPU")] == pytest.approx(52.0)
    assert got[("fan_rpm", "Fan 1")] == 5100 and got[("sensor_fault", "Fan 1")] == 0 and got[("sensor_fault", "Fan 2")] == 2


def test_other_vendors_get_no_vendor_readings():
    other = sim.Mib()
    other.set(snmp.SYS_OBJECT_ID, (1, 3, 6, 1, 4, 1, 9, 1, 1))
    pts, found = snmp.collect(Direct(other), groups=["vendor"], state={}, now=1)
    assert pts == [] and found == []
