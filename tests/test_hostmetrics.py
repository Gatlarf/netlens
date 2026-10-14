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
    assert pts == [] and found == ["network"]                           # the first round only learns the counters
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
