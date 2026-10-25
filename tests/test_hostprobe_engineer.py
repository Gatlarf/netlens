"""The digital engineer: every probe's answer is read, turned into evidence, and chained across probes into a root cause."""

import shutil
import stat
import subprocess
import time
from datetime import datetime, timezone

import pytest

from app import ask, licence, tsdb
from app.db import connect, init_db
from app.hostprobe import analyze, diagnose, parsers, scripts, service

GB = 1024 ** 3
NOW = 1792950000.0

CPU = """##version 4
##loadavg
11.50 9.20 6.10 3/812 99999
##cpus
4
##pressure
cpu some avg10=35.20 avg60=20.00 avg300=10.00 total=1
io some avg10=1.00 avg60=0.00 avg300=0.00 total=1
memory some avg10=0.00 avg60=0.00 avg300=0.00 total=0
##vmstat
 11  0      0 100000  1000 2000    0    0     0     0  570  719 90  6  2  0  2
##top
top - 18:52:08 up 18 days,  1 user,  load average: 11.50, 9.20, 6.10
%Cpu(s): 90.1 us,  6.0 sy,  0.0 ni,  1.9 id,  0.0 wa,  0.0 hi,  0.0 si,  2.0 st
    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
   2345 root      20   0 6716684   1.2g 145436 R 310.0   5.1   331:50.08 gvmd
   2400 postgres  20   0  666684 238628  45436 S  40.5   1.0     1:50.08 postgres
      1 root      20   0   22228  12800   9280 S   0.0   0.1     0:13.98 systemd
##ps
    PID %CPU %MEM   RSS     ELAPSED USER     COMMAND
   2345 99.0  5.1 1258291 2-11:30:53 root     gvmd
##containers
abc123def456|greenbone-gvmd-1
##cgroups
2345|abc123def456
##dockerstats
greenbone-gvmd-1|312.40%|1.2GiB / 8GiB|10MB / 20MB|0B / 0B
##end
"""

MEMORY = """##version 4
##meminfo
MemTotal:       16384000 kB
MemFree:          200000 kB
MemAvailable:     500000 kB
Cached:           300000 kB
SwapTotal:       4096000 kB
SwapFree:         500000 kB
##pressure
memory some avg10=22.00 avg60=15.00 avg300=5.00 total=1
##vmstat
 5  2 3500000 200000 1000 2000  400  800     0     0  570  719 20  6  60  14  0
##ps
    PID   RSS %MEM     ELAPSED USER     COMMAND
   4100 12000000 73.2    03:11:12 app      java
   4200 400000  2.4    10:00 app      postgres
##containers
##cgroups
##oom
[Sun Oct 25 02:48:31 2026] Out of memory: Killed process 4200 (postgres) total-vm:900kB, anon-rss:400kB
##dockerstats
##dockeroom
/db|false|7|0
/web|true|3|536870912
##end
"""

NETWORK = """##version 4
##time
1792950000
##net1
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  eth0: 1000000 1000 0 0 0 0 0 0 2000000 2000 0 0 0 0 0 0
    lo: 10 1 0 0 0 0 0 0 10 1 0 0 0 0 0 0
##net2
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  eth0: 126000000 90000 500 400 0 0 0 0 52000000 40000 100 50 0 0 0 0
    lo: 10 1 0 0 0 0 0 0 10 1 0 0 0 0 0 0
##snmp
Tcp: RtoAlgorithm InSegs OutSegs RetransSegs AttemptFails EstabResets
Tcp: 1 1000000 1000000 60000 10 5
##tcpext
##states
ESTAB|300
CLOSE-WAIT|450
##remote
250|10.0.0.99
##processes
    250 nginx
##listening
0.0.0.0:80|users:(("nginx",pid=1,fd=3))
##route
default via 192.168.0.1 dev eth0
##ping
gateway|192.168.0.1|3 packets transmitted, 3 received, 0% packet loss, time 2003ms rtt min/avg/max/mdev = 1.0/1.2/1.4/0.1 ms
internet|1.1.1.1|3 packets transmitted, 0 received, 100% packet loss, time 2003ms
dns|example.com|rc=2 ms=5000
##end
"""

APPS = """##version 4
##uptime
100000.0 1.0
##failed
foo.service loaded failed failed Foo daemon
##failedinfo
Id=foo.service Result=exit-code ExecMainStatus=3 NRestarts=12 InactiveEnterTimestamp=x 
##journal
40|foo
##journalsample
Oct 25 02:50:01 h foo[1]: it broke
##docker
/db|exited|137|true|7|healthy|2026-10-25T02:50:00Z|2026-10-25T02:49:50Z|postgres:16
/web|restarting|1|false|40||2026-10-25T02:51:00Z|2026-10-25T02:50:50Z|web:latest
##dockererrors
/web|900
##end
"""

CHANGES = """##version 4
##tz
+0100
##time
1792950000
##boots
##packages
2026-10-25 03:40:00 upgrade libssl3:amd64 1 2
##etc
1792950000.0\t/etc/app/app.conf
##docker
##users
root|0|/bin/bash
##keys
##end
"""


# ----------------------------------------------------------------------------- reading
def test_each_linux_answer_is_read():
    cpu = parsers.parse_probe("cpu", "linux", CPU)
    assert cpu["cpus"] == 4 and cpu["load"][0] == 11.5 and cpu["cpu_pct"]["us"] == 90.1 and cpu["cpu_pct"]["st"] == 2.0
    assert cpu["procs"][0]["name"] == "gvmd" and cpu["procs"][0]["container"] == "greenbone-gvmd-1" and cpu["procs"][0]["cpu"] == 310.0
    mem = parsers.parse_probe("memory", "linux", MEMORY)
    assert mem["used_pct"] > 96 and mem["swap_used"] > 3 * GB and mem["swap_io"] == {"si": 400.0, "so": 800.0} and mem["procs"][0]["name"] == "java" and mem["container_oom"][1]["oom"] is True
    net = parsers.parse_probe("network", "linux", NETWORK)
    eth = net["interfaces"][0]
    assert eth["name"] == "eth0" and eth["rx_bps"] == (126000000 - 1000000) * 8 and eth["rx_err"] == 500 and net["states"]["CLOSE-WAIT"] == 450
    assert net["tcp"]["RetransSegs"] == 60000 and net["ping"][1]["loss"] == 100.0 and net["dns"] == {"ok": False, "ms": 5000} and net["listening"][0]["process"] == "nginx"
    apps = parsers.parse_probe("apps", "linux", APPS)
    assert apps["failed_units"][0]["restarts"] == 12 and apps["containers"][0]["oom"] and apps["containers"][1]["errors"] == 900 and apps["errors"][0] == {"unit": "foo", "count": 40}
    ch = parsers.parse_probe("changes", "linux", CHANGES)
    assert {e["kind"] for e in ch["events"]} == {"package", "file"} and ch["events"][0]["at"] == 1792950000.0
    pkg = next(e for e in ch["events"] if e["kind"] == "package")
    assert pkg["at"] == datetime(2026, 10, 25, 2, 40, tzinfo=timezone.utc).timestamp()           # 03:40 local at +0100 is 02:40 UTC
    with pytest.raises(parsers.ProbeError):
        parsers.parse_probe("cpu", "linux", CPU.replace("##end", ""))


def test_windows_answers_are_read():
    import json

    def wrap(d):
        return "noise\n##netlens-probe\n" + json.dumps(d)

    cpu = parsers.parse_probe("cpu", "windows", wrap({"version": 4, "cpus": 8, "load": 95, "procs": [{"id": 4, "n": "sqlservr", "cpu": 640.0, "ws": 8 * GB}]}))
    assert cpu["cpu_pct"]["busy"] == 95 and cpu["procs"][0]["name"] == "sqlservr"
    mem = parsers.parse_probe("memory", "windows", wrap({"total_kb": 16 * 1024 ** 2, "free_kb": 500000, "procs": {"id": 4, "n": "x", "ws": 5 * GB}}))
    assert mem["used_pct"] > 96 and mem["procs"][0]["rss"] == 5 * GB
    net = parsers.parse_probe("network", "windows", wrap({"nics": [{"n": "Ethernet", "rx": 9e8, "tx": 1e6, "rxerr": 0}], "ping": [{"t": "gateway", "ip": "1.1.1.1", "ok": 0, "ms": None}], "dns": {"ok": True, "ms": 20}}))
    assert net["interfaces"][0]["rx_bps"] == 9e8 and net["ping"][0]["loss"] == 100.0
    apps = parsers.parse_probe("apps", "windows", wrap({"services": [{"n": "Print Spooler", "state": "Stopped", "exit": 1}], "errors": [{"n": "Disk", "c": 30}]}))
    assert apps["failed_units"][0]["unit"] == "Print Spooler" and apps["errors"][0]["count"] == 30
    hw = parsers.parse_probe("hardware", "windows", wrap({"disks": [{"n": "Samsung", "health": "Warning", "temp": 40, "werr": 2}]}))
    assert hw["disks"][0]["bad"]
    sec = parsers.parse_probe("security", "windows", wrap({"failed_total": 120, "failed": [{"ip": "1.2.3.4", "c": 100}], "firewall": [{"n": "Public", "on": False}]}))
    assert sec["failed_total"] == 120 and sec["firewall"]["Public"] == "inactive"
    with pytest.raises(parsers.ProbeError):
        parsers.parse_probe("cpu", "windows", "nothing")


# ----------------------------------------------------------------------------- meaning
def texts(evidence):
    return " | ".join(e["text"] for e in evidence)


def test_cpu_names_the_process_the_container_and_the_hypervisor():
    cpu = parsers.parse_probe("cpu", "linux", CPU)
    t = texts(analyze.analyze("cpu", cpu, {}))
    assert "98% busy" in t and "greenbone-gvmd-1" in t and "310% of one core" in t and "hypervisor" not in t       # steal is 2%: below the limit
    cpu["cpu_pct"]["st"] = 15.0
    assert "hypervisor takes 15%" in texts(analyze.analyze("cpu", cpu, {}))
    idle = parsers.parse_probe("cpu", "linux", CPU.replace("90.1 us,  6.0 sy,  0.0 ni,  1.9 id", "1.0 us, 1.0 sy, 0.0 ni, 98.0 id").replace("11.50 9.20 6.10", "0.1 0.1 0.1"))
    rule_out = analyze.analyze("cpu", idle, {})
    assert rule_out[0]["tags"] == ["ok:cpu"]                                                                       # "not busy" is evidence too


def test_memory_swap_oom_and_container_limits():
    mem = parsers.parse_probe("memory", "linux", MEMORY)
    t = texts(analyze.analyze("memory", mem, {}))
    assert "Memory is 97% used" in t and "java" in t and "swapping" in t and "killed postgres" in t and "container web was killed for exceeding its memory limit" in t


def test_network_finds_errors_retransmits_dns_and_where_the_internet_breaks():
    net = parsers.parse_probe("network", "linux", NETWORK)
    t = texts(analyze.analyze("network", net, {}))
    assert "errors or dropped packets" in t and "6.0% of the TCP segments" in t and "CLOSE-WAIT" in t and "beyond the gateway" in t and "Name lookups fail" in t and "250 open connections" in t


def test_apps_finds_the_restart_loop_the_oom_kill_and_the_failed_service():
    apps = parsers.parse_probe("apps", "linux", APPS)
    t = texts(analyze.analyze("apps", apps, {}))
    assert "service foo.service has failed" in t and "exit status 3" in t and "db was killed because it ran out of memory" in t and "web keeps restarting (40 restarts" in t and "900 error lines" in t


def test_changes_and_jobs_close_to_the_start_are_candidates_and_far_ones_are_ruled_out():
    ch = parsers.parse_probe("changes", "linux", CHANGES)
    near = analyze.analyze("changes", ch, {"onset": 1792950000.0 - 600})
    assert any("/etc/app/app.conf was changed" in e["text"] and e["private"] for e in near) and all(e["weight"] >= 45 for e in near)
    at_package = analyze.analyze("changes", ch, {"onset": datetime(2026, 10, 25, 2, 50, tzinfo=timezone.utc).timestamp()})
    assert any("libssl3" in e["text"] and "10 minutes before" in e["text"] for e in at_package)
    assert analyze.analyze("changes", ch, {"onset": 1792950000.0 + 86400})[0]["tags"] == ["ok:changes"]
    sched = {"jobs": [{"name": "greenbone-scan.timer", "source": "timer", "last": 1792950000.0 - 300, "next": None, "detail": "x"}], "runs": []}
    e = analyze.analyze("schedule", sched, {"onset": 1792950000.0})
    assert e and "started at" in e[0]["text"] and "5 minutes before" in e[0]["text"] and e[0]["tags"] == ["job:greenbone-scan.timer"]


def test_hardware_and_security():
    hw = {"disks": [{"dev": "/dev/sda", "health": "FAILED!", "detail": "Reallocated=40", "bad": True}], "raid": [{"name": "md0", "state": "active", "degraded": True, "detail": "1 of 2 disks up"}], "zfs": [], "temps": [{"name": "cpu", "c": 91.0}],
          "errors": ["ata1: error"], "readonly": ["/data|ext4"], "ups": [{"name": "ups", "detail": "ups.status: OB "}]}
    t = texts(analyze.analyze("hardware", hw, {}))
    assert "/dev/sda reports trouble" in t and "md0 is degraded" in t and "91 °C" in t and "hardware, disk or memory errors" in t and "read-only" in t and "on battery" in t
    sec = {"failed_total": 300, "failed": [{"ip": "6.6.6.6", "count": 280}], "updates": {"pending": 40, "security": 3, "reboot": True}, "time_synced": False, "firewall": {"ufw": "inactive"}, "exposed": ["0.0.0.0:22"]}
    t = texts(analyze.analyze("security", sec, {}))
    assert "300 failed sign-in" in t and "6.6.6.6" in t and "3 security updates" in t and "clock is not synchronised" in t and "firewall is switched off" in t


# ----------------------------------------------------------------------------- chains
def chain_texts(evidence):
    return [c["text"] for c in analyze.correlate(evidence, {})]


def test_a_memory_hog_that_gets_a_database_killed_which_restarts_and_fills_the_disk():
    mem = analyze.analyze("memory", parsers.parse_probe("memory", "linux", MEMORY), {})
    apps = analyze.analyze("apps", parsers.parse_probe("apps", "linux", APPS), {})
    apps_db = [dict(e, tags=[t.replace("oom:db", "oom:postgres").replace("restart_loop:web", "restart_loop:postgres") for t in e["tags"]]) for e in apps]
    storage = [analyze.ev("storage", "cause", 85, "log grew", ["disk_full", "log_growth:postgres"], private=True)]
    chains = chain_texts(mem + apps_db + storage)
    assert chains[0].startswith("Java used most of the memory, so the kernel killed postgres; postgres restarts in a loop")
    assert any("restarts in a loop, its log keeps growing, and that fills the disk" in c for c in chains)


def test_a_scheduled_scan_and_the_processor_busy_since():
    cpu = analyze.analyze("cpu", parsers.parse_probe("cpu", "linux", CPU), {})
    sched = analyze.analyze("schedule", {"jobs": [{"name": "greenbone-scan.timer", "source": "timer", "last": NOW - 600, "next": None, "detail": ""}], "runs": []}, {"onset": NOW})
    c = analyze.correlate(cpu + sched, {})
    assert c[0]["text"].startswith("The scheduled job greenbone-scan.timer started at") and "busy with greenbone-gvmd-1 since" in c[0]["text"]


def test_a_change_before_the_trouble():
    ch = analyze.analyze("changes", parsers.parse_probe("changes", "linux", CHANGES), {"onset": 1792950000.0 - 300})
    apps = analyze.analyze("apps", parsers.parse_probe("apps", "linux", APPS), {})
    assert any(t.startswith("A change preceded the trouble") for t in chain_texts(ch + apps))


def test_the_internet_down_but_the_lan_fine_is_a_provider_problem():
    net = analyze.analyze("network", parsers.parse_probe("network", "linux", NETWORK), {})
    assert any("not: the problem is at the provider" in c or "the internet connection is not" in c for c in chain_texts(net))


# ----------------------------------------------------------------------------- from a symptom to a report
def test_the_plan_follows_the_symptom():
    assert diagnose.plan("out of memory")[:2] == ["memory", "apps"]
    assert diagnose.plan("network timeouts")[0] == "network" and diagnose.plan("the disk is full")[0] == "storage"
    assert diagnose.plan("why does it keep restarting")[0] == "apps" and diagnose.plan("slow")[0] == "cpu"
    assert diagnose.plan("") == list(scripts.PROBES) and diagnose.plan("zzz") == list(scripts.PROBES)
    assert diagnose.plan("", ["mem_pct"]) == ["memory", "apps"] and "network" in diagnose.plan("?", ["if_err_ps"])             # a reading over its limit narrows it down


@pytest.fixture
def conn(tmp_path, monkeypatch):
    tsdb.forget_all()
    c = connect(tmp_path / "e.db")
    init_db(c)
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'web1', 1, 'x', 'x')")
    c.commit()
    yield c
    c.close()
    tsdb.forget_all()


def fill(conn, now=None):
    now = now or time.time()
    for probe, text in (("cpu", CPU), ("memory", MEMORY), ("network", NETWORK), ("apps", APPS), ("changes", CHANGES)):
        service.store(conn, 1, True, "locked", None, parsers.parse_probe(probe, "linux", text), now=now - 60, probe=probe)


def test_a_diagnosis_from_the_snapshots(conn):
    service.save_settings(conn, {"devices": {"1": {"enabled": True}}})
    fill(conn)
    rep = diagnose.diagnose(conn, 1, "the server is slow")
    assert rep["device"] == "web1" and rep["probes"][0] == "cpu" and "cpu" in rep["taken"] and "hardware" in rep["missing"] and "schedule" in rep["missing"]
    assert rep["chains"] and rep["findings"][0]["level"] == "cause"
    all_text = " ".join(f["text"] for f in rep["findings"])
    assert "greenbone-gvmd-1" in all_text and "Ruled out" not in all_text
    empty = diagnose.diagnose(conn, 1, "zzz", time.time() + 10 * 86400)                                                  # snapshots a week old are not today's picture
    assert not empty["taken"] and empty["findings"] == []


def test_the_model_never_gets_names_and_log_lines_unless_allowed(conn):
    service.save_settings(conn, {"devices": {"1": {"enabled": True}}})
    fill(conn)
    plain = ask.TOOLS["host_activity"][0](conn, {"device": "web1", "symptom": "memory"}, None)
    assert "killed postgres" in str(plain)
    token = ask._FOR_MODEL.set(True)
    try:
        hidden = ask.TOOLS["host_activity"][0](conn, {"device": "web1", "symptom": "memory"}, None)
        assert "kernel killed postgres" not in str(hidden) and "Out of memory" not in str(hidden)           # the log line is private, the process name is not
        service.save_settings(conn, {"names_to_llm": True})
        assert "kernel killed postgres" in str(ask.TOOLS["host_activity"][0](conn, {"device": "web1", "symptom": "memory"}, None))
    finally:
        ask._FOR_MODEL.reset(token)


def test_ask_routes_to_the_engineer(conn):
    service.save_settings(conn, {"devices": {"1": {"enabled": True}}})
    fill(conn)
    for q in ("why is web1 slow?", "what is using the cpu on web1", "why did web1 restart"):
        assert ask.route(q, ["web1"], conn)[0] == "host_activity", q
    a = ask.answer(conn, "why is web1 slow?", None)
    assert a["tools"] == ["host_activity"] and "web1" in a["answer"] and "greenbone-gvmd-1" in a["answer"]


def test_an_alarm_calls_for_the_right_probes(conn):
    service.save_settings(conn, {"devices": {"1": {"enabled": True, "probes": ["cpu", "memory", "apps"]}}})
    now = time.time()
    for probe in ("cpu", "memory", "apps"):
        service.store(conn, 1, True, "direct", None, {"platform": "linux"}, now=now - 3600, probe=probe)
    assert service.due(conn, now) == []                                                                              # looked at an hour ago, a day is the baseline
    conn.execute("INSERT INTO host_monitors (id, device_id, method, address, port, created) VALUES (7, 1, 'ssh', 'a', 22, 'x')")
    conn.execute("INSERT INTO metric_state (monitor_id, metric, label, level, since, value) VALUES (7, 'mem_pct', '', 'critical', 'x', 98)")
    conn.commit()
    assert sorted(service.due(conn, now)) == [(1, "apps"), (1, "memory")]                                            # memory pressure: look at memory and applications, not the processor
    assert service.device_config(conn, 1)["probes"] == ["cpu", "memory", "apps"]
    with pytest.raises(ValueError):
        service.save_settings(conn, {"devices": {"1": {"probes": ["cpu", "telepathy"]}}})


# ----------------------------------------------------------------------------- the host side
@pytest.fixture
def fakebin(tmp_path):
    d = tmp_path / "bin"
    d.mkdir()
    sudo = d / "sudo"
    sudo.write_text('#!/bin/sh\n[ "$1" = "-n" ] && shift\necho "SUDO RAN: $*"\n')
    sudo.chmod(sudo.stat().st_mode | stat.S_IEXEC)
    entry = tmp_path / "entry"
    entry.write_text(scripts.linux_entry())
    entry.chmod(entry.stat().st_mode | stat.S_IEXEC)
    return d, entry


def run_entry(fakebin, ask_text):
    d, entry = fakebin
    env = {"PATH": f"{d}:/usr/bin:/bin", "SSH_ORIGINAL_COMMAND": ask_text}
    return subprocess.run(["sh", str(entry)], env=env, capture_output=True, text=True)


def test_the_entry_script_runs_a_probe_by_name_and_nothing_else(fakebin):
    for name in scripts.PROBES:
        r = run_entry(fakebin, f"netlens-probe {name}")
        assert r.returncode == 0 and r.stdout.strip() == f"SUDO RAN: {scripts.WRAPPER_PATH} {name}", name
    for bad in ("", "id", "netlens-probe", "netlens-probe cpu; id", "netlens-probe ../../bin/sh", "netlens-probe CPU", "sh -c 'netlens-probe cpu'", "netlens-probe cpu memory", "netlens-probe -h"):
        r = run_entry(fakebin, bad)
        assert r.returncode == 2 and "refused" in r.stderr and "SUDO RAN" not in r.stdout, bad


def test_the_wrapper_runs_a_probe_and_refuses_an_unknown_one(tmp_path):
    w = tmp_path / "probe"
    w.write_text(scripts.linux_wrapper())
    bad = subprocess.run(["sh", str(w), "format-disk"], capture_output=True, text=True)
    assert bad.returncode == 2 and "unknown probe" in bad.stderr
    ok = subprocess.run(["sh", str(w), "changes"], capture_output=True, text=True, timeout=60)
    assert ok.returncode == 0 and "##end" in ok.stdout and f"##version {scripts.SCRIPT_VERSION}" in ok.stdout
    parsers.parse_probe("changes", "linux", ok.stdout)                                                                 # the real output of the real script parses


def test_the_setup_files_cover_every_probe():
    setup = scripts.linux_setup("netlens-ro", "ssh-ed25519 AAAA k", "ssh-ed25519 AAAA ca")
    for name in scripts.PROBES:
        assert f"{scripts.WRAPPER_PATH} {name}" in setup["sudoers"]
    assert f'command="{scripts.ENTRY_PATH}",restrict' in setup["authorized_keys"] and f"ForceCommand {scripts.ENTRY_PATH}" in setup["sshd_config"]
    assert scripts.ENTRY_PATH in setup["install"] and "entry" in setup


def test_no_probe_changes_anything():
    forbidden = ("rm ", "mv ", "chmod", "chown", "kill ", "tee ", "> /", "mkfs", "systemctl restart", "systemctl stop", "systemctl start", "systemctl enable", "docker rm", "docker stop", "docker exec", "docker run",
                 "docker restart", "truncate", "apt-get install", "apt-get -y", "dnf install", "systemctl reboot", "shutdown -", "/sbin/reboot", "poweroff", "mount ", "umount", "iptables -A", "ufw enable", "ufw allow", "ufw deny")
    for name in scripts.PROBES:
        text = scripts.linux_script(name)
        for word in forbidden:
            assert word not in text, (name, word)
        win = scripts.windows_script(name)
        for word in ("Remove-", "Set-", "New-Item", "New-Local", "New-Net", "Stop-", "Start-Service", "Restart-", "Invoke-", "Write-", "Out-File", "Add-Content", "Clear-", "Disable-", "Enable-", "Uninstall-", "Install-"):
            assert word not in win, (name, word)


@pytest.mark.skipif(not shutil.which("pwsh"), reason="PowerShell is not installed here")
def test_the_windows_scripts_parse_in_powershell(tmp_path):
    for name in scripts.PROBES:
        f = tmp_path / f"{name}.ps1"
        f.write_text(scripts.windows_script(name))
        check = ("$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('" + str(f) + "',[ref]$t,[ref]$e);if($e.Count){$e|%{$_.Message};exit 1}")
        r = subprocess.run(["pwsh", "-NoProfile", "-Command", check], capture_output=True, text=True)
        assert r.returncode == 0, (name, r.stdout)
    w = tmp_path / "wrapper.ps1"
    w.write_text(scripts.windows_wrapper())
    r = subprocess.run(["pwsh", "-NoProfile", "-Command", "$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('" + str(w) + "',[ref]$t,[ref]$e);if($e.Count){$e|%{$_.Message};exit 1}"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


# ----------------------------------------------------------------------------- Windows: what the limited probe account really returned (captured on a real Windows 11 host)
def test_windows_answers_from_a_limited_account_are_read_and_say_what_could_not_be_read():
    import json as _json

    def wrap(d):
        return "##netlens-probe\n" + _json.dumps(d)

    cpu = parsers.parse_probe("cpu", "windows", wrap({"version": 6, "cpus": 20, "load": 10.7, "queue": 0, "diskq": 0, "procs": [{"id": 0, "n": "searchindexer", "cpu": 58.3, "ws": 0}], "notes": []}))
    assert cpu["cpu_pct"] == {"busy": 10.7} and cpu["procs"][0]["name"] == "searchindexer"
    mem = parsers.parse_probe("memory", "windows", wrap({"total_kb": 49679100, "free_kb": 29912068, "commit_total_kb": 137438953344, "commit_free_kb": 135286597760, "pagefile_pct": 1.75,
                                                       "procs": [{"id": 0, "n": "vmmemwsl", "ws": 3345068032, "pm": 0}], "notes": []}))
    assert 39 < mem["used_pct"] < 40 and mem["swap_total"] == 0 and mem["procs"][0]["name"] == "vmmemwsl"                           # a 64-bit "virtual size" is not a swap size
    hw = parsers.parse_probe("hardware", "windows", wrap({"version": 6, "notes": ["disk health (SMART) needs more rights than the probe account has: Access denied"]}))
    found = analyze.analyze("hardware", hw, {})
    assert any("Could not read part of this: disk health (SMART) needs more rights" in e["text"] and e["tags"] == ["cannot_read"] for e in found)
    sched = parsers.parse_probe("schedule", "windows", wrap({"tasks": [{"n": "\\Backup", "last": "2026-10-25T02:50:00.0000000Z", "next": None, "res": 267011}, {"n": "\\Sync", "last": "2026-10-25T02:49:00.0000000Z", "next": None, "res": -2147160572}]}))
    onset = datetime(2026, 10, 25, 2, 55, tzinfo=timezone.utc).timestamp()
    texts_ = " | ".join(e["text"] for e in analyze.analyze("schedule", sched, {"onset": onset}))
    assert "\\Backup started at" in texts_ and "\\Sync started at" in texts_ and "ended with an error" in texts_ and texts_.count("ended with an error") == 1       # 267011 is "not yet run", not an error
    sec = parsers.parse_probe("security", "windows", wrap({"failed_total": 4, "firewall": [{"n": "Domain", "on": False}, {"n": "Public", "on": False}], "time_synced": False, "admins": ["PC\\Administrator"]}))
    t = " | ".join(e["text"] for e in analyze.analyze("security", sec, {}))
    assert "firewall is switched off" in t and "clock is not synchronised" in t
