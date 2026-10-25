"""Different from normal: a probe's answer against what the same probe saw on the same host before."""

import copy
import time

import pytest

from app import tsdb
from app.db import connect, init_db
from app.hostprobe import baseline, diagnose, parsers, service
from tests.test_hostprobe_engineer import APPS, CPU, GB, MEMORY, NETWORK

MB = 1024 ** 2


def calm_cpu():
    d = parsers.parse_probe("cpu", "linux", CPU)
    d["cpu_pct"] = {"us": 4.0, "sy": 2.0, "id": 94.0, "wa": 0.0, "st": 0.0}
    d["procs"] = [{"pid": 1, "name": "plex", "user": "x", "cpu": 12.0, "mem_pct": 2.0, "container": None}]
    return d


def test_nothing_is_said_before_a_few_days_of_history():
    assert baseline.compare("cpu", parsers.parse_probe("cpu", "linux", CPU), [calm_cpu()]) == []
    assert baseline.compare("cpu", parsers.parse_probe("cpu", "linux", CPU), []) == []


def test_the_processor_and_the_process_that_is_new_to_the_top():
    hist = [calm_cpu() for _ in range(4)]
    found = baseline.compare("cpu", parsers.parse_probe("cpu", "linux", CPU), hist)
    text = " | ".join(e["text"] for e in found)
    assert "98% busy; it is normally about 6%" in text and "greenbone-gvmd-1 uses 310% of a core and is not normally among the busiest processes" in text
    assert all("unusual" in e["tags"] for e in found)
    normal = baseline.compare("cpu", calm_cpu(), hist)
    assert normal and normal[0]["tags"] == ["ok:cpu_normal"]                                    # "this is normal" is an answer too


def test_memory_a_process_that_holds_far_more_than_it_does():
    def mem(java_gb, used):
        d = parsers.parse_probe("memory", "linux", MEMORY)
        d["used_pct"], d["procs"] = used, [{"pid": 1, "name": "java", "user": "a", "rss": int(java_gb * GB), "pmem": 1.0, "container": None}]
        d["swap_used"] = 0
        return d

    hist = [mem(1.2, 38.0) for _ in range(4)]
    text = " | ".join(e["text"] for e in baseline.compare("memory", mem(11.4, 91.0), hist))
    assert "Memory is 91% used; it is normally about 38%" in text and "java holds 11.4 GB; it normally holds about 1.2 GB" in text
    assert [e for e in baseline.compare("memory", mem(1.4, 40.0), hist) if "unusual" in e["tags"]] == []


def test_network_a_new_talker_a_new_listener_and_traffic():
    base = parsers.parse_probe("network", "linux", NETWORK)
    quiet = copy.deepcopy(base)
    quiet["interfaces"][0].update(rx_bps=2e6, tx_bps=1e6)
    quiet["remote"], quiet["listening"] = [{"ip": "192.168.0.7", "count": 4}], [{"addr": "0.0.0.0:80", "process": "nginx"}]
    quiet["states"] = {"ESTAB": 20}
    hist = [copy.deepcopy(quiet) for _ in range(4)]
    now = copy.deepcopy(base)
    now["listening"] = [{"addr": "0.0.0.0:80", "process": "nginx"}, {"addr": "0.0.0.0:4444", "process": "nc"}]
    text = " | ".join(e["text"] for e in baseline.compare("network", now, hist))
    assert "10.0.0.99 has 250 connections to this host and was never seen before" in text and "New ports are listening that were not before: 0.0.0.0:4444 (nc)" in text and "Network traffic is" in text
    assert "300 connections are established; normally about 20" in text


def test_apps_a_container_that_started_restarting_and_a_service_that_never_failed():
    old = parsers.parse_probe("apps", "linux", APPS)
    for c in old["containers"]:
        c["restarts"], c["state"] = 1, "running"
    old["failed_units"] = []
    hist = [copy.deepcopy(old) for _ in range(4)]
    now = parsers.parse_probe("apps", "linux", APPS)
    text = " | ".join(e["text"] for e in baseline.compare("apps", now, hist))
    assert "web restarted 39 times since the look before" in text and "foo.service fails now and never failed before" in text


def test_security_new_accounts_new_exposure_and_a_brute_force_burst():
    base = {"platform": "linux", "failed_total": 3, "users": ["root", "pi"], "admins": ["sudo:x:27:pi"], "exposed": ["0.0.0.0:22"], "accepted": [{"ip": "192.168.0.5", "user": "pi", "method": "publickey", "count": 2}]}
    hist = [dict(base) for _ in range(4)]
    now = dict(base, failed_total=900, users=["root", "pi", "backdoor"], exposed=["0.0.0.0:22", "0.0.0.0:4444"], accepted=base["accepted"] + [{"ip": "6.6.6.6", "user": "root", "method": "password", "count": 1}])
    got = baseline.compare("security", now, hist)
    text = " | ".join(e["text"] for e in got)
    assert "900 failed sign-ins in 24 hours; normally about 3" in text and "New accounts that can sign in: backdoor" in text and "0.0.0.0:4444" in text and "6.6.6.6" in text
    assert any(e["private"] for e in got)                                                      # the addresses are not for the language model


def test_hardware_a_disk_that_is_wearing_out():
    def hw(n):
        return {"platform": "linux", "temps": [{"name": "cpu", "c": 45.0}], "disks": [{"dev": "/dev/sda", "health": "PASSED", "detail": f"Reallocated_Sector_Ct={n}", "bad": False}]}

    got = baseline.compare("hardware", hw(12), [hw(0), hw(0), hw(4)])
    assert any("Reallocated_Sector_Ct rose from 4 to 12" in e["text"] and e["weight"] >= 80 for e in got)


def test_storage_a_jump_against_how_it_usually_changes():
    def st(used_gb):
        return {"platform": "linux", "mounts": [{"mount": "/", "fs": "ext4", "size": 100 * GB, "used": used_gb * GB, "dirs": [], "files": []}]}

    hist = [st(70), st(70.2), st(70.1), st(70.3)]
    assert "grew by 16.0 GB since the look before" in baseline.compare("storage", st(86.3), hist)[0]["text"]
    assert baseline.compare("storage", st(70.5), hist) == []


def test_a_surprise_in_old_data_never_breaks_a_diagnosis():
    assert baseline.compare("cpu", {"platform": "linux", "procs": [{"oops": 1}], "cpu_pct": {"id": 1}}, [{"platform": "linux"}] * 4) == []
    assert baseline.compare("cpu", {"platform": "windows"}, [{"platform": "linux"}] * 4) == []                  # another kind of host is not a baseline
    assert baseline.compare("changes", {}, [{}] * 4) == []


# ----------------------------------------------------------------------------- end to end: snapshots in the database
@pytest.fixture
def conn(tmp_path):
    tsdb.forget_all()
    c = connect(tmp_path / "b.db")
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'web1', 1, 'x', 'x')")
    c.commit()
    yield c
    c.close()
    tsdb.forget_all()


def test_the_diagnosis_says_what_is_different_and_leaves_alarm_snapshots_out_of_normal(conn):
    now = time.time()
    service.save_settings(conn, {"devices": {"1": {"enabled": True}}})
    for day in range(5, 0, -1):
        service.store(conn, 1, True, "locked", None, calm_cpu(), now=now - day * 86400, probe="cpu", reason="schedule")
    for hours in (30, 20):                              # looks taken while the processor was over its limit are not "normal"
        service.store(conn, 1, True, "locked", None, parsers.parse_probe("cpu", "linux", CPU), now=now - hours * 3600, probe="cpu", reason="alarm")
    service.store(conn, 1, True, "locked", None, parsers.parse_probe("cpu", "linux", CPU), now=now - 60, probe="cpu", reason="alarm")
    last = service.latest_ok(conn, 1, probe="cpu")
    assert len(service.history(conn, 1, "cpu", last["taken"])) == 5
    rep = diagnose.diagnose(conn, 1, "slow")
    unusual = [f for f in rep["findings"] if f.get("unusual")]
    assert unusual and any("normally about 6%" in f["text"] for f in unusual)
    assert any("greenbone-gvmd-1" in f["text"] for f in unusual)


def test_why_a_snapshot_was_taken_is_kept(conn):
    service.store(conn, 1, True, "direct", None, {"platform": "linux"}, probe="cpu", reason="alarm")
    assert conn.execute("SELECT reason FROM probe_snapshots").fetchone()["reason"] == "alarm"
    service.save_settings(conn, {"devices": {"1": {"enabled": True, "probes": ["cpu"]}}})
    conn.execute("INSERT INTO host_monitors (id, device_id, method, address, port, created) VALUES (7, 1, 'ssh', 'a', 22, 'x')")
    conn.execute("INSERT INTO metric_state (monitor_id, metric, label, level, since, value) VALUES (7, 'cpu_pct', '', 'critical', 'x', 99)")
    conn.commit()
    assert service.due_with_reason(conn, time.time() + 1000) == [(1, "cpu", "alarm")]
