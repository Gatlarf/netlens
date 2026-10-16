"""The Proxmox Backup Server plugin against a simulated server (shapes recorded from PBS 4.2 on 2026-10-16)."""

import importlib.util
import json
import time
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.fake_pbs import FakePbs

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "pbs"
spec = importlib.util.spec_from_file_location("pbs_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

NOW = int(time.time())
DAY = 86400


def snap(kind, bid, ago_days, comment="", size=1000, verified=None, protected=False):
    s = {"backup-type": kind, "backup-id": bid, "backup-time": NOW - int(ago_days * DAY), "comment": comment, "size": size, "owner": "root@pam", "protected": protected, "files": []}
    if verified:
        s["verification"] = {"state": verified, "upid": "x"}
    return s


SNAPSHOTS = {"main": [snap("vm", "100", d, "BlueIris") for d in (0.2, 1.2, 2.2, 3.2)] + [snap("ct", "102", d, "lxc-web1", verified="ok", protected=(d == 5)) for d in (0.3, 1.3, 2.3, 5)]
             + [snap("host", "hostcfg-nuc", 20, ""), snap("vm", "107", 0.1, "vm-playground"), snap("ct", "100", 60, "old-ct")]}


def task(worker, status, ended=NOW - 3600, kind="backup", upid=None):
    return {"upid": upid or f"UPID:x:{worker}:{status}:{ended}", "worker_type": kind, "worker_id": worker, "status": status, "endtime": ended, "starttime": (ended or NOW) - 60}


TASKS = [task("main:vm/107", "unable to connect to the guest agent", ended=NOW - 600), task("main:vm/107", "OK", ended=NOW - 90000), task("main:ct/102", "WARNINGS: 2", ended=NOW - 1000),
         task("main:vm/100", "OK", ended=NOW - 4000), task("main:vm/101", "OK", ended=NOW - 5000), {**task("main:vm/100", "", ended=None), "endtime": None}]
PROBLEMS = [TASKS[0], TASKS[2], task("main", "WARNINGS: 1", kind="prunejob"), task(None, "WARNINGS: 1", kind="aptupdate"), task("main", "verification failed - please check the log", kind="verificationjob")]
JOBS = {"gc": [{"store": "main", "last-run-state": "OK", "last-run-endtime": NOW - 7200}], "prune": [{"store": "main", "last-run-state": "WARNINGS: 1", "last-run-endtime": NOW - 3600}],
        "verify": [], "sync": [{"store": "main", "last-run-state": "connection refused", "last-run-endtime": NOW - 100}]}
USAGE = [{"store": "main", "total": 2000, "used": 500, "avail": 1500, "estimated-full-date": NOW + 20 * DAY}]


@pytest.fixture
def pbs(tmp_path):
    with FakePbs(tmp_path, SNAPSHOTS, TASKS, PROBLEMS, USAGE, JOBS) as s:
        yield s


def config(s, **entry):
    return {"servers": [{"host": s.url, "token_id": "netlens@pbs!netlens", "secret": "secret", "fingerprint": s.fingerprint, **entry}], "timeout": 5}


def test_manifest_and_output_follow_the_contract(pbs):
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "backup"
    out = validate_output("backup", plugin.fetch(config(pbs)))
    assert out["servers"][0]["version"] == "4.2" and out["servers"][0]["ip"] == "127.0.0.1"
    store = out["stores"][0]
    assert store["used"] == 500 and store["total"] == 2000 and store["full"] is not None
    assert (store["gc_state"], store["prune_state"], store["verify_state"], store["sync_state"]) == ("ok", "warning", "none", "failed")
    targets = {t["backup_id"] + t["type"]: t for t in out["targets"]}
    assert sorted(targets) == ["100ct", "100vm", "102ct", "107vm", "hostcfg-nuchost"]


def test_targets_carry_age_interval_state_and_name(pbs):
    out = validate_output("backup", plugin.fetch(config(pbs)))
    t = {x["backup_id"] + x["type"]: x for x in out["targets"]}
    bi = t["100vm"]
    assert bi["name"] == "BlueIris" and bi["count"] == 4 and bi["interval"] == DAY and bi["last_state"] == "ok" and bi["verify_state"] == "none"
    web = t["102ct"]
    assert web["verify_state"] == "ok" and web["protected"] == 1 and web["last_state"] == "warning"           # the newest backup task ended with warnings
    assert t["107vm"]["last_state"] == "failed" and t["107vm"]["interval"] is None                           # the newest task failed; one snapshot only
    assert t["hostcfg-nuchost"]["type"] == "host" and t["100ct"]["type"] == "ct"                             # ct 100 is not vm 100


def test_problems_list_only_backup_related_jobs(pbs):
    out = validate_output("backup", plugin.fetch(config(pbs)))
    kinds = sorted((p["kind"], p["state"]) for p in out["problems"])
    assert kinds == [("backup", "failed"), ("backup", "warning"), ("prune", "warning"), ("verify", "failed")]       # aptupdate is no backup problem
    backup = next(p for p in out["problems"] if p["state"] == "failed" and p["kind"] == "backup")
    assert backup["target_id"] in {t["id"] for t in out["targets"]} and "vm 107" in backup["text"]


def test_a_certificate_that_does_not_match_the_fingerprint_is_refused(pbs):
    with pytest.raises(plugin.PbsError, match="does not match the fingerprint"):
        plugin.fetch(config(pbs, fingerprint="00" * 32))
    assert pbs.seen == []                                                                          # nothing, not even the token, was sent


def test_without_fingerprint_the_normal_check_refuses_a_self_signed_certificate(pbs):
    with pytest.raises(plugin.PbsError, match="secure connection"):
        plugin.fetch(config(pbs, fingerprint=""))
    assert plugin.fetch({**config(pbs, fingerprint=""), "verify_tls": False})["servers"]


def test_wrong_token_stops_retries(pbs):
    with pytest.raises(plugin.AuthRefused) as exc:
        plugin.fetch(config(pbs, secret="nope"))
    assert exc.value.auth_failed and "Audit" in str(exc.value)


def test_a_token_without_task_rights_still_works(tmp_path):
    with FakePbs(tmp_path, SNAPSHOTS, TASKS, PROBLEMS, USAGE, JOBS, allow_tasks=False) as s:
        out = validate_output("backup", plugin.fetch(config(s)))
        assert all(t["last_state"] == "ok" for t in out["targets"]) and out["problems"] == []
        assert "Sys.Audit" in " ".join(out["servers"][0]["warnings"])


def test_a_token_that_sees_no_datastore_says_so(tmp_path):
    with FakePbs(tmp_path, {}, usage=[]) as s:
        out = plugin.fetch(config(s))
        assert out["stores"] == [] and "Audit role" in out["servers"][0]["warnings"][0]


def test_message_and_settings(pbs):
    message = plugin.test(config(pbs))["message"]
    assert "Proxmox Backup Server (4.2)" in message and "1 datastore" in message and "5 backed up" in message and "1 with a failed last backup" in message
    with pytest.raises(ValueError):
        plugin.parse_servers({"servers": []})
    with pytest.raises(ValueError):
        plugin.parse_servers({"servers": [{"host": "https://x:8007"}]})
    with pytest.raises(plugin.PbsError, match="token id"):
        plugin.parse_servers({"servers": [{"host": "https://x:8007", "token_id": "nope", "secret": "s"}]})
    with pytest.raises(plugin.PbsError, match="fingerprint"):
        plugin.parse_servers({"servers": [{"host": "https://x:8007", "token_id": "a@b!c", "secret": "s", "fingerprint": "12:34"}]})
    with pytest.raises(plugin.PbsError):
        plugin.parse_servers({"servers": [{"host": "http://x:8007", "token_id": "a@b!c", "secret": "s"}]})


def test_diagnose_has_only_counts(pbs):
    report = plugin.diagnose(config(pbs))
    text = json.dumps(report)
    steps = report["servers"][0]["steps"]
    assert steps["snapshots"]["count"] == len(SNAPSHOTS["main"]) and steps["snapshots"]["groups"] == 5 and steps["datastores"]["count"] == 1
    for secret in ("BlueIris", "lxc-web1", "127.0.0.1", "secret", "main", "netlens@pbs"):
        assert secret not in text


def test_diagnose_error_has_no_address(pbs):
    report = plugin.diagnose(config(pbs, secret="nope"if False else "secret", fingerprint="00" * 32))
    assert "127.0.0.1" not in json.dumps(report) and "does not match" in json.dumps(report)


def test_state_helpers():
    assert plugin.state_of("OK") == "ok" and plugin.state_of("WARNINGS: 3") == "warning" and plugin.state_of("boom") == "failed" and plugin.state_of(None) == "none"
    assert plugin.interval_of([{"backup-time": 100}, {"backup-time": 40}]) is None
    assert plugin.interval_of([{"backup-time": t} for t in (300, 200, 100, 0)]) == 100
