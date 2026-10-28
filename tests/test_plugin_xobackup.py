"""The Xen Orchestra backup plugin against a simulated Xen Orchestra that replays answers recorded from a real Xen Orchestra 6 (tests/fake_xen.py):
one VM backed up to a local repository by a nightly job, one failed run (a wrongly configured job) and one good run."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.fake_xen import FakeXen

ROOT = Path(__file__).resolve().parents[1] / "plugins" / "xobackup"
spec = importlib.util.spec_from_file_location("xobackup_plugin", ROOT / "plugin.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

VM2 = "b35fce12-befd-a53c-1fd1-55c62eb4abb2"
REPO = "8f461b19-7e34-4544-965c-73f0c96001c3"


def config(fake, **row):
    return {"servers": [{"host": fake.url, "username": "admin@admin.net", "password": "admin", **row}], "verify_tls": False, "allow_http": True}


RECORDED = 1793208545  # the successful run in the recording (2026-10-28 17:29:05 UTC)


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    """A day after the recording, so the recorded failure is 'recent' and the new runs below are newer than the recorded success."""
    monkeypatch.setattr(plugin, "_now", lambda: RECORDED + 86400)


def now_ms():
    return (RECORDED + 86400) * 1000


def test_manifest_is_valid():
    manifest = json.loads((ROOT / "plugin.json").read_text())
    assert validate_manifest(manifest)["kind"] == "backup"


def test_what_a_real_xen_orchestra_reports():
    with FakeXen() as fake:
        out = plugin.fetch(config(fake))
    validate_output("backup", out)
    server, = out["servers"]
    assert server["id"] == "xo" and server["ip"] is None and server["online"] is True
    store, = out["stores"]
    assert store["name"] == "lab-local" and store["total"] == 126226378752 and store["avail"] == 40492515328 and store["server_id"] == "xo"
    target, = out["targets"]
    assert target["backup_id"] == VM2 and target["name"] == "lab-vm2" and target["type"] == "vm"
    assert target["count"] == 1 and target["last_state"] == "ok" and target["last_size"] == 2119168 and target["store_id"] == store["id"]
    assert target["last_backup"] == "2026-10-28T17:29:02Z" and target["interval"] == 86400      # the nightly schedule


def test_a_failed_run_is_a_problem_but_only_within_a_week(monkeypatch):
    with FakeXen() as fake:
        out = plugin.fetch(config(fake))
        problem, = out["problems"]
        plugin._now = lambda: RECORDED + 30 * 86400       # a month later it is old news
        assert plugin.fetch(config(fake))["problems"] == []
    assert problem["state"] == "failed" and problem["kind"] == "backup" and problem["target_id"] is None
    assert problem["text"].startswith("lab-nightly: Cannot read properties") and problem["at"]


def test_a_failed_vm_task_points_at_its_target_and_the_last_run_state_follows():
    with FakeXen() as fake:
        log = copy.deepcopy(fake.xo["backup-logs"][1])
        log.update(id="1793290000000", status="failure", start=now_ms() - 7200_000, end=now_ms() - 7100_000)
        log["tasks"][0]["status"] = "failure"
        log["tasks"][0]["result"] = {"message": "VDI_IN_USE on 10.1.2.3 (https://xo.example.com/x)"}
        fake.xo["backup-logs"].append(log)
        fake.dashboards[VM2]["backupsInfo"]["lastRuns"].append({"backupJobId": "9b495ffd-ac13-4cd7-911c-9ce78e27ea97", "timestamp": now_ms() - 7100_000, "status": "failure"})
        out = plugin.fetch(config(fake))
    target, = out["targets"]
    assert target["last_state"] == "failed" and target["count"] == 1            # the newest run failed; the old copy is still there
    problem = next(p for p in out["problems"] if p["target_id"])
    assert problem["target_id"] == target["id"]
    assert "10.1.2.3" not in problem["text"] and "example.com" not in problem["text"]


def test_disabled_repository_and_a_vm_without_backups():
    with FakeXen() as fake:
        fake.xo["backup-repositories"][0]["enabled"] = False
        out = plugin.fetch(config(fake))
    assert any("switched off" in w for w in out["servers"][0]["warnings"])
    assert [t["name"] for t in out["targets"]] == ["lab-vm2"]                   # lab-vm1 has no backup: Netlens lists it as 'without a backup' itself


def test_login_and_address_problems():
    with FakeXen() as fake:
        with pytest.raises(plugin.XenAuthError) as exc:
            plugin.test(config(fake, password="wrong"))
        assert exc.value.auth_failed is True
        assert "1 backed-up VM(s)" in plugin.test(config(fake))["message"]
    with FakeXen(xo=False, xapi=True) as master:
        with pytest.raises(plugin.XenError, match="not a Xen Orchestra"):
            plugin.test(config(master))


def test_two_servers_get_their_own_ids():
    with FakeXen() as a, FakeXen() as b:
        out = plugin.fetch({"servers": [{"host": a.url, "token": "tok"}, {"host": b.url, "token": "tok"}], "verify_tls": False, "allow_http": True})
    validate_output("backup", out)
    assert [s["id"] for s in out["servers"]] == ["xo1", "xo2"] and len(out["targets"]) == 2


@pytest.mark.parametrize("cron, seconds", [("0 3 * * *", 86400), ("*/15 * * * *", 900), ("0 */6 * * *", 21600), ("0 * * * *", 3600), ("0 8,20 * * *", 43200),
                                            ("0 2 * * 1", 604800), ("0 2 * * 1,3,5", 201600), ("30 1 1 * *", 2592000), ("nonsense", None)])
def test_schedule_interval(cron, seconds):
    assert plugin.cron_interval(cron) == seconds


def test_stamps():
    assert plugin.stamp(1793208545539) == "2026-10-28T17:29:05Z"
    assert plugin.stamp(1793208545) == "2026-10-28T17:29:05Z"          # some fields are in seconds
    assert plugin.stamp(None) is None and plugin.stamp(0) is None


def test_diagnostic_report_has_no_names_or_addresses():
    with FakeXen() as fake:
        report = plugin.diagnose(config(fake))
    text = json.dumps(report)
    assert report["result"]["backed_up_vms"] == 1 and report["result"]["repositories"] == 1
    for leak in ("lab-vm", "lab-nightly", "lab-local", "127.0.0.1", "file:///", "storage/backups", "Cannot read properties"):
        assert leak not in text, leak
