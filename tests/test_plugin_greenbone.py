"""The Greenbone plugin against a fake gvmd that replays what a real Greenbone Community 22.7 answered (recorded 2026-10-18)."""

import json
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.fake_gvmd import FakeGvmd, results_from_fixture
from tests.plugin_modules import load

plugin = load("greenbone")
ROOT = Path(__file__).resolve().parents[1] / "plugins" / "greenbone"
CONFIG = {"min_severity": "0.1", "min_qod": 70, "max_age_days": 30, "timeout": 10}


@pytest.fixture
def gvmd(tmp_path):
    with FakeGvmd(tmp_path) as s:
        yield s


def config(s, **over):
    return {**CONFIG, "servers": [{"host": s.address, "username": "netlens", "password": "secret", "fingerprint": s.fingerprint}], **over}


def test_manifest_and_the_recorded_results_follow_the_contract(gvmd):
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "vulnerability"
    out = validate_output("vulnerability", plugin.fetch(config(gvmd)))
    assert out["servers"][0]["name"] == "Greenbone" and out["servers"][0]["version"] == "22.7" and out["servers"][0]["last_scan"] and out["servers"][0]["warnings"] == []
    by = {f["title"]: f for f in out["findings"]}
    assert len(by) == 5 and all(f["host_ip"] == "192.168.1.20" for f in out["findings"])
    gvm = by["OpenVAS / Greenbone Vulnerability Manager (GVM) Default Credentials (OMP/GMP Protocol)"]
    assert (gvm["severity"], gvm["score"], gvm["port"], gvm["proto"]) == ("critical", 10.0, 9390, "tcp") and gvm["solution"].startswith("Change the password")
    assert by["SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection"]["severity"] == "medium" and by["SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection"]["score"] == 4.3
    assert by["TCP Timestamps Information Disclosure"]["port"] is None and by["Weak MAC Algorithm(s) Supported (SSH)"]["port"] == 22      # "general/tcp" has no port
    assert {f["severity"] for f in out["findings"]} == {"critical", "medium", "low"} and all(f["last_seen"] for f in out["findings"])
    assert len({f["id"] for f in out["findings"]}) == 5 and all(f["id"].startswith(gvmd.address) for f in out["findings"])


def test_the_filter_uses_only_what_greenbone_understands(gvmd):
    plugin.fetch(config(gvmd))
    plugin.fetch(config(gvmd, min_severity="7"))
    filters = [a["filter"] for tag, a in gvmd.seen if tag == "get_results"]
    assert "severity>0.0" in filters[0] and "min_qod=70" in filters[0] and "severity>6.9" in filters[1]
    assert not any(">=" in f for f in filters)                                   # gvmd has no ">=": such a filter silently matched nothing


def test_old_results_and_duplicates(tmp_path):
    from datetime import datetime, timedelta, timezone

    fresh = results_from_fixture(datetime.now(timezone.utc) - timedelta(hours=1))
    old = results_from_fixture(datetime.now(timezone.utc) - timedelta(days=90))
    again = results_from_fixture(datetime.now(timezone.utc) - timedelta(days=3))                 # an older scan that saw the same findings
    with FakeGvmd(tmp_path, results=fresh + old[:2] + again) as s:
        out = plugin.fetch(config(s))
        assert len(out["findings"]) == 5                                                          # the same finding is one finding, whatever scan it came from
    (tmp_path / "o").mkdir()
    with FakeGvmd(tmp_path / "o", results=old) as s:
        r = plugin.fetch(config(s))
        assert r["findings"] == []


def test_paging_goes_on_until_a_short_page(tmp_path):
    from datetime import datetime, timedelta, timezone

    base = results_from_fixture(datetime.now(timezone.utc) - timedelta(hours=1))
    many = []
    import copy

    for i in range(520):
        r = copy.deepcopy(base[i % 5])
        r.find("host").text = f"10.9.{i // 250}.{i % 250 + 1}"
        many.append(r)
    with FakeGvmd(tmp_path, results=many) as s:
        out = plugin.fetch(config(s))
        assert len(out["findings"]) == 520 and [a["filter"].split("first=")[1].split()[0] for t, a in s.seen if t == "get_results"] == ["1", "501"]


def test_errors_are_explained_and_the_password_never_shows(gvmd):
    with pytest.raises(plugin.AuthRefused) as e:
        plugin.fetch(config(gvmd, servers=[{"host": gvmd.address, "username": "netlens", "password": "WRONGPW", "fingerprint": gvmd.fingerprint}]))
    assert "WRONGPW" not in str(e.value) and getattr(e.value, "auth_failed", False)
    with pytest.raises(plugin.GvmError, match="does not match the fingerprint"):
        plugin.fetch(config(gvmd, servers=[{"host": gvmd.address, "username": "netlens", "password": "secret", "fingerprint": "00" * 32}]))
    for bad in ({"servers": []}, {"servers": [{"host": "x"}]}):
        with pytest.raises((ValueError, plugin.GvmError)):
            plugin.parse_servers(bad)
    with pytest.raises(plugin.GvmError, match="cannot reach"):
        plugin.fetch({**CONFIG, "servers": [{"host": "127.0.0.1:1", "username": "a", "password": "b"}], "timeout": 2})
    assert "Connected to 1 Greenbone server (22.7): 5 findings (1 critical, 1 medium, 3 low) on 1 host" in plugin.test(config(gvmd))["message"]


def test_a_scanner_that_never_ran_says_so(tmp_path):
    with FakeGvmd(tmp_path, last_report=False, results=[]) as s:
        r = plugin.fetch(config(s))
        assert r["findings"] == [] and r["servers"][0]["last_scan"] is None and r["servers"][0]["warnings"]


def test_diagnose_has_no_names_or_addresses(gvmd):
    report = plugin.diagnose(config(gvmd))
    text = str(report)
    for secret in ("192.168.1.20", "Default Credentials", "secret", "TLSv1"):
        assert secret not in text
    steps = report["servers"][0]["steps"]
    assert steps["login"]["ok"] and steps["results"]["usable"] == 5 and steps["results"]["levels"] == {"critical": 1, "low": 3, "medium": 1} and "nvt" in steps["results"]["child_tags"]
    assert "<server>" in plugin._problem(plugin.GvmError("cannot reach 10.0.0.5:9390: refused"))
