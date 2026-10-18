"""The Tenable Nessus plugin against a simulated Nessus (shapes from the Nessus API documentation; not recorded from a real scanner)."""

import time
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.fake_https import FakeHttps
from tests.plugin_modules import load

plugin = load("nessus")
ROOT = Path(__file__).resolve().parents[1] / "plugins" / "nessus"
NOW = int(time.time())


def plugin_attrs(cve=None, score="7.5", solution="Upgrade.", kev=False):
    attrs = [{"attribute_name": "solution", "attribute_value": solution}, {"attribute_name": "cvss_base_score", "attribute_value": score}]
    if cve:
        attrs.append({"attribute_name": "cve", "attribute_value": cve})
    if kev:
        attrs.append({"attribute_name": "cisa-known-exploited", "attribute_value": "2024-07-01"})
    return {"id": 1, "attributes": attrs}


def routes(scan_end=NOW - 3600):
    return {
        "/server/properties": {"nessus_ui_version": "10.8.3"},
        "/scans": {"scans": [{"id": 5, "name": "LAN", "status": "completed", "last_modification_date": scan_end}, {"id": 6, "name": "Running", "status": "running", "last_modification_date": NOW}]},
        "/scans/5": {"info": {"scan_end": scan_end}, "hosts": [{"host_id": 11, "hostname": "192.168.1.20", "critical": 1, "high": 1, "medium": 0, "low": 0, "info": 3},
                                                              {"host_id": 12, "hostname": "192.168.1.31", "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 5}]},
        "/scans/5/hosts/11": {"info": {"host-ip": "192.168.1.20", "host-fqdn": "nas.lan", "mac-address": "AA-00-00-00-00-01"},
                              "vulnerabilities": [{"plugin_id": 1001, "plugin_name": "Samba RCE", "severity": 4, "count": 1}, {"plugin_id": 1002, "plugin_name": "SSH weak algorithms", "severity": 1, "count": 1},
                                                  {"plugin_id": 1003, "plugin_name": "OS identification", "severity": 0, "count": 1}]},
        "/plugins/plugin/1001": plugin_attrs("CVE-2025-1111,CVE-2025-2222", "9.8", "Update Samba.", kev=True),
        "/plugins/plugin/1002": plugin_attrs(None, "2.6", "Disable them."),
    }


CONFIG = {"min_severity": "1", "max_age_days": 30, "detail_lookups": 300, "timeout": 5}


@pytest.fixture
def nessus(tmp_path):
    with FakeHttps(tmp_path, routes()) as s:
        yield s


def config(s, **over):
    return {**CONFIG, "servers": [{"host": s.url, "access_key": "AK", "secret_key": "SK", "fingerprint": s.fingerprint}], **over}


def test_manifest_and_output_follow_the_contract(nessus):
    assert validate_manifest(__import__("json").loads((ROOT / "plugin.json").read_text()))["kind"] == "vulnerability"
    out = validate_output("vulnerability", plugin.fetch(config(nessus)))
    assert out["servers"][0]["name"] == "Nessus" and out["servers"][0]["version"] == "10.8.3" and out["servers"][0]["last_scan"]
    by = {f["title"]: f for f in out["findings"]}
    assert sorted(by) == ["SSH weak algorithms", "Samba RCE"]                                   # info is left out, so is the running scan
    rce = by["Samba RCE"]
    assert (rce["severity"], rce["score"], rce["cve"], rce["exploited"], rce["host_mac"], rce["host_name"]) == ("critical", 9.8, ["CVE-2025-1111", "CVE-2025-2222"], True, "aa:00:00:00:00:01", "nas.lan")
    assert rce["solution"] == "Update Samba." and by["SSH weak algorithms"]["severity"] == "low" and by["SSH weak algorithms"]["exploited"] is False
    assert "/scans/6" not in nessus.seen and "/scans/5/hosts/12" not in nessus.seen            # nothing to fetch for a host without findings


def test_thresholds_age_and_lookup_limit(nessus, tmp_path):
    out = plugin.fetch(config(nessus, min_severity="3"))
    assert [f["title"] for f in out["findings"]] == ["Samba RCE"]
    (tmp_path / "o").mkdir()
    with FakeHttps(tmp_path / "o", routes(scan_end=NOW - 90 * 86400)) as o:
        r = plugin.fetch(config(o))
        assert r["findings"] == [] and r["servers"][0]["warnings"] and r["servers"][0]["last_scan"] is None
    r = plugin.fetch(config(nessus, detail_lookups=1))
    assert {f["title"]: f["score"] for f in r["findings"]} == {"Samba RCE": 9.8, "SSH weak algorithms": None}      # only the most serious was looked up


def test_errors_are_explained_and_the_secret_never_shows(nessus, tmp_path):
    with pytest.raises(plugin.AuthRefused) as e:
        plugin.fetch(config(nessus, servers=[{"host": nessus.url, "access_key": "AK", "secret_key": "WRONG", "fingerprint": nessus.fingerprint}]))
    assert "WRONG" not in str(e.value) and getattr(e.value, "auth_failed", False)
    with pytest.raises(plugin.NessusError, match="does not match the fingerprint"):
        plugin.fetch(config(nessus, servers=[{"host": nessus.url, "access_key": "AK", "secret_key": "SK", "fingerprint": "00" * 32}]))
    for bad in ({"servers": []}, {"servers": [{"host": "x"}]}, {"servers": [{"host": "http://x", "access_key": "a", "secret_key": "b"}]}):
        with pytest.raises((ValueError, plugin.NessusError)):
            plugin.parse_servers(bad)
    assert "Connected to 1 Nessus scanner (10.8.3): 2 findings (1 critical, 1 low) on 1 host" in plugin.test(config(nessus))["message"]


def test_diagnose_has_no_names_or_addresses(nessus):
    text = str(plugin.diagnose(config(nessus)))
    for secret in ("192.168.1.20", "nas.lan", "Samba", "CVE-2025", "AA-00", "SK"):
        assert secret not in text
    step = plugin.diagnose(config(nessus))["servers"][0]["steps"]
    assert step["scans"]["count"] == 2 and step["host"]["vulnerabilities"] == 3 and "cvss_base_score" in step["plugin"]["attribute_names"]
    assert "<server>" in plugin._problem(plugin.NessusError("cannot reach 10.0.0.5:8834: refused"))
