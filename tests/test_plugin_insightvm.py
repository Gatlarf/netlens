"""The Rapid7 InsightVM plugin against a simulated console (shapes from the InsightVM API v3 documentation; not recorded from a real console)."""

import base64
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.plugins.contract import validate_manifest, validate_output
from tests.fake_https import FakeHttps
from tests.plugin_modules import load

plugin = load("insightvm")
ROOT = Path(__file__).resolve().parents[1] / "plugins" / "insightvm"
AUTH = ("Authorization", "Basic " + base64.b64encode(b"netlens:pw").decode())
RECENT = datetime.fromtimestamp(time.time() - 3600, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
OLD = "2020-01-01T00:00:00.000Z"


def paged(items, **page):
    def answer(q):
        n, size = int(q.get("page", 0)), int(q.get("size", 500))
        return {"resources": items[n * size:(n + 1) * size], "page": {"number": n, "size": size, "totalPages": max(1, -(-len(items) // size)), "totalResources": len(items)}}
    return answer


ASSETS = [
    {"id": 1, "ip": "192.168.1.20", "mac": "AA:00:00:00:00:01", "hostName": "nas.lan", "history": [{"date": OLD}, {"date": RECENT}], "vulnerabilities": {"critical": 1, "severe": 1, "moderate": 1, "total": 3}},
    {"id": 2, "ip": "192.168.1.30", "mac": None, "hostName": "cam", "history": [{"date": OLD}], "vulnerabilities": {"critical": 1, "severe": 0, "moderate": 0, "total": 1}},        # not assessed lately
    {"id": 3, "ip": "192.168.1.40", "history": [{"date": RECENT}], "vulnerabilities": {"critical": 0, "severe": 0, "moderate": 0, "total": 0}},
]
ASSET_VULNS = [
    {"id": "samba-cve-2025-1111", "status": "vulnerable-exploited", "instances": 1, "results": [{"port": 445, "protocol": "tcp", "status": "vulnerable-exploited"}]},
    {"id": "ssh-weak", "status": "vulnerable-version", "instances": 1, "results": [{"port": 22, "protocol": "tcp"}]},
    {"id": "tls-old", "status": "vulnerable-version", "instances": 1, "results": [{"port": 443, "protocol": "tcp"}]},
    {"id": "gone", "status": "not-vulnerable-version", "instances": 0, "results": []},
]
VULNS = {"samba-cve-2025-1111": {"id": "samba-cve-2025-1111", "title": "Samba remote code execution", "severity": "Critical", "severityScore": 10, "cvss": {"v3": {"score": 9.8}, "v2": {"score": 10.0}}, "cves": ["CVE-2025-1111"], "exploits": 2, "malwareKits": 0},
         "ssh-weak": {"id": "ssh-weak", "title": "SSH weak algorithms", "severity": "Severe", "severityScore": 7, "cvss": {"v2": {"score": 7.2}}, "cves": [], "exploits": 0},
         "tls-old": {"id": "tls-old", "title": "TLS 1.0 enabled", "severity": "Moderate", "severityScore": 4, "cvss": {}, "cves": [], "exploits": 0}}


def routes():
    r = {"/api/3/administration/info": {"version": {"semantic": "6.6.280"}}, "/api/3/assets": paged(ASSETS), "/api/3/assets/1/vulnerabilities": paged(ASSET_VULNS),
         "/api/3/solutions/s1": {"id": "s1", "summary": {"text": "Install the vendor update."}}, "/api/3/vulnerabilities/samba-cve-2025-1111/solutions": {"resources": [{"id": "s1"}]}}
    for vid, doc in VULNS.items():
        r[f"/api/3/vulnerabilities/{vid}"] = doc
    return r


@pytest.fixture
def console(tmp_path):
    with FakeHttps(tmp_path, routes(), header=AUTH) as s:
        yield s


def config(s, **over):
    return {"min_severity": "moderate", "max_age_days": 30, "detail_lookups": 300, "timeout": 5, "servers": [{"host": s.url, "username": "netlens", "password": "pw", "fingerprint": s.fingerprint}], **over}


def test_manifest_and_output_follow_the_contract(console):
    assert validate_manifest(json.loads((ROOT / "plugin.json").read_text()))["kind"] == "vulnerability"
    out = validate_output("vulnerability", plugin.fetch(config(console)))
    assert out["servers"][0]["name"] == "InsightVM" and out["servers"][0]["version"] == "6.6.280" and out["servers"][0]["last_scan"]
    by = {f["title"]: f for f in out["findings"]}
    assert sorted(by) == ["SSH weak algorithms", "Samba remote code execution", "TLS 1.0 enabled"]        # 'not vulnerable' is left out; the asset not assessed lately too
    s = by["Samba remote code execution"]
    assert (s["severity"], s["score"], s["cve"], s["exploited"], s["port"], s["host_mac"], s["host_name"]) == ("critical", 9.8, ["CVE-2025-1111"], True, 445, "aa:00:00:00:00:01", "nas.lan")
    assert s["solution"] == "Install the vendor update." and by["SSH weak algorithms"]["severity"] == "high" and by["SSH weak algorithms"]["score"] == 7.2
    assert by["TLS 1.0 enabled"]["severity"] == "medium" and by["TLS 1.0 enabled"]["score"] == 4 and by["TLS 1.0 enabled"]["exploited"] is False
    assert "/api/3/assets/2/vulnerabilities" not in console.seen and "/api/3/assets/3/vulnerabilities" not in console.seen


def test_thresholds_and_paging(console, tmp_path):
    assert sorted(f["title"] for f in plugin.fetch(config(console, min_severity="severe"))["findings"]) == ["SSH weak algorithms", "Samba remote code execution"]
    assert [f["title"] for f in plugin.fetch(config(console, min_severity="critical"))["findings"]] == ["Samba remote code execution"]
    many = [{"id": 100 + i, "ip": f"10.0.{i // 250}.{i % 250 + 1}", "history": [{"date": RECENT}], "vulnerabilities": {"critical": 0, "severe": 0, "moderate": 0, "total": 0}} for i in range(1200)]
    (tmp_path / "m").mkdir()
    with FakeHttps(tmp_path / "m", {**routes(), "/api/3/assets": paged(many)}, header=AUTH) as m:
        r = plugin.fetch(config(m))
        assert r["findings"] == [] and r["servers"][0]["warnings"] == []
        assert m.seen.count("/api/3/assets") == 3                                                       # 1200 assets at 500 a page


def test_errors_are_explained_and_the_password_never_shows(console):
    with pytest.raises(plugin.AuthRefused) as e:
        plugin.fetch(config(console, servers=[{"host": console.url, "username": "netlens", "password": "WRONGPW", "fingerprint": console.fingerprint}]))
    assert "WRONGPW" not in str(e.value) and getattr(e.value, "auth_failed", False)
    with pytest.raises(plugin.VmError, match="does not match the fingerprint"):
        plugin.fetch(config(console, servers=[{"host": console.url, "username": "netlens", "password": "pw", "fingerprint": "00" * 32}]))
    for bad in ({"servers": []}, {"servers": [{"host": "x"}]}, {"servers": [{"host": "http://x", "username": "a", "password": "b"}]}):
        with pytest.raises((ValueError, plugin.VmError)):
            plugin.parse_servers(bad)
    assert "Connected to 1 InsightVM console (6.6.280): 3 findings (1 critical, 1 high, 1 medium) on 1 host" in plugin.test(config(console))["message"]


def test_diagnose_has_no_names_or_addresses(console):
    report = plugin.diagnose(config(console))
    text = str(report)
    for secret in ("192.168.1.20", "nas.lan", "Samba", "CVE-2025", "AA:00", "pw'"):
        assert secret not in text
    steps = report["servers"][0]["steps"]
    assert steps["assets"]["sample"] == 3 and steps["asset_vulnerabilities"]["count"] == 4 and steps["vulnerability"]["severity"] == "Critical"
    assert "<server>" in plugin._problem(plugin.VmError("cannot reach 10.0.0.5:3780: refused"))
