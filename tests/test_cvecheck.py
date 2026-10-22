"""The light CVE check: CPE names from nmap, version ranges, the NVD questions (faked), cache, findings."""

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app import cvecheck
from app.db import init_db

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)


def cve(cid, matches, score=7.5, severity="HIGH", published="2021-03-05T00:00:00.000"):
    return {"cve": {"id": cid, "published": published, "descriptions": [{"lang": "en", "value": f"{cid} description"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score}, "baseSeverity": severity}]},
                    "configurations": [{"nodes": [{"cpeMatch": [dict(vulnerable=True, **m) for m in matches]}]}]}}


def crit(product="openssh", **bounds):
    return {"criteria": f"cpe:2.3:a:openbsd:{product}:*:*:*:*:*:*:*:*", **bounds}


NVD = [
    cve("CVE-2007-0001", [crit()]),                                                              # "every version": too vague to report
    cve("CVE-2021-28041", [crit(versionStartIncluding="8.2", versionEndExcluding="8.5")], 7.1),    # contains 8.4
    cve("CVE-2023-0001", [crit(versionEndExcluding="8.0")], 9.8, "CRITICAL"),                     # older versions only
    cve("CVE-2020-0002", [{"criteria": "cpe:2.3:a:openbsd:openssh:8.4:*:*:*:*:*:*:*"}], 5.0, "MEDIUM"),    # exactly this version
    cve("CVE-2019-0003", [{"criteria": "cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*", "versionEndExcluding": "99"}]),    # another product
]


@pytest.fixture
def conn(tmp_path):
    c = sqlite3.connect(tmp_path / "t.db")
    c.row_factory = sqlite3.Row
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, custom_name, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'nas', 1, 'x', 'x')")
    c.execute("INSERT INTO ports (device_id, proto, port, state, service, product, version, cpe, updated) VALUES (1, 'tcp', 22, 'open', 'ssh', 'OpenSSH', '8.4p1 Debian 5', 'cpe:/a:openbsd:openssh:8.4p1', 'x')")
    c.execute("INSERT INTO ports (device_id, proto, port, state, service, product, version, cpe, updated) VALUES (1, 'tcp', 80, 'open', 'http', 'nginx', NULL, NULL, 'x')")
    c.commit()
    return c


class Nvd:
    def __init__(self, rows=NVD, fail=None):
        self.rows, self.calls, self.fail = rows, [], fail

    def __call__(self, url, key):
        self.calls.append(url)
        if self.fail:
            raise cvecheck.NvdError(self.fail)
        return {"vulnerabilities": self.rows, "totalResults": len(self.rows)}


def test_cpe_names_from_nmap():
    assert cvecheck.parse_cpe("cpe:/a:openbsd:openssh:8.4p1") == ("openbsd", "openssh", "8.4", "p1")
    assert cvecheck.parse_cpe("cpe:/a:nginx:nginx:1.18.0") == ("nginx", "nginx", "1.18.0", "")
    assert cvecheck.parse_cpe("cpe:/o:linux:linux_kernel:5.4") is None            # an operating system, not an application
    assert cvecheck.parse_cpe("cpe:/a:apache:http_server") is None                # no version
    assert cvecheck.cpe23("openbsd", "openssh", "8.4", "p1") == r"cpe:2.3:a:openbsd:openssh:8.4:p1:*:*:*:*:*:*"


def test_version_order_and_ranges():
    assert cvecheck.vkey("8.4") < cvecheck.vkey("8.10") and cvecheck.vkey("1.1.1") < cvecheck.vkey("1.1.1k") < cvecheck.vkey("1.1.1l")
    rng = lambda **b: cvecheck.in_range("8.4", crit(**b))
    assert rng(versionStartIncluding="8.2", versionEndExcluding="8.5") is True
    assert rng(versionEndExcluding="8.4") is False and rng(versionEndIncluding="8.4") is True and rng(versionStartExcluding="8.4") is False
    assert rng() is None                                                            # all versions: says nothing


def test_only_ranges_that_contain_the_version_count():
    got = cvecheck.condense(NVD, "openbsd", "openssh", "8.4")
    assert [c["id"] for c in got["cves"]] == ["CVE-2021-28041", "CVE-2020-0002"] and got["vague"] == 1
    assert got["cves"][0]["severity"] == "high" and got["cves"][0]["score"] == 7.1


def test_a_run_stores_findings_asks_once_and_uses_the_cache(conn):
    nvd = Nvd()
    last = cvecheck.run(conn, fetch=nvd, sleep=lambda s: None, now=NOW)
    assert last["ok"] and last["asked"] == 1 and last["findings"] == 2 and last["vague_cves_ignored"] == 1 and len(nvd.calls) == 1
    assert "cpeName=cpe%3A2.3%3Aa%3Aopenbsd%3Aopenssh%3A8.4%3Ap1" in nvd.calls[0]
    rows = conn.execute("SELECT * FROM vuln_findings WHERE plugin_id = 'cvecheck' ORDER BY score DESC").fetchall()
    assert [r["cves"] for r in rows] == ['["CVE-2021-28041"]', '["CVE-2020-0002"]']
    assert rows[0]["device_id"] == 1 and rows[0]["port"] == 22 and "OpenSSH 8.4p1 Debian 5" in rows[0]["title"] and "distribution package" in rows[0]["solution"]
    cvecheck.run(conn, fetch=nvd, sleep=lambda s: None, now=NOW + timedelta(days=1))
    assert len(nvd.calls) == 1                                                       # answered from the cache
    cvecheck.run(conn, fetch=nvd, sleep=lambda s: None, now=NOW + timedelta(days=8))
    assert len(nvd.calls) == 2                                                       # a week later it asks again
    first = conn.execute("SELECT first_seen FROM vuln_findings LIMIT 1").fetchone()[0]
    assert first == "2026-10-22T12:00:00Z"                                           # a finding keeps the day it was first seen


def test_the_minimum_severity_filters(conn):
    cvecheck.save_settings(conn, {"min_severity": "high"})
    assert cvecheck.run(conn, fetch=Nvd(), sleep=lambda s: None, now=NOW)["findings"] == 1


def test_an_nvd_problem_keeps_the_rest_and_is_reported(conn):
    last = cvecheck.run(conn, fetch=Nvd(fail="the NVD asked to slow down"), sleep=lambda s: None, now=NOW)
    assert last["ok"] is False and "slow down" in last["error"] and last["findings"] == 0 and last["left"] == 1
    assert cvecheck.due(conn, NOW + timedelta(minutes=31)) is False                  # switched off by default
    cvecheck.save_settings(conn, {"enabled": True})
    assert cvecheck.due(conn, NOW + timedelta(minutes=31)) is True                   # a cut-short run is retried soon
    assert json.loads(conn.execute("SELECT value FROM settings WHERE key = 'cvecheck.last'").fetchone()[0])["ok"] is False


def test_remove_clears_the_findings(conn):
    cvecheck.run(conn, fetch=Nvd(), sleep=lambda s: None, now=NOW)
    cvecheck.remove(conn)
    assert conn.execute("SELECT COUNT(*) FROM vuln_findings").fetchone()[0] == 0 and cvecheck.get_last(conn) is None


def test_the_api_key_is_never_shown(conn):
    cvecheck.save_settings(conn, {"api_key": "SECRET-KEY"})
    state = cvecheck.public_state(conn)
    assert state["has_api_key"] is True and "SECRET-KEY" not in json.dumps(state)


# ------------------------------------------------------------------ the API
@pytest.fixture
def api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app import licence
    from app.api import cvecheck as api_module
    from app.config import load_settings
    from app.db import connect
    from app.main import create_app

    path = tmp_path / "api.db"
    c = connect(path)
    init_db(c)
    c.close()
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    started = []
    monkeypatch.setattr(api_module, "run_in_background", lambda db_path: started.append(db_path) or True)
    with TestClient(create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path), headers={"Authorization": "Bearer secret"}) as tc:
        tc.started = started
        yield tc


def test_the_api_switches_the_check_on_and_off(api):
    state = api.get("/api/cve-check").json()
    assert state["enabled"] is False and state["has_api_key"] is False and state["allowed"] is True
    assert api.post("/api/cve-check/run").status_code == 409                          # not switched on yet
    on = api.put("/api/cve-check", json={"enabled": True, "min_severity": "high", "api_key": "SECRET-KEY"}).json()
    assert on["enabled"] is True and on["min_severity"] == "high" and on["has_api_key"] is True and "SECRET-KEY" not in json.dumps(on)
    assert len(api.started) == 1                                                       # switching on starts a first run
    assert api.post("/api/cve-check/run").status_code == 200 and len(api.started) == 2
    assert api.put("/api/cve-check", json={"enabled": False, "clear_api_key": True}).json()["has_api_key"] is False
    assert api.put("/api/cve-check", json={"min_severity": "nonsense"}).status_code == 422


def test_without_a_licence_the_check_is_refused(api, monkeypatch):
    from app import licence

    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: False)
    assert api.put("/api/cve-check", json={"enabled": True}).status_code == 402
