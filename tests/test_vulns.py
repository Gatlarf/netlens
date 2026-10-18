import pytest
from fastapi.testclient import TestClient

from app import licence, vulns
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app
from app.plugins.contract import ContractError, validate_output

NOW = "2026-03-10T12:00:00Z"


def finding(fid="f1", **kw):
    base = {"id": fid, "server_id": "s1", "host_ip": "192.168.1.20", "title": "OpenSSH out of date", "severity": "high", "cve": ["cve-2024-6387"], "score": 8.1, "port": 22}
    base.update(kw)
    return base


def output(*findings):
    return {"servers": [{"id": "s1", "name": "Greenbone", "version": "22.4", "last_scan": NOW}], "findings": list(findings)}


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen, trusted) VALUES (1, 'aa:00:00:00:00:01', '192.168.1.20', 'nas', 1, 'x', 'x', 1)")
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen, trusted) VALUES (2, 'aa:00:00:00:00:02', '192.168.1.30', 'cam', 1, 'x', 'x', 0)")
    c.commit()
    yield c
    c.close()


def kinds(conn):
    return [r["kind"] for r in conn.execute("SELECT kind FROM events ORDER BY id")]


# ------------------------------------------------------------------ contract
def test_the_contract_normalises_and_rejects():
    out = validate_output("vulnerability", output(finding(), finding("f2", host_ip=None, host_mac="AA-00-00-00-00-02", severity="critical", exploited=True, cve=[], port=None)))
    assert out["findings"][0]["cve"] == ["CVE-2024-6387"] and out["findings"][1]["host_mac"] == "aa:00:00:00:00:02" and out["findings"][1]["exploited"] is True
    assert out["servers"][0]["last_scan"] == NOW
    for bad in ({"host_ip": None}, {"severity": "scary"}, {"cve": ["nope"]}, {"server_id": "zz"}, {"title": ""}, {"port": 70000}, {"host_ip": "not an ip"}):
        with pytest.raises(ContractError):
            validate_output("vulnerability", output(finding(**bad)))
    assert len(validate_output("vulnerability", output(finding(), finding()))["findings"]) == 1          # the same id twice


# ------------------------------------------------------------------ storing and events
def apply(conn, *findings, now=None):
    return vulns.apply_vulns(conn, "gb", validate_output("vulnerability", output(*findings)), {})


def test_findings_are_matched_to_devices_and_the_first_sync_is_a_baseline(conn):
    r = apply(conn, finding(), finding("f2", host_ip=None, host_mac="aa:00:00:00:00:02", severity="critical"), finding("f3", host_ip="10.9.9.9", severity="low"))
    assert r == {"servers": 1, "findings": 3, "matched": 2, "events": 0} and kinds(conn) == []              # what is already there is not announced
    listing = vulns.findings(conn)
    assert [f["severity"] for f in listing] == ["critical", "high", "low"] and listing[0]["device"] == "cam" and listing[2]["device"] == "10.9.9.9"
    assert vulns.summary(conn) == {"configured": True, "servers": 1, "counts": {"critical": 1, "high": 1, "medium": 0, "low": 1, "info": 0}, "total": 3, "devices": 2, "exploited": 0, "last_scan": NOW}


def test_only_new_serious_findings_are_announced_once_and_grouped_per_device(conn):
    apply(conn, finding())
    r = apply(conn, finding(), finding("n1", severity="critical", title="Remote code execution", cve=["CVE-2025-1111"]), finding("n2", severity="high", exploited=True, title="Old kernel"),
              finding("n3", severity="high", title="Plain high"), finding("n4", host_ip="192.168.1.30", severity="critical", title="Camera backdoor"))
    assert r["events"] == 2 and kinds(conn) == ["vuln_critical", "vuln_critical"]
    details = [row["detail"] for row in conn.execute("SELECT detail FROM events ORDER BY id")]
    assert any(d.startswith("nas: 2 new serious vulnerabilities: Remote code execution (CVE-2025-1111) and 1 more") and "known to be exploited" in d for d in details)
    assert any(d.startswith("cam: 1 new serious vulnerability: Camera backdoor") for d in details)
    assert apply(conn, finding(), finding("n1", severity="critical", title="Remote code execution"))["events"] == 0                      # not new any more
    assert vulns.counts(conn)["critical"] == 1 and vulns.counts(conn)["high"] == 1                                           # n2..n4 fixed: gone


def test_top_devices_servers_and_removal(conn):
    apply(conn, finding(severity="critical"), finding("f2", severity="high", exploited=True), finding("f3", host_ip="192.168.1.30", severity="medium"))
    top = vulns.top_devices(conn)
    assert [(d["device"], d["critical"], d["high"], d["exploited"]) for d in top] == [("nas", 1, 1, 1), ("cam", 0, 0, 0)]
    assert vulns.servers(conn)[0]["name"] == "Greenbone"
    assert [f["id"] for f in vulns.findings(conn, device_id=2)] == ["f3"] and [f["id"] for f in vulns.findings(conn, q="cve-2024")] == ["f1", "f2", "f3"]
    vulns.remove_plugin(conn, "gb")
    assert vulns.summary(conn)["total"] == 0 and not vulns.summary(conn)["configured"]


# ------------------------------------------------------------------ the API and the licence
@pytest.fixture
def client(tmp_path):
    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen, trusted) VALUES (1, 'aa:00:00:00:00:01', '192.168.1.20', 'nas', 1, 'x', 'x', 1)")
    c.commit()
    apply(c, finding())
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as tc:
        yield tc


def test_the_api_lists_findings_and_is_a_paid_feature(client, monkeypatch):
    assert "vulnerabilities" in licence.PAID_FEATURES
    assert client.get("/api/vulns").json()["allowed"] is False                    # the free edition: nothing is listed
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: True)
    r = client.get("/api/vulns").json()
    r = client.get("/api/vulns").json()
    assert r["allowed"] is True and r["summary"]["counts"]["high"] == 1 and r["findings"][0]["device"] == "nas" and r["top"][0]["device"] == "nas"
    assert client.get("/api/vulns", params={"severity": "critical"}).json()["findings"] == []
    assert client.get("/api/vulns", params={"device_id": 1}).json()["findings"][0]["cve"] == ["CVE-2024-6387"]
    assert client.get("/api/dashboard").json()["summary"]["vulns"]["counts"]["high"] == 1
    monkeypatch.setattr(licence, "allows", lambda conn, feature, now=None: False)
    locked = client.get("/api/vulns").json()
    assert locked == {"allowed": False, "summary": None, "servers": [], "top": [], "findings": []}
    from app.stats import vulns_summary

    assert vulns_summary(connect(client.app.state.db_path))["allowed"] is False
    assert TestClient(client.app).get("/api/vulns").status_code == 401
