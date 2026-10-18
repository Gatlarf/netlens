import base64

import pytest
from fastapi.testclient import TestClient

from app import documentation as docs
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app

LOGO = "data:image/png;base64," + base64.b64encode(b"\x89PNG tiny").decode()


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    c.execute("INSERT INTO device_groups (id, name, color) VALUES (1, 'Office', '#888888')")
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, vendor, os_name, device_type, online, first_seen, last_seen, trusted, group_id, notes) VALUES (1, 'aa:00:00:00:00:01', '192.168.1.20', 'nas', 'Synology', 'DSM 7', 'nas', 1, 'x', 'x', 1, 1, 'Holds the <b>backups</b>')")
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen, trusted, device_type) VALUES (2, 'aa:00:00:00:00:02', '192.168.1.3', '<script>alert(1)</script>', 0, 'x', 'x', 0, 'camera')")
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen, trusted, report_exclude) VALUES (3, 'aa:00:00:00:00:03', '192.168.1.99', 'testbox', 1, 'x', 'x', 0, 1)")
    c.execute("INSERT INTO service_checks (name, kind, host, port, enabled, last_up, created) VALUES ('NAS web', 'http', '192.168.1.20', 5000, 1, 0, 'x')")
    c.commit()
    yield c
    c.close()


def test_settings_are_validated_and_kept(conn):
    assert docs.get_settings(conn)["sections"] == [s for s, _ in docs.SECTIONS]
    s = docs.save_settings(conn, {"company": "  Acme   IT ", "customer": "Bakery Janssens", "accent": "#112233", "logo": LOGO, "sections": ["devices", "summary"]})
    assert s["company"] == "Acme IT" and s["sections"] == ["summary", "devices"] and docs.get_settings(conn)["logo"] == LOGO
    for bad in ({"accent": "red"}, {"logo": "data:image/svg+xml;base64,AAAA"}, {"logo": "http://x/logo.png"}, {"logo": "data:image/png;base64," + "A" * 300_000}, {"sections": ["nope"]}, {"company": "x" * 200}):
        with pytest.raises(docs.DocError):
            docs.save_settings(conn, bad)
    assert docs.save_settings(conn, {"logo": ""})["logo"] == ""


def test_the_document_has_the_sections_and_escapes_everything(conn):
    docs.save_settings(conn, {"customer": 'Bakery <i>"Janssens"</i>', "company": "Acme IT", "prepared_by": "Sam", "footer": "Confidential", "logo": LOGO})
    page = docs.render(docs.collect(conn, ["192.168.1.0/24"]), docs.get_settings(conn))
    assert page.startswith("<!doctype html>") and "<script" not in page.lower().replace("<script>", "X", 0) and "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "Bakery &lt;i&gt;&quot;Janssens&quot;&lt;/i&gt;" in page and "Holds the &lt;b&gt;backups&lt;/b&gt;" in page and "Prepared by Sam" in page and "Confidential" in page and LOGO in page
    for heading in ("Summary", "Network", "Devices (2)", "Monitored services", "Certificates", "Backups", "Security", "Open points"):
        assert f"<h2>{heading}</h2>" in page
    assert "testbox" not in page                                                           # left out of reports
    assert page.index("192.168.1.3") < page.index("192.168.1.20")                          # sorted by address
    assert "Office" in page and "Synology" in page and "<span class=\"b bad\">down</span>" in page
    assert "http://" not in page.replace("http://192.168.1.20", "") and "src=\"http" not in page            # nothing external
    only = docs.save_settings(conn, {"sections": ["devices"]})
    page = docs.render(docs.collect(conn, []), only)
    assert "<h2>Devices (2)</h2>" in page and "<h2>Summary</h2>" not in page


def test_open_points_and_security(conn, monkeypatch):
    from app import licence, vulns
    from app.plugins.contract import validate_output

    monkeypatch.setattr(licence, "allows", lambda c, feature, now=None: True)
    out = validate_output("vulnerability", {"servers": [{"id": "s", "name": "GB"}], "findings": [{"id": "f", "server_id": "s", "host_ip": "192.168.1.20", "title": "Samba <RCE>", "severity": "critical", "cve": ["CVE-2025-1111"], "port": 445}]})
    vulns.apply_vulns(conn, "gb", out, {})
    page = docs.render(docs.collect(conn, ["192.168.1.0/24"]), docs.get_settings(conn))
    assert "1 critical vulnerability found by the scanner." in page and "Samba &lt;RCE&gt;" in page and "CVE-2025-1111" in page
    assert "1 monitored service is down: NAS web." in page and "2 open points." in page
    monkeypatch.setattr(licence, "allows", lambda c, feature, now=None: False)
    assert "No vulnerability scanner is connected" in docs.render(docs.collect(conn, []), docs.get_settings(conn))


@pytest.fixture
def client(tmp_path):
    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.1.0/24"}), db_path=path)
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as tc:
        yield tc


def test_the_api(client):
    got = client.get("/api/documentation").json()
    assert got["settings"]["accent"] == "#1f6feb" and [s["id"] for s in got["sections"]][0] == "summary"
    assert client.put("/api/documentation", json={"customer": "Bakery", "accent": "#ff0000"}).json()["settings"]["customer"] == "Bakery"
    assert client.put("/api/documentation", json={"accent": "nope"}).status_code == 422
    page = client.get("/api/documentation/export")
    assert page.status_code == 200 and "text/html" in page.headers["content-type"] and "Bakery · Network documentation" in page.text and "content-disposition" not in page.headers
    assert client.get("/api/documentation/export", params={"download": "true"}).headers["content-disposition"] == 'attachment; filename="bakery-network-documentation.html"'
    anon = TestClient(client.app)
    assert anon.get("/api/documentation").status_code == 401 and anon.get("/api/documentation/export").status_code == 401


def test_a_remote_site_gets_its_own_documentation_and_a_customer(client):
    import gzip as _gzip
    import json as _json

    made = client.post("/api/probes", json={"name": "Bakery shop"}).json()
    pid, token = made["probe"]["id"], made["token"]
    assert made["probe"]["customer"] == ""
    assert client.patch(f"/api/probes/{pid}", json={"customer": "  Bakery   Janssens "}).json()["customer"] == "Bakery Janssens"
    assert client.patch(f"/api/probes/{pid}", json={"customer": "x" * 70}).status_code == 422
    assert client.get("/api/probes").json()[0]["customer"] == "Bakery Janssens"
    anon = TestClient(client.app)
    body = {"devices": [{"key": "aa:00:00:00:00:09", "mac": "aa:00:00:00:00:09", "ip": "10.1.0.5", "name": "till <b>1</b>", "vendor": "Acme", "type": "pc", "online": True, "always_on": False, "ports": [],
                         "first_seen": "2026-03-10T12:00:00Z", "last_seen": "2026-03-10T12:00:00Z"}],
            "services": [{"key": "s1", "name": "Shop web", "kind": "http", "target": "http://10.1.0.5/", "state": "down", "ms": None, "detail": "timed out", "since": "2026-03-10T12:00:00Z", "checked": "2026-03-10T12:00:00Z"}],
            "problems": [{"device_key": "k", "device": "nas", "metric": "disk_pct", "label": "/", "level": "critical", "value": 97, "title": "Disk", "unit": "%", "since": "2026-03-10T12:00:00Z"}]}
    assert anon.post("/api/probe/push", content=_gzip.compress(_json.dumps(body).encode()), headers={"Authorization": f"Bearer {token}", "Content-Encoding": "gzip", "Content-Type": "application/json"}).status_code == 200
    page = client.get(f"/api/documentation/site/{pid}")
    assert page.status_code == 200 and "Bakery Janssens · Network documentation" in page.text and "till &lt;b&gt;1&lt;/b&gt;" in page.text and "Shop web" in page.text
    assert "nas: disk is past its limit." in page.text and "<h2>Certificates</h2>" not in page.text and "<h2>Network</h2>" not in page.text
    assert 'filename="shop' not in client.get(f"/api/documentation/site/{pid}").headers.get("content-disposition", "") and client.get(f"/api/documentation/site/{pid}", params={"download": "true"}).headers["content-disposition"].startswith('attachment; filename="bakery-shop')
    assert client.get("/api/documentation/site/999").status_code == 404 and anon.get(f"/api/documentation/site/{pid}").status_code == 401
