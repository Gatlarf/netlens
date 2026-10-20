import os

from app.scanner import diagnose as d


def _status(monkeypatch, **fields):
    base = {"CapBnd": "0000000000003000", "CapEff": "0000000000000000", "NoNewPrivs": "0"}
    monkeypatch.setattr(d, "_status", lambda: {**base, **fields})
    monkeypatch.setattr(d.os, "geteuid", lambda: fields.pop("uid", 10001) if False else 10001)


def test_capabilities_missing_from_the_container(monkeypatch):
    _status(monkeypatch, CapBnd="0000000000000000")
    monkeypatch.setattr(d, "nmap_file_capability", lambda: True)
    out = d.diagnose("dnet: Failed to open device eth1")
    assert "NET_RAW and NET_ADMIN" in out["cause"] and "cap_add" in out["cause"]


def test_only_one_capability_missing(monkeypatch):
    _status(monkeypatch, CapBnd="0000000000002000")                 # NET_RAW only (bit 13)
    monkeypatch.setattr(d, "nmap_file_capability", lambda: True)
    assert "NET_ADMIN" in d.diagnose()["cause"] and "NET_RAW and" not in d.diagnose()["cause"]


def test_no_new_privileges(monkeypatch):
    _status(monkeypatch, NoNewPrivs="1")
    monkeypatch.setattr(d, "nmap_file_capability", lambda: True)
    assert "no-new-privileges" in d.diagnose()["cause"]


def test_the_interface_is_not_visible_without_the_host_network(monkeypatch):
    _status(monkeypatch)
    monkeypatch.setattr(d, "nmap_file_capability", lambda: True)
    monkeypatch.setattr(d, "interfaces", lambda: ["eth0", "lo"])
    out = d.diagnose("nmap exited with code 1: dnet: Failed to open device eth1\nQUITTING!")
    assert "eth1" in out["cause"] and "network_mode: host" in out["cause"]


def test_the_file_capability_was_lost_as_on_a_synology(monkeypatch):
    _status(monkeypatch)
    monkeypatch.setattr(d, "nmap_file_capability", lambda: False)
    monkeypatch.setattr(d, "interfaces", lambda: ["eth0", "eth1", "lo"])
    out = d.diagnose("nmap exited with code 1: dnet: Failed to open device eth1\nQUITTING!")
    assert 'user: "0:0"' in out["cause"] and "DAC_OVERRIDE" in out["cause"] and out["file_capability"] is False
    assert any("MISSING" in f for f in out["findings"]) and any("eth1 is among" in f for f in out["findings"])


def test_nothing_obviously_wrong(monkeypatch):
    _status(monkeypatch)
    monkeypatch.setattr(d, "nmap_file_capability", lambda: True)
    monkeypatch.setattr(d, "interfaces", lambda: ["eth0"])
    assert d.diagnose("dnet: Failed to open device eth0")["cause"] is None


def test_the_real_environment_does_not_crash():
    out = d.diagnose("whatever")
    assert isinstance(out["findings"], list) and out["findings"] and os.name == "posix"


def test_the_endpoint_is_admin_only(tmp_path):
    from fastapi.testclient import TestClient

    from app import users
    from app.config import load_settings
    from app.db import connect, init_db
    from app.main import create_app

    p = tmp_path / "t.db"
    c = connect(p)
    init_db(c)
    users.create_user(c, "vera", "a-long-enough-password", "viewer")
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=p)
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as admin:
        assert "findings" in admin.get("/api/scans/diagnose").json()
    with TestClient(app) as viewer:
        viewer.post("/api/login", json={"username": "vera", "password": "a-long-enough-password"})
        assert viewer.get("/api/scans/diagnose").status_code == 403


def test_aufs_is_named_as_the_reason_when_the_capability_is_lost(monkeypatch):
    _status(monkeypatch)
    monkeypatch.setattr(d, "nmap_file_capability", lambda: False)
    monkeypatch.setattr(d, "root_filesystem", lambda: "aufs")
    monkeypatch.setattr(d, "interfaces", lambda: ["eth0", "eth1"])
    out = d.diagnose("nmap exited with code 1: dnet: Failed to open device eth1")
    assert "aufs" in out["cause"] and "ext4" in out["cause"] and "DAC_OVERRIDE" in out["cause"] and out["filesystem"] == "aufs"
    assert any("container file system: aufs" in f for f in out["findings"])


def test_the_root_file_system_is_read_from_the_mounts(monkeypatch, tmp_path):
    f = tmp_path / "mountinfo"
    f.write_text("161 101 0:82 / / rw,relatime master:3 - aufs none rw,si=abc\n162 161 0:84 / /proc rw - proc proc rw\n")
    real = d.Path
    monkeypatch.setattr(d, "Path", lambda p: f if p == "/proc/self/mountinfo" else real(p))
    assert d.root_filesystem() == "aufs"
