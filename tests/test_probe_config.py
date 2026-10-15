import json

import pytest
from fastapi.testclient import TestClient

from app import central, probe_config, tsdb
from app.config import load_settings
from app.db import connect, init_db, set_setting
from app.hostmetrics import service as hm
from app.main import create_app

AUTH = {"Authorization": "Bearer secret"}


@pytest.fixture
def conn(tmp_path):
    tsdb.forget_all()
    c = connect(tmp_path / "t.db")
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'nas', 1, 'x', 'x')")
    c.execute("INSERT INTO probes (id, name, token_hash, created) VALUES (1, 'Branch', 'h', 'x')")
    c.commit()
    yield c
    c.close()
    tsdb.forget_all()


CONFIG = {
    "services": [{"name": "Shop", "kind": "http", "host": "shop.example.org", "port": 443, "path": "/", "expect": "200", "interval_s": 60}],
    "monitors": [{"device_key": "aa:00:00:00:00:01", "method": "snmp", "version": "2c", "community": "s3cret", "interval_s": 120}],
}


def test_save_validates_and_bumps_the_revision(conn):
    cfg = probe_config.save(conn, 1, CONFIG)
    assert cfg["rev"] == 1 and cfg["services"][0]["key"].startswith("svc-shop")
    assert probe_config.save(conn, 1, CONFIG)["rev"] == 2
    for bad in ({"services": [{"name": "x", "kind": "http", "host": "bad host!"}]},
                {"services": [{"name": "p", "kind": "process", "host": "10.0.0.5", "path": "nginx"}]},
                {"monitors": [{"device_key": "", "method": "snmp"}]},
                {"monitors": [{"device_key": "a", "method": "ssh", "username": "u"}]},
                {"monitors": [{"device_key": "a", "method": "snmp", "version": "2c"}, {"device_key": "a", "method": "snmp", "version": "2c"}]}):
        with pytest.raises(probe_config.ConfigError):
            probe_config.save(conn, 1, bad)


def test_logins_are_kept_encrypted_and_hidden(conn):
    probe_config.save(conn, 1, CONFIG)
    raw = conn.execute("SELECT value FROM settings WHERE key = 'probe.config.1'").fetchone()[0]
    assert "s3cret" not in raw                                                 # encrypted at rest
    pub = probe_config.public(probe_config.load(conn, 1))
    assert "s3cret" not in json.dumps(pub) and pub["monitors"][0]["has_community"] is True
    again = {"services": CONFIG["services"], "monitors": [{"device_key": "aa:00:00:00:00:01", "method": "snmp", "version": "2c", "interval_s": 300}]}
    probe_config.save(conn, 1, again)
    assert probe_config.load(conn, 1)["monitors"][0]["community"] == "s3cret"   # not sent again: kept


def test_a_site_gets_the_configuration_only_when_it_asks_and_differs(conn):
    probe_config.save(conn, 1, CONFIG)
    assert probe_config.for_probe(conn, 1, {"config_rev": 0}) is None          # did not opt in
    got = probe_config.for_probe(conn, 1, {"accepts_config": True, "config_rev": 0})
    assert got["rev"] == 1 and got["monitors"][0]["community"] == "s3cret"
    assert probe_config.for_probe(conn, 1, {"accepts_config": True, "config_rev": 1}) is None


def test_apply_on_the_remote_site(conn):
    cfg = probe_config.save(conn, 1, CONFIG)
    first = probe_config.apply(conn, cfg)
    assert first == {"services": 1, "monitors": 1, "skipped": []}
    svc = conn.execute("SELECT * FROM service_checks WHERE source LIKE 'central:%'").fetchall()
    assert len(svc) == 1 and svc[0]["host"] == "shop.example.org"
    mon = hm.get_monitor(conn, 1)
    assert mon["source"] == "central" and mon["address"] == "10.0.0.5" and hm.load_secret(conn, mon)["community"] == "s3cret"
    # a changed and a removed item
    cfg2 = {"rev": 2, "services": [], "monitors": []}
    probe_config.apply(conn, cfg2)
    assert conn.execute("SELECT COUNT(*) FROM service_checks WHERE source LIKE 'central:%'").fetchone()[0] == 0
    assert hm.get_monitor(conn, 1) is None


def test_a_monitor_made_here_is_not_taken_over(conn):
    hm.save_monitor(conn, 1, {"method": "snmp", "address": "10.0.0.5", "community": "mine"})
    result = probe_config.apply(conn, probe_config.save(conn, 1, CONFIG))
    assert result["monitors"] == 0 and "already has a monitor" in result["skipped"][0]
    assert hm.get_monitor(conn, 1)["source"] is None


def test_unknown_device_is_reported_not_fatal(conn):
    cfg = {"rev": 1, "services": [], "monitors": [{"device_key": "ip:10.9.9.9", "method": "snmp", "version": "2c", "community": "x", "interval_s": 60}]}
    result = probe_config.apply(conn, cfg)
    assert result["monitors"] == 0 and "not known here" in result["skipped"][0]


def test_garbage_from_the_central_side_is_ignored(conn):
    result = probe_config.apply(conn, {"rev": 3, "services": ["x", {"key": "../../etc", "name": "a"}, {"key": "ok", "name": "n", "kind": "nope", "host": "h"}], "monitors": [5, None]})
    assert result["services"] == 0 and result["monitors"] == 0


def test_report_round_trip_applies_and_remembers_the_revision(conn, monkeypatch):
    path = conn.execute("PRAGMA database_list").fetchone()[2]
    central_cfg = probe_config.save(conn, 1, CONFIG)
    set_setting(conn, central.LINK_KEY, json.dumps({"url": "https://c.example", "token": "nlp_x", "enabled": True, "interval_s": 60, "accept_config": True}))
    seen = {}

    def send(url, token, payload, timeout=25.0):
        seen["payload"] = payload
        return {"ok": True, "events": 0, "config": central_cfg}

    monkeypatch.setattr(central, "send", send)
    status = central.push_once(path, force=True)
    assert status["ok"] and status["config"]["services"] == 1
    assert seen["payload"]["accepts_config"] is True and seen["payload"]["config_rev"] == 0
    assert central.get_config_rev(conn) == central_cfg["rev"]
    central.push_once(path, force=True)
    assert seen["payload"]["config_rev"] == central_cfg["rev"]                 # the next report names the revision it has


def test_managed_things_cannot_be_edited_on_the_remote_site(tmp_path):
    tsdb.forget_all()
    p = tmp_path / "t.db"
    c = connect(p)
    init_db(c)
    c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 'nas', 1, 'x', 'x')")
    c.commit()
    probe_config.apply(c, {"rev": 1, **CONFIG, "services": [{"key": "shop", **CONFIG["services"][0]}]})
    check_id = c.execute("SELECT id FROM service_checks").fetchone()[0]
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=p)
    with TestClient(app, headers=AUTH) as tc:
        assert tc.patch(f"/api/service-checks/{check_id}", json={"name": "x"}).status_code == 409
        assert tc.delete(f"/api/service-checks/{check_id}").status_code == 409
        assert tc.put("/api/devices/1/monitor", json={"method": "snmp", "community": "x"}).status_code == 409
        assert tc.delete("/api/devices/1/monitor").status_code == 409
        assert tc.get("/api/devices/1/monitor").json()["monitor"]["managed"] is True
    tsdb.forget_all()


def test_the_api_on_the_central_side(tmp_path):
    tsdb.forget_all()
    p = tmp_path / "t.db"
    c = connect(p)
    init_db(c)
    c.execute("INSERT INTO probes (id, name, token_hash, created) VALUES (1, 'Branch', 'h', 'x')")
    c.commit()
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=p)
    with TestClient(app, headers=AUTH) as tc:
        assert tc.get("/api/probes/1/config").json() == {"rev": 0, "services": [], "monitors": []}
        r = tc.put("/api/probes/1/config", json=CONFIG)
        assert r.status_code == 200 and r.json()["rev"] == 1 and "s3cret" not in r.text
        assert tc.put("/api/probes/1/config", json={"services": [{"name": "x", "kind": "http", "host": "no spaces"}]}).status_code == 422
        assert tc.get("/api/probes/9/config").status_code == 404
    tsdb.forget_all()
