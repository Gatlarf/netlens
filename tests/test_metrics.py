import re

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.main import create_app
from app.metrics import render_metrics
from tests.test_stats import AUTH, NOW, db  # noqa: F401 - the seeded database

LINE = re.compile(r'^(# (HELP|TYPE) \w+ .+|[a-z_][a-z0-9_]*(\{([a-z_]+="([^"\\]|\\.)*",?)*\})? -?[0-9.e+-]+)$')


def parse(text):
    samples = {}
    for line in text.strip().splitlines():
        assert LINE.match(line), f"not valid exposition format: {line!r}"
        if not line.startswith("#"):
            name, _, value = line.rpartition(" ")
            samples[name] = float(value)
    return samples


def test_exposition_format_and_values(db):
    conn, _ = db
    text = render_metrics(conn, NOW)
    s = parse(text)
    assert s['netlens_devices{state="total"}'] == 5 and s['netlens_devices{state="online"}'] == 3 and s['netlens_devices{state="unknown"}'] == 5
    assert s['netlens_device_up{name="Router",ip="10.0.0.1",mac="aa:00:00:00:00:01",type="router"}'] == 1
    assert s['netlens_device_up{name="Phone",ip="10.0.1.3",mac="aa:00:00:00:00:03",type="phone"}'] == 0
    assert s["netlens_open_ports"] == 5 and s["netlens_problem"] == 0 and s["netlens_scan_running"] == 0
    assert s['netlens_scans_total{kind="quick",status="failed"}'] == 1
    assert s['netlens_scan_last_duration_seconds{kind="quick"}'] == 10 and s['netlens_scan_hosts_found{kind="deep"}'] == 29
    assert s['netlens_plugin_up{plugin="asus"}'] == 1 and 'plugin="proxmox"' not in text  # disabled plugins are not reported
    assert s['netlens_uptime_ratio{window="7d"}'] == pytest.approx(0.8194, abs=0.001)
    assert text.count("# TYPE netlens_devices ") == 1  # each metric is declared once
    assert 'netlens_info{version="' in text


def test_labels_are_escaped(db):
    conn, _ = db
    conn.execute('UPDATE devices SET custom_name = ? WHERE id = 1', ('Bert\'s "router"\\\nlab',))
    text = render_metrics(conn, NOW)
    assert 'name="Bert\'s \\"router\\"\\\\\\nlab"' in text
    parse(text)


def test_services_and_wifi_metrics(db):
    conn, _ = db
    conn.execute("INSERT INTO service_checks (id, name, kind, host, port, enabled, last_up, last_ms, created) VALUES (1, 'Web', 'tcp', 'a', 80, 1, 1, 12.5, ?)", (NOW,))
    conn.execute("INSERT INTO service_checks (id, name, kind, host, port, enabled, last_up, created) VALUES (2, 'Paused', 'tcp', 'a', 81, 0, 1, ?)", (NOW,))
    conn.execute("INSERT INTO wifi_samples (device_id, ts, node, band, rssi) VALUES (3, '2026-03-10T11:30:00Z', 'Garden', '5 GHz', -64)")
    conn.commit()
    s = parse(render_metrics(conn, NOW))
    assert s['netlens_service_up{name="Web",kind="tcp"}'] == 1 and s['netlens_service_response_seconds{name="Web"}'] == 0.0125
    assert not any("Paused" in k for k in s)
    assert s['netlens_wifi_signal_dbm{device="Phone",node="Garden",band="5 GHz"}'] == -64 and s["netlens_wifi_clients"] == 1


def test_endpoint_needs_the_token(db):
    conn, path = db
    conn.commit()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app) as c:
        assert c.get("/metrics").status_code == 401
        assert c.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
        r = c.get("/metrics", headers=AUTH)
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain; version=0.0.4")
        parse(r.text)


def test_identification_backup_and_system_metrics(db):
    conn, _ = db
    s = parse(render_metrics(conn, NOW, passive={"enabled": True, "running": True, "frames": 12, "applied": 3, "error": None}))
    assert s["netlens_devices_flapping"] == 1
    assert s['netlens_devices_by_type{type="router"}'] == 1
    assert s['netlens_devices_by_group{group="(no group)"}'] == 5
    assert s['netlens_identification_devices{kind="unknown_type"}'] >= 0 and 'netlens_identification_devices{kind="gentle"}' in s
    assert s['netlens_dhcp_servers{trusted="true"}'] == 0 and s['netlens_dhcp_servers{trusted="false"}'] == 0
    assert s["netlens_database_size_bytes"] > 0
    assert s["netlens_vendor_registry_entries"] > 50000 and s['netlens_database_rows{table="devices"}'] == 5
    assert s["netlens_passive_running"] == 1 and s["netlens_passive_announcements_total"] == 12 and s["netlens_passive_devices_updated_total"] == 3
    assert s["netlens_backup_enabled"] in (0, 1) and s["netlens_scans_failed_24h"] >= 0


def test_backup_result_is_exported(db):
    import json

    from app.db import set_setting

    conn, _ = db
    set_setting(conn, "backup.last", json.dumps({"ok": False, "at": "2026-10-09T10:00:00Z", "name": None, "error": "disk full"}))
    conn.commit()
    s = parse(render_metrics(conn, NOW))
    assert s["netlens_backup_last_ok"] == 0 and s["netlens_backup_last_timestamp_seconds"] > 0 and s["netlens_problem"] == 1
