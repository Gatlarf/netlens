import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import connect, init_db, set_setting
from app.main import create_app
from app.stats import RANGES, compute_stats, record_daily_snapshot, summary

NOW = "2026-03-10T12:00:00Z"
AUTH = {"Authorization": "Bearer secret"}


def ago(hours=0, days=0):
    dt = datetime.strptime(NOW, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) - timedelta(hours=hours, days=days)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def device(conn, id, mac, ip, *, online=1, vendor=None, dtype=None, os_name=None, first=None, last=None, name=None):
    conn.execute(
        "INSERT INTO devices (id, mac, primary_ip, hostname, vendor, os_name, device_type, online, first_seen, last_seen, custom_name) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (id, mac, ip, None, vendor, os_name, dtype, online, first or ago(days=60), last or ago(hours=1), name),
    )


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    device(conn, 1, "aa:00:00:00:00:01", "10.0.0.1", vendor="ASUS", dtype="router", os_name="Linux 5.4, Linux 5.10", name="Router")
    device(conn, 2, "aa:00:00:00:00:02", "10.0.0.2", vendor="Synology", dtype="nas", os_name="Linux 4.4", name="NAS")
    device(conn, 3, "aa:00:00:00:00:03", "10.0.1.3", online=0, vendor="Apple", dtype="phone", last=ago(hours=36), name="Phone")
    device(conn, 4, "aa:00:00:00:00:04", "10.0.1.4", online=0, last=ago(days=45), first=ago(days=90), name="Old")
    device(conn, 5, "aa:00:00:00:00:05", "10.0.1.5", vendor="Apple", dtype="phone", first=ago(hours=5), name="New")
    # uptime: router always up (rtt 1 ms), NAS up with rtt 20, phone flaps every scan in the last day, 24 scans two hours apart
    for i in range(24):
        ts = ago(hours=2 * (23 - i))
        conn.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (1, ?, 1, 1.0)", (ts,))
        conn.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (2, ?, ?, 20.0)", (ts, 1 if i != 5 else 0))
        conn.execute("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (3, ?, ?, NULL)", (ts, i % 2))
    conn.executemany("INSERT INTO ports (device_id, proto, port, state, service, updated) VALUES (?,?,?,?,?,'2026-03-10T00:00:00Z')", [
        (1, "tcp", 80, "open", "http"), (1, "tcp", 443, "open", "https"), (1, "tcp", 22, "open", "ssh"),
        (2, "tcp", 80, "open", "http"), (2, "tcp", 445, "open", "smb"), (2, "tcp", 23, "closed", "telnet"),
    ])
    conn.executemany("INSERT INTO events (ts, device_id, kind, detail) VALUES (?,?,?,?)", [
        (ago(hours=5), 5, "device_new", "10.0.1.5"), (ago(hours=30), 3, "device_offline", "10.0.1.3"),
        (ago(days=3), 2, "port_opened", "445"), (ago(days=20), 3, "device_offline", "10.0.1.3"),
        (ago(days=2), 1, "host_timeout", "10.0.0.1"),
    ])
    conn.executemany("INSERT INTO scans (kind, status, started, finished, hosts_found) VALUES (?,?,?,?,?)", [
        ("quick", "done", ago(hours=6), ago(hours=6)[:-3] + "10Z", 30), ("quick", "done", ago(hours=4), ago(hours=4)[:-3] + "20Z", 31),
        ("quick", "failed", ago(hours=3), ago(hours=3), 0), ("deep", "done", ago(hours=2), ago(hours=2)[:-3] + "40Z", 29),
        ("quick", "done", ago(hours=1), ago(hours=1)[:-3] + "10Z", 32),
    ])
    conn.execute("INSERT INTO ignored_devices (mac, ip, label, added) VALUES ('aa:aa', NULL, 'x', ?)", (NOW,))
    # hierarchy: NAS and phone sit below the router
    conn.executemany("INSERT INTO relations (src_id, dst_id, kind, source, confidence, manual) VALUES (?,?,'uplink','plugin:asus',1.0,0)", [(2, 1), (3, 1)])
    conn.executemany("INSERT INTO hypervisor_guests (plugin_id, guest_id, name, kind, host_name, status, updated) VALUES ('proxmox', ?, ?, 'lxc', 'pve1', ?, ?)", [
        ("1", "a", "running", NOW), ("2", "b", "stopped", NOW)])
    set_setting(conn, "plugin.asus", json.dumps({"enabled": True, "config": {}}))
    set_setting(conn, "plugin.asus.status", json.dumps({"ts": NOW, "ok": True}))
    set_setting(conn, "plugin.asus.data", json.dumps({
        "nodes": [{"mac": "aa:aa:aa:aa:aa:01", "macs": ["aa:aa:aa:aa:aa:01"], "name": "Main", "role": "gateway"},
                  {"mac": "aa:aa:aa:aa:aa:02", "macs": ["aa:aa:aa:aa:aa:02"], "name": "Garden", "role": "node"}],
        "clients": [{"mac": "x1", "node_mac": None, "medium": "wired"}, {"mac": "x2", "node_mac": "aa:aa:aa:aa:aa:02", "medium": "wifi", "band": "5 GHz"},
                    {"mac": "x3", "node_mac": "aa:aa:aa:aa:aa:02", "medium": "wifi", "band": "2.4 GHz"}]}))
    set_setting(conn, "plugin.proxmox", json.dumps({"enabled": False, "config": {}}))
    conn.commit()
    return conn, path


def test_overview(db):
    conn, _ = db
    o = compute_stats(conn, "7d", NOW)["overview"]
    assert (o["total"], o["online"], o["offline"], o["online_pct"]) == (5, 3, 2, 60.0)
    assert (o["new_24h"], o["new_7d"], o["new_30d"], o["stale_30d"], o["ignored"]) == (1, 1, 1, 1, 1)


def test_composition(db):
    conn, _ = db
    c = compute_stats(conn, "7d", NOW)["composition"]
    assert {t["label"]: t["count"] for t in c["by_type"]} == {"phone": 2, "nas": 1, "router": 1, "unknown": 1}
    assert c["by_vendor"][0] == {"label": "Apple", "count": 2}
    assert {o["label"]: o["count"] for o in c["by_os"]}["Linux 5.4"] == 1 and {o["label"]: o["count"] for o in c["by_os"]}["Unknown"] == 3
    assert {s["label"]: s["count"] for s in c["by_subnet"]} == {"10.0.0.0/24": 2, "10.0.1.0/24": 3}
    assert c["connection"] == {"wired": 1, "wifi": 2, "unknown": 0}
    assert {b["label"]: b["count"] for b in c["wifi_bands"]} == {"5 GHz": 1, "2.4 GHz": 1}
    assert {n["label"]: n["count"] for n in c["clients_per_node"]} == {"Main": 1, "Garden": 2}
    assert c["top_level"] == 3 and c["with_parent"] == 2  # router, old, new are top level


def test_availability(db):
    conn, _ = db
    a = compute_stats(conn, "7d", NOW)["availability"]
    assert a["uptime_7d"] == pytest.approx((24 + 23 + 12) / 72 * 100, abs=0.01)
    assert [r["name"] for r in a["least_reliable"]][:2] == ["Phone", "NAS"]
    assert a["most_reliable"][0]["name"] == "Router" and a["most_reliable"][0]["uptime"] == 100.0
    assert a["least_reliable"][0]["uptime"] == 50.0 and a["least_reliable"][0]["outages"] == 12
    assert [f["name"] for f in a["flapping"]] == ["Phone"] and a["flapping"][0]["flaps_24h"] >= 6
    assert [o["name"] for o in a["longest_outages"]] == ["Old", "Phone"] and a["longest_outages"][1]["seconds"] == 36 * 3600
    assert a["avg_rtt_ms"] == pytest.approx(10.5, abs=0.1) and a["slowest"][0]["name"] == "NAS"


def test_ports_and_structure_and_events(db):
    conn, _ = db
    s = compute_stats(conn, "7d", NOW)
    p = s["ports"]
    assert p["open_total"] == 5 and p["devices_with_open"] == 2 and p["devices_without_open"] == 3 and p["opened_7d"] == 1
    assert p["top_ports"][0] == {"label": "80/tcp http", "count": 2} and p["most_open"][0] == {"id": 1, "name": "Router", "count": 3}
    assert {x["label"] for x in p["top_services"]} == {"http", "https", "ssh", "smb"}
    st = s["structure"]
    assert st["max_depth"] == 1 and st["busiest_parents"] == [{"id": 1, "name": "Router", "children": 2}]
    assert st["hypervisor_hosts"] == [{"plugin": "proxmox", "host": "pve1", "guests": 2, "running": 1}]
    e = s["events"]
    assert e["total"] == 4 and {k["label"]: k["count"] for k in e["by_kind"]} == {"device_new": 1, "device_offline": 1, "port_opened": 1, "host_timeout": 1}
    assert [r["kind"] for r in e["recent"]][:2] == ["host_timeout", "device_offline"] and e["recent"][0]["device"] == "Router"  # newest id first
    assert s["events"]["most_active"][0]["count"] == 1


def test_scans(db):
    conn, _ = db
    sc = compute_stats(conn, "7d", NOW)["scans"]
    quick = sc["by_kind"]["quick"]
    assert (quick["total"], quick["done"], quick["failed"], quick["median_s"], quick["max_s"]) == (4, 3, 1, 10, 20)
    assert sc["by_kind"]["deep"]["median_s"] == 40 and sc["host_timeouts"] == 1 and sc["total"] == 5
    assert [t["hosts"] for t in sc["hosts_trend"]] == [30, 31, 29, 32]
    assert sc["last"]["hosts_found"] == 32


def test_history_ranges_and_snapshots(db):
    conn, _ = db
    record_daily_snapshot(conn, NOW)
    record_daily_snapshot(conn, NOW)  # same day: updated, not duplicated
    h = compute_stats(conn, "7d", NOW)["history"]
    assert h["daily"] == [{"day": "2026-03-10", "devices": 5, "online": 3, "new_devices": 1, "open_ports": 5, "events": 1, "scans": 5}]
    assert h["bucket"] == "hour" and len(h["online_series"]) >= 12
    assert compute_stats(conn, "30d", NOW)["history"]["bucket"] == "day"
    conn.execute("INSERT INTO stats_daily (day, devices, online) VALUES ('2024-01-01', 1, 1)")
    record_daily_snapshot(conn, NOW)
    assert conn.execute("SELECT COUNT(*) FROM stats_daily WHERE day = '2024-01-01'").fetchone()[0] == 0  # retention
    with pytest.raises(ValueError):
        compute_stats(conn, "1y", NOW)
    assert set(RANGES) == {"24h", "7d", "30d", "90d"}


def test_system_and_plugins(db):
    conn, path = db
    sysinfo = compute_stats(conn, "7d", NOW, db_path=str(path))["system"]
    assert sysinfo["db_bytes"] > 0 and sysinfo["rows"]["devices"] == 5 and sysinfo["rows"]["checks"] == 72
    assert {p["id"]: (p["enabled"], p["ok"]) for p in sysinfo["plugins"]} == {"asus": (True, True), "proxmox": (False, None)}


def test_empty_database_gives_empty_answers(tmp_path):
    conn = connect(tmp_path / "e.db")
    init_db(conn)
    s = compute_stats(conn, "7d", NOW)
    assert s["overview"]["total"] == 0 and s["overview"]["online_pct"] is None and s["availability"]["uptime_7d"] is None
    assert s["scans"]["by_kind"] == {} and s["history"]["online_series"] == [] and s["structure"]["max_depth"] == 0
    assert summary(conn, NOW)["devices"]["total"] == 0 and summary(conn, NOW)["problem"] is False


def test_summary_document(db):
    conn, _ = db
    doc = summary(conn, NOW, scan_running=True)
    assert doc["api"] == 1 and doc["generated"] == NOW and doc["scans"]["running"] is True
    assert doc["devices"] == {"total": 5, "online": 3, "offline": 2, "new_24h": 1, "new_7d": 1, "stale_30d": 1, "unknown": 5, "flapping": 1}
    assert doc["wifi"] == {"clients": 0, "weak": 0, "avg_rssi": None}
    assert doc["ports"] == {"open": 5} and doc["events"]["24h"] == 1 and doc["events"]["last_id"] == 5
    assert doc["uptime"]["24h"] is not None and doc["scans"]["last"]["kind"] == "quick" and doc["scans"]["last_ok_age_s"] == 3600 - 10
    dev = {d["id"]: d for d in doc["device_list"]}
    assert dev[2] == {"id": 2, "name": "NAS", "ip": "10.0.0.2", "mac": "aa:00:00:00:00:02", "online": True, "type": "nas", "vendor": "Synology",
                      "last_seen": ago(hours=1), "trusted": False, "parent_id": 1, "parent_name": "Router", "group": None}
    assert dev[1]["parent_id"] is None and len(dev) == 5
    assert doc["scans"]["failed_24h"] == 1 and doc["problems"] == 0 and doc["problem"] is False  # an old failure that later scans recovered from


def test_summary_problem_logic(db):
    conn, _ = db
    assert summary(conn, NOW)["problem"] is False
    conn.execute("INSERT INTO scans (kind, status, started, finished, hosts_found) VALUES ('quick', 'failed', ?, ?, 0)", (ago(hours=0.1), ago(hours=0.1)))
    assert summary(conn, NOW)["problems"] == 1  # the most recent scan failed
    conn.execute("DELETE FROM scans WHERE status = 'failed'")
    assert summary(conn, NOW)["problem"] is False
    set_setting(conn, "plugin.asus.status", json.dumps({"ts": NOW, "ok": False, "error": "login refused"}))
    d = summary(conn, NOW)
    assert d["problems"] == 1 and d["plugins"][0]["error"] == "login refused"
    conn.execute("DELETE FROM scans")
    assert summary(conn, NOW)["scans"]["last_ok_age_s"] is None  # no scan yet is not a problem by itself
    conn.execute("INSERT INTO scans (kind, status, started, finished, hosts_found) VALUES ('quick', 'done', ?, ?, 1)", (ago(hours=10), ago(hours=10)))
    assert summary(conn, NOW)["problems"] == 2  # failing plugin + last good scan older than 3 h


# ---------------------------------------------------------------- API
@pytest.fixture
def client(db):
    conn, path = db
    conn.commit()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app, headers=AUTH) as c:
        yield c


def test_api_stats_and_summary(client):
    body = client.get("/api/stats").json()
    assert body["range"] == "7d" and set(body) >= {"overview", "composition", "availability", "history", "ports", "structure", "scans", "events", "system"}
    assert client.get("/api/stats", params={"range": "24h"}).json()["range"] == "24h"
    assert client.get("/api/stats", params={"range": "1y"}).status_code == 422
    s = client.get("/api/stats/summary").json()
    assert s["api"] == 1 and s["devices"]["total"] == 5 and len(s["device_list"]) == 5


def test_api_requires_login(client):
    bad = {"Authorization": "Bearer no"}
    assert client.get("/api/stats", headers=bad).status_code == 401
    assert client.get("/api/stats/summary", headers=bad).status_code == 401


def test_api_results_are_cached_briefly(client, db):
    conn, _ = db
    first = client.get("/api/stats/summary").json()["devices"]["total"]
    device(conn, 9, "aa:00:00:00:00:09", "10.0.9.9")
    conn.commit()
    assert client.get("/api/stats/summary").json()["devices"]["total"] == first  # served from the 30 s cache


def test_events_since_id(client):
    ids = [e["id"] for e in client.get("/api/events").json()]
    newer = client.get("/api/events", params={"since_id": sorted(ids)[2]}).json()
    assert sorted(e["id"] for e in newer) == sorted(ids)[3:]
    assert client.get("/api/events", params={"since_id": max(ids)}).json() == []


def test_wifi_picture_and_trust_counts(db):
    conn, _ = db
    conn.execute("UPDATE devices SET trusted = 1 WHERE id IN (1, 2)")
    for dev, node, band, rssi in ((1, "Garden", "5 GHz", -50), (2, "Garden", "2.4 GHz", -80), (3, "Attic", "5 GHz", -70)):
        conn.execute("INSERT INTO wifi_samples (device_id, ts, node, band, rssi) VALUES (?, ?, ?, ?, 0)", (dev, ago(hours=3), node, band))  # too old
        conn.execute("INSERT INTO wifi_samples (device_id, ts, node, band, rssi) VALUES (?, ?, ?, ?, ?)", (dev, ago(hours=1), node, band, rssi))
    conn.execute("INSERT INTO events (ts, device_id, kind, detail) VALUES (?, 3, 'wifi_roamed', 'a -> b')", (ago(days=1),))
    w = compute_stats(conn, "7d", NOW)["wifi"]
    assert w["clients"] == 3 and w["weak"] == 1 and w["avg_rssi"] == -67 and w["roams_7d"] == 1
    assert {q["label"]: q["count"] for q in w["quality"]} == {"excellent (-55 and better)": 1, "fair (-66 to -75)": 1, "weak (below -75)": 1}
    assert [x["name"] for x in w["weakest"]] == ["NAS", "Phone", "Router"] and w["weakest"][0]["node"] == "Garden"
    doc = summary(conn, NOW)
    assert doc["devices"]["unknown"] == 3 and doc["wifi"] == {"clients": 3, "weak": 1, "avg_rssi": -67}
    assert {d["id"]: d["trusted"] for d in doc["device_list"]} == {1: True, 2: True, 3: False, 4: False, 5: False}


def _real_ago(**kw):
    from app.db import utcnow
    from app.stats import _ago

    return _ago(utcnow(), **kw)


def test_device_wifi_endpoint(client, db):
    conn, _ = db
    for i, (node, rssi) in enumerate((("Garden", -60), ("Garden", -62), ("Attic", -70))):
        conn.execute("INSERT INTO wifi_samples (device_id, ts, node, band, rssi, tx_mbps) VALUES (3, ?, ?, '5 GHz', ?, 72.2)", (_real_ago(hours=2 - i * 0.5), node, rssi))
    roam_ts = _real_ago(hours=1)  # computed once: asking the clock twice can straddle a second
    conn.execute("INSERT INTO events (ts, device_id, kind, detail) VALUES (?, 3, 'wifi_roamed', 'Garden -> Attic (5 GHz)')", (roam_ts,))
    conn.commit()
    body = client.get("/api/devices/3/wifi", params={"hours": 24}).json()
    assert [s["rssi"] for s in body["samples"]] == [-60, -62, -70]
    assert body["current"]["node"] == "Attic" and body["current"]["quality"] == "fair" and body["current"]["tx_mbps"] == 72.2
    assert body["roams"] == [{"ts": roam_ts, "detail": "Garden -> Attic (5 GHz)"}]
    assert client.get("/api/devices/1/wifi").json() == {"current": None, "samples": [], "roams": []}
    assert client.get("/api/devices/99/wifi").status_code == 404
    assert client.get("/api/devices/3/wifi", headers={"Authorization": "Bearer no"}).status_code == 401


def test_service_checks_in_the_statistics_and_the_summary(db):
    conn, _ = db
    conn.execute("INSERT INTO service_checks (id, name, kind, host, port, enabled, last_up, last_ms, last_detail, created) VALUES (1, 'Web', 'tcp', 'a', 80, 1, 1, 4.0, 'port open', ?)", (NOW,))
    conn.execute("INSERT INTO service_checks (id, name, kind, host, port, enabled, last_up, last_detail, created) VALUES (2, 'DB', 'tcp', 'b', 5432, 1, 0, 'refused', ?)", (NOW,))
    conn.execute("INSERT INTO service_checks (id, name, kind, host, port, enabled, last_up, created) VALUES (3, 'Paused', 'tcp', 'c', 1, 0, 0, ?)", (NOW,))
    conn.executemany("INSERT INTO service_results (check_id, ts, up) VALUES (?, ?, ?)", [(1, ago(hours=1), 1), (1, ago(hours=2), 0), (2, ago(hours=1), 0)])
    svc = compute_stats(conn, "7d", NOW)["services"]
    assert (svc["total"], svc["up"], svc["down"]) == (3, 1, 1)  # a paused check is neither up nor down
    assert {c["name"]: c["uptime_24h"] for c in svc["checks"]} == {"DB": 0.0, "Paused": None, "Web": 50.0}
    doc = summary(conn, NOW)
    assert doc["services"] == {"total": 3, "up": 1, "down": 1} and doc["problems"] >= 1 and doc["problem"] is True


def test_summary_carries_identification_backup_and_passive(db):
    conn, _ = db
    doc = summary(conn, NOW, passive={"enabled": True, "running": False, "frames": 4, "applied": 1, "error": "x"})
    assert set(doc["identification"]) == {"unknown_type", "private_mac", "no_vendor", "manual_type", "gentle", "nameless", "no_os"}
    assert doc["backup"] == {"enabled": False, "last_at": None, "last_ok": None, "last_error": None, "age_s": None}
    assert doc["passive"] == {"enabled": True, "running": False, "frames": 4, "applied": 1}   # the error text stays out
    assert doc["netchecks"]["dhcp_servers"] == 0 and doc["devices"]["flapping"] == 1
    assert summary(conn, NOW)["passive"] is None


def test_stats_page_data_has_the_new_groups(db):
    conn, _ = db
    s = compute_stats(conn, "7d", NOW)
    assert {"identification", "backups", "netchecks"} <= set(s)
    assert s["composition"]["by_group"][0]["label"] == "(no group)"
    assert s["availability"]["flapping_total"] == 1 and "schema" in s["system"] and s["system"]["vendor_entries"] > 50000
