"""Backup targets tied to guests: matching, late and failed detection, events, the unprotected list, the API and the dashboard numbers."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import guestbackups as gb
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app
from app.plugins.contract import validate_output

NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)


def at(**delta):
    return (NOW - timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    for pid, gid, name, kind, status in (("proxmox", "100", "BlueIris", "qemu", "running"), ("proxmox", "102", "lxc-web1", "lxc", "running"), ("proxmox", "106", "vm-siemens", "qemu", "stopped"),
                                         ("proxmox", "109", "never-backed-up", "qemu", "running"), ("docker", "abc", "web", "container", "running")):
        dev = c.execute("INSERT INTO devices (primary_ip, first_seen, last_seen) VALUES (?, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')", (f"10.0.0.{len(gid)}{ord(gid[0]) % 50}",)).lastrowid if kind != "container" else None
        c.execute("INSERT INTO hypervisor_guests (plugin_id, guest_id, name, kind, host_name, status, macs, ips, device_id, updated) VALUES (?, ?, ?, ?, 'nuc', ?, '[]', '[]', ?, '2026-10-16T00:00:00Z')",
                  (pid, gid, name, kind, status, dev))
    c.commit()
    return c


def target(tid, btype, bid, name="", last=None, state="ok", interval=86400, count=5, verify="none"):
    return {"id": tid, "server_id": "s", "store_id": "st", "type": btype, "backup_id": bid, "name": name, "count": count, "last_backup": last, "last_state": state, "last_size": 10, "verify_state": verify,
            "interval": interval, "protected": 0}


def output(*targets, full=None, problems=()):
    return validate_output("backup", {"servers": [{"id": "s", "name": "pbs", "ip": "10.0.0.9", "version": "4.2"}], "problems": list(problems),
                                      "stores": [{"id": "st", "server_id": "s", "name": "main", "total": 1000, "used": 400, "avail": 600, "full": full}], "targets": list(targets)})


def events(conn, kind=None):
    rows = conn.execute("SELECT kind, detail FROM events" + (" WHERE kind = ?" if kind else "") + " ORDER BY id", (kind,) if kind else ()).fetchall()
    return [(r["kind"], r["detail"]) for r in rows]


def test_targets_are_matched_to_guests_by_type_and_id(conn):
    data = output(target("a", "vm", "100", "BlueIris", at(hours=3)), target("b", "ct", "100", "old", at(days=40)), target("c", "ct", "102", "lxc-web1", at(hours=2)), target("d", "host", "nuc", "", at(days=3)))
    summary = gb.apply_backup(conn, "pbs", data, now=NOW)
    assert summary["matched"] == 2
    rows = {r["target_id"]: r for r in conn.execute("SELECT * FROM backup_targets")}
    assert rows["a"]["guest_id"] == "100" and rows["a"]["device_id"] is not None and rows["c"]["guest_id"] == "102"
    assert rows["b"]["guest_id"] is None                                               # ct 100 is not the VM 100


def test_the_name_saved_with_the_backup_tells_two_hypervisors_apart(conn):
    conn.execute("INSERT INTO hypervisor_guests (plugin_id, guest_id, name, kind, host_name, status, macs, ips, updated) VALUES ('proxmox2', '100', 'Other', 'qemu', 'n2', 'running', '[]', '[]', 'x')")
    conn.commit()
    gb.apply_backup(conn, "pbs", output(target("a", "vm", "100", "Other", at(hours=3))), now=NOW)
    assert conn.execute("SELECT guest_plugin_id FROM backup_targets").fetchone()[0] == "proxmox2"


def test_late_uses_the_usual_interval(conn):
    assert gb.late_after(None) == timedelta(hours=36) and gb.late_after(86400) == timedelta(hours=60) and gb.late_after(3600) == timedelta(hours=6)
    data = output(target("daily", "vm", "100", "BlueIris", at(hours=70)), target("weekly", "ct", "102", "lxc-web1", at(days=9), interval=7 * 86400),
                  target("fine", "vm", "106", "vm-siemens", at(hours=20)))
    gb.apply_backup(conn, "pbs", data, now=NOW)
    late = {r["target_id"]: r["stale"] for r in conn.execute("SELECT target_id, stale FROM backup_targets")}
    assert late == {"daily": 1, "weekly": 0, "fine": 0}


def test_a_target_nobody_owns_is_retired_not_late(conn):
    gb.apply_backup(conn, "pbs", output(target("gone", "vm", "999", "deleted", at(days=40)), target("recent", "vm", "998", "recently deleted", at(days=3))), now=NOW)
    flags = {r["target_id"]: r["stale"] for r in conn.execute("SELECT target_id, stale FROM backup_targets")}
    assert flags == {"gone": 0, "recent": 1}


def test_events_only_on_change_and_never_on_the_first_sync(conn):
    first = output(target("a", "vm", "100", "BlueIris", at(hours=3), state="failed"))
    gb.apply_backup(conn, "pbs", first, now=NOW)
    assert events(conn) == []                                                          # the first sync is not news
    gb.apply_backup(conn, "pbs", first, now=NOW)
    assert events(conn) == []
    gb.apply_backup(conn, "pbs", output(target("a", "vm", "100", "BlueIris", at(hours=3), state="ok")), now=NOW)
    assert [k for k, _ in events(conn)] == ["guest_backup_recovered"]


def test_a_failing_and_a_late_backup_raise_one_event_each(conn):
    gb.apply_backup(conn, "pbs", output(target("a", "vm", "100", "BlueIris", at(hours=3)), target("b", "ct", "102", "lxc-web1", at(hours=3))), now=NOW)
    later = output(target("a", "vm", "100", "BlueIris", at(hours=3), state="failed"), target("b", "ct", "102", "lxc-web1", at(hours=90)))
    gb.apply_backup(conn, "pbs", later, now=NOW)
    gb.apply_backup(conn, "pbs", later, now=NOW)
    got = events(conn)
    assert [k for k, _ in got] == ["guest_backup_failed", "guest_backup_late"] and "BlueIris" in got[0][1] and "no new backup since" in got[1][1]
    assert conn.execute("SELECT device_id FROM events WHERE kind = 'guest_backup_failed'").fetchone()[0] is not None          # on the guest's device


def test_a_store_that_will_fill_up_raises_capacity_events_once(conn):
    gb.apply_backup(conn, "pbs", output(full=at(days=-200)), now=NOW)
    gb.apply_backup(conn, "pbs", output(full=at(days=-20)), now=NOW)
    gb.apply_backup(conn, "pbs", output(full=at(days=-20)), now=NOW)
    gb.apply_backup(conn, "pbs", output(full=at(days=-2)), now=NOW)
    assert [k for k, _ in events(conn)] == ["capacity_warning", "capacity_critical"]


def test_unprotected_guests_appear_only_once_a_backup_plugin_has_data(conn):
    assert gb.unprotected(conn) == []
    gb.apply_backup(conn, "pbs", output(target("a", "vm", "100", "BlueIris", at(hours=3)), target("c", "ct", "102", "lxc-web1", at(hours=2))), now=NOW)
    names = [g["name"] for g in gb.unprotected(conn)]
    assert names == ["never-backed-up", "vm-siemens"]                                  # Docker containers are not guests to back up
    summary = gb.summary(conn)
    assert summary["configured"] and summary["guests"] == 4 and summary["protected"] == 2 and summary["unprotected"] == 2


def test_overview_and_device_card(conn):
    gb.apply_backup(conn, "pbs", output(target("a", "vm", "100", "BlueIris", at(hours=3), state="failed", verify="ok"), full=at(days=-10),
                                        problems=[{"id": "p", "server_id": "s", "kind": "backup", "state": "failed", "at": at(hours=1), "text": "x"}]), now=NOW)
    view = gb.overview(conn, NOW)
    t = view["targets"][0]
    assert t["device"] is not None and t["age_s"] == 3 * 3600 and t["verify_state"] == "ok" and view["stores"][0]["days_to_full"] == 10 and view["stores"][0]["percent"] == 40.0
    assert view["summary"]["failed"] == 1 and view["summary"]["stores_at_risk"] == 1 and view["summary"]["problems"] == 1 and len(view["problems"]) == 1
    card = gb.for_device(conn, t["device_id"], NOW)
    assert card["last_state"] == "failed" and card["count"] == 5 and gb.for_device(conn, 9999) is None


def test_removing_the_plugin_removes_everything(conn):
    gb.apply_backup(conn, "pbs", output(target("a", "vm", "100", "BlueIris", at(hours=3))), now=NOW)
    gb.remove_plugin(conn, "pbs")
    assert gb.summary(conn)["configured"] is False and conn.execute("SELECT COUNT(*) FROM backup_targets").fetchone()[0] == 0


@pytest.fixture
def client(tmp_path):
    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=path)
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as tc:
        tc.path = path
        yield tc


def test_api_dashboard_metrics_and_device(client):
    assert client.get("/api/guest-backups").json()["summary"]["configured"] is False
    conn = connect(client.path)
    conn.execute("INSERT INTO devices (primary_ip, first_seen, last_seen) VALUES ('10.0.0.5', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')")
    dev = conn.execute("SELECT id FROM devices").fetchone()[0]
    conn.execute("INSERT INTO hypervisor_guests (plugin_id, guest_id, name, kind, host_name, status, macs, ips, device_id, updated) VALUES ('proxmox', '100', 'BlueIris', 'qemu', 'nuc', 'running', '[]', '[]', ?, 'x')", (dev,))
    conn.commit()
    now = datetime.now(timezone.utc)
    gb.apply_backup(conn, "pbs", output(target("a", "vm", "100", "BlueIris", (now - timedelta(hours=100)).strftime("%Y-%m-%dT%H:%M:%SZ")), full=None), now=now)
    conn.close()
    body = client.get("/api/guest-backups").json()
    assert body["summary"]["late"] == 1 and body["targets"][0]["late"] is True and body["servers"][0]["name"] == "pbs"
    summary = client.get("/api/stats/summary").json()
    assert summary["guest_backups"]["configured"] and summary["guest_backups"]["late"] == 1
    assert any("not backed up on time" in i["text"] for i in client.get("/api/dashboard").json()["attention"])
    text = client.get("/metrics").text
    assert "netlens_backup_targets_late 1" in text and 'netlens_backup_age_seconds{' in text and 'netlens_backup_store_used_bytes{store="main"} 400' in text
    assert client.get(f"/api/devices/{dev}").json()["guest_backup"]["late"] is True
