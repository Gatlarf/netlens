"""Storage plugins: the output contract, matching to devices, events only on change, the API and the device card."""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app import storage
from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app
from app.plugins.contract import ContractError, validate_output

NOW = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    for ip, mac in (("10.0.0.5", "aa:bb:cc:00:00:05"), ("10.0.0.6", "aa:bb:cc:00:00:06"), ("10.0.0.20", "aa:bb:cc:00:00:20")):
        c.execute("INSERT INTO devices (primary_ip, mac, first_seen, last_seen) VALUES (?, ?, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')", (ip, mac))
    c.commit()
    return c


def doc(health="ok", used=500, disk="ok", alerts=(), pool_health="ok"):
    return validate_output("storage", {
        "systems": [{"id": "a1", "name": "ontap1", "ip": "10.0.0.5", "vendor": "NetApp", "model": "AFF A250", "version": "9.14", "health": health}],
        "controllers": [{"id": "n1", "system_id": "a1", "name": "node-1", "mac": "AA:BB:CC:00:00:06"}, {"id": "n2", "system_id": "a1", "name": "node-2", "ip": "10.9.9.9"}],
        "pools": [{"id": "p1", "system_id": "a1", "name": "aggr1", "total": 1000, "used": used, "avail": 1000 - used, "health": pool_health, "raid": "raid_dp"}],
        "volumes": [{"id": "v1", "system_id": "a1", "pool_id": "p1", "name": "vol_data", "kind": "share", "protocol": "NFS", "size": 100, "used": 40, "clients": ["10.0.0.20", "10.0.0.20", "10.7.7.7"]}],
        "disks": [{"id": "d1", "system_id": "a1", "name": "1.0.1", "slot": "1", "state": disk}],
        "alerts": list(alerts),
    })


def kinds(conn):
    return [(r["kind"], r["detail"]) for r in conn.execute("SELECT kind, detail FROM events ORDER BY id")]


def test_contract_rejects_unknown_references_and_bad_values():
    with pytest.raises(ContractError):
        validate_output("storage", {"systems": [], "pools": [{"id": "p", "system_id": "nope"}]})
    with pytest.raises(ContractError):
        validate_output("storage", {"systems": [{"id": "a"}], "disks": [{"id": "d", "system_id": "a", "state": "exploded"}]})
    with pytest.raises(ContractError):
        validate_output("storage", {"systems": [{"id": "a"}], "volumes": [{"id": "v", "system_id": "a", "pool_id": "missing"}]})
    assert validate_output("storage", {})["systems"] == []


def test_matches_system_controller_and_clients_to_devices(conn):
    out = storage.apply_storage(conn, "ontap", doc(), now=NOW)
    assert out["systems"] == 1 and out["events"] == 0
    view = storage.overview(conn)
    ids = {r["primary_ip"]: r["id"] for r in conn.execute("SELECT id, primary_ip FROM devices")}
    assert view["systems"][0]["device_id"] == ids["10.0.0.5"]
    by_name = {c["name"]: c for c in view["controllers"]}
    assert by_name["node-1"]["device_id"] == ids["10.0.0.6"]          # found by MAC
    assert by_name["node-2"]["device_id"] is None                     # not on the network
    clients = view["volumes"][0]["clients"]
    assert [c["ip"] for c in clients] == ["10.0.0.20", "10.7.7.7"]
    assert clients[0]["device_id"] == ids["10.0.0.20"] and clients[1]["device_id"] is None
    on_host = storage.for_device(conn, ids["10.0.0.20"])
    assert on_host["uses"][0]["volume"] == "vol_data" and not on_host["systems"]
    assert storage.for_device(conn, ids["10.0.0.5"])["systems"][0]["name"] == "ontap1"
    assert storage.for_device(conn, 99999) is None


def test_events_only_on_change(conn):
    storage.apply_storage(conn, "ontap", doc(), now=NOW)
    storage.apply_storage(conn, "ontap", doc(health="critical", used=960, disk="failed", pool_health="warning"), now=NOW)
    got = kinds(conn)
    assert ("storage_degraded", "ontap1: health is critical") in got
    assert ("storage_degraded", "Pool aggr1 on ontap1: health is warning") in got
    assert ("storage_degraded", "Disk 1 of ontap1: failed") in got
    assert ("capacity_critical", "Pool aggr1 on ontap1 is 96.0% full") in got
    n = len(got)
    storage.apply_storage(conn, "ontap", doc(health="critical", used=960, disk="failed", pool_health="warning"), now=NOW)
    assert len(kinds(conn)) == n                                       # same state again: nothing new
    storage.apply_storage(conn, "ontap", doc(), now=NOW)
    recovered = [k for k, _ in kinds(conn) if k == "storage_recovered"]
    assert len(recovered) == 3


def test_pool_warning_then_critical_and_first_sync_is_silent(conn):
    storage.apply_storage(conn, "ontap", doc(used=900), now=NOW)       # first sync: already at 90 percent, not news
    assert kinds(conn) == []
    storage.apply_storage(conn, "ontap", doc(used=970), now=NOW)
    assert [k for k, _ in kinds(conn)] == ["capacity_critical"]


def test_new_critical_alert_is_an_event_once(conn):
    storage.apply_storage(conn, "ontap", doc(), now=NOW)
    alert = {"id": "x1", "system_id": "a1", "severity": "critical", "text": "Battery failed"}
    storage.apply_storage(conn, "ontap", doc(alerts=[alert]), now=NOW)
    storage.apply_storage(conn, "ontap", doc(alerts=[alert]), now=NOW)
    assert kinds(conn) == [("storage_degraded", "ontap1: Battery failed")]
    assert storage.summary(conn)["alerts"] == 1


def test_remove_plugin_and_empty_summary(conn):
    assert storage.summary(conn)["configured"] is False
    storage.apply_storage(conn, "ontap", doc(), now=NOW)
    assert storage.summary(conn)["configured"] is True
    storage.remove_plugin(conn, "ontap")
    assert storage.overview(conn)["systems"] == []


def test_api_and_device_detail(tmp_path):
    db = tmp_path / "n.db"
    c = connect(db)
    init_db(c)
    c.execute("INSERT INTO devices (primary_ip, mac, first_seen, last_seen) VALUES ('10.0.0.5', 'aa:bb:cc:00:00:05', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')")
    c.commit()
    storage.apply_storage(c, "ontap", doc(), now=NOW)
    device_id = c.execute("SELECT id FROM devices").fetchone()[0]
    c.close()
    client = TestClient(create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=db), headers={"Authorization": "Bearer secret"})
    body = client.get("/api/storage").json()
    assert body["summary"]["systems"] == 1 and body["pools"][0]["percent"] == 50.0
    assert client.get(f"/api/devices/{device_id}").json()["storage"]["systems"][0]["vendor"] == "NetApp"
