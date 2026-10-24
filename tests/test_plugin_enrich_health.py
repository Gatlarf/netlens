import pytest

from app import tsdb
from app.db import connect, init_db
from app.plugins.contract import ContractError, validate_output
from app.plugins.enrich import record_node_health

MAC = "aa:00:00:00:00:10"


def topo(metrics, firmware=None, ports=None):
    return {"nodes": [{"mac": MAC, "ip": "10.0.0.1", "name": "Router", "role": "gateway", "metrics": metrics, **({"firmware": firmware} if firmware else {}), **({"ports": ports} if ports else {})}], "clients": []}


@pytest.fixture
def conn(tmp_path):
    tsdb.forget_all()
    c = connect(tmp_path / "netlens.db")
    init_db(c)
    c.execute("INSERT INTO devices (id, primary_ip, mac, online, first_seen, last_seen) VALUES (1, '10.0.0.1', ?, 1, '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z')", (MAC,))
    c.commit()
    yield c
    c.close()
    tsdb.forget_all()


def test_the_contract_accepts_readings_and_rejects_unknown_ones():
    out = validate_output("topology", topo([{"metric": "temp_c", "value": 61.5}, {"metric": "cpu_pct", "used": 10, "total": 100}, {"metric": "mem_pct", "value": None}], {"version": "1.0", "latest": "1.1"}))
    node = out["nodes"][0]
    assert [m["metric"] for m in node["metrics"]] == ["temp_c", "cpu_pct"] and node["metrics"][0]["unit"] == "°C" and node["firmware"] == {"version": "1.0", "latest": "1.1"}
    with pytest.raises(ContractError):
        validate_output("topology", topo([{"metric": "bogus", "value": 1}]))
    with pytest.raises(ContractError):
        validate_output("topology", topo([{"metric": "cpu_pct", "used": 5}]))


def test_readings_become_a_monitored_device_and_the_processor_is_a_growth(conn):
    first = validate_output("topology", topo([{"metric": "temp_c", "value": 60}, {"metric": "cpu_pct", "used": 100, "total": 1000}, {"metric": "uptime_s", "value": 5000}]))
    assert record_node_health(conn, "asus", first, "2026-10-24T10:00:00Z") == {"devices": 1, "readings": 2, "firmware": 0}      # no processor figure yet: it needs two syncs
    second = validate_output("topology", topo([{"metric": "temp_c", "value": 61}, {"metric": "cpu_pct", "used": 160, "total": 1200}]))
    assert record_node_health(conn, "asus", second, "2026-10-24T10:15:00Z")["readings"] == 2
    store = tsdb.for_conn(conn)
    assert store.latest("device", 1, "cpu_pct")[1] == pytest.approx(30.0)                  # 60 more used of 200 more total
    monitor = conn.execute("SELECT method, source, last_ok FROM host_monitors WHERE device_id = 1").fetchone()
    assert tuple(monitor) == ("plugin", "asus", 1)


def test_a_device_with_its_own_monitor_is_left_alone(conn):
    conn.execute("INSERT INTO host_monitors (device_id, method, address, port, credential, interval_s, groups, alerts, enabled, created) VALUES (1, 'snmp', '10.0.0.1', 161, '', 60, '[]', 1, 1, '2026-10-01T00:00:00Z')")
    conn.commit()
    out = record_node_health(conn, "asus", validate_output("topology", topo([{"metric": "temp_c", "value": 60}])), "2026-10-24T10:00:00Z")
    assert out["devices"] == 0 and conn.execute("SELECT method FROM host_monitors").fetchone()[0] == "snmp"


def test_a_waiting_firmware_update_is_an_event_once(conn):
    data = validate_output("topology", topo([], {"version": "388_1", "latest": "388_2"}))
    assert record_node_health(conn, "asus", data, "2026-10-24T10:00:00Z")["firmware"] == 1
    assert record_node_health(conn, "asus", data, "2026-10-24T10:15:00Z")["firmware"] == 0
    assert conn.execute("SELECT COUNT(*) FROM events WHERE kind = 'firmware_update'").fetchone()[0] == 1
    done = validate_output("topology", topo([], {"version": "388_2", "latest": None}))
    record_node_health(conn, "asus", done, "2026-10-24T11:00:00Z")
    newer = validate_output("topology", topo([], {"version": "388_2", "latest": "388_3"}))
    assert record_node_health(conn, "asus", newer, "2026-10-24T12:00:00Z")["firmware"] == 1
