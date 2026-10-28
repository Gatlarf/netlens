"""Plugin kind "metrics": the contract and what Netlens does with the readings (app/metricsource.py)."""

import json

import pytest

from app import tsdb
from app.db import connect, init_db
from app.hostmetrics import service as hm
from app.metricsource import apply_metrics
from app.plugins import categories
from app.plugins.contract import ContractError, KINDS, validate_output

NOW = "2026-10-28T10:00:00Z"


@pytest.fixture
def conn(tmp_path):
    tsdb.forget_all()
    c = connect(tmp_path / "m.db")
    init_db(c)
    for i, (mac, ip, name) in enumerate([("aa:00:00:00:00:01", "10.0.0.1", "web01"), ("aa:00:00:00:00:02", "10.0.0.2", "web02.lan"), ("aa:00:00:00:00:03", "10.0.0.3", "db01"),
                                         ("aa:00:00:00:00:04", "10.0.0.4", "twin"), ("aa:00:00:00:00:05", "10.0.0.5", "twin")], start=1):
        c.execute("INSERT INTO devices (id, mac, primary_ip, hostname, online, first_seen, last_seen) VALUES (?,?,?,?,1,?,?)", (i, mac, ip, name, NOW, NOW))
    c.commit()
    yield c
    c.close()
    tsdb.forget_all()


def host(hid, readings, **kw):
    return {"id": hid, "name": kw.get("name", hid), "ip": kw.get("ip"), "macs": kw.get("macs", []), "readings": readings}


def reading(metric, value, label="", samples=None):
    return {"metric": metric, "label": label, "unit": "", "value": value, "samples": samples or []}


def test_the_kind_is_known_and_has_a_category():
    assert "metrics" in KINDS and categories.category_of("metrics") == "monitoring"
    assert any(c["id"] == "monitoring" for c in categories.listing())


def test_the_contract():
    good = {"hosts": [{"id": "a", "ip": "10.0.0.1", "readings": [{"metric": "cpu_pct", "value": 5}, {"metric": "disk_pct", "label": "/", "samples": [[1790000000, 61], [1790000060, 62]]},
                                                              {"metric": "mem_pct"}]}]}
    out = validate_output("metrics", good)
    assert len(out["hosts"][0]["readings"]) == 2 and out["hosts"][0]["readings"][1]["unit"] == "%"          # a reading without a figure is left out
    for bad in ({"hosts": [{"id": "a"}, {"id": "a"}]}, {"hosts": [{"readings": []}]}, {"hosts": [{"id": "a", "readings": [{"metric": "bogus", "value": 1}]}]},
                {"hosts": [{"id": "a", "readings": [{"metric": "cpu_pct", "value": "x"}]}]}, {"hosts": [{"id": "a", "readings": [{"metric": "cpu_pct", "samples": [[1]]}]}]},
                {"hosts": [{"id": "a", "ip": "not-an-ip"}]}, {"hosts": "x"}, []):
        with pytest.raises(ContractError):
            validate_output("metrics", bad)
    many = {"hosts": [{"id": "a", "readings": [{"metric": "cpu_pct", "samples": [[1790000000 + i, 1] for i in range(500)]}]}]}
    assert len(validate_output("metrics", many)["hosts"][0]["readings"][0]["samples"]) == 240


def data_of(*hosts):
    return validate_output("metrics", {"hosts": list(hosts)})


def test_hosts_are_matched_by_ip_then_mac_then_name_and_a_shared_name_is_never_guessed(conn):
    out = data_of({"id": "1", "name": "whatever", "ip": "10.0.0.1", "readings": [{"metric": "cpu_pct", "value": 1}]},
                  {"id": "2", "name": "x", "macs": ["AA-00-00-00-00-02"], "readings": [{"metric": "cpu_pct", "value": 2}]},
                  {"id": "3", "name": "DB01.corp.example", "readings": [{"metric": "cpu_pct", "value": 3}]},
                  {"id": "4", "name": "twin", "readings": [{"metric": "cpu_pct", "value": 4}]},
                  {"id": "5", "name": "nobody", "readings": [{"metric": "cpu_pct", "value": 5}]})
    s = apply_metrics(conn, "prometheus", out)
    assert s["hosts"] == 5 and s["matched"] == 3 and s["unmatched"] == 2
    rows = {r["device_id"]: r for r in conn.execute("SELECT * FROM host_monitors")}
    assert set(rows) == {1, 2, 3} and all(r["method"] == "plugin" and r["source"] == "prometheus" and r["last_ok"] == 1 for r in rows.values())
    store = tsdb.for_conn(conn)
    assert store.latest("device", 1, "cpu_pct")[1] == 1 and store.latest("device", 2, "cpu_pct")[1] == 2 and store.latest("device", 3, "cpu_pct")[1] == 3
    assert store.latest("device", 4, "cpu_pct") is None and store.latest("device", 5, "cpu_pct") is None        # "twin" is two devices: not guessed


def test_the_history_fills_the_graph_and_a_repeated_window_does_no_harm(conn):
    samples = [[1790000000 + 60 * i, 10.0 + i] for i in range(10)]
    out = data_of({"id": "1", "ip": "10.0.0.1", "readings": [{"metric": "cpu_pct", "value": 19.0, "samples": samples}]})
    first = apply_metrics(conn, "prometheus", out)
    assert first["samples"] >= 10
    store = tsdb.for_conn(conn)
    again = apply_metrics(conn, "prometheus", out)
    assert again["matched"] == 1
    raw = connect_raw(conn)
    assert raw.execute("SELECT COUNT(*) FROM raw r JOIN series s ON s.id = r.series WHERE s.metric = 'cpu_pct' AND r.ts BETWEEN 1790000000 AND 1790000540").fetchone()[0] == 10


def connect_raw(conn):
    import sqlite3
    store = tsdb.for_conn(conn)
    c = sqlite3.connect(store.path)
    c.row_factory = sqlite3.Row
    return c


def test_a_device_monitored_another_way_is_left_alone(conn):
    hm.save_monitor(conn, 3, {"method": "snmp", "address": "10.0.0.3", "community": "public"})
    conn.execute("INSERT INTO host_monitors (device_id, method, address, port, credential, interval_s, groups, alerts, enabled, created, source) VALUES (1,'agent','',0,'',60,'[]',1,1,?,'agent:7')", (NOW,))
    conn.execute("INSERT INTO host_monitors (device_id, method, address, port, credential, interval_s, groups, alerts, enabled, created, source) VALUES (2,'plugin','',0,'',900,'[]',1,1,?,'mikrotik')", (NOW,))
    conn.commit()
    out = data_of(*({"id": str(i), "ip": f"10.0.0.{i}", "readings": [{"metric": "cpu_pct", "value": 9}]} for i in (1, 2, 3)))
    s = apply_metrics(conn, "prometheus", out)
    assert s["skipped"] == 3 and s["matched"] == 0
    assert tsdb.for_conn(conn).latest("device", 1, "cpu_pct") is None
    assert conn.execute("SELECT method FROM host_monitors WHERE device_id = 3").fetchone()[0] == "snmp"


def test_the_usual_limits_and_alerts_apply(conn):
    for i in range(6):
        apply_metrics(conn, "prometheus", data_of({"id": "1", "ip": "10.0.0.1", "readings": [{"metric": "disk_pct", "label": "/", "value": 97}]}))
    kinds = [r["kind"] for r in conn.execute("SELECT kind FROM events")]
    assert "metric_critical" in kinds or "metric_warning" in kinds
    assert any(p["device_id"] == 1 and p["metric"] == "disk_pct" for p in hm.problems(conn))


def test_the_monitors_page_shows_the_plugin_as_the_source(conn):
    apply_metrics(conn, "prometheus", data_of({"id": "1", "ip": "10.0.0.1", "readings": [{"metric": "cpu_pct", "value": 1}]}))
    row = conn.execute("SELECT * FROM host_monitors WHERE device_id = 1").fetchone()
    assert hm.public(conn, row)["source"] == "prometheus" and row["method"] == "plugin"


@pytest.mark.asyncio
async def test_a_metrics_plugin_runs_through_the_plugin_service_end_to_end(tmp_path):
    from app.db import get_or_create_device
    from app.plugins.registry import discover
    from app.plugins.service import PluginService, get_status, merge_config, save_state
    from tests.plugin_helpers import fake, make_runner, write_plugin

    tsdb.forget_all()
    path = tmp_path / "s.db"
    c = connect(path)
    init_db(c)
    dev = get_or_create_device(c, "aa:00:00:00:00:09", "10.0.0.9")
    c.close()
    write_plugin(tmp_path, "prom", kind="metrics", manifest={"config": [{"key": "host", "type": "text", "label": "Host"}]})
    c = connect(path)
    save_state(c, "prom", True, merge_config(discover(tmp_path)["prom"], {}, {"host": "x"}))
    c.close()
    out = {"hosts": [{"id": "n:9100", "name": "n", "ip": "10.0.0.9", "readings": [{"metric": "mem_pct", "value": 42.0, "samples": [[1790000000, 40.0], [1790000060, 42.0]]},
                                                                               {"metric": "net_rx_bps", "label": "eth0", "value": 123.0}]}]}
    svc = PluginService(str(path), tmp_path, make_runner(prom=fake(fetch=lambda cfg: out)))
    result = await svc.sync("prom")
    assert result == {"hosts": 1, "matched": 1, "readings": 2, "samples": 4, "skipped": 0, "unmatched": 0}
    c = connect(path)
    assert get_status(c, "prom")["ok"] is True
    store = tsdb.for_conn(c)
    assert store.latest("device", dev, "mem_pct")[1] == 42.0 and store.latest("device", dev, "net_rx_bps", "eth0")[1] == 123.0
    c.close()
    tsdb.forget_all()
