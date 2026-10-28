"""The open-ended questions of "Ask your network": any stored reading, lists of devices sorted and filtered, what the host probes found on every host, traffic
per device, the network checks, the list of questions nobody could answer, and the model's second try."""

import json
import time

import pytest
from fastapi.testclient import TestClient

from app import ask, asklog, ask_data, tsdb
from app.hostprobe import parsers, service
from tests.test_ask_more import NOW, conn  # noqa: F401 - the same small network

T = int(NOW.timestamp())


def record(conn, did, metric, points, label="", unit=""):
    for age, v in points:
        tsdb.for_conn(conn).record([("device", did, metric, v, label, unit)], ts=T - age)


def test_any_reading_is_ranked_and_one_device_has_a_history(conn):
    record(conn, 7, "temp_c", [(3600, 40.0), (1800, 55.0), (60, 71.0)], unit="°C")
    record(conn, 1, "temp_c", [(60, 48.0)], unit="°C")
    top = ask.TOOLS["metric"][0](conn, {"metric": "how hot is it", "days": 1}, NOW)
    assert top["metric"] == "temp_c" and [v["device"] for v in top["values"]] == ["sw-garden", "nas"] and top["values"][0]["latest"] == 71.0
    assert top["values"][0]["period"]["max"] == 71.0 and top["values"][0]["period"]["min"] == 40.0
    assert ask.TOOLS["metric"][0](conn, {"metric": "temperature", "device": "garden", "order": "lowest"}, NOW)["values"][0]["device"] == "sw-garden"
    assert "sw-garden" in ask.render("metric", top)
    assert ask.TOOLS["metric"][0](conn, {"metric": "temperature", "device": "nobody"}, NOW)["error"]
    menu = ask.TOOLS["metric"][0](conn, {}, NOW)                                                      # no metric named: say what exists
    assert menu["metric"] is None and any(a["metric"] == "temp_c" and a["devices"] == 2 for a in menu["available"])


def test_a_drop_of_the_uptime_counter_is_a_reboot(conn):
    record(conn, 1, "uptime_s", [(20000, 500000.0), (15000, 505000.0), (10000, 600.0), (5000, 5600.0), (60, 10500.0)], unit="s")
    record(conn, 7, "uptime_s", [(20000, 100000.0), (10000, 110000.0), (60, 120000.0)], unit="s")
    got = ask.TOOLS["metric"][0](conn, {"metric": "uptime", "days": 1}, NOW)
    assert [r["device"] for r in got["rebooted"]] == ["nas"] and got["rebooted"][0]["reboots"] == 1
    assert "nas rebooted 1x" in ask.render("metric", got)
    assert "None of the" in ask.render("metric", ask.TOOLS["metric"][0](conn, {"metric": "reboot", "device": "garden"}, NOW))


def test_stale_readings_are_not_current(conn):
    record(conn, 1, "swap_pct", [(10 * 86400, 80.0)])
    assert ask.TOOLS["metric"][0](conn, {"metric": "swap"}, NOW)["values"] == []


def test_device_lists_sort_filter_and_page(conn):
    conn.execute("UPDATE devices SET first_seen = '2026-01-01T00:00:00Z', last_seen = '2026-02-01T00:00:00Z', online = 0 WHERE id = 2")
    conn.execute("UPDATE devices SET hostname = NULL WHERE id = 4")
    conn.commit()
    find = ask.TOOLS["search_devices"][0]
    old = find(conn, {"sort": "oldest", "limit": 2}, NOW)
    assert old["devices"][0]["name"] == "hp-laserjet" and old["devices"][0]["first_seen"].startswith("2026-01") and len(old["devices"]) == 2 and old["count"] == 7
    assert [d["name"] for d in find(conn, {"not_seen_days": 60}, NOW)["devices"]] == ["hp-laserjet"]
    assert find(conn, {"missing": "hostname"}, NOW)["count"] == 1
    page2 = find(conn, {"sort": "name", "limit": 3, "offset": 3}, NOW)
    assert page2["shown"] == "4-6" and len(page2["devices"]) == 3
    assert find(conn, {"limit": "x", "offset": "-5", "not_seen_days": "soon"}, NOW)["count"] == 7          # nonsense arguments are ignored, never an error


def test_the_findings_of_every_host_with_probes(conn):
    nic = {"name": "eth0", "rx_bps": 0, "tx_bps": 0, "rx_pkts": 0, "tx_pkts": 0, "rx_err": 0, "tx_err": 0, "rx_drop": 0, "tx_drop": 0, "rx_err_total": 900, "tx_err_total": 0,
           "rx_drop_total": 0, "tx_drop_total": 0, "rx_pkts_total": 100000, "tx_pkts_total": 100000}
    service.save_settings(conn, {"devices": {"1": {"enabled": True}, "6": {"enabled": True}}})
    service.store(conn, 1, True, "locked", None, {"platform": "linux", "interfaces": [nic], "tcp": {}, "states": {}, "remote": [], "processes": [], "listening": [], "ping": [], "dns": []}, now=time.time() - 60, probe="network")
    got = ask.TOOLS["host_findings"][0](conn, {"topic": "errors on the network interface"}, None)
    assert got["hosts_looked_at"] == 1 and got["no_probe_data_yet"] == ["desktop-1"] and any("eth0" in f["text"] and f["device"] == "nas" for f in got["findings"])
    assert "nas" in ask.render("host_findings", got)
    assert ask.TOOLS["host_findings"][0](conn, {"topic": "zzzz"}, None)["findings"] == []


def test_traffic_per_device_and_the_network_checks(conn):
    assert ask.TOOLS["usage"][0](conn, {"days": 7}, NOW)["available"] is False and "No plugin" in ask.render("usage", ask.TOOLS["usage"][0](conn, {}, NOW))
    assert ask.TOOLS["network_health"][0](conn, {}, NOW)["ipv4"] == {"checked": False}
    from app import ipv4health
    from app.db import set_setting

    set_setting(conn, ipv4health.KEY, json.dumps({"verdict": "warn", "headline": "IPv4 needs a look", "ts": "2026-11-01T11:30:00Z", "findings": [{"level": "warn", "key": "k", "title": "The range is nearly full", "text": "x"}],
                                                  "subnets": [{"range": "192.168.1.0/24", "online": 5, "known": 200, "size": 254, "usage": 79, "attached": True}]}))
    got = ask.TOOLS["network_health"][0](conn, {}, NOW)
    assert got["ipv4"]["ranges"][0]["roughly_free"] == 54 and "54 of 254 addresses free" in ask.render("network_health", got)


@pytest.mark.parametrize("q,tool", [("Which devices rebooted last week?", "metric"), ("what is the uptime of the nas", "metric"), ("how hot is my switch", "metric"), ("Which IP addresses are free in my network?", "network_health"),
                                    ("How full is my DHCP range?", "network_health"), ("Which devices use the most bandwidth?", "usage"), ("who is using the bandwidth", "usage")])
def test_the_words_that_pick_the_new_questions(conn, q, tool):
    names = [r["hostname"] for r in conn.execute("SELECT hostname FROM devices")]
    assert ask.route(q, names, conn)[0] == tool, q
    assert ask.route("which devices were offline over the last 7 days", names, conn)[0] != "metric"


def test_questions_without_an_answer_are_kept_once_and_can_be_switched_off(conn):
    a = ask.answer(conn, "Xyzzy plugh the sky colour?", NOW, mode="rules")
    ask.answer(conn, "xyzzy plugh the sky colour?", NOW, mode="rules")
    assert a["understood"] is False
    got = asklog.items(conn)
    assert len(got) == 1 and got[0]["n"] == 2 and got[0]["q"].startswith("Xyzzy") and set(got[0]) == {"q", "n", "first", "last", "tools", "source"}      # nothing about who asked or what was said
    ask.answer(conn, "how many devices are online?", NOW, mode="rules")                       # an answered question is not kept
    assert len(asklog.items(conn)) == 1
    asklog.set_enabled(conn, False)
    ask.answer(conn, "something else nobody can answer", NOW, mode="rules")
    assert len(asklog.items(conn)) == 1
    assert asklog.clear(conn) == 1 and asklog.items(conn) == []
    assert asklog.is_miss({"answer": "The data does not tell.", "tools": ["x"]}) and not asklog.is_miss({"answer": "3 devices are online.", "tools": ["overview"]})


def test_a_model_that_gives_up_is_shown_the_tools_it_has_not_tried(conn):
    seen = []

    def model(messages):
        seen.append(messages[-1]["content"])
        if len(seen) == 1:
            return json.dumps({"tool": "overview", "args": {}})
        if len(seen) == 2:
            return json.dumps({"answer": "The data does not tell."})
        if len(seen) == 3:
            assert "You have not tried:" in messages[-1]["content"] and "metric" in messages[-1]["content"]
            return json.dumps({"tool": "metric", "args": {"metric": "temperature"}})
        return json.dumps({"answer": "No device reports a temperature."})

    a = ask.answer(conn, "Which switch is running hot?", NOW, ask=model)
    assert a["source"] == "model" and a["tools"] == ["overview", "metric"] and a["answer"].startswith("No device")
    gives_up = ask.answer(conn, "Which switch is running hot?", NOW, ask=lambda m: json.dumps({"answer": "The data does not tell."}) if len(m) > 3 else json.dumps({"tool": "overview", "args": {}}))
    assert "does not tell" in gives_up["answer"] and len(asklog.items(conn)) >= 1                # it may give up in the end, after one more chance; the question is kept
    assert ask.untried_tools("which switch is hot", ["metric"])[:1] != ["metric"]
    assert ask.suggest("which devices use the most traffic")[:1] == ["Which devices and applications use the most traffic?"]


def test_the_list_of_questions_is_for_administrators(tmp_path, monkeypatch):
    import app.main as main
    from app.config import load_settings

    monkeypatch.setenv("NETLENS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NETLENS_TOKEN", "t" * 32)
    app = main.create_app(load_settings(), scheduler=False)
    with TestClient(app) as c:
        h = {"Authorization": "Bearer " + "t" * 32}
        assert c.get("/api/insights/ask/misses", headers=h).json() == {"enabled": True, "items": []}
        assert c.put("/api/insights/ask/misses", headers=h, json={"enabled": False}).json() == {"enabled": False}
        assert c.delete("/api/insights/ask/misses", headers=h).json() == {"removed": 0}
        assert c.get("/api/insights/ask/misses").status_code == 401


def test_readings_that_flip_between_two_values_are_not_reboots(conn):
    """Two collectors, or a blip, can make the counter jump back and forth; a reboot is a new start time that stays."""
    record(conn, 1, "uptime_s", [(age, 1_000_000.0 - age + (0 if i % 2 else 90_000)) for i, age in enumerate(range(20000, 0, -1000))], unit="s")
    assert ask.TOOLS["metric"][0](conn, {"metric": "uptime", "days": 1}, NOW)["rebooted"] == []
