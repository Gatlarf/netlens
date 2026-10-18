import asyncio

import pytest

from app import ipv4health, ipv6health, nethealth
from app.db import connect, init_db
from app.notify import channels as ch


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.db")
    init_db(c)
    yield c
    c.close()


def result(*findings):
    return {"findings": [{"level": lvl, "key": ipv6health.finding_key(title), "title": title, "text": "Explained."} for lvl, title in findings]}


def kinds(conn):
    return [r["kind"] for r in conn.execute("SELECT kind FROM events ORDER BY id")]


def test_finding_keys_ignore_the_numbers():
    assert ipv6health.finding_key("2 routers offer a way out over IPv6") == ipv6health.finding_key("3 routers offer a way out over IPv6")
    assert ipv6health.finding_key("10.0.0.0/24 is nearly full") != ipv6health.finding_key("The gateway does not answer")


def test_a_problem_is_announced_on_the_second_run_only_and_once(conn):
    bad = result(("bad", "The gateway does not answer"), ("good", "The internet works over IPv4"))
    assert nethealth.update(conn, "v4", bad) == [] and kinds(conn) == []            # one blip is not an alert
    assert nethealth.update(conn, "v4", bad) == ["net_critical"]
    assert nethealth.update(conn, "v4", bad) == [] and kinds(conn) == ["net_critical"]    # announced once
    detail = conn.execute("SELECT detail FROM events").fetchone()[0]
    assert detail.startswith("IPv4: The gateway does not answer.")
    assert nethealth.update(conn, "v4", result(("good", "The gateway answers"))) == ["net_ok"]
    assert kinds(conn) == ["net_critical", "net_ok"] and nethealth.attention(conn) == []


def test_a_problem_that_goes_away_before_it_was_announced_is_forgotten_quietly(conn):
    nethealth.update(conn, "v6", result(("warn", "2 routers offer a way out over IPv6")))
    assert nethealth.update(conn, "v6", result()) == [] and kinds(conn) == []


def test_a_warning_that_becomes_a_problem_is_announced_again_and_families_are_separate(conn):
    warn, bad = result(("warn", "10.0.0.0/24 is filling up")), result(("bad", "10.0.0.0/24 is filling up"))
    nethealth.update(conn, "v4", warn)
    assert nethealth.update(conn, "v4", warn) == ["net_warning"]
    assert nethealth.update(conn, "v4", bad) == ["net_critical"]
    nethealth.update(conn, "v6", warn)
    assert kinds(conn) == ["net_warning", "net_critical"]                          # the IPv6 one has run once only
    assert [(i["level"], i["text"]) for i in nethealth.attention(conn)] == [("bad", "IPv4: 10.0.0.0/24 is filling up")]


def test_round_once_runs_both_checks(conn, tmp_path, monkeypatch):
    async def v4(c, ranges, ip_path="ip"):
        return result(("bad", "There is no default gateway"))

    async def v6(c, ip_path="ip"):
        return result(("info", "Per-device results are off"))

    monkeypatch.setattr(ipv4health, "run", v4)
    monkeypatch.setattr(ipv6health, "run", v6)
    path = str(tmp_path / "t.db")
    asyncio.run(nethealth.round_once(path, lambda: ["10.0.0.0/24"]))
    asyncio.run(nethealth.round_once(path, lambda: ["10.0.0.0/24"]))
    assert kinds(connect(path)) == ["net_critical"]


def test_the_kinds_are_known_to_the_channels_and_the_dashboard(conn):
    from app import siem
    from app.dashboard import _network_attention

    assert {"net_critical", "net_warning", "net_ok"} <= set(ch.EVENT_LABELS) and "net_critical" in ch.DEFAULT_EVENTS and "net_warning" not in ch.DEFAULT_EVENTS
    assert siem.severity("net_critical") == 2 and siem.severity("net_warning") == 4 and siem.severity("net_ok") == 6
    assert ch.severity_of("net_critical") == "critical"
    bad = result(("bad", "A DHCP server you have not approved answers"))
    nethealth.update(conn, "v4", bad)
    nethealth.update(conn, "v4", bad)
    assert _network_attention(conn) == [{"level": "bad", "text": "IPv4: A DHCP server you have not approved answers", "href": "#/network-health"}]
