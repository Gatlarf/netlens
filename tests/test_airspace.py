"""The air around access points (channels, neighbours, advice), the internet connections of a gateway, and the traffic worked out from client byte counters."""
import pytest

from app import airspace, tsdb, uplinks
from app.db import connect, init_db
from app.plugins import enrich
from app.plugins.contract import ContractError, validate_output

AP = "aa:00:00:00:00:10"
GW = "aa:00:00:00:00:20"
PHONE = "02:11:22:33:44:55"


@pytest.fixture
def conn(tmp_path):
    tsdb.forget_all()
    c = connect(tmp_path / "netlens.db")
    init_db(c)
    for i, (ip, mac, name) in enumerate(((("10.0.0.2", AP, "Hall AP"), ("10.0.0.1", GW, "Gateway"), ("10.0.0.50", PHONE, "phone"))), 1):
        c.execute("INSERT INTO devices (id, primary_ip, mac, hostname, online, first_seen, last_seen) VALUES (?, ?, ?, ?, 1, '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z')", (i, ip, mac, name))
    c.commit()
    yield c
    c.close()
    tsdb.forget_all()


def radio(channel=6, band="2.4 GHz", **kw):
    return {"name": f"wifi-{band}", "band": band, "channel": channel, "width_mhz": 20, "clients": 4, "utilization_pct": 30, **kw}


def neighbour(n, channel, signal=-60, band="2.4 GHz", ssid=None, width=None):
    return {"bssid": f"de:ad:be:ef:00:{n:02x}", "ssid": ssid or f"net{n}", "band": band, "channel": channel, "signal_dbm": signal, "width_mhz": width}


def topo(wifi=None, uplinks_=None, clients=()):
    return validate_output("topology", {"nodes": [{"mac": AP, "ip": "10.0.0.2", "name": "Hall AP", "role": "ap", **({"wifi": wifi} if wifi else {})},
                                                  {"mac": GW, "ip": "10.0.0.1", "name": "Gateway", "role": "gateway", **({"uplinks": uplinks_} if uplinks_ else {})}], "clients": list(clients)})


def test_the_contract_checks_radios_neighbours_and_connections():
    out = topo({"radios": [radio(), radio(6)], "neighbours": [neighbour(1, 6), neighbour(1, 11)]})            # a radio name and a BSSID count once
    wifi = out["nodes"][0]["wifi"]
    assert len(wifi["radios"]) == 1 and len(wifi["neighbours"]) == 1 and wifi["scanned"]
    assert "wifi" not in topo({"radios": [], "neighbours": []})["nodes"][0]
    with pytest.raises(ContractError):
        topo(uplinks_={"mode": "magic", "connections": [{"name": "WAN"}]})
    with pytest.raises(ContractError):
        topo(uplinks_={"mode": "failover", "connections": [{"name": "WAN", "up": "yes"}]})
    assert topo(uplinks_={"mode": None, "connections": []})["nodes"][1].get("uplinks") is None


def test_a_crowded_channel_is_told_with_a_quieter_one(conn):
    crowd = [neighbour(i, 6, -55 - i) for i in range(1, 6)] + [neighbour(9, 1, -85)]
    airspace.record(conn, "openwrt", topo({"radios": [radio(6)], "neighbours": crowd}), "2026-11-16T10:00:00Z")
    info = airspace.for_device(conn, 1)
    r = info["radios"][0]
    assert r["advice"]["networks"] == 5 + 0 or r["advice"]["networks"] >= 5                      # the five on channel 6 (the faint one on 1 does not overlap it much)
    assert r["advice"]["suggest"]["channel"] == 11 and r["neighbours"] == 5
    lines = airspace.attention(conn)
    assert len(lines) == 1 and "channel 11" in lines[0]["text"] and lines[0]["href"] == "#/device/1/network/wifichannels"


def test_a_quiet_channel_and_our_own_access_points_raise_nothing(conn):
    airspace.record(conn, "openwrt", topo({"radios": [radio(6)], "neighbours": [neighbour(1, 1, -80)]}), "2026-11-16T10:00:00Z")
    assert airspace.attention(conn) == [] and airspace.for_device(conn, 1)["radios"][0]["advice"]["suggest"] is None
    own = {"bssid": GW, "ssid": "mine", "band": "2.4 GHz", "channel": 6, "signal_dbm": -30, "width_mhz": None}
    airspace.record(conn, "openwrt", topo({"radios": [radio(6)], "neighbours": [own]}), "2026-11-16T10:30:00Z")
    assert airspace.for_device(conn, 1)["radios"][0]["advice"]["networks"] == 0                    # a device Netlens knows is not a neighbour


def test_5_ghz_channels_overlap_by_width_and_a_busy_radio_is_told(conn):
    wide = radio(36, "5 GHz", width_mhz=80, utilization_pct=91)
    airspace.record(conn, "unifi", topo({"radios": [wide], "neighbours": [neighbour(1, 48, -50, "5 GHz", width=20), neighbour(2, 52, -50, "5 GHz", width=20)]}), "2026-11-16T10:00:00Z")
    r = airspace.for_device(conn, 1)["radios"][0]
    assert r["advice"]["networks"] == 1                                    # 36 at 80 MHz covers 36-48: the neighbour on 48 overlaps, the one on 52 does not
    assert [l["level"] for l in airspace.attention(conn)] == ["warn"] and "91%" in airspace.attention(conn)[0]["text"]


def test_neighbours_are_kept_between_syncs_that_do_not_scan_and_forgotten_after_a_week(conn):
    airspace.record(conn, "openwrt", topo({"radios": [radio()], "neighbours": [neighbour(1, 6)]}), "2026-11-10T10:00:00Z")
    airspace.record(conn, "openwrt", topo({"radios": [radio(11)], "neighbours": [], "scanned": False}), "2026-11-10T10:10:00Z")        # no scan this time
    info = airspace.for_device(conn, 1)
    assert len(info["neighbours"]) == 1 and info["radios"][0]["channel"] == 11
    assert not airspace.scan_due(conn, "openwrt", now="2026-11-10T10:20:00Z") and airspace.scan_due(conn, "openwrt", now="2026-11-10T11:00:00Z")
    airspace.record(conn, "openwrt", topo({"radios": [radio(11)], "neighbours": [], "scanned": False}), "2026-11-18T10:00:00Z")
    assert airspace.for_device(conn, 1)["neighbours"] == []


def test_connections_events_and_attention(conn):
    both = {"mode": "failover", "connections": [{"name": "WAN", "up": True, "active": True, "priority": 1}, {"name": "WAN 2", "up": True, "active": False, "priority": 2}]}
    uplinks.record(conn, "unifi", topo(uplinks_=both), "2026-11-16T10:00:00Z")
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0 and uplinks.attention(conn) == []        # the first sync tells nothing
    failed = {"mode": "failover", "connections": [{"name": "WAN", "up": False, "active": False, "priority": 1}, {"name": "WAN 2", "up": True, "active": True, "priority": 2}]}
    uplinks.record(conn, "unifi", topo(uplinks_=failed), "2026-11-16T10:05:00Z")
    kinds = [(r["kind"], r["detail"]) for r in conn.execute("SELECT kind, detail FROM events ORDER BY id")]
    assert kinds == [("uplink_down", "Gateway: WAN went down"), ("uplink_failover", "Gateway: the traffic moved from WAN to WAN 2")]
    lines = uplinks.attention(conn)
    assert len(lines) == 1 and lines[0]["level"] == "warn" and "WAN is down" in lines[0]["text"] and "1 of 2 still up" in lines[0]["text"] and lines[0]["href"] == "#/device/2/network/uplinks"
    uplinks.record(conn, "unifi", topo(uplinks_=failed), "2026-11-16T10:10:00Z")
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 2                                        # nothing changed: nothing new
    uplinks.record(conn, "unifi", topo(uplinks_=both), "2026-11-16T10:15:00Z")
    assert [r["kind"] for r in conn.execute("SELECT kind FROM events ORDER BY id")][2:] == ["uplink_up", "uplink_failover"]
    info = uplinks.for_device(conn, 2)
    assert info["mode"] == "failover" and [c["name"] for c in info["connections"]] == ["WAN", "WAN 2"] and info["connections"][0]["active"] is True


def test_traffic_per_day_is_the_growth_of_the_counters(conn):
    def sync(rx, tx, when):
        out = topo(clients=[{"mac": PHONE, "ip": "10.0.0.50", "node_mac": AP, "medium": "wifi", "rx_bytes": rx, "tx_bytes": tx}])
        return enrich.record_client_counters(conn, "openwrt", out, when)

    assert sync(1000, 100, "2026-11-16T10:00:00Z") == 0                          # the first sight only stores the counters
    assert sync(1600, 160, "2026-11-16T10:15:00Z") == 1
    assert sync(1900, 200, "2026-11-16T10:30:00Z") == 1
    row = conn.execute("SELECT rx_bytes, tx_bytes FROM client_usage WHERE device_id = 3 AND day = '2026-11-16'").fetchone()
    assert tuple(row) == (900, 100)
    assert sync(50, 10, "2026-11-16T11:00:00Z") == 1                             # the device re-joined: the counter started again
    assert tuple(conn.execute("SELECT rx_bytes, tx_bytes FROM client_usage WHERE device_id = 3").fetchone()) == (950, 110)
    assert sync(80, 20, "2026-11-17T00:10:00Z") == 1
    assert [tuple(r) for r in conn.execute("SELECT day, rx_bytes FROM client_usage WHERE device_id = 3 ORDER BY day")] == [("2026-11-16", 950), ("2026-11-17", 30)]


def test_an_unknown_device_and_a_client_without_counters_are_left_out(conn):
    out = topo(clients=[{"mac": "02:00:00:00:00:99", "ip": "10.9.9.9", "node_mac": AP, "medium": "wifi", "rx_bytes": 5, "tx_bytes": 5}, {"mac": PHONE, "ip": "10.0.0.50", "node_mac": AP, "medium": "wifi"}])
    assert enrich.record_client_counters(conn, "openwrt", out, "2026-11-16T10:00:00Z") == 0
    assert conn.execute("SELECT COUNT(*) FROM client_counters").fetchone()[0] == 0


def test_ask_answers_about_channels_and_internet_connections(conn):
    from app import ask, ask_more

    both = {"mode": "failover", "connections": [{"name": "WAN", "interface": "wan1", "up": True, "active": True, "priority": 1}, {"name": "WAN2", "interface": "wan2", "up": True, "active": False, "priority": 2}]}
    failed = {"mode": "failover", "connections": [{**both["connections"][0], "up": False, "active": False}, {**both["connections"][1], "active": True}]}
    uplinks.record(conn, "unifi", topo(uplinks_=both), "2026-11-16T10:00:00Z")
    uplinks.record(conn, "unifi", topo(uplinks_=failed), "2026-11-16T10:05:00Z")
    airspace.record(conn, "unifi", topo({"radios": [radio(6)], "neighbours": [neighbour(i, 6) for i in range(1, 5)] + [neighbour(9, 11, -80)], "scanned": True}), "2026-11-16T10:00:00Z")
    air, up = ask_more.t_airspace(conn, {}), ask_more.t_uplinks(conn, {})
    assert air["access_points"][0]["access_point"] == "Hall AP" and air["access_points"][0]["radios"][0]["other_networks_on_this_channel"] == 4
    assert up["gateways"][0]["connections"][0]["up"] is False and "WAN is down" in up["problems"][0]
    assert "Hall AP" in ask_more.r_airspace(air) and "WAN DOWN" in ask_more.r_uplinks(up)
    assert ask.route("is my wifi channel crowded?", ["Hall AP"], conn)[0] == "airspace"
    assert ask.route("is the second internet connection up?", ["Hall AP"], conn)[0] == "uplinks"
    assert ask.route("which devices have a weak wifi signal", ["Hall AP"], conn)[0] == "wifi"
