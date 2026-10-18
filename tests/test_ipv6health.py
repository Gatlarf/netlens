import asyncio

from app import ipv6health as h

ADDR = """\
1: lo    inet6 ::1/128 scope host \\       valid_lft forever preferred_lft forever
2: eth0    inet6 2a02:1810:1:ab00:1234:56ff:fe78:9abc/64 scope global dynamic mngtmpaddr noprefixroute \\       valid_lft 7199sec preferred_lft 3599sec
2: eth0    inet6 2a02:1810:1:ab00:aaaa:bbbb:cccc:dddd/64 scope global temporary dynamic \\       valid_lft 7199sec preferred_lft 3599sec
2: eth0    inet6 fd12:3456:789a:1::5/64 scope global dadfailed tentative \\       valid_lft forever preferred_lft forever
2: eth0    inet6 fe80::1234:56ff:fe78:9abc/64 scope link \\       valid_lft forever preferred_lft forever
3: docker0    inet6 fd00:dead::1/64 scope global \\       valid_lft forever preferred_lft forever
"""
ROUTES = """\
2a02:1810:1:ab00::/64 dev eth0 proto ra metric 256 expires 7000sec pref medium
fd12:3456:789a:1::/64 dev eth0 proto kernel metric 256 pref medium
fe80::/64 dev eth0 proto kernel metric 256 pref medium
default via fe80::1 dev eth0 proto ra metric 1024 expires 1790sec pref medium
"""
NEIGH = """\
fe80::1 dev eth0 lladdr aa:bb:cc:00:00:01 router REACHABLE
fe80::77 dev eth0 lladdr aa:bb:cc:00:00:77 router STALE
2a02:1810:1:ab00::50 dev eth0 lladdr aa:bb:cc:00:00:50 STALE
fe80::99 dev eth0  FAILED
"""


def raw(**over):
    base = {"addresses": h.parse_addresses(ADDR), "routes": h.parse_routes(ROUTES), "routers": h.parse_routers(NEIGH),
            "internet": {"ok": True, "target": "2606:4700:4700::1111", "ms": 12.0}, "dns": {"ok": True, "name": "ipv6.google.com", "answer": "2a00::1"}}
    base.update(over)
    return base


def device(i, name, mac, addresses=(), online=True):
    return {"id": i, "name": name, "mac": mac, "online": online, "addresses": [{"ip": a, "scope": "global" if not a.startswith("fd") else "ula"} for a in addresses]}


def titles(result):
    return {f["title"]: f["level"] for f in result["findings"]}


def test_parsers():
    addrs = h.parse_addresses(ADDR)
    assert [a["addr"] for a in addrs] == ["2a02:1810:1:ab00:1234:56ff:fe78:9abc", "2a02:1810:1:ab00:aaaa:bbbb:cccc:dddd", "fd12:3456:789a:1::5", "fe80::1234:56ff:fe78:9abc"]    # no lo, no docker0
    assert addrs[1]["temporary"] and addrs[2]["dadfailed"] and addrs[0]["scope"] == "global" and addrs[2]["scope"] == "ula"
    r = h.parse_routes(ROUTES)
    assert r["defaults"] == [{"via": "fe80::1", "dev": "eth0", "proto": "ra", "metric": "1024"}] and [p["prefix"] for p in r["prefixes"]] == ["2a02:1810:1:ab00::/64", "fd12:3456:789a:1::/64"]
    assert [x["mac"] for x in h.parse_routers(NEIGH)] == ["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:77"]
    assert h.prefix64("2a02:1810:1:ab00:1::5") == "2a02:1810:1:ab00::/64"


def test_a_healthy_network_with_one_router():
    facts = {"discovery": True, "devices": [device(1, "router", "aa:bb:cc:00:00:01"), device(2, "nas", "aa:bb:cc:00:00:50", ["2a02:1810:1:ab00::50"]), device(3, "plug", "aa:bb:cc:00:00:60")]}
    res = h.analyse(raw(addresses=[a for a in h.parse_addresses(ADDR) if not a["dadfailed"]], routers=h.parse_routers(NEIGH)[:1]), facts, {"2a02:1810:1:ab00::50"})
    t = titles(res)
    assert res["verdict"] == "good" and t["One router handles IPv6"] == "good" and t["The internet works over IPv6"] == "good"
    assert t["1 of 3 online devices have an IPv6 address"] == "info" and t["Every device with an IPv6 address answers"] == "good"
    assert any("router)" in f["text"] for f in res["findings"] if f["title"] == "One router handles IPv6")                    # the router is named
    assert res["subnets"][0]["prefix"] == "2a02:1810:1:ab00::/64" and res["subnets"][0]["devices"] == 1 and res["subnets"][0]["this_computer"]


def test_problems_are_found():
    facts = {"discovery": True, "devices": [device(2, "nas", "aa:bb:cc:00:00:50", ["2a02:9999:0:1::50"]), device(3, "tv", "aa:bb:cc:00:00:61", ["2a02:1810:1:ab00::61"])]}
    res = h.analyse(raw(routes={"defaults": [{"via": "fe80::1", "dev": "eth0", "proto": "ra", "metric": ""}, {"via": "fe80::77", "dev": "eth0", "proto": "ra", "metric": ""}], "prefixes": []},
                        internet={"ok": False, "target": "x", "ms": None}, dns={"ok": False, "name": "ipv6.google.com"}), facts, set())
    t = titles(res)
    assert res["verdict"] == "bad" and t["Another device uses the same IPv6 address"] == "bad" and t["The internet cannot be reached over IPv6"] == "bad"
    assert t["2 routers offer a way out over IPv6"] == "warn" and t["1 device uses a different prefix than this computer"] == "warn"
    assert t["2 devices did not answer a ping over IPv6"] == "info" and t["Names do not resolve to IPv6 addresses"] == "warn"


def test_no_default_route_and_ipv4_only_networks():
    res = h.analyse(raw(routes={"defaults": [], "prefixes": []}), {"discovery": False, "devices": []})
    assert titles(res)["There is an address but no way out"] == "bad" and titles(res)["Per-device results are off"] == "info"
    only4 = h.analyse({"addresses": [a for a in h.parse_addresses(ADDR) if a["scope"] == "link"], "routes": {"defaults": [], "prefixes": []}, "routers": [], "internet": {"ok": False, "target": "x", "ms": None},
                       "dns": {"ok": False, "name": "x"}}, {"discovery": True, "devices": [device(1, "a", "aa:00:00:00:00:01")]})
    assert only4["verdict"] == "info" and "does not hand out IPv6" in only4["findings"][0]["title"]


def test_private_addresses_only_and_deprecated_prefix():
    ula = [a for a in h.parse_addresses(ADDR) if a["addr"].startswith("fd12")]
    ula[0]["dadfailed"] = False
    res = h.analyse(raw(addresses=ula), {"discovery": False, "devices": []})
    assert titles(res)["Only private (unique-local) addresses"] == "info"
    old = [dict(a, deprecated=True) for a in h.parse_addresses(ADDR) if a["scope"] == "global" and not a["dadfailed"]]
    assert titles(h.analyse(raw(addresses=old), {"discovery": False, "devices": []}))["The internet addresses are expiring"] == "warn"


def test_collect_and_the_api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app.config import load_settings
    from app.db import connect, init_db
    from app.main import create_app

    async def fake_collect(ip_path="ip"):
        return raw()

    async def fake_ping(addresses, nmap_path="nmap", timeout=40.0):
        return set()

    monkeypatch.setattr(h, "collect", fake_collect)
    monkeypatch.setattr(h, "ping_many", fake_ping)
    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret"}), db_path=path)
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as client:
        assert client.get("/api/ipv6/health").json() == {"result": None, "discovery": False}
        res = client.post("/api/ipv6/health/run").json()["result"]
        assert res["findings"] and res["ts"] and client.get("/api/ipv6/health").json()["result"]["headline"] == res["headline"]
        assert TestClient(app).get("/api/ipv6/health").status_code == 401


def test_tcp_probe_reports_failure_quickly():
    assert asyncio.run(h._tcp("::1", 9, timeout=1.0)) is None
