from app import ipv4health as h

ADDR = """\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: eth0    inet 192.168.1.5/24 brd 192.168.1.255 scope global dynamic eth0\\       valid_lft 80000sec preferred_lft 80000sec
3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever preferred_lft forever
"""
ROUTE = "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.5 metric 100\n"


def dev(i, name, ip, mac, online=True):
    return {"id": i, "name": name, "ip": ip, "mac": mac, "online": online}


def server(ip="192.168.1.1", trusted=True, router="192.168.1.1", **kw):
    return {"ip": ip, "trusted": trusted, "router": router, "dns": ["192.168.1.1"], "name": kw.get("name")}


def raw(**over):
    base = {"addresses": h.parse_addresses(ADDR), "defaults": h.parse_default_routes(ROUTE), "nameservers": ["192.168.1.1"], "internet": {"ok": True, "target": "1.1.1.1", "ms": 9.0},
            "dns": {"ok": True, "name": "example.com", "answer": "93.184.216.34"}, "gateway_up": True}
    base.update(over)
    return base


def facts(**over):
    base = {"devices": [dev(1, "router", "192.168.1.1", "aa:00:00:00:00:01"), dev(2, "nas", "192.168.1.20", "aa:00:00:00:00:02")], "ranges": ["192.168.1.0/24"],
            "dhcp": [server(name="router")], "dhcp_last": {"ok": True}, "gateway": None, "events": {}, "reused_addresses": 0}
    base.update(over)
    return base


def titles(res):
    return {f["title"]: f["level"] for f in res["findings"]}


def test_parsers():
    assert [(a["iface"], a["addr"], a["network"]) for a in h.parse_addresses(ADDR)] == [("eth0", "192.168.1.5", "192.168.1.0/24")]
    assert h.parse_default_routes(ROUTE) == [{"via": "192.168.1.1", "dev": "eth0", "metric": "100"}]
    assert h.parse_resolv("# x\nnameserver 192.168.1.1\nnameserver 2001:4860:4860::8888\nsearch lan\nnameserver bogus\n") == ["192.168.1.1", "2001:4860:4860::8888"]
    assert h.parse_addresses("2: eth0 inet 169.254.3.4/16 scope link eth0")[0]["selfassigned"] is True


def test_a_healthy_network():
    res = h.analyse(raw(), facts())
    t = titles(res)
    assert res["verdict"] == "good" and t["The gateway answers"] == "good" and t["The internet works over IPv4"] == "good" and t["Names resolve"] == "good"
    assert t["One DHCP server hands out addresses"] == "good" and "router" in res["findings"][0]["text"]            # the gateway is named
    assert res["subnets"] == [{"range": "192.168.1.0/24", "online": 2, "known": 2, "size": 254, "usage": 1, "attached": True}]


def test_problems():
    clash = [dev(1, "router", "192.168.1.1", "aa:00:00:00:00:01"), dev(2, "nas", "192.168.1.20", "aa:00:00:00:00:02"), dev(3, "printer", "192.168.1.20", "aa:00:00:00:00:03"), dev(4, "pc", "169.254.8.8", "aa:00:00:00:00:04")]
    res = h.analyse(raw(gateway_up=False, dns={"ok": False, "name": "example.com"}), facts(devices=clash, dhcp=[server(), server("192.168.1.99", trusted=False, name="vm")], events={"gateway_changed": 2}, reused_addresses=7))
    t = titles(res)
    assert res["verdict"] == "bad" and t["The gateway does not answer"] == "bad" and t["Two devices use the same IP address"] == "bad" and t["A DHCP server you have not approved answers"] == "bad"
    assert t["Names do not resolve"] == "bad" and t["The device behind the gateway address changed"] == "warn" and t["Addresses keep moving between devices"] == "warn"
    assert t["1 device gave themselves a 169.254 address"] == "warn"


def test_no_gateway_no_address_and_full_ranges():
    t = titles(h.analyse(raw(defaults=[]), facts()))
    assert t["There is no default gateway"] == "bad"
    assert titles(h.analyse(raw(addresses=[]), facts()))["This computer has no IPv4 address"] == "bad"
    assert titles(h.analyse(raw(addresses=h.parse_addresses("2: eth0 inet 169.254.1.1/16 scope link eth0")), facts()))["This computer gave itself a 169.254 address"] == "bad"
    crowd = [dev(i, f"d{i}", f"10.0.0.{i}", f"aa:00:00:00:{i // 256:02x}:{i % 256:02x}") for i in range(1, 246)]
    full = h.analyse(raw(), facts(devices=crowd, ranges=["10.0.0.0/24"]))
    assert titles(full)["10.0.0.0/24 is nearly full"] == "bad" and titles(full)["10.0.0.0/24 is not directly connected to this computer"] == "info"
    assert titles(h.analyse(raw(), facts(devices=crowd[:210], ranges=["10.0.0.0/24"])))["10.0.0.0/24 is filling up"] == "warn"


def test_dhcp_variants_and_outside_ranges():
    t = titles(h.analyse(raw(), facts(dhcp=[server(), server("192.168.1.2")])))
    assert t["2 DHCP servers answer"] == "warn"
    assert titles(h.analyse(raw(), facts(dhcp=[server(router="192.168.1.254")])))["DHCP offers another gateway than this computer uses"] == "warn"
    assert titles(h.analyse(raw(), facts(dhcp=[], dhcp_last=None)))["No DHCP check yet"] == "info"
    assert titles(h.analyse(raw(), facts(dhcp=[])))["No DHCP server answered"] == "info"
    far = facts(devices=[dev(1, "router", "192.168.1.1", "aa:00:00:00:00:01"), dev(9, "far", "10.9.9.9", "aa:00:00:00:00:09")])
    assert titles(h.analyse(raw(), far))["1 online device outside the scanned ranges"] == "info"
    two = titles(h.analyse(raw(), facts(ranges=["192.168.1.0/24", "192.168.2.0/24"])))
    assert two["2 subnets are scanned"] == "info"


def test_the_api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app.config import load_settings
    from app.db import connect, init_db
    from app.main import create_app

    async def fake_collect(ip_path="ip"):
        return raw()

    monkeypatch.setattr(h, "collect", fake_collect)
    path = tmp_path / "t.db"
    c = connect(path)
    init_db(c)
    c.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.1.0/24"}), db_path=path)
    with TestClient(app, headers={"Authorization": "Bearer secret"}) as client:
        assert client.get("/api/ipv4/health").json() == {"result": None}
        res = client.post("/api/ipv4/health/run").json()["result"]
        assert res["findings"] and res["ts"] and res["subnets"][0]["range"] == "192.168.1.0/24"
        assert client.get("/api/ipv4/health").json()["result"]["headline"] == res["headline"]
        assert TestClient(app).get("/api/ipv4/health").status_code == 401
