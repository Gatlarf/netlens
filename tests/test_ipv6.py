from app import tsdb
from app.db import connect, init_db
from app.scanner import ipv6

NEIGH = """\
fe80::a00:27ff:fe12:3456 dev eth0 lladdr 08:00:27:12:34:56 router STALE
2001:db8::10 dev eth0 lladdr 08:00:27:12:34:56 REACHABLE
fd00::5 dev eth0 lladdr aa:bb:cc:dd:ee:01 DELAY
fe80::dead dev eth0  FAILED
fe80::beef dev eth0 lladdr 00:00:00:00:00:00x STALE
ff02::1 dev eth0 lladdr 33:33:00:00:00:01 PERMANENT
::1 dev lo lladdr 00:00:00:00:00:00 PERMANENT
garbage
"""


def test_scope_and_parsing():
    assert [ipv6.scope_of(a) for a in ("fe80::1", "fe80::1%eth0", "fd12::1", "2001:db8::1", "ff02::1", "::1", "::", "1.2.3.4", "nope")] == ["link", "link", "ula", "global", None, None, None, None, None]
    entries = ipv6.parse_neigh(NEIGH)
    assert [(e["ip"], e["mac"]) for e in entries] == [("fe80::a00:27ff:fe12:3456", "08:00:27:12:34:56"), ("2001:db8::10", "08:00:27:12:34:56"), ("fd00::5", "aa:bb:cc:dd:ee:01")]
    assert ipv6.parse_interfaces("2: eth0    inet6 fe80::1/64 scope link\n5: veth12  inet6 fe80::2/64 scope link\n3: br-abc inet6 fe80::3/64 scope link\n2: eth0    inet6 fe80::9/64 scope link\n7: lo inet6 ::1/128 scope host") == ["eth0"]


def test_addresses_attach_to_known_devices_only(tmp_path):
    tsdb.forget_all()
    conn = connect(tmp_path / "v6.db")
    init_db(conn)
    conn.execute("INSERT INTO devices (mac, primary_ip, first_seen, last_seen) VALUES ('08:00:27:12:34:56', '192.168.1.5', '2026-10-17T00:00:00Z', '2026-10-17T00:00:00Z')")
    conn.commit()
    did = conn.execute("SELECT id FROM devices").fetchone()["id"]
    result = ipv6.apply(conn, ipv6.parse_neigh(NEIGH), now="2026-10-17T10:00:00Z")
    assert result == {"attached": 2, "unknown": 1}
    got = ipv6.for_device(conn, did)
    assert [(a["scope"], a["ip"]) for a in got] == [("global", "2001:db8::10"), ("link", "fe80::a00:27ff:fe12:3456")]
    # seen again later: the same rows, newer last_seen; old ones are forgotten after 30 days
    ipv6.apply(conn, ipv6.parse_neigh(NEIGH), now="2026-10-18T10:00:00Z")
    assert len(ipv6.for_device(conn, did)) == 2 and ipv6.for_device(conn, did)[0]["first_seen"] == "2026-10-17T10:00:00Z"
    ipv6.apply(conn, [], now="2026-12-30T00:00:00Z")
    assert ipv6.for_device(conn, did) == []
    tsdb.forget_all()


def test_api_and_device_detail(tmp_path):
    from fastapi.testclient import TestClient

    from app.config import load_settings
    from app.main import create_app

    tsdb.forget_all()
    settings = load_settings({"NETLENS_DATA_DIR": str(tmp_path), "NETLENS_TOKEN": "secret", "NETLENS_RANGES": "192.168.250.0/30"})
    with TestClient(create_app(settings)) as client:
        h = {"Authorization": "Bearer secret"}
        assert client.get("/api/ipv6", headers=h).json()["enabled"] is False
        assert client.put("/api/ipv6", json={"enabled": True}, headers=h).json()["enabled"] is True
        conn = connect(tmp_path / "netlens.db")
        conn.execute("INSERT INTO devices (mac, primary_ip, first_seen, last_seen) VALUES ('aa:bb:cc:dd:ee:01', '192.168.1.9', '2026-10-17T00:00:00Z', '2026-10-17T00:00:00Z')")
        conn.commit()
        did = conn.execute("SELECT id FROM devices").fetchone()["id"]
        ipv6.apply(conn, ipv6.parse_neigh(NEIGH))
        conn.close()
        assert client.get(f"/api/devices/{did}", headers=h).json()["ipv6"][0]["ip"] == "fd00::5"
        assert client.get("/api/ipv6", headers=h).json()["addresses"] == 1
    tsdb.forget_all()
