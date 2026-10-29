"""Link groups (app/linkgroups.py): the switch ports of a host's bond, and a warning when a member loses its link."""

from datetime import datetime, timedelta, timezone

import pytest

from app import linkgroups
from app.db import connect, init_db
from app.plugins.enrich import record_switch_ports
from app.scanner.nmap_parser import ScanHost
from app.scanner.store import save_scan_results

T0 = datetime(2026, 10, 29, 9, 0, 0, tzinfo=timezone.utc)
SWITCH_MAC, NAS_MAC = "aa:00:00:00:00:01", "aa:00:00:00:00:02"


def at(minutes):
    return (T0 + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def host(ip, mac):
    return ScanHost(ip=ip, mac=mac, vendor=None, hostnames=[], ports=[], os_name=None, os_accuracy=None, os_type=None, ttl=64, via="arp")


@pytest.fixture
def env(tmp_path):
    conn = connect(tmp_path / "n.db")
    init_db(conn)
    save_scan_results(conn, [host("10.0.0.2", SWITCH_MAC), host("10.0.0.20", NAS_MAC)], "quick", now=at(0))
    ids = {r["mac"]: r["id"] for r in conn.execute("SELECT id, mac FROM devices")}
    yield conn, ids[NAS_MAC], ids[SWITCH_MAC]
    conn.close()


def sync(conn, ups, minute):
    """A switch plugin sync: `ups` is {port: link up?}."""
    ports = [{"port": p, "name": f"p{p}", "enabled": True, "up": up, "speed_mbps": 1000 if up else None} for p, up in ups.items()]
    record_switch_ports(conn, "tplink", {"nodes": [{"macs": [SWITCH_MAC], "ip": "10.0.0.2", "name": "switch", "mac": SWITCH_MAC, "ports": ports}]}, now=at(minute))
    return linkgroups.evaluate(conn, at(minute))


def kinds(conn):
    return [(r["kind"], r["detail"]) for r in conn.execute("SELECT kind, detail FROM events WHERE kind IN ('link_degraded', 'link_recovered') ORDER BY id")]


def test_a_lost_link_is_reported_once_and_the_recovery_too(env):
    conn, nas, switch = env
    sync(conn, {1: True, 2: True, 3: True, 4: True, 5: False}, 1)
    linkgroups.create(conn, "TrueNAS bond", nas, switch, [3, 4])
    assert sync(conn, {1: True, 2: True, 3: True, 4: True, 5: False}, 2) == 0         # the first reading is never an event
    assert linkgroups.listing(conn, now=at(2))[0]["status"] == "ok"

    assert sync(conn, {1: True, 2: True, 3: True, 4: False, 5: False}, 3) == 1
    assert sync(conn, {1: True, 2: True, 3: True, 4: False, 5: False}, 4) == 0         # still the same: no repeat
    assert len(kinds(conn)) == 1 and "1 of 2 links up" in kinds(conn)[0][1] and "port 4" in kinds(conn)[0][1]
    event = conn.execute("SELECT device_id FROM events WHERE kind = 'link_degraded'").fetchone()
    assert event["device_id"] == nas                                                   # the event belongs to the host, not the switch

    assert sync(conn, {3: False, 4: False}, 5) == 1                                    # both gone: worse
    assert kinds(conn)[-1][0] == "link_degraded" and "no link on any" in kinds(conn)[-1][1]
    assert sync(conn, {3: True, 4: False}, 6) == 0                                     # partly back: not a new problem, not recovered yet
    assert sync(conn, {3: True, 4: True}, 7) == 1
    assert kinds(conn)[-1] == ("link_recovered", "TrueNAS bond: all 2 links are up again")


def test_ports_that_other_things_use_are_not_part_of_the_group(env):
    conn, nas, switch = env
    sync(conn, {1: True, 2: True, 3: True, 4: True}, 1)
    linkgroups.create(conn, "bond", nas, switch, [3, 4])
    assert sync(conn, {1: False, 2: True, 3: True, 4: True}, 2) == 0                  # port 1 is somebody else's
    assert not kinds(conn)


def test_a_silent_switch_claims_nothing(env):
    conn, nas, switch = env
    sync(conn, {3: True, 4: True}, 1)
    linkgroups.create(conn, "bond", nas, switch, [3, 4])
    assert linkgroups.evaluate(conn, at(120)) == 0                                    # no sync for two hours: the state is unknown
    assert linkgroups.listing(conn, now=at(120))[0]["status"] == "unknown"
    assert sync(conn, {3: True, 4: False}, 121) == 0                                  # unknown to degraded says nothing about a change
    assert not kinds(conn)


def test_what_a_group_must_be(env):
    conn, nas, switch = env
    sync(conn, {1: True, 2: True, 3: True}, 1)
    with pytest.raises(linkgroups.LinkGroupError, match="2 to"):
        linkgroups.create(conn, "bond", nas, switch, [1])
    with pytest.raises(linkgroups.LinkGroupError, match="does not report port 9"):
        linkgroups.create(conn, "bond", nas, switch, [1, 9])
    with pytest.raises(linkgroups.LinkGroupError, match="different"):
        linkgroups.create(conn, "bond", switch, switch, [1, 2])
    with pytest.raises(linkgroups.LinkGroupError, match="name"):
        linkgroups.create(conn, "  ", nas, switch, [1, 2])
    with pytest.raises(linkgroups.LinkGroupError, match="no switch ports"):
        linkgroups.create(conn, "bond", switch, nas, [1, 2])
    linkgroups.create(conn, "one", nas, switch, [1, 2])
    with pytest.raises(linkgroups.LinkGroupError, match="already belongs"):
        linkgroups.create(conn, "two", nas, switch, [2, 3])


def test_the_dashboard_and_the_answers_see_a_lost_link(env):
    conn, nas, switch = env
    clock = datetime.now(timezone.utc)

    def now(minutes):
        return (clock + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def sync_real(ups, minutes):
        ports = [{"port": p, "name": None, "enabled": True, "up": up, "speed_mbps": 1000 if up else None} for p, up in ups.items()]
        record_switch_ports(conn, "tplink", {"nodes": [{"macs": [SWITCH_MAC], "ip": "10.0.0.2", "name": "switch", "mac": SWITCH_MAC, "ports": ports}]}, now=now(minutes))
        linkgroups.evaluate(conn, now(minutes))

    sync_real({3: True, 4: True}, -2)
    linkgroups.create(conn, "NAS bond", nas, switch, [3, 4])
    from app import dashboard
    assert not [p for p in dashboard.current_problems(conn) if "bonded" in p["text"]]
    sync_real({3: True, 4: False}, -1)
    s = linkgroups.summary(conn)
    assert (s["groups"], s["degraded"], s["down"], s["first_host"]) == (1, 1, 0, nas)
    problems = [p for p in dashboard.current_problems(conn) if "bonded" in p["text"]]
    assert problems and "lost a link" in problems[0]["text"]
    from app import ask_more
    answer = ask_more.r_bonds(ask_more.t_bonds(conn, {}))
    assert "NAS bond" in answer and "1 of 2 links up" in answer and "port 4" in answer


def test_api(tmp_path):
    from fastapi.testclient import TestClient

    from app.config import load_settings
    from app.main import create_app

    path = tmp_path / "api.db"
    conn = connect(path)
    init_db(conn)
    save_scan_results(conn, [host("10.0.0.2", SWITCH_MAC), host("10.0.0.20", NAS_MAC)], "quick", now=at(0))
    ids = {r["mac"]: r["id"] for r in conn.execute("SELECT id, mac FROM devices")}
    now = datetime.now(timezone.utc)
    record_switch_ports(conn, "tplink", {"nodes": [{"macs": [SWITCH_MAC], "ip": "10.0.0.2", "name": "switch", "mac": SWITCH_MAC,
                                                   "ports": [{"port": p, "name": None, "enabled": True, "up": True, "speed_mbps": 1000} for p in (1, 2, 3)]}]}, now=now.strftime("%Y-%m-%dT%H:%M:%SZ"))
    conn.close()
    nas, switch = ids[NAS_MAC], ids[SWITCH_MAC]
    with TestClient(create_app(load_settings({"NETLENS_TOKEN": "t"}), db_path=path), headers={"Authorization": "Bearer t"}) as client:
        assert client.get("/api/link-groups").json() == {"groups": []}
        bad = client.post("/api/link-groups", json={"name": "b", "host_device_id": nas, "switch_device_id": switch, "ports": [1, 8]})
        assert bad.status_code == 422 and "port 8" in bad.json()["detail"]
        made = client.post("/api/link-groups", json={"name": "NAS bond", "host_device_id": nas, "switch_device_id": switch, "ports": [1, 2]})
        assert made.status_code == 201
        group = made.json()["groups"][0]
        assert group["status"] == "ok" and group["host_device_id"] == nas and [m["port"] for m in group["ports"]] == [1, 2]
        assert len(client.get(f"/api/link-groups?device_id={switch}").json()["groups"]) == 1             # found from the switch as well
        assert client.get("/api/link-groups?device_id=999").json()["groups"] == []
        renamed = client.patch(f"/api/link-groups/{group['id']}", json={"name": "NAS bond 2", "ports": [2, 3]}).json()["groups"][0]
        assert renamed["name"] == "NAS bond 2" and [m["port"] for m in renamed["ports"]] == [2, 3]
        assert client.delete(f"/api/link-groups/{group['id']}").status_code == 200
        assert client.delete(f"/api/link-groups/{group['id']}").status_code == 404
        assert client.patch("/api/link-groups/999", json={"name": "x"}).status_code == 404
