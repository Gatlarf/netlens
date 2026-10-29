"""The list of networks is what is scanned: a Scan switch per network, detected networks, and a smooth move from the older list of ranges."""

import json

import pytest
from fastapi.testclient import TestClient

from app import networks
from app.config import load_settings
from app.db import connect, get_setting, init_db, set_setting
from app.main import create_app
from app.scanner.nmap_runner import ScanError
from app.scanner.orchestrator import ScanManager


@pytest.fixture
def db(tmp_path):
    conn = connect(tmp_path / "n.db")
    init_db(conn)
    yield conn
    conn.close()


def rows(conn):
    return {n["cidr"]: n for n in networks.listing(conn)}


def test_a_fresh_installation_scans_what_it_finds_on_its_network_cards(db):
    networks.absorb_legacy(db, ())
    networks.refresh_detected(db, ["192.168.1.0/24", "172.17.0.0/16"])                  # the docker bridge is too big to scan: left out
    assert networks.scan_targets(db) == ["192.168.1.0/24"]
    assert rows(db)["192.168.1.0/24"]["source"] == "detected"
    networks.refresh_detected(db, ["192.168.1.0/24", "10.0.5.0/24"])                      # a VLAN interface was added: it is scanned too
    assert networks.scan_targets(db) == ["192.168.1.0/24", "10.0.5.0/24"]
    networks.refresh_detected(db, ["192.168.1.0/24"])                                     # and removed: not scanned, not listed
    assert networks.scan_targets(db) == ["192.168.1.0/24"] and set(rows(db)) == {"192.168.1.0/24"}


def test_a_detected_network_can_be_switched_off_and_stays_off(db):
    networks.absorb_legacy(db, ())
    networks.refresh_detected(db, ["192.168.1.0/24", "10.0.5.0/24"])
    r = rows(db)
    networks.set_scan(db, r["10.0.5.0/24"]["id"], False)
    networks.refresh_detected(db, ["192.168.1.0/24", "10.0.5.0/24"])
    assert networks.scan_targets(db) == ["192.168.1.0/24"]
    assert rows(db)["10.0.5.0/24"]["status"] == "off"


def test_ranges_set_the_older_way_keep_being_the_only_ones_scanned(db):
    set_setting(db, "ranges", json.dumps(["192.168.5.0/24", "10.0.0.0/22"]))              # what an installation had before networks were the list
    db.commit()
    networks.absorb_legacy(db, ())
    assert networks.scan_targets(db) == ["192.168.5.0/24", "10.0.0.0/22"]
    assert get_setting(db, "ranges") is None                                               # the old key is gone: the list is the one place
    networks.refresh_detected(db, ["192.168.1.0/24"])                                      # the card's network is listed, not scanned: nothing changes for them
    assert networks.scan_targets(db) == ["192.168.5.0/24", "10.0.0.0/22"]
    assert rows(db)["192.168.1.0/24"]["scan"] is False
    networks.absorb_legacy(db, ())                                                         # every start runs it again
    assert networks.scan_targets(db) == ["192.168.5.0/24", "10.0.0.0/22"]


def test_the_environment_list_is_only_a_start_and_the_web_choice_wins(db):
    networks.absorb_legacy(db, ["10.1.0.0/24"])
    assert networks.scan_targets(db) == ["10.1.0.0/24"] and rows(db)["10.1.0.0/24"]["source"] == "env"
    networks.refresh_detected(db, ["192.168.1.0/24"])
    assert networks.scan_targets(db) == ["10.1.0.0/24"]                                    # an environment list means "these"
    networks.set_scan(db, rows(db)["10.1.0.0/24"]["id"], False)
    networks.absorb_legacy(db, ["10.1.0.0/24"])                                            # the next start does not switch it back on
    assert networks.scan_targets(db) == []


def test_a_restored_older_backup_brings_its_ranges_in(db):
    networks.absorb_legacy(db, ())
    networks.refresh_detected(db, ["192.168.1.0/24"])
    set_setting(db, "ranges", json.dumps(["10.7.0.0/24"]))                                 # the key an older backup contains
    db.commit()
    networks.absorb_legacy(db, ())
    assert networks.scan_targets(db) == ["192.168.1.0/24", "10.7.0.0/24"] and get_setting(db, "ranges") is None


def test_adding_and_removing_by_hand(db):
    networks.absorb_legacy(db, ())
    networks.refresh_detected(db, ["192.168.1.0/24"])
    new = networks.add(db, "10.2.0.7/24", "  Guest   Wi-Fi ")
    assert rows(db)["10.2.0.0/24"]["label"] == "Guest Wi-Fi" and "10.2.0.0/24" in networks.scan_targets(db)
    with pytest.raises(ValueError, match="in the list already"):
        networks.add(db, "10.2.0.0/24")
    with pytest.raises(ValueError, match="not scannable"):
        networks.add(db, "8.8.8.0/24")                                                      # only private ranges
    with pytest.raises(ValueError, match="not scannable"):
        networks.add(db, "10.0.0.0/8")                                                      # and not bigger than a /20
    with pytest.raises(ValueError, match="switch Scan off"):
        networks.remove(db, rows(db)["192.168.1.0/24"]["id"])                                # a detected network would come back
    assert networks.remove(db, new) is True and "10.2.0.0/24" not in rows(db)
    assert networks.remove(db, new) is False


def test_the_older_exact_list_still_works_and_can_be_reset(db):
    networks.absorb_legacy(db, ())
    networks.refresh_detected(db, ["192.168.1.0/24"])
    networks.set_exact(db, ["10.4.0.0/24"])
    assert networks.scan_targets(db) == ["10.4.0.0/24"]
    networks.set_exact(db, [])
    assert networks.scan_targets(db) == ["192.168.1.0/24"]                                  # back to what the network cards say
    assert rows(db)["10.4.0.0/24"]["scan"] is False                                         # and the network that was added stays in the list, switched off


class Runner:
    def __init__(self):
        self.calls = []

    async def __call__(self, kind, targets, **kw):
        self.calls.append(list(targets))
        return "<nmaprun></nmaprun>"


@pytest.mark.asyncio
async def test_the_scan_follows_the_switches(tmp_path):
    path = tmp_path / "s.db"
    conn = connect(path)
    init_db(conn)
    conn.close()
    cards = ["192.168.1.0/24", "10.0.5.0/24"]

    async def provider():
        return cards

    async def names():
        return {}

    runner = Runner()
    manager = ScanManager(str(path), load_settings({"NETLENS_TOKEN": "t"}), runner=runner, names_provider=names, ranges_provider=provider)
    told = []
    manager.ranges_changed = told.append
    assert await manager._scan_targets() == ["192.168.1.0/24", "10.0.5.0/24"] and told[-1] == ["192.168.1.0/24", "10.0.5.0/24"]
    conn = connect(path)
    networks.set_scan(conn, rows(conn)["10.0.5.0/24"]["id"], False)
    conn.close()
    assert await manager._scan_targets() == ["192.168.1.0/24"]
    conn = connect(path)
    networks.set_scan(conn, rows(conn)["192.168.1.0/24"]["id"], False)
    conn.close()
    with pytest.raises(ScanError, match="no scan ranges found"):
        await manager._scan_targets()


def test_the_api(tmp_path):
    path = tmp_path / "api.db"
    conn = connect(path)
    init_db(conn)
    conn.close()
    app = create_app(load_settings({"NETLENS_TOKEN": "t"}), db_path=path)

    async def cards():
        return ["192.168.1.0/24"]
    app.state.scan_manager.ranges_provider = cards
    with TestClient(app, headers={"Authorization": "Bearer t"}) as c:
        listing = c.get("/api/networks").json()["networks"]
        assert [(n["cidr"], n["source"], n["scan"]) for n in listing] == [("192.168.1.0/24", "detected", True)]          # listed before any scan
        assert c.post("/api/networks", json={"cidr": "10.9.0.0/24", "name": "IoT"}).status_code == 201
        assert c.post("/api/networks", json={"cidr": "10.9.0.0/24"}).status_code == 409
        assert c.post("/api/networks", json={"cidr": "8.8.8.0/24"}).status_code == 422
        assert app.state.settings.ranges == ("192.168.1.0/24", "10.9.0.0/24")                                            # the rest of the program sees the same list
        net = {n["cidr"]: n for n in c.get("/api/networks").json()["networks"]}
        off = c.patch(f"/api/networks/{net['192.168.1.0/24']['id']}", json={"scan": False}).json()["networks"]
        assert {n["cidr"]: n["status"] for n in off}["192.168.1.0/24"] == "off" and app.state.settings.ranges == ("10.9.0.0/24",)
        assert c.get("/api/config").json()["ranges"] == ["10.9.0.0/24"]
        assert c.delete(f"/api/networks/{net['192.168.1.0/24']['id']}").status_code == 409
        assert c.delete(f"/api/networks/{net['10.9.0.0/24']['id']}").status_code == 200
        assert c.patch("/api/networks/999", json={"scan": True}).status_code == 404
        assert c.patch("/api/networks/999", json={}).status_code == 404
        assert c.delete("/api/networks/999").status_code == 404
