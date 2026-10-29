"""Devices with more than one address (app/multiip.py): a fixed address next to a DHCP lease must not make the entry flip, a lease that is
handed over (1 hour leases) must still be reported, and a real change between addresses is never hidden."""

from datetime import datetime, timedelta, timezone

import pytest

from app import flapping, multiip
from app.db import connect, init_db
from app.scanner.nmap_parser import ScanHost
from app.scanner.store import save_scan_results

START = datetime(2026, 10, 1, 8, 0, 0, tzinfo=timezone.utc)
STEP = timedelta(minutes=5)           # a scan every five minutes
LEASE = 12                            # an hour of five-minute scans


def host(ip, mac):
    return ScanHost(ip=ip, mac=mac, vendor=None, hostnames=[], ports=[], os_name=None, os_accuracy=None, os_type=None, ttl=64, via="arp")


@pytest.fixture
def db(tmp_path):
    conn = connect(tmp_path / "n.db")
    init_db(conn)
    yield conn
    conn.close()


class Clock:
    def __init__(self, conn):
        self.conn, self.n = conn, 0

    def scan(self, *pairs):
        """One scan; pairs are (ip, mac) that answered."""
        when = (START + STEP * self.n).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.n += 1
        save_scan_results(self.conn, [host(ip, mac) for ip, mac in pairs], "quick", now=when)
        return when

    def changes(self, mac=None):
        return [r["detail"] for r in self.conn.execute("SELECT detail FROM events WHERE kind = 'ip_changed' ORDER BY id")]

    def primary(self, mac):
        return self.conn.execute("SELECT primary_ip FROM devices WHERE mac = ?", (mac,)).fetchone()["primary_ip"]

    def device(self, mac):
        return self.conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()


PBS = "10:66:6a:37:09:9d"
PHONE = "46:e5:be:5c:c0:c8"


def test_two_live_addresses_stop_flipping_once_detected(db):
    c = Clock(db)
    for _ in range(40):
        c.scan(("192.168.0.201", PBS), ("192.168.0.135", PBS))
    changes = c.changes()
    assert len(changes) <= 2 * multiip.ENTER + 2        # the first scans flip as before ...
    n = len(changes)
    for _ in range(40):
        c.scan(("192.168.0.201", PBS), ("192.168.0.135", PBS))
    assert len(c.changes()) == n                        # ... and then nothing, the primary stays where it is
    assert multiip.state(c.device(PBS))["auto"] is True
    assert c.primary(PBS) in ("192.168.0.201", "192.168.0.135")


def test_new_lease_every_hour_is_always_reported(db):
    """A phone with a one hour lease that gets a different address every hour: every handover is an event, the primary follows."""
    c = Clock(db)
    addresses = ["192.168.1.50", "192.168.1.61", "192.168.1.72", "192.168.1.83"]
    for ip in addresses:
        for _ in range(LEASE):
            c.scan((ip, PHONE))
    assert c.changes() == ["192.168.1.50 -> 192.168.1.61", "192.168.1.61 -> 192.168.1.72", "192.168.1.72 -> 192.168.1.83"]
    assert c.primary(PHONE) == "192.168.1.83"
    assert multiip.state(c.device(PHONE))["multi"] is False


def test_lease_handover_with_overlap_is_not_a_second_address(db):
    """Old and new address answer together for two scans (a stale ARP entry): that is a handover, not a device with two addresses."""
    c = Clock(db)
    for _ in range(LEASE):
        c.scan(("192.168.1.50", PHONE))
    for _ in range(2):
        c.scan(("192.168.1.50", PHONE), ("192.168.1.61", PHONE))
    for _ in range(LEASE):
        c.scan(("192.168.1.61", PHONE))
    assert not multiip.state(c.device(PHONE))["multi"]
    assert c.primary(PHONE) == "192.168.1.61"
    assert c.changes()[-1].endswith("-> 192.168.1.61") or c.changes()[-2].endswith("-> 192.168.1.61")


def test_a_handover_after_detection_is_still_reported(db):
    """Two live addresses; one of them goes away for good: that is a real change and it shows."""
    c = Clock(db)
    for _ in range(20):
        c.scan(("10.0.0.2", PBS), ("10.0.0.9", PBS))
    stable = len(c.changes())
    primary = c.primary(PBS)
    other = "10.0.0.9" if primary == "10.0.0.2" else "10.0.0.2"
    for _ in range(6):                                   # the primary is gone for good (longer than the grace)
        c.scan((other, PBS))
    assert c.primary(PBS) == other
    assert len(c.changes()) == stable + 1
    assert c.changes()[-1] == f"{primary} -> {other}"


def test_one_lost_probe_does_not_move_the_primary(db):
    c = Clock(db)
    for _ in range(20):
        c.scan(("10.0.0.2", PBS), ("10.0.0.9", PBS))
    primary, n = c.primary(PBS), len(c.changes())
    other = "10.0.0.9" if primary == "10.0.0.2" else "10.0.0.2"
    c.scan((other, PBS))                                 # the primary missed one scan
    c.scan(("10.0.0.2", PBS), ("10.0.0.9", PBS))
    assert c.primary(PBS) == primary
    assert len(c.changes()) == n


def test_real_flapping_between_addresses_is_not_hidden(db):
    """An address that alternates (never two at once) is a flapping device and every change is an event."""
    c = Clock(db)
    for i in range(12):
        c.scan(("10.0.0.2" if i % 2 == 0 else "10.0.0.9", PBS))
    assert len(c.changes()) == 11
    assert not multiip.state(c.device(PBS))["multi"]


def test_pinned_address_stays_primary(db):
    c = Clock(db)
    c.scan(("192.168.0.201", PBS), ("192.168.0.135", PBS))
    db.execute("UPDATE devices SET pinned_ip = '192.168.0.201' WHERE mac = ?", (PBS,))
    db.commit()
    for _ in range(30):
        c.scan(("192.168.0.135", PBS), ("192.168.0.201", PBS))      # the pinned one is scanned last on purpose
        assert c.primary(PBS) == "192.168.0.201"
    assert c.changes()[-1:] != ["192.168.0.135 -> 192.168.0.201"] or len(c.changes()) <= 2


def test_pinned_address_that_is_silent_never_stays_as_a_dead_primary(db):
    c = Clock(db)
    c.scan(("192.168.0.201", PBS), ("192.168.0.135", PBS))
    db.execute("UPDATE devices SET pinned_ip = '192.168.0.201' WHERE mac = ?", (PBS,))
    db.commit()
    for _ in range(10):
        c.scan(("192.168.0.201", PBS), ("192.168.0.135", PBS))
    for _ in range(6):
        c.scan(("192.168.0.135", PBS))
    assert c.primary(PBS) == "192.168.0.135"


def test_owner_flag_applies_at_once(db):
    c = Clock(db)
    c.scan(("10.0.0.2", PBS), ("10.0.0.9", PBS))
    db.execute("UPDATE devices SET multi_ip = 1 WHERE mac = ?", (PBS,))
    db.commit()
    n = len(c.changes())
    for _ in range(10):
        c.scan(("10.0.0.2", PBS), ("10.0.0.9", PBS))
    assert len(c.changes()) == n


def test_devices_with_one_address_are_not_written_every_scan(db):
    c = Clock(db)
    c.scan(("10.0.0.5", PHONE))
    c.scan(("10.0.0.5", PHONE))
    assert c.device(PHONE)["multi_score"] == 0
    assert multiip.state(c.device(PHONE)) == {"flag": False, "pinned": None, "auto": False, "multi": False}


def test_flapping_analysis_names_the_two_addresses_and_how_to_silence_it(db):
    c = Clock(db)
    for _ in range(12):
        c.scan(("192.168.0.201", PBS), ("192.168.0.135", PBS))
    device_id = c.device(PBS)["id"]
    found, info = flapping.address_findings(db, device_id, "2000-01-01T00:00:00Z")
    assert info["several_addresses"] and found[0]["level"] == "warn" if "level" in found[0] else found
    text = " ".join(str(v) for v in found[0].values())
    assert "192.168.0.201" in text and "192.168.0.135" in text and "on purpose" in text


def test_flapping_analysis_when_the_owner_says_it_is_meant(db):
    c = Clock(db)
    for _ in range(4):
        c.scan(("192.168.0.201", PBS), ("192.168.0.135", PBS))
    db.execute("UPDATE devices SET multi_ip = 1 WHERE mac = ?", (PBS,))
    db.commit()
    found, _ = flapping.address_findings(db, c.device(PBS)["id"], "2000-01-01T00:00:00Z")
    assert len(found) == 1 and "on purpose" in " ".join(str(v) for v in found[0].values()).lower()


def test_pinned_address_that_does_not_answer_is_called_out(db):
    c = Clock(db)
    for _ in range(4):
        c.scan(("192.168.0.201", PBS), ("192.168.0.135", PBS))
    db.execute("UPDATE devices SET pinned_ip = '192.168.0.201' WHERE mac = ?", (PBS,))
    db.commit()
    for _ in range(6):
        c.scan(("192.168.0.135", PBS))
    found, info = flapping.address_findings(db, c.device(PBS)["id"], "2000-01-01T00:00:00Z")
    assert info["pinned"] == "192.168.0.201"
    assert any("not answering" in " ".join(str(v) for v in f.values()) for f in found)


def test_device_settings_through_the_api(tmp_path):
    from fastapi.testclient import TestClient

    from app.config import load_settings
    from app.main import create_app

    path = tmp_path / "api.db"
    conn = connect(path)
    init_db(conn)
    c = Clock(conn)
    for _ in range(3):
        c.scan(("192.168.0.201", PBS), ("192.168.0.135", PBS))
    device_id = c.device(PBS)["id"]
    conn.close()
    with TestClient(create_app(load_settings({"NETLENS_TOKEN": "t"}), db_path=path), headers={"Authorization": "Bearer t"}) as client:
        detail = client.get(f"/api/devices/{device_id}").json()
        assert detail["multi_ip"] is False and detail["pinned_ip"] is None and detail["multi_auto"] is True
        assert client.patch(f"/api/devices/{device_id}", json={"pinned_ip": "10.9.9.9"}).status_code == 422       # never seen on this device
        done = client.patch(f"/api/devices/{device_id}", json={"multi_ip": True, "pinned_ip": "192.168.0.201"}).json()
        assert done["multi_ip"] is True and done["pinned_ip"] == "192.168.0.201"
        assert client.patch(f"/api/devices/{device_id}", json={"pinned_ip": ""}).json()["pinned_ip"] is None
