import sqlite3

import pytest

from app.db import init_db
from app.plugins.contract import ContractError, validate_output
from app.plugins.enrich import record_client_hints
from app.scanner import fingerprint, store

NODE = {"mac": "02:00:00:00:00:01", "role": "gateway", "name": "gw"}


def clients(**extra):
    return {"nodes": [NODE], "clients": [{"mac": "02:00:00:00:10:01", "ip": "10.0.0.50", **extra}]}


def test_contract_accepts_the_optional_fields():
    out = validate_output("topology", clients(vendor="MSFT 5.0", os="Windows 11", model="X1", device_type="pc"))
    c = out["clients"][0]
    assert (c["vendor"], c["os"], c["model"], c["device_type"]) == ("MSFT 5.0", "Windows 11", "X1", "pc")


def test_contract_ignores_an_unknown_type_but_refuses_a_non_text_one():
    assert validate_output("topology", clients(device_type="toaster"))["clients"][0]["device_type"] is None
    with pytest.raises(ContractError):
        validate_output("topology", clients(device_type=5))


def test_fields_default_to_none():
    c = validate_output("topology", clients())["clients"][0]
    assert c["vendor"] is None and c["device_type"] is None


def test_dhcp_class_fingerprints():
    assert fingerprint.os_from_dhcp_class("MSFT 5.0") == "Windows"
    assert fingerprint.os_from_dhcp_class("android-dhcp-13") == "Android 13"
    assert fingerprint.os_from_dhcp_class("dhcpcd-6.8.2:Linux-3.8.13+:armv") == "Linux"
    assert fingerprint.os_from_dhcp_class("Samsung Electronics") is None
    assert fingerprint.os_from_dhcp_params([1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]) == "Windows"
    assert fingerprint.os_from_dhcp_params([1, 3, 6, 15, 26, 28, 51, 58, 59, 43]) == "Android"
    assert fingerprint.os_from_dhcp_params([99]) is None


@pytest.fixture
def conn(tmp_path):
    c = sqlite3.connect(tmp_path / "t.db")
    c.row_factory = sqlite3.Row
    init_db(c)
    c.execute("INSERT INTO devices (primary_ip, mac, first_seen, last_seen, online) VALUES ('10.0.0.50', '02:00:00:00:10:01', 'x', 'x', 1)")
    c.commit()
    return c


def device(conn):
    return conn.execute("SELECT device_type, vendor, hints FROM devices").fetchone()


def test_router_knowledge_reaches_the_classifier(conn):
    data = validate_output("topology", clients(vendor="MSFT 5.0"))
    assert record_client_hints(conn, data) == 1
    row = device(conn)
    assert "os:Windows" in row["hints"] and row["device_type"] == "pc" and row["vendor"] is None  # a DHCP class is not a manufacturer


def test_router_type_is_replaced_and_vendor_filled(conn):
    record_client_hints(conn, validate_output("topology", clients(vendor="Acme Cams", device_type="camera")))
    assert device(conn)["device_type"] == "camera" and device(conn)["vendor"] == "Acme Cams"
    record_client_hints(conn, validate_output("topology", clients(device_type="printer")))
    assert "ctl:camera" not in device(conn)["hints"] and device(conn)["device_type"] == "printer"


def test_teaching_by_overriding(conn):
    for i in range(3):
        conn.execute("INSERT INTO devices (primary_ip, mac, vendor, type_override, first_seen, last_seen, online) VALUES (?, ?, 'Acme', 'speaker', 'x', 'x', 1)", (f"10.0.1.{i}", f"02:00:00:00:20:0{i}"))
    conn.execute("UPDATE devices SET vendor = 'Acme', type_override = NULL WHERE id = 1")
    conn.commit()
    store.relearn_vendor(conn, 2)
    assert device(conn)["device_type"] == "speaker"
    report = store.identification_report(conn, 1)
    assert report["evidence"][0]["type"] == "speaker" and "set 3 other Acme" in report["evidence"][0]["why"]
