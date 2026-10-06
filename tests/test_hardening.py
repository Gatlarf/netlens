import pytest
from fastapi.testclient import TestClient
from pathlib import Path
from app.scanner.nmap_parser import parse_nmap_xml
from app.scanner.names import parse_upnp_description
from app.config import load_settings
from app.main import create_app
from app.db import connect, init_db, get_or_create_device


def test_parse_nmap_xml_rejects_entity():
    xml_text = '<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY a "x">]><nmaprun/>'
    with pytest.raises(ValueError):
        parse_nmap_xml(xml_text)


def test_parse_nmap_xml_plain_doctype_returns_empty():
    xml_text = '<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun></nmaprun>'
    result = parse_nmap_xml(xml_text)
    assert result == []


def test_parse_upnp_description_rejects_entity():
    payload = '<!ENTITY a "x">'
    result = parse_upnp_description(payload)
    assert result == {}


def test_parse_upnp_description_normal():
    payload = '<root><device><friendlyName>TestDevice</friendlyName></device></root>'
    result = parse_upnp_description(payload)
    assert result == {"friendly_name": "TestDevice"}


def test_patch_device_custom_name_too_long():
    settings = load_settings({"NETLENS_TOKEN": "t"})
    tmp_path = Path("/tmp/test_hardening")
    tmp_path.mkdir(exist_ok=True)
    db_path = tmp_path / "t.db"
    app = create_app(settings, db_path=db_path)
    conn = connect(db_path)
    init_db(conn)
    get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.5")
    conn.close()

    with TestClient(app) as c:
        c.headers.update({"Authorization": "Bearer t"})
        response = c.patch("/api/devices/1", json={"custom_name": "a" * 101})
        assert response.status_code == 422


def test_patch_device_custom_name_ok():
    settings = load_settings({"NETLENS_TOKEN": "t"})
    tmp_path = Path("/tmp/test_hardening")
    tmp_path.mkdir(exist_ok=True)
    db_path = tmp_path / "t.db"
    app = create_app(settings, db_path=db_path)
    conn = connect(db_path)
    init_db(conn)
    get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.5")
    conn.close()

    with TestClient(app) as c:
        c.headers.update({"Authorization": "Bearer t"})
        response = c.patch("/api/devices/1", json={"custom_name": "a" * 100})
        assert response.status_code == 200


def test_patch_device_notes_too_long():
    settings = load_settings({"NETLENS_TOKEN": "t"})
    tmp_path = Path("/tmp/test_hardening")
    tmp_path.mkdir(exist_ok=True)
    db_path = tmp_path / "t.db"
    app = create_app(settings, db_path=db_path)
    conn = connect(db_path)
    init_db(conn)
    get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.5")
    conn.close()

    with TestClient(app) as c:
        c.headers.update({"Authorization": "Bearer t"})
        response = c.patch("/api/devices/1", json={"notes": "a" * 4001})
        assert response.status_code == 422


def test_patch_device_notes_ok():
    settings = load_settings({"NETLENS_TOKEN": "t"})
    tmp_path = Path("/tmp/test_hardening")
    tmp_path.mkdir(exist_ok=True)
    db_path = tmp_path / "t.db"
    app = create_app(settings, db_path=db_path)
    conn = connect(db_path)
    init_db(conn)
    get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.5")
    conn.close()

    with TestClient(app) as c:
        c.headers.update({"Authorization": "Bearer t"})
        response = c.patch("/api/devices/1", json={"notes": "a" * 4000})
        assert response.status_code == 200