import csv
import io
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import load_settings
from app.db import connect, init_db
from app.main import create_app
from app.scanner.nmap_parser import parse_nmap_xml
from app.scanner.store import save_scan_results


def _seed_db(db_path: Path) -> None:
    conn = connect(db_path)
    init_db(conn)
    xml_text = Path(__file__).parent.joinpath("fixtures", "deep.xml").read_text(encoding="utf-8")
    save_scan_results(conn, parse_nmap_xml(xml_text), "deep")
    conn.close()


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    settings = load_settings({"NETLENS_TOKEN": "t"})
    app = create_app(settings, db_path=tmp_path / "t.db")
    _seed_db(tmp_path / "t.db")
    with TestClient(app) as c:
        yield c


def test_relations_empty(client: TestClient) -> None:
    resp = client.get("/api/relations")
    assert resp.status_code == 200
    assert resp.json() == []


def test_create_relation(client: TestClient) -> None:
    resp = client.post("/api/relations", json={"src_id": 2, "dst_id": 1})
    assert resp.status_code == 201
    data = resp.json()
    assert isinstance(data["id"], int)

    resp = client.get("/api/relations")
    assert resp.status_code == 200
    relations = resp.json()
    assert len(relations) == 1
    assert relations[0]["id"] == data["id"]
    assert relations[0]["manual"] == 1
    assert relations[0]["kind"] == "manual"


def test_create_relation_self_link(client: TestClient) -> None:
    resp = client.post("/api/relations", json={"src_id": 1, "dst_id": 1})
    assert resp.status_code == 422


def test_create_relation_unknown_device(client: TestClient) -> None:
    resp = client.post("/api/relations", json={"src_id": 999, "dst_id": 1})
    assert resp.status_code == 422


def test_create_relation_invalid_kind(client: TestClient) -> None:
    resp = client.post("/api/relations", json={"src_id": 2, "dst_id": 1, "kind": "bogus"})
    assert resp.status_code == 422


def test_delete_relation(client: TestClient) -> None:
    resp = client.post("/api/relations", json={"src_id": 2, "dst_id": 1})
    assert resp.status_code == 201
    relation_id = resp.json()["id"]

    resp = client.delete(f"/api/relations/{relation_id}")
    assert resp.status_code == 204

    resp = client.get("/api/relations")
    assert resp.status_code == 200
    assert resp.json() == []


def test_delete_relation_unknown(client: TestClient) -> None:
    resp = client.delete("/api/relations/999")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "relation not found"


def test_delete_relation_twice(client: TestClient) -> None:
    resp = client.post("/api/relations", json={"src_id": 2, "dst_id": 1})
    assert resp.status_code == 201
    relation_id = resp.json()["id"]

    resp = client.delete(f"/api/relations/{relation_id}")
    assert resp.status_code == 204

    resp = client.delete(f"/api/relations/{relation_id}")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "relation not found"


def test_map_nodes(client: TestClient) -> None:
    resp = client.get("/api/map")
    assert resp.status_code == 200
    data = resp.json()

    nodes = data["nodes"]
    assert len(nodes) == 4
    assert [n["id"] for n in nodes] == [1, 2, 3, 4]

    for node in nodes:
        for key in ("id", "label", "ip", "mac", "vendor", "type", "online", "pos_x", "pos_y", "open_ports", "tags"):
            assert key in node

    node1 = nodes[0]
    assert node1["label"] == "router.lan"
    assert node1["open_ports"] == 4
    assert node1["online"] is True
    assert node1["type"] == "router"

    edges = data["edges"]
    assert len(edges) == 0


def test_map_edges_after_relation(client: TestClient) -> None:
    resp = client.post("/api/relations", json={"src_id": 2, "dst_id": 1})
    assert resp.status_code == 201

    resp = client.get("/api/map")
    assert resp.status_code == 200
    data = resp.json()

    edges = data["edges"]
    assert len(edges) == 1
    edge = edges[0]
    for key in ("id", "from", "to", "kind", "source", "confidence", "manual"):
        assert key in edge
    assert edge["from"] == 2
    assert edge["to"] == 1
    assert edge["manual"] is True


def test_map_positions_after_patch(client: TestClient) -> None:
    resp = client.patch("/api/devices/1", json={"pos_x": 12.5, "pos_y": -3})
    assert resp.status_code == 200

    resp = client.get("/api/map")
    assert resp.status_code == 200
    data = resp.json()

    node1 = data["nodes"][0]
    assert node1["pos_x"] == 12.5
    assert node1["pos_y"] == -3


def test_export_devices_json(client: TestClient) -> None:
    resp = client.get("/api/export/devices.json")
    assert resp.status_code == 200

    content_disposition = resp.headers.get("Content-Disposition", "")
    assert "attachment" in content_disposition
    assert "netlens-devices.json" in content_disposition

    data = resp.json()
    assert len(data) == 4

    expected_keys = {
        "id", "name", "ip", "mac", "hostname", "vendor", "type",
        "os", "os_confidence", "online", "first_seen", "last_seen",
        "tags", "notes", "open_ports",
    }

    for device in data:
        for key in expected_keys:
            assert key in device

    device1 = next(d for d in data if d["id"] == 1)
    assert device1["open_ports"] == ["tcp/22/ssh", "tcp/53/domain", "tcp/80/http", "tcp/443/https"]


def test_export_devices_csv(client: TestClient) -> None:
    resp = client.get("/api/export/devices.csv")
    assert resp.status_code == 200
    assert resp.headers.get("Content-Type", "").startswith("text/csv")

    content = resp.text
    reader = csv.reader(io.StringIO(content))
    rows = list(reader)

    header = rows[0]
    expected_header = [
        "id", "name", "ip", "mac", "hostname", "vendor", "type",
        "os", "os_confidence", "online", "first_seen", "last_seen",
        "tags", "notes", "open_ports",
    ]
    assert header == expected_header

    data_rows = rows[1:]
    assert len(data_rows) == 4


def test_export_csv_injection(client: TestClient) -> None:
    resp = client.patch("/api/devices/3", json={"custom_name": "=cmd|' /C calc'!A0"})
    assert resp.status_code == 200

    resp = client.get("/api/export/devices.csv")
    assert resp.status_code == 200

    content = resp.text
    reader = csv.reader(io.StringIO(content))
    rows = list(reader)

    header = rows[0]
    name_index = header.index("name")

    device3_row = next(row for row in rows[1:] if row[0] == "3")
    name_cell = device3_row[name_index]
    assert name_cell.startswith("'")


def test_relations_requires_auth(client: TestClient) -> None:
    client.headers.pop("Authorization")
    resp = client.get("/api/relations")
    assert resp.status_code == 401


def test_map_requires_auth(client: TestClient) -> None:
    client.headers.pop("Authorization")
    resp = client.get("/api/map")
    assert resp.status_code == 401


def test_export_json_requires_auth(client: TestClient) -> None:
    client.headers.pop("Authorization")
    resp = client.get("/api/export/devices.json")
    assert resp.status_code == 401


def test_export_csv_requires_auth(client: TestClient) -> None:
    client.headers.pop("Authorization")
    resp = client.get("/api/export/devices.csv")
    assert resp.status_code == 401