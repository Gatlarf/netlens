import sqlite3
from pathlib import Path
from typing import Any

import pytest

from app.config import load_settings
from app.db import connect, init_db
from app.scanner.orchestrator import ScanManager
from app.scanner.relstore import add_manual, delete_relation, list_relations


@pytest.fixture
def settings() -> dict[str, Any]:
    return load_settings({"NETLENS_TOKEN": "t", "NETLENS_RANGES": "192.168.1.0/24"})


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "t.db"
    conn = connect(path)
    init_db(conn)
    conn.close()
    return path


@pytest.fixture
def xml_text() -> str:
    fixture_path = Path(__file__).parent / "fixtures" / "deep.xml"
    return fixture_path.read_text()


@pytest.fixture
def fake_runner(xml_text: str):
    async def fake_runner(kind: str, targets: list[str], *, nmap_path: str = "nmap") -> str:
        return xml_text
    return fake_runner


@pytest.fixture
def fake_names():
    async def fake_names() -> dict[str, str]:
        return {}
    return fake_names


@pytest.fixture
def fake_gateway():
    async def fake_gateway() -> str:
        return "192.168.1.1"
    return fake_gateway


@pytest.fixture
def fake_ranges():
    async def fake_ranges() -> list[str]:
        return ["192.168.1.0/24"]
    return fake_ranges


@pytest.fixture
def scan_manager(db_path: Path, settings: dict[str, Any], fake_runner, fake_names, fake_ranges, fake_gateway) -> ScanManager:
    return ScanManager(
        db_path,
        settings,
        runner=fake_runner,
        names_provider=fake_names,
        ranges_provider=fake_ranges,
        gateway_provider=fake_gateway,
    )


def get_device_id(conn: sqlite3.Connection, primary_ip: str) -> int:
    row = conn.execute("SELECT id FROM devices WHERE primary_ip = ?", (primary_ip,)).fetchone()
    if row is None:
        raise ValueError(f"Device with primary_ip {primary_ip} not found")
    return row["id"]


def get_or_create_device(conn: sqlite3.Connection, mac: str, primary_ip: str, device_type: str) -> int:
    row = conn.execute("SELECT id FROM devices WHERE mac = ?", (mac,)).fetchone()
    if row is not None:
        return row["id"]
    conn.execute(
        "INSERT INTO devices (mac, primary_ip, device_type, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
        (mac, primary_ip, device_type, "2024-01-01T00:00:00", "2024-01-01T00:00:00"),
    )
    conn.commit()
    row = conn.execute("SELECT id FROM devices WHERE mac = ?", (mac,)).fetchone()
    return row["id"]


@pytest.mark.asyncio
async def test_gateway_edges_default_route(scan_manager: ScanManager, db_path: Path) -> None:
    await scan_manager.start("deep")
    await scan_manager.wait()

    conn = connect(db_path)
    try:
        relations = list_relations(conn)
        assert len(relations) == 3

        gateway_id = get_device_id(conn, "192.168.1.1")
        for rel in relations:
            assert rel["dst_id"] == gateway_id
            assert rel["source"] == "default-route"
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_gateway_edges_heuristic_when_gateway_fails(scan_manager: ScanManager, db_path: Path) -> None:
    # Override gateway_provider to raise RuntimeError
    async def failing_gateway() -> str:
        raise RuntimeError("Gateway lookup failed")

    scan_manager.gateway_provider = failing_gateway

    await scan_manager.start("deep")
    await scan_manager.wait()

    conn = connect(db_path)
    try:
        # Check scan status
        scan_row = conn.execute("SELECT status FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        assert scan_row["status"] == "done"

        relations = list_relations(conn)
        assert len(relations) == 3

        # The router device should be 192.168.1.1
        router_id = get_device_id(conn, "192.168.1.1")
        for rel in relations:
            assert rel["dst_id"] == router_id
            assert rel["source"] == "heuristic"
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_manual_relation_survives_scan(scan_manager: ScanManager, db_path: Path) -> None:
    conn = connect(db_path)
    try:
        # Create devices with the same macs as fixture
        mac_20 = "b8:27:eb:12:34:56"
        mac_30 = "3c:2a:f4:00:00:09"

        id_20 = get_or_create_device(conn, mac_20, "192.168.1.20", "unknown")
        id_30 = get_or_create_device(conn, mac_30, "192.168.1.30", "unknown")

        # Add manual relation before scan
        add_manual(conn, id_20, id_30, kind="manual")

        # Run scan
        await scan_manager.start("deep")
        await scan_manager.wait()

        # Check that manual relation survived
        relations = list_relations(conn)
        manual_relations = [r for r in relations if r["source"] == "manual"]
        assert len(manual_relations) >= 1

        # Verify the specific manual relation exists
        found = False
        for rel in relations:
            if rel["src_id"] == id_20 and rel["dst_id"] == id_30 and rel["source"] == "manual":
                found = True
                break
        assert found
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_hidden_edge_stays_hidden(scan_manager: ScanManager, db_path: Path) -> None:
    conn = connect(db_path)
    try:
        # Run first scan
        await scan_manager.start("deep")
        await scan_manager.wait()

        relations = list_relations(conn)
        assert len(relations) == 3

        # Pick one inferred edge to hide
        edge_to_hide = relations[0]
        edge_id = edge_to_hide["id"]
        delete_relation(conn, edge_id)

        # Run second scan
        await scan_manager.start("deep")
        await scan_manager.wait()

        # Check that the hidden edge is not re-created
        relations_after = list_relations(conn)
        assert len(relations_after) == 2

        # Verify the hidden edge is not present
        for rel in relations_after:
            assert rel["id"] != edge_id
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_second_scan_does_not_duplicate_edges(scan_manager: ScanManager, db_path: Path) -> None:
    conn = connect(db_path)
    try:
        # Run first scan
        await scan_manager.start("deep")
        await scan_manager.wait()

        relations_first = list_relations(conn)
        assert len(relations_first) == 3

        # Run second scan
        await scan_manager.start("deep")
        await scan_manager.wait()

        relations_second = list_relations(conn)
        assert len(relations_second) == 3

        # Check no duplicates
        ids_first = {r["id"] for r in relations_first}
        ids_second = {r["id"] for r in relations_second}
        assert ids_first == ids_second
    finally:
        conn.close()