Fix the defects below and output the COMPLETE corrected file. Keep everything else identical.

DEFECTS:
test_add_manual_on_suppressed_edge_reactivates_it calls add_manual with the invalid kind 'test'. Valid kinds are only: manual, gateway, route, host-of, service. Use kind 'gateway' (the suppressed inferred edge must have the same kind).

CURRENT FILE:
import sqlite3
import pytest
from app.db import connect, init_db, get_or_create_device
from app.scanner.relstore import replace_inferred, list_relations, add_manual, delete_relation
from app.scanner.relations import Edge


def _setup_db() -> sqlite3.Connection:
    conn = connect(":memory:")
    init_db(conn)
    return conn


def _create_device(conn: sqlite3.Connection, mac: str, ip: str) -> int:
    device_id = get_or_create_device(conn, mac, ip)
    if device_id is None:
        raise ValueError("Failed to create device")
    return device_id


def test_replace_inferred_stores_edges_with_manual_zero():
    conn = _setup_db()
    src_id = _create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.1")
    dst_id = _create_device(conn, "aa:bb:cc:dd:ee:02", "192.168.1.2")

    edge = Edge(src_id=src_id, dst_id=dst_id, kind="test", source="test", confidence=0.9)
    replace_inferred(conn, [edge])

    relations = list_relations(conn)
    assert len(relations) == 1
    assert relations[0]["manual"] == 0
    assert relations[0]["src_id"] == src_id
    assert relations[0]["dst_id"] == dst_id
    assert relations[0]["kind"] == "test"
    assert relations[0]["source"] == "test"
    assert relations[0]["confidence"] == 0.9
    assert relations[0]["id"] is not None


def test_list_relations_returns_dicts_with_expected_keys():
    conn = _setup_db()
    src_id = _create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.1")
    dst_id = _create_device(conn, "aa:bb:cc:dd:ee:02", "192.168.1.2")

    edge = Edge(src_id=src_id, dst_id=dst_id, kind="test", source="test", confidence=0.9)
    replace_inferred(conn, [edge])

    relations = list_relations(conn)
    assert len(relations) == 1
    expected_keys = {"id", "src_id", "dst_id", "kind", "source", "confidence", "manual"}
    assert set(relations[0].keys()) == expected_keys


def test_replace_inferred_removes_old_inferred_edges():
    conn = _setup_db()
    src_id = _create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.1")
    dst_id = _create_device(conn, "aa:bb:cc:dd:ee:02", "192.168.1.2")

    edge1 = Edge(src_id=src_id, dst_id=dst_id, kind="test1", source="test", confidence=0.9)
    replace_inferred(conn, [edge1])

    edge2 = Edge(src_id=src_id, dst_id=dst_id, kind="test2", source="test", confidence=0.8)
    replace_inferred(conn, [edge2])

    relations = list_relations(conn)
    assert len(relations) == 1
    assert relations[0]["kind"] == "test2"
    assert relations[0]["confidence"] == 0.8


def test_manual_edges_survive_replace_inferred():
    conn = _setup_db()
    src_id = _create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.1")
    dst_id = _create_device(conn, "aa:bb:cc:dd:ee:02", "192.168.1.2")

    manual_id = add_manual(conn, src_id, dst_id, kind="manual")
    assert manual_id is not None

    edge = Edge(src_id=src_id, dst_id=dst_id, kind="inferred", source="test", confidence=0.9)
    replace_inferred(conn, [edge])

    relations = list_relations(conn)
    assert len(relations) == 2
    manual_relation = next(r for r in relations if r["manual"] == 1)
    assert manual_relation["id"] == manual_id
    assert manual_relation["kind"] == "manual"
    assert manual_relation["source"] == "manual"


def test_replace_inferred_does_not_overwrite_existing_manual_edge():
    conn = _setup_db()
    src_id = _create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.1")
    dst_id = _create_device(conn, "aa:bb:cc:dd:ee:02", "192.168.1.2")

    manual_id = add_manual(conn, src_id, dst_id, kind="manual")
    assert manual_id is not None

    edge = Edge(src_id=src_id, dst_id=dst_id, kind="manual", source="test", confidence=0.9)
    replace_inferred(conn, [edge])

    relations = list_relations(conn)
    assert len(relations) == 1
    assert relations[0]["id"] == manual_id
    assert relations[0]["manual"] == 1
    assert relations[0]["source"] == "manual"
    assert relations[0]["confidence"] == 1.0


def test_add_manual_returns_id():
    conn = _setup_db()
    src_id = _create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.1")
    dst_id = _create_device(conn, "aa:bb:cc:dd:ee:02", "192.168.1.2")

    relation_id = add_manual(conn, src_id, dst_id, kind="manual")
    assert relation_id is not None
    assert isinstance(relation_id, int)
    assert relation_id > 0


def test_add_manual_rejects_self_links():
    conn = _setup_db()
    src_id = _create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.1")

    with pytest.raises(ValueError):
        add_manual(conn, src_id, src_id, kind="manual")


def test_add_manual_rejects_unknown_devices():
    conn = _setup_db()
    src_id = _create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.1")

    with pytest.raises(ValueError):
        add_manual(conn, src_id, 9999, kind="manual")

    with pytest.raises(ValueError):
        add_manual(conn, 9999, src_id, kind="manual")


def test_add_manual_rejects_invalid_kinds():
    conn = _setup_db()
    src_id = _create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.1")
    dst_id = _create_device(conn, "aa:bb:cc:dd:ee:02", "192.168.1.2")

    with pytest.raises(ValueError):
        add_manual(conn, src_id, dst_id, kind="")

    with pytest.raises(ValueError):
        add_manual(conn, src_id, dst_id, kind=None)


def test_delete_relation_removes_manual_edge():
    conn = _setup_db()
    src_id = _create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.1")
    dst_id = _create_device(conn, "aa:bb:cc:dd:ee:02", "192.168.1.2")

    relation_id = add_manual(conn, src_id, dst_id, kind="manual")
    assert relation_id is not None

    assert delete_relation(conn, relation_id) is True
    relations = list_relations(conn)
    assert len(relations) == 0


def test_delete_relation_hides_inferred_edge():
    conn = _setup_db()
    src_id = _create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.1")
    dst_id = _create_device(conn, "aa:bb:cc:dd:ee:02", "192.168.1.2")

    edge = Edge(src_id=src_id, dst_id=dst_id, kind="test", source="test", confidence=0.9)
    replace_inferred(conn, [edge])

    relations = list_relations(conn)
    assert len(relations) == 1
    relation_id = relations[0]["id"]

    assert delete_relation(conn, relation_id) is True
    relations = list_relations(conn)
    assert len(relations) == 0


def test_replace_inferred_does_not_bring_back_deleted_inferred_edge():
    conn = _setup_db()
    src_id = _create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.1")
    dst_id = _create_device(conn, "aa:bb:cc:dd:ee:02", "192.168.1.2")

    edge = Edge(src_id=src_id, dst_id=dst_id, kind="test", source="test", confidence=0.9)
    replace_inferred(conn, [edge])

    relations = list_relations(conn)
    assert len(relations) == 1
    relation_id = relations[0]["id"]

    assert delete_relation(conn, relation_id) is True
    relations = list_relations(conn)
    assert len(relations) == 0

    replace_inferred(conn, [edge])
    relations = list_relations(conn)
    assert len(relations) == 0


def test_add_manual_on_suppressed_edge_reactivates_it():
    conn = _setup_db()
    src_id = _create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.1")
    dst_id = _create_device(conn, "aa:bb:cc:dd:ee:02", "192.168.1.2")

    edge = Edge(src_id=src_id, dst_id=dst_id, kind="test", source="test", confidence=0.9)
    replace_inferred(conn, [edge])

    relations = list_relations(conn)
    assert len(relations) == 1
    relation_id = relations[0]["id"]

    assert delete_relation(conn, relation_id) is True
    relations = list_relations(conn)
    assert len(relations) == 0

    new_id = add_manual(conn, src_id, dst_id, kind="test")
    assert new_id is not None

    relations = list_relations(conn)
    assert len(relations) == 1
    assert relations[0]["id"] == new_id
    assert relations[0]["manual"] == 1
    assert relations[0]["kind"] == "test"
    assert relations[0]["source"] == "manual"


def test_delete_relation_of_unknown_id_returns_false():
    conn = _setup_db()
    assert delete_relation(conn, 9999) is False


def test_deleting_device_cascades_relations():
    conn = _setup_db()
    src_id = _create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.1")
    dst_id = _create_device(conn, "aa:bb:cc:dd:ee:02", "192.168.1.2")

    edge = Edge(src_id=src_id, dst_id=dst_id, kind="test", source="test", confidence=0.9)
    replace_inferred(conn, [edge])

    relations = list_relations(conn)
    assert len(relations) == 1

    conn.execute("DELETE FROM devices WHERE id = ?", (src_id,))
    conn.commit()

    relations = list_relations(conn)
    assert len(relations) == 0