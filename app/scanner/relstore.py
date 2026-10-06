import sqlite3
from typing import Any

from app.scanner.relations import Edge


def replace_inferred(conn: sqlite3.Connection, edges: list[Edge]) -> None:
    conn.execute("DELETE FROM relations WHERE manual = 0")
    for edge in edges:
        conn.execute(
            """
            INSERT INTO relations (src_id, dst_id, kind, source, confidence, manual)
            VALUES (?, ?, ?, ?, ?, 0)
            ON CONFLICT(src_id, dst_id, kind) DO NOTHING
            """,
            (edge.src_id, edge.dst_id, edge.kind, edge.source, edge.confidence),
        )
    conn.commit()


def list_relations(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT id, src_id, dst_id, kind, source, confidence, manual
        FROM relations
        WHERE manual >= 0
        ORDER BY id
        """
    ).fetchall()
    return [dict(row) for row in rows]


def add_manual(
    conn: sqlite3.Connection,
    src_id: int,
    dst_id: int,
    kind: str = "manual",
) -> int:
    if src_id == dst_id:
        raise ValueError("src_id and dst_id must be different")

    allowed_kinds = {"manual", "gateway", "route", "host-of", "service"}
    if kind not in allowed_kinds:
        raise ValueError(f"invalid kind: {kind}")

    for device_id in (src_id, dst_id):
        row = conn.execute("SELECT id FROM devices WHERE id = ?", (device_id,)).fetchone()
        if row is None:
            raise ValueError("unknown device")

    existing = conn.execute(
        """
        SELECT id FROM relations
        WHERE src_id = ? AND dst_id = ? AND kind = ?
        """,
        (src_id, dst_id, kind),
    ).fetchone()

    if existing is not None:
        relation_id = existing["id"]
        conn.execute(
            """
            UPDATE relations
            SET manual = 1, source = 'manual', confidence = 1.0
            WHERE id = ?
            """,
            (relation_id,),
        )
    else:
        cursor = conn.execute(
            """
            INSERT INTO relations (src_id, dst_id, kind, source, confidence, manual)
            VALUES (?, ?, ?, 'manual', 1.0, 1)
            """,
            (src_id, dst_id, kind),
        )
        relation_id = cursor.lastrowid

    conn.commit()
    return relation_id


def delete_relation(conn: sqlite3.Connection, relation_id: int) -> bool:
    row = conn.execute(
        "SELECT manual FROM relations WHERE id = ?",
        (relation_id,),
    ).fetchone()

    if row is None:
        return False

    manual = row["manual"]

    if manual == 1:
        conn.execute("DELETE FROM relations WHERE id = ?", (relation_id,))
        conn.commit()
        return True

    if manual == 0:
        conn.execute("UPDATE relations SET manual = -1 WHERE id = ?", (relation_id,))
        conn.commit()
        return True

    return False