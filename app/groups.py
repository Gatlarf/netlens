"""Device groups (rooms, floors, owners...): a device is in at most one group, a group has a name and a colour."""

import re
import sqlite3

COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
PALETTE = ["#2563eb", "#16a34a", "#d97706", "#9333ea", "#dc2626", "#0891b2", "#be185d", "#65a30d", "#7c3aed", "#ea580c"]
MAX_GROUPS = 200


class GroupError(ValueError):
    pass


def _name(value: str) -> str:
    value = (value or "").strip()
    if not value or len(value) > 40:
        raise GroupError("a group name is 1 to 40 characters")
    return value


def _color(value: str | None, fallback: str) -> str:
    if value in (None, ""):
        return fallback
    if not COLOR_RE.match(value):
        raise GroupError("a colour looks like #2563eb")
    return value.lower()


def list_groups(conn: sqlite3.Connection) -> list[dict]:
    return [
        {"id": r["id"], "name": r["name"], "color": r["color"], "count": r["n"]}
        for r in conn.execute(
            "SELECT g.id, g.name, g.color, (SELECT COUNT(*) FROM devices d WHERE d.group_id = g.id) AS n FROM device_groups g ORDER BY g.name COLLATE NOCASE"
        )
    ]


def create(conn: sqlite3.Connection, name: str, color: str | None = None) -> int:
    name = _name(name)
    total = conn.execute("SELECT COUNT(*) FROM device_groups").fetchone()[0]
    if total >= MAX_GROUPS:
        raise GroupError("that is a lot of groups; delete some first")
    color = _color(color, PALETTE[total % len(PALETTE)])
    try:
        cur = conn.execute("INSERT INTO device_groups (name, color) VALUES (?, ?)", (name, color))
    except sqlite3.IntegrityError:
        raise GroupError("a group with that name exists")
    conn.commit()
    return cur.lastrowid


def update(conn: sqlite3.Connection, group_id: int, name: str | None = None, color: str | None = None) -> None:
    row = conn.execute("SELECT name, color FROM device_groups WHERE id = ?", (group_id,)).fetchone()
    if row is None:
        raise KeyError(group_id)
    try:
        conn.execute("UPDATE device_groups SET name = ?, color = ? WHERE id = ?",
                     (_name(name) if name is not None else row["name"], _color(color, row["color"]), group_id))
    except sqlite3.IntegrityError:
        raise GroupError("a group with that name exists")
    conn.commit()


def delete(conn: sqlite3.Connection, group_id: int) -> None:
    if conn.execute("DELETE FROM device_groups WHERE id = ?", (group_id,)).rowcount == 0:
        raise KeyError(group_id)
    conn.commit()  # devices in it become ungrouped (foreign key SET NULL)


def exists(conn: sqlite3.Connection, group_id: int) -> bool:
    return conn.execute("SELECT 1 FROM device_groups WHERE id = ?", (group_id,)).fetchone() is not None


def assign(conn: sqlite3.Connection, device_ids: list[int] | None, group_id: int | None) -> int:
    """Put devices in a group (None = take them out of any group). `device_ids` None = every device."""
    if group_id is not None and not exists(conn, group_id):
        raise KeyError(group_id)
    if device_ids is None:
        changed = conn.execute("UPDATE devices SET group_id = ?", (group_id,)).rowcount
    else:
        marks = ",".join("?" for _ in device_ids) or "NULL"
        changed = conn.execute(f"UPDATE devices SET group_id = ? WHERE id IN ({marks})", (group_id, *device_ids)).rowcount
    conn.commit()
    return changed


def lookup(conn: sqlite3.Connection) -> dict[int, dict]:
    return {r["id"]: {"name": r["name"], "color": r["color"]} for r in conn.execute("SELECT id, name, color FROM device_groups")}
