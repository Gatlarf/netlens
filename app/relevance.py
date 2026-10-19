"""Which devices matter: the ones that should always be on. A phone going offline is not news."""

from __future__ import annotations

import sqlite3

INFRA_TYPES = ("router", "switch", "ap", "server", "nas", "vm", "camera", "printer", "appliance")


def important_ids(conn: sqlite3.Connection) -> set[int] | None:
    """The ids of the devices marked always-on (and not left out of reports). Only when nothing is marked yet, the infrastructure kinds stand in for it.
    None when no device qualifies at all (then every device counts)."""
    marked = {r["id"] for r in conn.execute("SELECT id FROM devices WHERE report_exclude = 0 AND always_on = 1")}
    if marked:
        return marked
    marks = ",".join("?" * len(INFRA_TYPES))
    ids = {r["id"] for r in conn.execute(f"SELECT id FROM devices WHERE report_exclude = 0 AND COALESCE(type_override, device_type) IN ({marks})", INFRA_TYPES)}
    return ids or None
