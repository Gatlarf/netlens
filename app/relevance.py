"""Which devices matter: the ones that should always be on. A phone going offline is not news."""

from __future__ import annotations

import sqlite3

INFRA_TYPES = ("router", "switch", "ap", "server", "nas", "vm", "camera", "printer", "appliance")


def important_ids(conn: sqlite3.Connection) -> set[int] | None:
    """The ids of the devices marked always-on or of an infrastructure kind (and not left out of reports), or None when no device qualifies (then every device counts)."""
    marks = ",".join("?" * len(INFRA_TYPES))
    ids = {r["id"] for r in conn.execute(f"SELECT id FROM devices WHERE report_exclude = 0 AND (always_on = 1 OR COALESCE(type_override, device_type) IN ({marks}))", INFRA_TYPES)}
    return ids or None
