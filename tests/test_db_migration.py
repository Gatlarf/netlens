import sqlite3

from app.db import SCHEMA_VERSION, connect, get_or_create_device, init_db


def test_v1_database_is_migrated(tmp_path):
    path = tmp_path / "old.db"
    conn = connect(path)
    init_db(conn)
    device_id = get_or_create_device(conn, "aa:bb:cc:dd:ee:01", "192.168.1.5")
    # turn it back into a v1 database
    conn.execute("ALTER TABLE devices DROP COLUMN notify_offline")
    conn.execute("DROP TABLE checks")
    conn.execute("DROP TABLE proxmox_guests")
    conn.execute("UPDATE schema_version SET version = 1")
    conn.commit()
    conn.close()

    conn = connect(path)
    init_db(conn)
    assert conn.execute("SELECT version FROM schema_version").fetchone()[0] == SCHEMA_VERSION
    row = conn.execute("SELECT notify_offline FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["notify_offline"] == 1  # existing devices default to notifying
    conn.execute("SELECT * FROM checks").fetchall()
    conn.execute("SELECT * FROM proxmox_guests").fetchall()
    init_db(conn)  # idempotent
    conn.close()
