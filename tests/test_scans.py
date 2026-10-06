import pytest
from app.db import connect, init_db
from app.scanner.scans import create_scan, finish_scan, list_scans, running_scan


@pytest.fixture
def db():
    conn = connect(":memory:")
    init_db(conn)
    yield conn
    conn.close()


def test_create_scan_sets_status_running_and_finished_none(db):
    scan_id = create_scan(db, 'quick')
    assert scan_id is not None
    scan = list_scans(db, limit=1)[0]
    assert scan["id"] == scan_id
    assert scan["status"] == "running"
    assert scan["finished"] is None


def test_finish_scan_done_sets_finished_and_hosts_found(db):
    scan_id = create_scan(db, 'quick')
    finish_scan(db, scan_id, status="done", hosts_found=5)
    scan = list_scans(db, limit=1)[0]
    assert scan["id"] == scan_id
    assert scan["status"] == "done"
    assert scan["finished"] is not None
    assert scan["hosts_found"] == 5


def test_finish_scan_failed_stores_error(db):
    scan_id = create_scan(db, 'quick')
    finish_scan(db, scan_id, status="failed", error="timeout")
    scan = list_scans(db, limit=1)[0]
    assert scan["id"] == scan_id
    assert scan["status"] == "failed"
    assert scan["finished"] is not None
    assert scan["error"] == "timeout"


def test_finish_scan_invalid_status_raises_value_error(db):
    scan_id = create_scan(db, 'quick')
    with pytest.raises(ValueError):
        finish_scan(db, scan_id, status="invalid")


def test_finish_scan_unknown_id_raises_key_error(db):
    scan_id = create_scan(db, 'quick')
    with pytest.raises(KeyError):
        finish_scan(db, 9999, status="done", hosts_found=0)


def test_list_scans_newest_first(db):
    first_id = create_scan(db, 'quick')
    second_id = create_scan(db, 'quick')
    scans = list_scans(db)
    assert len(scans) == 2
    assert scans[0]["id"] == second_id
    assert scans[1]["id"] == first_id


def test_list_scans_honours_limit(db):
    for _ in range(5):
        create_scan(db, 'quick')
    scans = list_scans(db, limit=3)
    assert len(scans) == 3
    assert scans[0]["id"] == 5
    assert scans[1]["id"] == 4
    assert scans[2]["id"] == 3


def test_running_scan_returns_none_when_all_finished(db):
    scan_id = create_scan(db, 'quick')
    finish_scan(db, scan_id, status="done", hosts_found=0)
    assert running_scan(db) is None


def test_running_scan_returns_newest_running_one(db):
    first_id = create_scan(db, 'quick')
    second_id = create_scan(db, 'quick')
    finish_scan(db, first_id, status="done", hosts_found=0)
    result = running_scan(db)
    assert result is not None
    assert result["id"] == second_id
    assert result["status"] == "running"