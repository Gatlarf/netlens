import logging

from app import db, tsdb


def test_a_connection_knows_its_file_without_asking(tmp_path):
    conn = db.connect(tmp_path / "n.db")
    seen = []
    conn.set_trace_callback(seen.append)
    assert db.main_file(conn) == str((tmp_path / "n.db").resolve())
    assert tsdb.db_file(conn) == db.main_file(conn)
    assert not seen, "asking for the file must not run a statement"


def test_an_in_memory_connection_has_no_file():
    assert db.main_file(db.connect(":memory:")) == ""


def test_metrics_of_many_matches_metrics_of(tmp_path):
    conn = db.connect(tmp_path / "n.db")
    db.init_db(conn)
    store = tsdb.for_conn(conn)
    store.record([("device", 1, "cpu_pct", 12.0, "", "%"), ("device", 1, "net_rx_bps", 5.0, "eth0", "bps"), ("device", 2, "cpu_pct", 40.0, "", "%"), ("service", 1, "cert_days", 30.0, "", "d")], ts=1_000_000)
    store.record([("device", 1, "cpu_pct", 15.0, "", "%")], ts=1_000_060)
    many = store.metrics_of_many("device", [1, 2, 3])
    assert set(many) == {1, 2}
    assert many[1] == store.metrics_of("device", 1)
    assert [s["last"] for s in many[1] if s["metric"] == "cpu_pct"] == [15.0]          # the newest reading, not the first
    assert many[2][0]["last_ts"] == 1_000_000
    assert store.metrics_of_many("device") == many                                      # None = every device
    assert store.metrics_of("device", 99) == []
    assert list(store.metrics_of_many("service", [1])) == [1]


def test_metrics_of_many_takes_a_long_list(tmp_path):
    conn = db.connect(tmp_path / "n.db")
    db.init_db(conn)
    store = tsdb.for_conn(conn)
    store.record([("device", i, "cpu_pct", float(i), "", "%") for i in range(1, 1201)], ts=1_000_000)
    got = store.metrics_of_many("device", range(1, 1201))
    assert len(got) == 1200 and got[777][0]["last"] == 777.0


def test_the_slow_query_log_names_the_statement(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("NETLENS_SLOW_QUERY_MS", "0.0001")
    conn = db.connect(tmp_path / "n.db")
    with caplog.at_level(logging.WARNING, logger="netlens.slowquery"):
        conn.execute("SELECT 1 AS   one")
    assert any("SELECT 1 AS one" in r.getMessage() and " ms at " in r.getMessage() for r in caplog.records)


def test_the_slow_query_log_is_off_by_default(tmp_path, monkeypatch, caplog):
    monkeypatch.delenv("NETLENS_SLOW_QUERY_MS", raising=False)
    conn = db.connect(tmp_path / "n.db")
    assert type(conn) is db.Connection
    with caplog.at_level(logging.WARNING, logger="netlens.slowquery"):
        conn.execute("SELECT 1")
    assert not caplog.records
