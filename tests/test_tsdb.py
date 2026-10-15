import sqlite3

import pytest

from app import tsdb

T0 = 1_800_000_000 // 3600 * 3600        # an hour boundary


@pytest.fixture()
def store(tmp_path):
    tsdb.forget_all()
    s = tsdb.for_path(tmp_path / "netlens.db")
    yield s
    tsdb.forget_all()


def test_store_sits_next_to_the_main_database(tmp_path, store):
    assert store.path == str((tmp_path / "metrics.db").resolve())


def test_in_memory_database_has_no_store():
    conn = sqlite3.connect(":memory:")
    assert tsdb.for_conn(conn) is None


def test_record_and_query_raw(store):
    for i in range(10):
        store.record([("device", 1, "rtt_ms", 10 + i, "", "ms")], ts=T0 + i * 60)
    out = store.query("device", 1, "rtt_ms", span=3600, end=T0 + 600, points=600)
    assert out["unit"] == "ms"
    assert [p[1] for p in out["points"]] == [10 + i for i in range(10)]
    assert out["points"][0][0] == T0
    assert out["step"] == 6                                 # 3600 s over 600 points


def test_bad_values_are_ignored(store):
    n = store.record([("device", 1, "m", None), ("device", 1, "m", "x"), ("device", 1, "m", float("nan")), ("other", 1, "m", 1), ("device", 1, "ok", 1)], ts=T0)
    assert n == 1


def test_labels_are_separate_series(store):
    store.record([("device", 1, "disk_pct", 40, "/", "%"), ("device", 1, "disk_pct", 90, "/data", "%")], ts=T0)
    metrics = store.metrics_of("device", 1)
    assert [(m["label"], m["last"]) for m in metrics] == [("/", 40.0), ("/data", 90.0)]
    assert store.query("device", 1, "disk_pct", "/data", span=600, end=T0 + 5)["points"][0][1] == 90


def test_rollup_keeps_min_avg_max(store):
    for i, v in enumerate([10, 20, 30, 40]):
        store.record([("device", 1, "m", v)], ts=T0 + i * 60)
    store.rollup(now=T0 + 3600)
    # a long range uses the 5-minute tier
    out = store.query("device", 1, "m", span=10 * 86400, end=T0 + 3600, points=600)
    assert out["step"] % 300 == 0
    bucket = T0 // out["step"] * out["step"]
    assert out["points"] == [[bucket, 25.0, 10.0, 40.0]]


def test_newest_part_is_included_before_rollup(store):
    store.record([("device", 1, "m", 10)], ts=T0)
    store.rollup(now=T0 + 3600)                              # T0 is rolled up
    store.record([("device", 1, "m", 30)], ts=T0 + 3600 + 10)  # not yet
    out = store.query("device", 1, "m", span=10 * 86400, end=T0 + 3700, points=600)
    assert [p[1] for p in out["points"]] == [10.0, 30.0]


def test_hourly_tier_for_long_ranges(store):
    for i in range(0, 12):
        store.record([("device", 1, "m", i)], ts=T0 + i * 300)
    store.rollup(now=T0 + 7200)
    out = store.query("device", 1, "m", span=200 * 86400, end=T0 + 7200, points=100)
    assert out["step"] >= 3600
    assert len(out["points"]) == 1
    assert out["points"][0][1] == pytest.approx(5.5)
    assert out["points"][0][2:] == [0.0, 11.0]


def test_rolling_up_twice_does_not_double_count(store):
    for i in range(6):
        store.record([("device", 1, "m", 10)], ts=T0 + 3300 + i * 30)
    store.rollup(now=T0 + 3600)
    store.rollup(now=T0 + 3600)
    store.record([("device", 1, "m", 10)], ts=T0 + 3400)     # a late sample lands in the newest finished bucket
    store.rollup(now=T0 + 7200)
    conn = store._connect()
    n = conn.execute("SELECT n FROM m5 WHERE ts = ?", (T0 + 3300,)).fetchone()["n"]
    conn.close()
    assert n == 7


def test_prune_removes_old_samples_and_empty_series(store):
    store.record([("device", 1, "m", 1)], ts=T0)
    store.prune(now=T0 + tsdb.RAW_SECONDS + 10)
    assert store.metrics_of("device", 1) == []
    store.record([("device", 1, "m", 2)], ts=T0 + tsdb.RAW_SECONDS)   # the series can be created again
    assert store.latest("device", 1, "m") == (T0 + tsdb.RAW_SECONDS, 2.0)


def test_forget_removes_an_entity(store):
    store.record([("device", 1, "m", 1), ("device", 2, "m", 1)], ts=T0)
    store.forget("device", 1)
    assert store.metrics_of("device", 1) == []
    assert len(store.metrics_of("device", 2)) == 1


def test_query_of_unknown_series_is_empty(store):
    out = store.query("device", 9, "nothing")
    assert out["points"] == []


def test_backfill_copies_existing_history_once(tmp_path):
    from app.db import connect, init_db

    tsdb.forget_all()
    main = connect(tmp_path / "netlens.db")
    init_db(main)
    main.execute("INSERT INTO devices (id, mac, primary_ip, online, first_seen, last_seen) VALUES (1, 'aa:00:00:00:00:01', '10.0.0.5', 1, 'x', 'x')")
    main.execute("INSERT INTO service_checks (id, device_id, name, kind, host, port, created) VALUES (1, 1, 'w', 'tcp', '10.0.0.5', 80, 'x')")
    main.executemany("INSERT INTO checks (device_id, ts, up, rtt_ms) VALUES (1, ?, ?, ?)",
                     [("2026-03-10T12:00:00Z", 1, 4.0), ("2026-03-10T12:01:00Z", 0, None)])
    main.execute("INSERT INTO service_results (check_id, ts, up, ms, detail) VALUES (1, '2026-03-10T12:00:00Z', 1, 9.0, 'ok')")
    main.commit()
    store = tsdb.for_conn(main)
    now = 1773144000 + 3600
    assert store.backfill(main, now=now) == 5
    assert store.backfill(main, now=now) == 0                       # only once
    kinds = {(m["metric"]) for m in store.metrics_of("device", 1)}
    assert kinds == {"up", "rtt_ms"}
    out = store.query("device", 1, "up", span=400 * 86400, end=now, points=600)
    assert out["points"] and out["points"][0][1] == 0.5             # the two checks, as one hourly bucket
    tsdb.forget_all()


def test_history_added_after_a_rollup_still_reaches_the_long_tiers(store):
    now = T0 + 40 * 86400
    store.record([("device", 1, "m", 1.0)], ts=now - 60)
    store.rollup(now)                                        # the marks are now at "now"
    rows = [(now - 20 * 86400 + i * 600, "device", 1, "disk_pct", 50 + i / 100, "/", "%") for i in range(2000)]
    store.record_bulk(rows)
    store.rollup(now)
    store.prune(now)
    out = store.query("device", 1, "disk_pct", "/", span=30 * 86400, end=now, points=300)
    assert len(out["points"]) > 50
    assert out["points"][0][1] < out["points"][-1][1]
