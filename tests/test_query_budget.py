"""A page must not ask the database more questions when the network gets bigger.

With the database in the same file a question costs microseconds; with a database server on another machine each one is a round trip, so a page that
runs one query per device or per graph gets slow in exactly the networks that need the server. These tests build a small and a larger network, count
the statements each page runs, and fail when the count grows with the number of devices, monitors or checks (a loop with a query inside), or goes over
the budget below. tools/dbbench.py shows the same numbers, and what they would cost at 0.5 and 2 ms per statement.
"""
import sqlite3
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import dbbench  # noqa: E402

from app.config import load_settings  # noqa: E402
from app.main import create_app  # noqa: E402

SMALL, LARGE = 20, 100
GROWTH = 12            # how many more statements the larger network may need (a page can have a few optional parts)

# page -> most statements it may run on the larger network (the measured count plus a little room)
BUDGET = {
    "/api/session": 6, "/api/devices": 12, "/api/devices/1": 35, "/api/map": 12, "/api/events?limit=100": 6, "/api/uptime?range=24h": 25,
    "/api/service-checks": 10, "/api/probes": 6, "/api/monitors": 18, "/api/dashboard": 165, "/api/stats/summary": 110, "/api/stats?range=7d": 110,
    "/api/reports/availability": 30, "/api/insights": 30, "/api/changes": 10,
}


def count_pages(folder: Path) -> dict[str, int]:
    counted, real = dbbench.counting_connect()
    sqlite3.connect = counted
    try:
        app = create_app(load_settings({"NETLENS_TOKEN": "t", "NETLENS_DATA_DIR": str(folder)}), db_path=folder / "netlens.db")
        out = {}
        with TestClient(app) as client:
            for _label, path in dbbench.PAGES:
                app.state.__dict__.setdefault("stats_cache", {}).clear()
                dbbench.state["delay"], dbbench.state["n"] = 0.0, 0
                r = client.get(path, headers={"Authorization": "Bearer t"})
                assert r.status_code == 200, (path, r.status_code, r.text[:200])
                out[path] = dbbench.state["n"]
        return out
    finally:
        sqlite3.connect = real


@pytest.fixture(scope="module")
def counts(tmp_path_factory):
    result = {}
    for name, devices in (("small", SMALL), ("large", LARGE)):
        folder = tmp_path_factory.mktemp(name)
        dbbench.populate(folder, devices, days=1)
        result[name] = count_pages(folder)
    return result


def test_pages_do_not_ask_more_questions_in_a_bigger_network(counts):
    grown = {p: (counts["small"][p], counts["large"][p]) for p in counts["small"] if counts["large"][p] > counts["small"][p] + GROWTH}
    assert not grown, f"these pages run more statements the more devices there are (small, large): {grown}"


def test_pages_stay_within_their_statement_budget(counts):
    over = {p: (counts["large"][p], BUDGET[p]) for p in counts["large"] if counts["large"][p] > BUDGET[p]}
    assert not over, f"over budget (statements, budget): {over}"
    assert set(counts["large"]) == set(BUDGET)
