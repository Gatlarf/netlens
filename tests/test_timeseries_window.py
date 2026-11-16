"""Graph zoom (an explicit start and end) and the correlation of two measurements."""
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import tsdb
from app.api.timeseries import pearson
from app.config import load_settings
from app.main import create_app


@pytest.fixture
def client(tmp_path):
    tsdb.forget_all()
    app = create_app(load_settings({"NETLENS_TOKEN": "t", "NETLENS_DATA_DIR": str(tmp_path)}), db_path=tmp_path / "netlens.db")
    with TestClient(app) as c:
        c.headers["Authorization"] = "Bearer t"
        yield c, tmp_path
    tsdb.forget_all()


def fill(tmp_path, now, opposite=False):
    """An hour with one reading a minute: the load of device 1 and the response time of device 2 rise together (or, with `opposite`, against each other)."""
    from app.db import connect

    conn = connect(tmp_path / "netlens.db")
    try:
        store = tsdb.for_conn(conn)
        rows = []
        for i in range(60):
            t = now - 3600 + i * 60
            rows.append((t, "device", 1, "cpu_pct", 20 + i, "", "%"))
            rows.append((t, "device", 2, "rtt_ms", (65 - i if opposite else 5 + i) * 0.5, "eth0", "ms"))
        store.record_bulk(rows)
    finally:
        conn.close()


def test_pearson():
    assert pearson([(i, i * 2) for i in range(10)])["r"] == 1.0
    assert pearson([(i, -i) for i in range(10)])["r"] == -1.0
    assert pearson([(i, 5) for i in range(10)])["r"] is None            # one of them never changes
    assert pearson([(1, 1), (2, 2)])["r"] is None and pearson([(1, 1), (2, 2)])["n"] == 2
    line = pearson([(i, 3 * i + 1) for i in range(10)])
    assert round(line["slope"], 6) == 3 and round(line["intercept"], 6) == 1


def test_a_zoomed_period_is_validated(client):
    c, _dir = client
    assert c.get("/api/timeseries/device/1/cpu_pct?start=1000").status_code == 422                       # both or none
    assert c.get("/api/timeseries/device/1/cpu_pct?start=1000&end=1100").status_code == 422              # shorter than five minutes
    assert c.get(f"/api/timeseries/device/1/cpu_pct?start=0&end={400 * 86400}").status_code == 422        # longer than a year
    assert c.get("/api/timeseries/device/1/cpu_pct?range=bogus").status_code == 422
    now = int(time.time())
    ok = c.get(f"/api/timeseries/device/1/cpu_pct?start={now - 1800}&end={now}")
    assert ok.status_code == 200 and ok.json()["start"] == now - 1800 and ok.json()["end"] == now


def test_correlate_needs_two_wellformed_references(client):
    c, _dir = client
    assert c.get("/api/timeseries/correlate?x=device:1:cpu_pct").status_code == 422
    assert c.get("/api/timeseries/correlate?x=nonsense&y=device:1:cpu_pct").status_code == 422
    assert c.get("/api/timeseries/correlate?x=bogus:1:cpu_pct&y=device:1:cpu_pct").status_code == 404
    r = c.get("/api/timeseries/correlate?x=device:1:cpu_pct&y=device:2:rtt_ms:eth0&range=24h")
    assert r.status_code == 200 and r.json()["pairs"] == [] and r.json()["r"] is None                    # nothing recorded yet: an empty answer, not an error


def test_two_measurements_are_paired_by_time_and_correlated(client):
    c, tmp = client
    now = int(time.time())
    fill(tmp, now)
    r = c.get(f"/api/timeseries/correlate?x=device:1:cpu_pct&y=device:2:rtt_ms:eth0&start={now - 3600}&end={now}").json()
    assert r["n"] >= 30 and r["r"] > 0.99 and r["x"]["unit"] == "%" and r["y"]["unit"] == "ms"
    assert all(len(p) == 3 for p in r["pairs"]) and r["pairs"] == sorted(r["pairs"])
    assert r["slope"] > 0
    fill(tmp, now, opposite=True)
    assert c.get(f"/api/timeseries/correlate?x=device:1:cpu_pct&y=device:2:rtt_ms:eth0&start={now - 3600}&end={now}").json()["r"] < -0.99
    other = c.get(f"/api/timeseries/correlate?x=device:1:cpu_pct&y=device:1:missing&start={now - 3600}&end={now}").json()
    assert other["pairs"] == [] and other["r"] is None                     # a measurement that does not exist pairs with nothing


def test_a_viewer_may_correlate_and_a_customer_view_may_not(client):
    from app import auth

    assert auth.VIEWER_READABLE.match("/api/timeseries/correlate")
    assert not auth.SCOPED_READABLE.match("/api/timeseries/correlate")         # two devices could belong to different customers


def test_the_graph_cards_share_one_group_and_the_tools_are_wired():
    js = Path(__file__).resolve().parent.parent / "app" / "static" / "js"
    graph = (js / "timegraph.js").read_text(encoding="utf-8")
    assert "static shared(name)" in graph and "onSelect: (win) => mine.zoomTo(win)" in graph and "mine.hover(t, box)" in graph
    for card, name in (("performance.js", "perf:"), ("device_ports.js", "ports:")):
        text = (js / "cards" / card).read_text(encoding="utf-8")
        assert "GraphGroup.shared(" in text and name in text and "group.bar()" in text and "graphRangeTabs(group.range" in text
    tools = (js / "graphtools.js").read_text(encoding="utf-8")
    assert "export function chooseOverlay" in tools and "export async function openCorrelate" in tools and "/api/timeseries/correlate" in tools
