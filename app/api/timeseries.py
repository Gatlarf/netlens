"""Graph data: which measurements exist for a device or service check, and their history."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app import tsdb
from app.api.devices import get_conn

router = APIRouter(prefix="/api/timeseries", tags=["timeseries"])


def _store(conn) -> tsdb.Store:
    store = tsdb.for_conn(conn)
    if store is None:
        raise HTTPException(status_code=404, detail="no metrics store")
    return store


def _entity(entity: str) -> str:
    if entity not in tsdb.ENTITIES:
        raise HTTPException(status_code=404, detail="unknown entity")
    return entity


@router.get("/{entity}/{entity_id}")
def series(entity: str, entity_id: int, conn=Depends(get_conn)) -> dict:
    """The measurements of one device / check / probe, with the newest value of each."""
    store = _store(conn)
    return {"entity": _entity(entity), "entity_id": entity_id, "series": store.metrics_of(entity, entity_id), "ranges": list(tsdb.RANGES)}


MIN_WINDOW = 300                      # the shortest period a graph can be asked for (seconds)
MAX_WINDOW = 366 * 86400


def _window(range: str, start: int | None, end: int | None) -> tuple[int, int | None]:
    """(span, end) from a named range, or from an explicit start and end (a graph that was zoomed in on)."""
    if start is None and end is None:
        if range not in tsdb.RANGES:
            raise HTTPException(status_code=422, detail=f"range must be one of {', '.join(tsdb.RANGES)}")
        return tsdb.RANGES[range], None
    if start is None or end is None:
        raise HTTPException(status_code=422, detail="give both start and end")
    if end - start < MIN_WINDOW:
        raise HTTPException(status_code=422, detail=f"the period must be at least {MIN_WINDOW // 60} minutes")
    if end - start > MAX_WINDOW:
        raise HTTPException(status_code=422, detail="the period can be at most a year")
    return int(end - start), int(end)


@router.get("/{entity}/{entity_id}/{metric}")
def history(entity: str, entity_id: int, metric: str, label: str = "", range: str = Query("24h"), points: int = Query(240, ge=10, le=tsdb.MAX_POINTS),
            start: int | None = Query(None, ge=0), end: int | None = Query(None, ge=0), conn=Depends(get_conn)) -> dict:
    """One measurement over the last `range`, or between `start` and `end` (epoch seconds) when a graph is zoomed in."""
    span, until = _window(range, start, end)
    store = _store(conn)
    return store.query(_entity(entity), entity_id, metric, label, span=span, end=until, points=points)


def _ref(text: str, name: str) -> tuple[str, int, str, str]:
    """'device:12:cpu_pct' or 'device:12:if_util_pct:eth0' -> (entity, id, metric, label)."""
    parts = text.split(":", 3)
    if len(parts) < 3 or not parts[1].isdigit():
        raise HTTPException(status_code=422, detail=f"{name} must look like device:12:cpu_pct (an optional :label may follow)")
    return _entity(parts[0]), int(parts[1]), parts[2], parts[3] if len(parts) > 3 else ""


def pearson(pairs: list[tuple[float, float]]) -> dict:
    """Correlation of paired readings: r from -1 to 1 (None when there are too few pairs or one of the two never changes), and the straight line that fits them."""
    n = len(pairs)
    out: dict = {"n": n, "r": None, "slope": None, "intercept": None}
    if n < 8:
        return out
    mx, my = sum(p[0] for p in pairs) / n, sum(p[1] for p in pairs) / n
    sxx = sum((p[0] - mx) ** 2 for p in pairs)
    syy = sum((p[1] - my) ** 2 for p in pairs)
    sxy = sum((p[0] - mx) * (p[1] - my) for p in pairs)
    if sxx <= 1e-12 or syy <= 1e-12:
        return out
    out.update(r=round(sxy / (sxx * syy) ** 0.5, 3), slope=sxy / sxx, intercept=my - sxy / sxx * mx)
    return out


@router.get("/correlate")
def correlate(x: str, y: str, range: str = Query("24h"), start: int | None = Query(None, ge=0), end: int | None = Query(None, ge=0), conn=Depends(get_conn)) -> dict:
    """Two measurements (of the same or of different devices) paired by time over one period, for a scatter plot: [[t, x, y], ...] and how strongly they move together."""
    span, until = _window(range, start, end)
    store = _store(conn)
    refs = [_ref(x, "x"), _ref(y, "y")]
    # both are asked for the same period and the same number of points, so they come back in the same time steps
    got = [store.query(e, i, m, lbl, span=span, end=until, points=240) for e, i, m, lbl in refs]
    by_t = [{p[0]: p[1] for p in g["points"]} for g in got]
    pairs = [(t, by_t[0][t], by_t[1][t]) for t in sorted(by_t[0]) if t in by_t[1]]
    stats = pearson([(a, b) for _t, a, b in pairs])
    return {"x": {"ref": x, "unit": got[0]["unit"]}, "y": {"ref": y, "unit": got[1]["unit"]}, "start": got[0]["start"], "end": got[0]["end"], "step": got[0]["step"], "pairs": [list(p) for p in pairs], **stats}
