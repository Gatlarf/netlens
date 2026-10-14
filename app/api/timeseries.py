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


@router.get("/{entity}/{entity_id}/{metric}")
def history(entity: str, entity_id: int, metric: str, label: str = "", range: str = Query("24h"), points: int = Query(240, ge=10, le=tsdb.MAX_POINTS),
            conn=Depends(get_conn)) -> dict:
    if range not in tsdb.RANGES:
        raise HTTPException(status_code=422, detail=f"range must be one of {', '.join(tsdb.RANGES)}")
    store = _store(conn)
    return store.query(_entity(entity), entity_id, metric, label, span=tsdb.RANGES[range], points=points)
