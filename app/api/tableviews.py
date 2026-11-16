"""Saved views of the Devices table (the same machinery can serve another table: add its columns to app/tableviews.py)."""
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app import tableviews
from app.api.devices import get_conn

router = APIRouter(prefix="/api", tags=["table views"])


class MineBody(BaseModel):
    views: list[dict[str, Any]] = []
    active: str | None = None


class SharedBody(BaseModel):
    views: list[dict[str, Any]] = []


def _table(table: str) -> str:
    try:
        tableviews.check_table(table)
    except ValueError:
        raise HTTPException(status_code=404, detail="unknown table")
    return table


@router.get("/me/table-views/{table}")
def get_views(table: str, request: Request, conn=Depends(get_conn)) -> dict:
    """My views, the shared ones and the open one, with the columns the table offers."""
    _table(table)
    return {**tableviews.mine(conn, request.state.user, table), "shared": tableviews.shared(conn, table), "columns": list(tableviews.COLUMNS[table]), "locked": list(tableviews.LOCKED[table])}


@router.put("/me/table-views/{table}")
def put_views(table: str, body: MineBody, request: Request, conn=Depends(get_conn)) -> dict:
    _table(table)
    try:
        return tableviews.put_mine(conn, request.state.user, table, body.views, body.active)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.put("/table-views/{table}/shared")
def put_shared(table: str, body: SharedBody, conn=Depends(get_conn)) -> dict:
    """Administrators: the views everybody sees."""
    _table(table)
    try:
        return {"shared": tableviews.put_shared(conn, table, body.views)}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
