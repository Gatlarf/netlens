from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app import shares
from app.db import connect

router = APIRouter(prefix="/api", tags=["shares"])


class NewShare(BaseModel):
    name: str
    mode: str = "view"
    show_ips: bool = False
    show_macs: bool = False
    expires_days: int | None = None


@router.get("/shares")
def get_shares(request: Request) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        return {"links": shares.list_links(conn)}
    finally:
        conn.close()


@router.post("/shares", status_code=201)
def add_share(request: Request, body: NewShare) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        try:
            link_id = shares.create(conn, body.name, body.mode, body.show_ips, body.show_macs, body.expires_days)
        except shares.ShareError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        return {"id": link_id, "links": shares.list_links(conn)}
    finally:
        conn.close()


@router.delete("/shares/{link_id}")
def remove_share(request: Request, link_id: int) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        try:
            shares.delete(conn, link_id)
        except shares.ShareError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        return {"links": shares.list_links(conn)}
    finally:
        conn.close()
