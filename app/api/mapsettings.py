from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.db import connect, get_setting, set_setting

KEY = "map_default_layout"
LAYOUTS = ("free", "tree", "horizontal")
DEFAULT_LAYOUT = "free"

router = APIRouter(prefix="/api", tags=["map"])


def default_layout(conn) -> str:
    value = get_setting(conn, KEY)
    return value if value in LAYOUTS else DEFAULT_LAYOUT


class MapSettingsBody(BaseModel):
    default_layout: Literal["free", "tree", "horizontal"]


@router.get("/map-settings")
def get_map_settings(request: Request) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        return {"default_layout": default_layout(conn), "layouts": list(LAYOUTS)}
    finally:
        conn.close()


@router.put("/map-settings")
def put_map_settings(request: Request, body: MapSettingsBody) -> dict:
    """The layout the map opens with in browsers where nobody picked one in the map's own layout menu."""
    conn = connect(request.app.state.db_path)
    try:
        set_setting(conn, KEY, body.default_layout)
        return {"default_layout": default_layout(conn), "layouts": list(LAYOUTS)}
    finally:
        conn.close()
