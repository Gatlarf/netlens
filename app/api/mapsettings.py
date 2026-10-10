import re
from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, field_validator, model_validator

from app.db import connect, get_setting, set_setting

KEY = "map_default_layout"
SUFFIX_KEY = "domain_suffix"
GUESTS_KEY = "map_show_guests"
_SUFFIX_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
LAYOUTS = ("free", "tree", "horizontal")
DEFAULT_LAYOUT = "free"

router = APIRouter(prefix="/api", tags=["map"])


def default_layout(conn) -> str:
    value = get_setting(conn, KEY)
    return value if value in LAYOUTS else DEFAULT_LAYOUT


def domain_suffix(conn) -> str:
    return get_setting(conn, SUFFIX_KEY) or ""


def show_guests(conn) -> bool:
    """Whether containers and apps without a device of their own are drawn under their host (virtual machines are devices already)."""
    return get_setting(conn, GUESTS_KEY) == "1"


def _view(conn) -> dict:
    return {"default_layout": default_layout(conn), "layouts": list(LAYOUTS), "domain_suffix": domain_suffix(conn), "show_guests": show_guests(conn)}


class MapSettingsBody(BaseModel):
    default_layout: Literal["free", "tree", "horizontal"] | None = None
    domain_suffix: str | None = None
    show_guests: bool | None = None

    @field_validator("domain_suffix")
    @classmethod
    def _clean_suffix(cls, value):
        if value is None:
            return None
        value = value.strip().lower().strip(".")
        if value and (len(value) > 253 or not _SUFFIX_RE.match(value)):
            raise ValueError("enter a domain like home.example.com")
        return value

    @model_validator(mode="after")
    def _something_to_save(self):
        if self.default_layout is None and self.domain_suffix is None and self.show_guests is None:
            raise ValueError("nothing to save")
        return self


@router.get("/map-settings")
def get_map_settings(request: Request) -> dict:
    conn = connect(request.app.state.db_path)
    try:
        return _view(conn)
    finally:
        conn.close()


@router.put("/map-settings")
def put_map_settings(request: Request, body: MapSettingsBody) -> dict:
    """The layout the map opens with in browsers where nobody picked one, and the domain suffix hidden in displayed names."""
    conn = connect(request.app.state.db_path)
    try:
        if body.default_layout is not None:
            set_setting(conn, KEY, body.default_layout)
        if body.domain_suffix is not None:
            set_setting(conn, SUFFIX_KEY, body.domain_suffix)
        if body.show_guests is not None:
            set_setting(conn, GUESTS_KEY, "1" if body.show_guests else "0")
        return _view(conn)
    finally:
        conn.close()
