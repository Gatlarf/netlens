from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app import licence, shares
from app.db import connect

router = APIRouter(prefix="/api", tags=["shares"])

NEEDS_LICENCE = "limiting a link to some groups, or giving it your own brand name or colour, is part of the Small business and Enterprise editions (or the free trial): Settings → Licence"


class NewShare(BaseModel):
    name: str
    mode: str = "view"
    show_ips: bool = False
    show_macs: bool = False
    expires_days: int | None = None
    valid_from: str | None = None
    pin: str | None = None
    options: dict | None = None            # sections, service_ids, group_ids, fields, generic_names, event_limit, uptime_days, title, message, brand, accent, theme


class SharePatch(BaseModel):
    name: str | None = None
    show_ips: bool | None = None
    show_macs: bool | None = None
    expires_days: int | None = None        # only applied when sent: null = no end
    valid_from: str | None = None          # only applied when sent: null = from now on
    pin: str | None = None                 # "" removes the PIN, null leaves it
    options: dict | None = None
    new_token: bool = False                # a new address; the old one stops working


def _db(request: Request):
    return connect(request.app.state.db_path)


def _listing(conn) -> dict:
    return {"links": shares.list_links(conn), **shares.choices(conn), "sharing_allowed": licence.allows(conn, "sharing")}


def _paid_part(options: dict) -> tuple:
    return (tuple(options.get("group_ids") or ()), options.get("brand") or "", options.get("accent") or "")


def _check_licence(conn, options: dict | None, current: dict | None = None) -> None:
    """Customer scope and white label are business features. Existing links keep working; only setting or changing them asks for a licence."""
    if options is None:
        return
    try:
        clean = shares.clean_options(conn, options)
    except shares.ShareError:
        return  # the real error is reported when the options are saved
    if shares.uses_branding_or_scope(clean) and (current is None or _paid_part(clean) != _paid_part(current)) and not licence.allows(conn, "sharing"):
        raise HTTPException(status_code=402, detail=NEEDS_LICENCE)


@router.get("/shares")
def get_shares(request: Request) -> dict:
    conn = _db(request)
    try:
        return _listing(conn)
    finally:
        conn.close()


@router.post("/shares", status_code=201)
def add_share(request: Request, body: NewShare) -> dict:
    conn = _db(request)
    try:
        _check_licence(conn, body.options)
        try:
            link_id = shares.create(conn, body.name, body.mode, body.show_ips, body.show_macs, body.expires_days, body.options, body.pin, body.valid_from)
        except shares.ShareError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        return {"id": link_id, **_listing(conn)}
    finally:
        conn.close()


@router.patch("/shares/{link_id}")
def change_share(request: Request, link_id: int, body: SharePatch) -> dict:
    conn = _db(request)
    try:
        changes = {k: getattr(body, k) for k in body.model_fields_set}
        row = conn.execute("SELECT * FROM share_links WHERE id = ?", (link_id,)).fetchone()
        _check_licence(conn, changes.get("options"), shares.options_of(row) if row else None)
        try:
            shares.update(conn, link_id, changes)
        except shares.ShareError as exc:
            raise HTTPException(status_code=404 if str(exc).startswith("no such") else 422, detail=str(exc))
        return _listing(conn)
    finally:
        conn.close()


@router.delete("/shares/{link_id}")
def remove_share(request: Request, link_id: int) -> dict:
    conn = _db(request)
    try:
        try:
            shares.delete(conn, link_id)
        except shares.ShareError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        return _listing(conn)
    finally:
        conn.close()
