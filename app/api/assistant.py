"""Access for an AI assistant (see app/assistant.py): the guide it reads, the endpoints it may call, and the tokens it works with."""

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from app import assistant, licence, users
from app.api.devices import get_conn
from app.version import VERSION

router = APIRouter(prefix="/api", tags=["assistant"])


class NewAssistantToken(BaseModel):
    name: str = "AI assistant"
    mode: str = "read"          # read: look only; change: also change settings (needs the licence)


def _mode(request: Request) -> str:
    principal = getattr(request.state, "user", None)
    return getattr(principal, "assistant", None) or ("change" if principal is not None and principal.is_admin else "read")


@router.get("/assistant")
def assistant_status(conn=Depends(get_conn)) -> dict:
    rows = conn.execute("SELECT t.id, t.user_id, t.name, t.created, t.last_used, t.assistant AS mode, u.username FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.assistant IS NOT NULL ORDER BY t.id").fetchall()
    return {"change_allowed": licence.allows(conn, "assistant"), "tokens": [dict(r) for r in rows]}


@router.get("/assistant/guide")
def assistant_guide(request: Request) -> Response:
    """The instructions for an assistant, written for a language model. The address and the mode of the token that asks are filled in."""
    base = f"{request.headers.get('x-forwarded-proto') or request.url.scheme}://{request.headers.get('x-forwarded-host') or request.headers.get('host') or request.url.netloc}"
    return Response(assistant.guide_text(base, _mode(request), VERSION), media_type="text/markdown; charset=utf-8")


@router.get("/assistant/endpoints")
def assistant_endpoints(request: Request) -> dict:
    """Every call this token may make (and, with `allowed: false`, the ones it may not), with the fields of the request body when known."""
    mode = _mode(request)
    return {"mode": mode, "endpoints": assistant.endpoints(request.app.openapi(), mode)}


@router.post("/assistant/token", status_code=201)
def make_assistant_token(request: Request, body: NewAssistantToken, conn=Depends(get_conn)) -> dict:
    principal = getattr(request.state, "user", None)
    if body.mode not in assistant.MODES:
        raise HTTPException(status_code=422, detail="the mode is read or change")
    if principal is None or principal.user_id is None:
        raise HTTPException(status_code=409, detail="sign in with a user account (Settings → Users & tokens) to make an assistant token")
    if body.mode == "change" and not licence.allows(conn, "assistant"):
        raise HTTPException(status_code=402, detail="a token that may change settings needs a licence or the free trial (Settings → Licence); a read-only token is free")
    try:
        token_id, secret = users.create_api_token(conn, principal.user_id, body.name or "AI assistant", assistant=body.mode)
    except users.UserError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"id": token_id, "token": secret, "mode": body.mode, "guide": "/api/assistant/guide"}
