"""The key that protects the stored passwords: its state, and a way to keep a copy of it and to put it back after a restore."""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app import vault
from app.api.devices import get_conn
from app.terminal.access import classify

router = APIRouter(prefix="/api", tags=["vault"])


def _local_only(request: Request) -> None:
    allowed, why = classify(request, "off")       # the key is as sensitive as a shell: never through a proxy or from outside
    if not allowed:
        raise HTTPException(status_code=403, detail=f"the encryption key can only be shown or changed on a direct connection from the local network: {why}")


@router.get("/vault")
def get_status(conn=Depends(get_conn)) -> dict:
    return vault.status(conn)


@router.get("/vault/key")
def get_key(request: Request, conn=Depends(get_conn)) -> dict:
    _local_only(request)
    if vault.key_source(conn) != "file":
        raise HTTPException(status_code=409, detail="the key comes from NETLENS_SECRET_KEY: keep it where you set it")
    return {"key": vault.encode_key(vault._key(conn))}


class KeyBody(BaseModel):
    key: str | None = None
    passphrase: str | None = None      # the recovery passphrase: the key stored (wrapped) in the restored database


class RecoveryBody(BaseModel):
    passphrase: str


def _install(conn, raw: bytes) -> dict:
    from pathlib import Path

    path = Path(vault._db_file(conn)).parent / vault.KEY_FILE
    path.write_text(vault.encode_key(raw) + "\n")
    path.chmod(0o600)
    vault.forget_cached_key(conn)
    return vault.status(conn)


@router.put("/vault/key")
def put_key(body: KeyBody, request: Request, conn=Depends(get_conn)) -> dict:
    """Use this key, or the one the recovery passphrase unlocks (after restoring a backup on another machine). Refused while the current key
    still reads everything."""
    _local_only(request)
    if vault.key_source(conn) != "file":
        raise HTTPException(status_code=409, detail="the key comes from NETLENS_SECRET_KEY")
    if not body.key and not body.passphrase:
        raise HTTPException(status_code=422, detail="give the key or the recovery passphrase")
    state = vault.status(conn)
    if state["unreadable"] == 0 and state["encrypted"] > 0:
        raise HTTPException(status_code=409, detail="the current key reads every stored password; replacing it would lose them")
    try:
        raw = vault.recover(conn, body.passphrase) if body.passphrase else vault.parse_key(body.key)
    except vault.VaultError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _install(conn, raw)


@router.put("/vault/recovery")
def put_recovery(body: RecoveryBody, request: Request, conn=Depends(get_conn)) -> dict:
    """Set the recovery passphrase: from then on every backup carries the key, wrapped with it."""
    _local_only(request)
    if len(body.passphrase) < 8:
        raise HTTPException(status_code=422, detail="the passphrase needs at least 8 characters")
    vault.set_recovery(conn, body.passphrase)
    return vault.status(conn)
