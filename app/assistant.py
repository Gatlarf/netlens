"""Access for an AI assistant: a token that can read, or read and change settings, but cannot do the dangerous things.

An assistant (Claude, ChatGPT, a local model with tools) that helps with setup or changes talks to the normal API with its own token. The token is made in
Settings → AI assistant. `read` can only look; `change` can also change settings (a paid feature, like other business conveniences) and is cut back to `read` when the
licence ends. Neither can touch users, tokens, stored secrets, sharing links, single sign-on, backups and restores, the terminal and remote sessions, or the licence,
and a `change` token cannot create or edit remediation rules (they run commands), upload a plugin, apply a Netlens update or delete most things. Every change is in the
audit log under the name of the token. The guide it is pointed to (assistant_guide.md) tells it to ask the person before changing anything.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from fastapi import HTTPException

from app import licence

GUIDE = Path(__file__).resolve().parent / "assistant_guide.md"
MODES = ("read", "change")
# nothing here, not even to read: secrets, accounts, ways to run commands, ways to take everything
NEVER = re.compile(r"^/api/(users|roles|tls|cert-login|approvals|vault|shares|sso|backup|restore|auth|setup|login|logout|me|assistant/token|terminal|remote|central|mcp|ingest)(/|$)")
# reading is fine, changing is not
READ_ONLY_FOR_CHANGE = re.compile(r"^/api/(licence|remediation|engineer|update|backups|siem|documentation|probes/[^/]+/token)(/|$)")
DELETABLE = re.compile(r"^/api/((service-checks|maintenance|notify-channels|groups)/[^/]+|snoozes)$")      # snoozes are ended with DELETE /api/snoozes?subject=...
WHY = {
    "never": "an assistant token may not use this part of Netlens (accounts, secrets, backups, remote sessions and sharing are for people)",
    "read": "this token can only read; ask the person to create a token that may change settings (Settings → AI assistant)",
    "write": "an assistant may not change this part of Netlens; tell the person what to do and let them do it in the interface",
    "delete": "an assistant may only delete service checks, maintenance windows, snoozes, notification channels and groups; ask the person to delete other things",
}


def effective_mode(conn: sqlite3.Connection, stored: str, role: str) -> str:
    """A change token needs an administrator behind it and a licence; otherwise it can only read."""
    if stored == "change" and role == "admin" and licence.allows(conn, "assistant"):
        return "change"
    return "read"


def check(method: str, path: str, mode: str) -> None:
    """Raise 403 (with a reason the assistant can read out) when this token may not make this request."""
    if NEVER.match(path):
        raise HTTPException(status_code=403, detail=WHY["never"])
    if method in ("GET", "HEAD"):
        return
    if mode != "change":
        raise HTTPException(status_code=403, detail=WHY["read"])
    if READ_ONLY_FOR_CHANGE.match(path) or (method == "POST" and path == "/api/plugins"):
        raise HTTPException(status_code=403, detail=WHY["write"])
    if method == "DELETE" and not DELETABLE.match(path):
        raise HTTPException(status_code=403, detail=WHY["delete"])


def guide_text(base_url: str, mode: str, version: str) -> str:
    text = GUIDE.read_text(encoding="utf-8")
    return text.replace("{{base_url}}", base_url.rstrip("/")).replace("{{mode}}", mode).replace("{{version}}", version)


def endpoints(openapi: dict, mode: str) -> list[dict]:
    """What this token can call: method, path, summary and the fields of a JSON body when the API describes them."""
    schemas = (openapi.get("components") or {}).get("schemas") or {}
    out = []
    for path, ops in sorted(openapi.get("paths", {}).items()):
        if not path.startswith("/api/"):
            continue
        for method, op in ops.items():
            method = method.upper()
            if method not in ("GET", "POST", "PUT", "PATCH", "DELETE") or NEVER.match(path):
                continue
            can = method == "GET" or (mode == "change" and not READ_ONLY_FOR_CHANGE.match(path) and not (method == "POST" and path == "/api/plugins")
                                      and (method != "DELETE" or DELETABLE.match(path)))
            item = {"method": method, "path": path, "summary": op.get("summary") or "", "allowed": bool(can)}
            ref = (((op.get("requestBody") or {}).get("content") or {}).get("application/json") or {}).get("schema", {}).get("$ref", "")
            fields = (schemas.get(ref.rsplit("/", 1)[-1]) or {}).get("properties") if ref else None
            if fields:
                required = set((schemas.get(ref.rsplit("/", 1)[-1]) or {}).get("required") or [])
                item["body"] = {k: (v.get("type") or "any") + (" (required)" if k in required else "") for k, v in fields.items()}
            out.append(item)
    return out
