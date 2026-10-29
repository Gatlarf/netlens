"""Delinea Secret Server (on premises, or Secret Server Cloud).

NOT TESTED ON A REAL SYSTEM. Written from Delinea's REST API documentation (OAuth2 password grant at `/oauth2/token`, `GET /api/v1/secrets/{id}`, `POST
/api/v1/secrets/{id}/check-in`) and tested against a stand-in (tests/fake_delinea.py) that follows it. The parts most likely to differ on a real server are marked
"verify" below: how a secret that requires check-out or a comment is read, and the exact name of the comment parameter.

Netlens signs in as an **application user** (a normal Secret Server user with a long random password, no interactive use, allowed from the Netlens address and given
*View* on the folders that hold the monitoring and access accounts, nothing else). It reads one secret by its numeric id, takes the user name and password (or private
key) from the secret's fields, and, if Secret Server checked the secret out for it, checks it in again shortly after (see `pam.release_later`).
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any

from app import pam
from app.pam import PamError, http

_FIELDS = {"username": ("username", "user-name", "login"), "password": ("password",), "private_key": ("private-key", "privatekey", "private-key-pem"), "passphrase": ("private-key-passphrase", "passphrase"),
           "domain": ("domain",)}


class SecretServer:
    name = "delinea_ss"
    title = "Delinea Secret Server - not tested on a real system"
    holds = True

    @staticmethod
    def validate(entry: dict) -> None:
        http.base_url(entry.get("url"), "the address of Secret Server")
        if not re.fullmatch(r"\d{1,9}", str(entry.get("secret_id_ref") or "")):
            raise PamError("the secret id is the number in the secret's address (…/secrets/1234)")
        if not entry.get("app_user") or not entry.get("app_password"):
            raise PamError("give Netlens its Secret Server application user and password")
        if entry.get("app_domain") and not re.fullmatch(r"[\w.\-]{1,100}", str(entry["app_domain"])):
            raise PamError("the domain of the application user is not valid")

    @staticmethod
    def where(entry: dict) -> str:
        return f"secret {entry.get('secret_id_ref') or ''}"

    @staticmethod
    def public(entry: dict) -> dict:
        return {"secret_id_ref": entry.get("secret_id_ref", ""), "app_user": entry.get("app_user", ""), "app_domain": entry.get("app_domain", ""), "has_ca": bool(entry.get("ca_cert")), "auth": "application user"}

    @staticmethod
    def fetch(entry: dict, ctx: "pam.Context") -> "pam.Fetched":
        base = http.base_url(entry.get("url"), "the address of Secret Server")
        ca = str(entry.get("ca_cert") or "")
        form = {"grant_type": "password", "username": str(entry["app_user"]), "password": str(entry["app_password"])}
        if entry.get("app_domain"):
            form["domain"] = str(entry["app_domain"])
        status, token_answer = http.form_call("POST", f"{base}/oauth2/token", fields=form, ca_cert=ca)
        token = token_answer.get("access_token") if status == 200 and isinstance(token_answer, dict) else ""
        if not token:
            raise PamError("Secret Server refused the application user" + (f" ({status})" if status != 200 else "") + ": check its name, password, domain and that it may sign in from here")
        headers = {"Authorization": f"Bearer {token}", "X-Netlens-Correlation": ctx.correlation}
        sid = str(entry["secret_id_ref"])
        comment = " ".join(f"Netlens: {ctx.user or 'job'}, {ctx.purpose}{', ' + ctx.reason if ctx.reason else ''} [{ctx.correlation}]".split())[:200]
        # verify: a secret that requires check-out or a comment is checked out by the GET itself when it is given a comment (parameter name from the documentation)
        status, secret = http.call("GET", f"{base}/api/v1/secrets/{sid}?autoComment={urllib.parse.quote(comment)}", headers=headers, ca_cert=ca)
        if status != 200 or not isinstance(secret, dict):
            raise PamError(_explain(status, secret))
        values: dict[str, str] = {}
        for item in secret.get("items") or []:
            if not isinstance(item, dict) or not isinstance(item.get("itemValue"), str) or not item["itemValue"]:
                continue
            slug = str(item.get("slug") or item.get("fieldName") or "").lower()
            for target, names in _FIELDS.items():
                if slug in names and target not in values:
                    values[target] = item["itemValue"]
        if not values.get("username") and entry.get("username"):
            values["username"] = str(entry["username"])
        if not values.get("username") or not (values.get("password") or values.get("private_key")):
            raise PamError("the secret has no user name and password (or key) in fields Netlens recognises: username, password, private-key")
        checked_out = bool(secret.get("checkedOut"))

        def release() -> None:
            if checked_out:
                try:
                    http.call("POST", f"{base}/api/v1/secrets/{sid}/check-in", headers=headers, body={}, ca_cert=ca, timeout=5)
                except PamError:
                    pass                                    # Secret Server checks it in by itself when the check-out interval ends

        return pam.Fetched(values, f"secret {sid}", release if checked_out else None)


def _explain(status: int, answer: Any) -> str:
    text = " ".join(str(answer.get("message") or answer.get("errorCode") or "").split())[:160] if isinstance(answer, dict) else ""
    tail = f" ({text})" if text else ""
    if status in (401, 403):
        return "Secret Server says the application user may not read that secret (it needs View on the folder, and a comment or check-out may be required)" + tail
    if status == 404:
        return "Secret Server has no such secret, or the application user cannot see it" + tail
    if status in (429, 500, 502, 503, 504):
        return f"Secret Server is not available right now ({status})" + tail
    return f"Secret Server answered {status}" + tail


pam.register(SecretServer.name, SecretServer, SecretServer.title)
