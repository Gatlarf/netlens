"""CyberArk Privileged Access Manager: the Central Credential Provider (CCP) web service.

NOT TESTED ON A REAL SYSTEM. Written from CyberArk's documentation ("Central Credential Provider REST web service", `GET .../AIMWebService/api/Accounts`) and tested
against a stand-in server (tests/fake_cyberark.py) that follows it; the stand-in proves how this code reads the documentation, not how the product behaves.

How Netlens identifies itself: the **application id** (AppID) of an application you created in CyberArk, and, strongly recommended, a **client certificate** (mutual TLS)
that the application is bound to in CyberArk (Application authentication: certificate serial number, issuer, or DN) and an allowed address. Netlens sends the application
id, the safe and the account object name, and a *reason* that names Netlens, the person, the purpose and the correlation id, so the CyberArk audit shows who the
password was really for. `FailRequestOnPasswordChange=true`: a password that is being changed right now is refused, not handed out half-way.

Least privilege on the CyberArk side: the application may only *retrieve* from the safes that hold monitoring and access accounts (the "Retrieve accounts" permission,
nothing else), from the Netlens address, and the account may require dual control/exclusive access only if you accept that a person is not there to approve for a monitor.
"""

from __future__ import annotations

import urllib.parse
from typing import Any

from app import pam
from app.pam import PamError, http

PATH = "/AIMWebService"
_NAME_RE = r"^[^\x00-\x1f\x7f&=?#%;]{1,200}$"          # no characters that could add a parameter or change the query


def _name(value: Any, what: str, required: bool = True) -> str:
    import re

    text = str(value or "").strip()
    if not text:
        if required:
            raise PamError(f"{what} is missing")
        return ""
    if not re.fullmatch(_NAME_RE, text):
        raise PamError(f"{what} is not valid (no & = ? # % ; or control characters)")
    return text


def _base(entry: dict) -> str:
    url = http.base_url(entry.get("url"), "the address of the CyberArk web service")
    return url if urllib.parse.urlparse(url).path.strip("/") else url + PATH


class CyberArkCCP:
    name = "cyberark_ccp"
    title = "CyberArk (Central Credential Provider) - not tested on a real system"

    @staticmethod
    def validate(entry: dict) -> None:
        _base(entry)
        _name(entry.get("appid"), "the application id (AppID)")
        _name(entry.get("safe"), "the safe", required=False)
        _name(entry.get("folder"), "the folder", required=False)
        if not (entry.get("object") or entry.get("account_user")):
            raise PamError("name the account: its object name, or its user name (with the address if several accounts share it)")
        _name(entry.get("object"), "the account object name", required=False)
        _name(entry.get("account_user"), "the account user name", required=False)
        _name(entry.get("account_address"), "the account address", required=False)
        if bool(entry.get("client_cert")) != bool(entry.get("client_key")):
            raise PamError("give both the client certificate and its key, or neither")
        if str(entry.get("content_as") or "password") not in ("password", "private_key"):
            raise PamError("the retrieved secret is either a password or a private key")
        if not str(entry.get("url") or "").startswith("https://") and entry.get("client_cert"):
            raise PamError("a client certificate needs an https address")

    @staticmethod
    def where(entry: dict) -> str:
        return "/".join(x for x in (entry.get("safe") or "", entry.get("object") or f"{entry.get('account_user') or ''}@{entry.get('account_address') or ''}".strip("@")) if x)

    @staticmethod
    def public(entry: dict) -> dict:
        return {"appid": entry.get("appid", ""), "safe": entry.get("safe", ""), "folder": entry.get("folder", ""), "object": entry.get("object", ""), "account_user": entry.get("account_user", ""),
                "account_address": entry.get("account_address", ""), "content_as": entry.get("content_as") or "password", "has_ca": bool(entry.get("ca_cert")),
                "auth": "certificate" if entry.get("client_cert") else "appid", "has_client_cert": bool(entry.get("client_cert"))}

    @staticmethod
    def fetch(entry: dict, ctx: "pam.Context") -> "pam.Fetched":
        query = {"AppID": _name(entry.get("appid"), "the application id (AppID)"), "FailRequestOnPasswordChange": "true",
                 "Reason": " ".join(f"Netlens: {ctx.user or 'job'}, {ctx.purpose}{', ' + ctx.reason if ctx.reason else ''} [{ctx.correlation}]".split())[:200]}
        for key, field in (("Safe", "safe"), ("Folder", "folder"), ("Object", "object"), ("UserName", "account_user"), ("Address", "account_address")):
            value = _name(entry.get(field), field, required=False)
            if value:
                query[key] = value
        url = f"{_base(entry)}/api/Accounts?{urllib.parse.urlencode(query, quote_via=urllib.parse.quote)}"
        status, answer = http.call("GET", url, ca_cert=str(entry.get("ca_cert") or ""), client_cert=str(entry.get("client_cert") or ""), client_key=str(entry.get("client_key") or ""))
        if status != 200 or not isinstance(answer, dict):
            raise PamError(_explain(status, answer))
        content = answer.get("Content")
        if not isinstance(content, str) or not content:
            raise PamError("CyberArk answered without a secret: check that the application may retrieve this account")
        if str(answer.get("PasswordChangeInProcess", "")).lower() == "true":
            raise PamError("CyberArk is changing this account's password right now: try again in a moment")
        username = str(answer.get("UserName") or entry.get("username") or entry.get("account_user") or "")
        if not username:
            raise PamError("CyberArk did not return a user name and none is set on the login")
        key = "private_key" if str(entry.get("content_as") or "password") == "private_key" else "password"
        values = {"username": username, key: content}
        if entry.get("domain"):
            values["domain"] = str(entry["domain"])
        return pam.Fetched(values, "ccp:" + str(answer.get("Name") or entry.get("object") or "")[:80])


def _explain(status: int, answer: Any) -> str:
    code = str(answer.get("ErrorCode") or "")[:16] if isinstance(answer, dict) else ""
    text = " ".join(str(answer.get("ErrorMsg") or "").split())[:160] if isinstance(answer, dict) else ""
    tail = f" ({code}{': ' + text if text else ''})" if code or text else ""
    if status in (401, 403):
        return "CyberArk refused the application: check the application id, the client certificate binding, the allowed address and the safe permissions" + tail
    if status == 404:
        return "CyberArk has no such account: check the safe, folder and object name" + tail
    if status == 400:
        return "CyberArk did not accept the request: check the application id and the account fields" + tail
    if status in (429, 500, 502, 503, 504):
        return f"CyberArk is not available or could not hand out the password right now ({status})" + tail
    return f"CyberArk answered {status}" + tail


pam.register(CyberArkCCP.name, CyberArkCCP, CyberArkCCP.title)
