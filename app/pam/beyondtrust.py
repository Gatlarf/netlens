"""BeyondTrust Password Safe (API v3).

NOT TESTED ON A REAL SYSTEM. Written from BeyondTrust's Password Safe API guide (`POST /Auth/SignAppIn` with an `Authorization: PS-Auth key=..; runas=..;` header,
`GET /ManagedAccounts`, `POST /Requests`, `GET /Credentials/{requestId}`, `PUT /Requests/{id}/Checkin`, `POST /Auth/Signout`) and tested against a stand-in
(tests/fake_beyondtrust.py) that follows it. Likely to differ on a real server (verify): the exact check-in verb, how a request that needs approval answers, and the
sign-in variants (API key plus a run-as user, with or without a password).

Netlens signs in with an **API registration** (a key, restricted to the Netlens address, with the *Password Safe Role* that may only request passwords) and a run-as
user. For each use it signs in, looks up the managed account, makes a short **request** for the password with the reason (the request carries the person, purpose and
correlation id), reads it, and checks the request in and signs out shortly after (see `pam.release_later`). A request that needs approval cannot be granted to a monitor
or while nobody is there: it is refused with a clear message.
"""

from __future__ import annotations

import urllib.parse
from typing import Any

from app import pam
from app.pam import PamError, http

API = "/BeyondTrust/api/public/v3"
DURATION_MIN = 5


def _base(entry: dict) -> str:
    url = http.base_url(entry.get("url"), "the address of Password Safe")
    return url if urllib.parse.urlparse(url).path.strip("/") else url + API


class PasswordSafe:
    name = "beyondtrust_ps"
    title = "BeyondTrust Password Safe - not tested on a real system"
    holds = True

    @staticmethod
    def validate(entry: dict) -> None:
        _base(entry)
        if not entry.get("api_key") or not entry.get("run_as"):
            raise PamError("give Netlens the API key of its registration and the user it runs as")
        if not (entry.get("ps_system") and entry.get("ps_account")):
            raise PamError("name the managed system and the managed account")
        for field in ("api_key", "run_as", "ps_system", "ps_account"):
            if any(c in str(entry.get(field) or "") for c in ";=\r\n"):
                raise PamError(f"{field} may not contain ; = or line breaks")

    @staticmethod
    def where(entry: dict) -> str:
        return f"{entry.get('ps_system') or ''}/{entry.get('ps_account') or ''}"

    @staticmethod
    def public(entry: dict) -> dict:
        return {"ps_system": entry.get("ps_system", ""), "ps_account": entry.get("ps_account", ""), "run_as": entry.get("run_as", ""), "has_ca": bool(entry.get("ca_cert")), "auth": "API key"}

    @staticmethod
    def fetch(entry: dict, ctx: "pam.Context") -> "pam.Fetched":
        base = _base(entry)
        session = http.Session(str(entry.get("ca_cert") or ""))
        auth = f"PS-Auth key={entry['api_key']}; runas={entry['run_as']};" + (f" pwd=[{entry['run_as_password']}];" if entry.get("run_as_password") else "")
        status, answer = session.call("POST", f"{base}/Auth/SignAppIn", headers={"Authorization": auth, "X-Netlens-Correlation": ctx.correlation}, body={})
        if status != 200:
            raise PamError("Password Safe refused the API registration or the run-as user" + f" ({status})" + ": check the key, the user, and that the key may be used from here")

        rid: str | None = None

        def release() -> None:
            """Check the request in (if there is one) and sign out; used after the login attempt, and at once when something goes wrong."""
            try:
                if rid:
                    session.call("PUT", f"{base}/Requests/{urllib.parse.quote(rid)}/Checkin", body={"Reason": "Netlens: login attempt finished"})
            except PamError:
                pass                                        # the request ends by itself after its duration
            finally:
                try:
                    session.call("POST", f"{base}/Auth/Signout", body={})
                except PamError:
                    pass

        try:
            query = urllib.parse.urlencode({"systemName": entry["ps_system"], "accountName": entry["ps_account"]})
            status, found = session.call("GET", f"{base}/ManagedAccounts?{query}")
            if status != 200 or not isinstance(found, dict) or "SystemId" not in found or "AccountId" not in found:
                raise PamError("Password Safe has no such managed account, or this registration may not see it" + (f" ({status})" if status != 200 else ""))
            reason = " ".join(f"Netlens: {ctx.user or 'job'}, {ctx.purpose}{', ' + ctx.reason if ctx.reason else ''} [{ctx.correlation}]".split())[:200]
            status, request_id = session.call("POST", f"{base}/Requests", body={"SystemID": found["SystemId"], "AccountID": found["AccountId"], "DurationMinutes": DURATION_MIN,
                                                                               "Reason": reason, "AccessType": "View", "ConflictOption": "reuse"})
            if status not in (200, 201) or request_id in (None, "", {}):
                raise PamError(_explain(status, request_id))
            candidate = str(request_id).strip('"')
            if not candidate.replace("-", "").isalnum():
                raise PamError("Password Safe answered with a request id that does not look right")
            rid = candidate
            status, password = session.call("GET", f"{base}/Credentials/{urllib.parse.quote(rid)}")
            if status != 200 or not isinstance(password, str) or not password:
                raise PamError(_explain(status, password if isinstance(password, dict) else None, "Password Safe did not hand out the password (the request may need approval)"))
            username = str(found.get("AccountName") or entry.get("username") or "")
            if not username:
                raise PamError("Password Safe did not return a user name and none is set on the login")
        except Exception:
            release()
            raise
        values = {"username": username, "password": password}
        if found.get("DomainName") or entry.get("domain"):
            values["domain"] = str(found.get("DomainName") or entry.get("domain"))
        return pam.Fetched(values, f"request {rid}", release)


def _explain(status: int, answer: Any, default: str = "") -> str:
    text = " ".join(str(answer.get("Message") or answer.get("message") or "").split())[:160] if isinstance(answer, dict) else (answer if isinstance(answer, str) and len(answer) < 160 and not default else "")
    tail = f" ({text})" if text else ""
    if status in (401, 403):
        return "Password Safe refused the request: this registration may not request that account" + tail
    if status == 409:
        return "Password Safe has a conflicting request for this account" + tail
    if status in (429, 500, 502, 503, 504):
        return f"Password Safe is not available right now ({status})" + tail
    return (default or f"Password Safe answered {status}") + tail


pam.register(PasswordSafe.name, PasswordSafe, PasswordSafe.title)
