"""HashiCorp Vault and OpenBao, key/value secrets engine (version 1 and 2).

Netlens signs in with an AppRole (preferred: the secret id can be limited by address and number of uses, and the token it gets lives for minutes) or with a token, reads
one secret, and for an AppRole login revokes the token again straight away. The secret holds the fields of a login; which key means what is configurable
(`username`, `password`, `private_key`, `passphrase`, `domain` by default).

Least privilege on the Vault side: a policy that allows `read` on the path(s) that hold monitoring and access accounts, nothing else.
"""

from __future__ import annotations

import re
from typing import Any

from app import pam
from app.pam import PamError, http

DEFAULT_MOUNT = "secret"
_PATH_RE = re.compile(r"^[A-Za-z0-9_.@:+= -]+(/[A-Za-z0-9_.@:+= -]+)*$")
_FIELD_KEYS = {"username_field": "username", "password_field": "password", "key_field": "private_key", "passphrase_field": "passphrase", "domain_field": "domain"}


def _path(value: Any, what: str) -> str:
    text = str(value or "").strip().strip("/")
    if not text or not _PATH_RE.fullmatch(text) or any(part in ("", ".", "..") for part in text.split("/")):
        raise PamError(f"{what} is not valid: use letters, digits and / only, for example netlens/linux-admin")
    return text


class VaultKV:
    name = "vault_kv"
    title = "HashiCorp Vault / OpenBao (KV secrets)"

    @staticmethod
    def validate(entry: dict) -> None:
        http.base_url(entry.get("url"))
        _path(entry.get("mount") or DEFAULT_MOUNT, "the secrets engine name")
        _path(entry.get("path"), "the secret path")
        if str(entry.get("kv_version") or "2") not in ("1", "2"):
            raise PamError("the KV version must be 1 or 2")
        if entry.get("namespace"):
            _path(entry["namespace"], "the namespace")
        if entry.get("token"):
            return
        if not (entry.get("role_id") and entry.get("secret_id")):
            raise PamError("give Netlens a way to sign in: an AppRole (role id and secret id), or a token")
        _path(entry.get("approle_mount") or "approle", "the AppRole mount")

    @staticmethod
    def where(entry: dict) -> str:
        return "/".join(x for x in (entry.get("mount") or DEFAULT_MOUNT, entry.get("path") or "") if x)

    @staticmethod
    def public(entry: dict) -> dict:
        return {"namespace": entry.get("namespace", ""), "kv_version": entry.get("kv_version") or "2", "auth": "token" if entry.get("token") else "approle",
                "approle_mount": entry.get("approle_mount", ""), "role_id": entry.get("role_id", ""), "has_ca": bool(entry.get("ca_cert")),
                "username_field": entry.get("username_field", ""), "password_field": entry.get("password_field", ""), "key_field": entry.get("key_field", ""),
                "passphrase_field": entry.get("passphrase_field", ""), "domain_field": entry.get("domain_field", "")}

    @staticmethod
    def fetch(entry: dict, ctx: "pam.Context") -> "pam.Fetched":
        base = http.base_url(entry.get("url"))
        ca = str(entry.get("ca_cert") or "")
        extra = {"X-Netlens-Correlation": ctx.correlation}
        if entry.get("namespace"):
            extra["X-Vault-Namespace"] = _path(entry["namespace"], "the namespace")
        token, revoke = str(entry.get("token") or ""), False
        if not token:
            mount = _path(entry.get("approle_mount") or "approle", "the AppRole mount")
            status, answer = http.call("POST", f"{base}/v1/auth/{mount}/login", headers=extra, body={"role_id": entry.get("role_id"), "secret_id": entry.get("secret_id")}, ca_cert=ca)
            token = ((answer or {}).get("auth") or {}).get("client_token") if status == 200 and isinstance(answer, dict) else ""
            if not token:
                raise PamError(_explain(status, answer, "the AppRole sign-in was refused: check the role id and secret id (and that the secret id has not expired or been used up)"))
            revoke = True
        headers = {**extra, "X-Vault-Token": token}

        def release() -> None:
            if revoke:
                try:
                    http.call("POST", f"{base}/v1/auth/token/revoke-self", headers=headers, body={}, ca_cert=ca, timeout=5)
                except PamError:
                    pass                                    # the token lives for minutes anyway

        try:
            mount, path, version = _path(entry.get("mount") or DEFAULT_MOUNT, "the secrets engine name"), _path(entry.get("path"), "the secret path"), str(entry.get("kv_version") or "2")
            url = f"{base}/v1/{http.quote_path(mount)}/{'data/' if version == '2' else ''}{http.quote_path(path)}"
            status, answer = http.call("GET", url, headers=headers, ca_cert=ca)
            if status != 200 or not isinstance(answer, dict):
                raise PamError(_explain(status, answer, f"the PAM system answered {status}"))
            data = answer.get("data")
            if version == "2":
                data = (data or {}).get("data") if isinstance(data, dict) else None
            if not isinstance(data, dict):
                raise PamError("there is no secret at that path (or it has been deleted)")
            values = {}
            for key, target in _FIELD_KEYS.items():
                name = str(entry.get(key) or target)
                if isinstance(data.get(name), str) and data[name]:
                    values[target] = data[name]
            if not values.get("username") and entry.get("username"):
                values["username"] = str(entry["username"])
            if not values.get("username") or not (values.get("password") or values.get("private_key")):
                raise PamError("the secret does not hold a user name and a password or key under the field names set for this login")
            lease = str(answer.get("request_id") or "")
        except Exception:
            release()
            raise
        return pam.Fetched(values, lease, release)


def _explain(status: int, answer: Any, default: str) -> str:
    errors = " ".join("; ".join(str(e) for e in (answer or {}).get("errors", []) if isinstance(e, str)).replace("*", " ").split())[:160] if isinstance(answer, dict) else ""
    if status == 403:
        return "the PAM system says this identity may not read that secret (check the policy)" + (f": {errors}" if errors else "")
    if status == 404:
        return "there is no secret at that path (check the engine name, the path and the KV version)"
    if status in (429, 500, 502, 503, 504):
        return f"the PAM system is not available right now ({status})" + (f": {errors}" if errors else "")
    return default + (f" ({errors})" if errors else "")


pam.register(VaultKV.name, VaultKV, VaultKV.title)
