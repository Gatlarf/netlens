"""The master key, kept by an external key service (Enterprise).

Without this, the key that protects every stored secret lives in a file next to the database (or in an environment variable): anybody who copies the data volume has both.
With a key service the file holds only a **wrapped** copy: the master key encrypted by a key that never leaves the service (HashiCorp Vault or OpenBao *transit*). Netlens asks the
service to unwrap it at start-up and keeps the result in memory only. Revoke Netlens' access in the service and a copy of the data volume is useless; rotate the key in the
service and `rewrap` moves the wrapped copy to the new version without touching the master key or any secret.

Configuration is in the environment, because the credentials to reach the service cannot be stored in the database they protect:

    NETLENS_KMS=vault_transit      NETLENS_KMS_URL=https://vault.example.com:8200      NETLENS_KMS_KEY=netlens      [NETLENS_KMS_MOUNT=transit]  [NETLENS_KMS_NAMESPACE=...]
    NETLENS_KMS_ROLE_ID / NETLENS_KMS_SECRET_ID (AppRole, preferred) or NETLENS_KMS_TOKEN;  each also as ..._FILE for a Docker or Kubernetes secret;  NETLENS_KMS_CA_FILE for a private CA

Least privilege in the service: the identity may `update` on `transit/encrypt/<key>`, `transit/decrypt/<key>`, `transit/rewrap/<key>` and `read` on `transit/keys/<key>`: nothing else.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

from app import pam
from app.pam import PamError, http

WRAPPED_FILE = "secret.key.kms"


class KmsError(Exception):
    """A sentence the administrator can act on. Never contains a key."""


def _env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if value:
        return value
    path = os.environ.get(name + "_FILE", "").strip()
    if path:
        try:
            return Path(path).read_text().strip()
        except OSError as exc:
            raise KmsError(f"{name}_FILE names {path} but it cannot be read: {exc.strerror or exc}") from None
    return ""


def configured() -> bool:
    return os.environ.get("NETLENS_KMS", "").strip() != ""


def config() -> dict[str, str]:
    provider = os.environ.get("NETLENS_KMS", "").strip()
    if provider != "vault_transit":
        raise KmsError("NETLENS_KMS must be vault_transit (HashiCorp Vault or OpenBao transit)")
    cfg = {"provider": provider, "url": os.environ.get("NETLENS_KMS_URL", "").strip(), "key": os.environ.get("NETLENS_KMS_KEY", "").strip(),
           "mount": os.environ.get("NETLENS_KMS_MOUNT", "transit").strip() or "transit", "namespace": os.environ.get("NETLENS_KMS_NAMESPACE", "").strip(),
           "ca": "", "token": _env("NETLENS_KMS_TOKEN"), "role_id": _env("NETLENS_KMS_ROLE_ID"), "secret_id": _env("NETLENS_KMS_SECRET_ID")}
    ca_file = os.environ.get("NETLENS_KMS_CA_FILE", "").strip()
    if ca_file:
        try:
            cfg["ca"] = Path(ca_file).read_text()
        except OSError as exc:
            raise KmsError(f"NETLENS_KMS_CA_FILE cannot be read: {exc.strerror or exc}") from None
    for name in ("mount", "key"):
        if not cfg[name] or not all(c.isalnum() or c in "-_." for c in cfg[name]):
            raise KmsError(f"NETLENS_KMS_{name.upper()} is missing or not valid (letters, digits, - _ .)")
    if not cfg["token"] and not (cfg["role_id"] and cfg["secret_id"]):
        raise KmsError("give NETLENS_KMS_TOKEN, or NETLENS_KMS_ROLE_ID and NETLENS_KMS_SECRET_ID (or their _FILE forms)")
    return cfg


class _Session:
    """One sign-in to the service for a few calls; an AppRole token is revoked at the end."""

    def __init__(self, cfg: dict[str, str]) -> None:
        self.cfg = cfg
        try:
            self.base = http.base_url(cfg["url"], "NETLENS_KMS_URL")
        except PamError as exc:
            raise KmsError(str(exc)) from None
        self.headers = {"X-Vault-Namespace": cfg["namespace"]} if cfg["namespace"] else {}
        self.token, self.revoke = cfg["token"], False

    def __enter__(self) -> "_Session":
        if not self.token:
            status, answer = self._call("POST", "/v1/auth/approle/login", {"role_id": self.cfg["role_id"], "secret_id": self.cfg["secret_id"]}, auth=False)
            self.token = ((answer or {}).get("auth") or {}).get("client_token") if status == 200 and isinstance(answer, dict) else ""
            if not self.token:
                raise KmsError("the key service refused the AppRole of Netlens: check the role id and secret id")
            self.revoke = True
        return self

    def __exit__(self, *exc) -> None:
        if self.revoke:
            try:
                self._call("POST", "/v1/auth/token/revoke-self", {})
            except KmsError:
                pass

    def _call(self, method: str, path: str, body: dict | None = None, auth: bool = True) -> tuple[int, Any]:
        headers = {**self.headers, **({"X-Vault-Token": self.token} if auth else {})}
        try:
            return http.call(method, self.base + path, headers=headers, body=body, ca_cert=self.cfg["ca"])
        except PamError as exc:
            raise KmsError(str(exc).replace("the PAM system", "the key service")) from None

    def transit(self, op: str, body: dict) -> dict:
        status, answer = self._call("POST", f"/v1/{self.cfg['mount']}/{op}/{self.cfg['key']}", body)
        if status != 200 or not isinstance(answer, dict) or not isinstance(answer.get("data"), dict):
            errors = " ".join(str(e) for e in (answer or {}).get("errors", []))[:140] if isinstance(answer, dict) else ""
            if status == 403:
                raise KmsError("the key service says Netlens may not use this key (check the policy)" + (f": {errors}" if errors else ""))
            if status == 404:
                raise KmsError("the key service has no such transit key or engine (check NETLENS_KMS_MOUNT and NETLENS_KMS_KEY)")
            raise KmsError(f"the key service answered {status}" + (f": {errors}" if errors else ""))
        return answer["data"]

    def latest_version(self) -> int | None:
        status, answer = self._call("GET", f"/v1/{self.cfg['mount']}/keys/{self.cfg['key']}")
        try:
            return int(answer["data"]["latest_version"]) if status == 200 else None
        except (KeyError, TypeError, ValueError):
            return None


def wrap(raw: bytes) -> str:
    with _Session(config()) as s:
        return str(s.transit("encrypt", {"plaintext": base64.b64encode(raw).decode()})["ciphertext"])


def unwrap(ciphertext: str) -> bytes:
    with _Session(config()) as s:
        try:
            raw = base64.b64decode(s.transit("decrypt", {"ciphertext": ciphertext})["plaintext"])
        except (KeyError, ValueError):
            raise KmsError("the key service answered, but not with a key") from None
    if len(raw) != 32:
        raise KmsError("the key service returned something that is not a Netlens key")
    return raw


def rewrap(ciphertext: str) -> tuple[str, int | None]:
    """The same wrapped key under the newest version of the transit key. Returns (new ciphertext, the version now in use)."""
    with _Session(config()) as s:
        new = str(s.transit("rewrap", {"ciphertext": ciphertext})["ciphertext"])
        return new, s.latest_version()


def wrapped_path(db_file: str) -> Path:
    return Path(db_file).parent / WRAPPED_FILE


def read_wrapped(db_file: str) -> dict | None:
    path = wrapped_path(db_file)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        raise KmsError(f"{path} cannot be read: restore it from a backup of the data volume") from None
    return data if isinstance(data, dict) and isinstance(data.get("ciphertext"), str) else None


def write_wrapped(db_file: str, ciphertext: str) -> None:
    cfg = config()
    path = wrapped_path(db_file)
    tmp = path.with_name(path.name + ".new")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump({"provider": cfg["provider"], "key": cfg["key"], "mount": cfg["mount"], "ciphertext": ciphertext}, handle)
    os.replace(tmp, path)


def describe(db_file: str) -> dict[str, Any]:
    """For the status page (never the key): where it is held, which transit key, which version wraps the key now, and whether a plain-text copy is still on disk."""
    if not configured():
        return {"enabled": False}
    out: dict[str, Any] = {"enabled": True, "provider": "vault_transit"}
    try:
        cfg = config()
        out.update(url=cfg["url"], key=cfg["key"], mount=cfg["mount"])
        wrapped = read_wrapped(db_file) if db_file else None
        out["wrapped"] = bool(wrapped)
        if wrapped:
            parts = wrapped["ciphertext"].split(":")
            out["version"] = int(parts[1][1:]) if len(parts) > 2 and parts[1].startswith("v") and parts[1][1:].isdigit() else None
        out["plaintext_key_on_disk"] = bool(db_file) and (Path(db_file).parent / "secret.key").exists()
    except KmsError as exc:
        out["error"] = str(exc)
    return out
