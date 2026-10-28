"""Where the login for a probe comes from. A probe never has to use the password that is stored for a monitor: a provider hands out a
credential for this one run, and a credential from a certificate authority is valid for minutes only.

  static      the login stored with the host monitor (password or private key), as before
  netlens_ca  Netlens is the SSH certificate authority: a new key pair and a certificate valid for a few minutes for every run. The host only
              has to trust the CA public key (TrustedUserCAKeys); nothing secret is stored on it or sent to it.
  vault_ssh   an SSH secrets engine of HashiCorp Vault or OpenBao signs the certificate; Netlens holds a token or an AppRole, not a login

A provider is one async function (conn, config, monitor secret) -> Credential. Another system (Teleport, step-ca, a cloud service that hands
out short-lived tokens) is added with `register()`: nothing else has to change.
"""

from __future__ import annotations

import asyncio
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

import asyncssh

DEFAULT_TTL_S = 300
MIN_TTL_S, MAX_TTL_S = 60, 3600
CA_KEY = "hostprobe.ca"


class CredentialError(Exception):
    """A sentence the user can act on."""


@dataclass
class Credential:
    username: str
    password: str | None = None
    private_key: str | None = None
    passphrase: str | None = None
    certificate: str | None = None
    expires: float | None = None                 # when it stops working; None for a stored login
    source: str = "static"
    meta: dict[str, Any] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        return {"source": self.source, "username": self.username, "expires": self.expires, "certificate": bool(self.certificate), "key_id": self.meta.get("key_id")}


Provider = Callable[[Any, dict, dict], Awaitable[Credential]]
PROVIDERS: dict[str, Provider] = {}


def register(name: str, provider: Provider) -> None:
    PROVIDERS[name] = provider


async def issue(conn, name: str, config: dict, monitor_secret: dict) -> Credential:
    provider = PROVIDERS.get(name or "static")
    if provider is None:
        raise CredentialError(f"unknown credential source: {name}")
    return await provider(conn, config or {}, monitor_secret or {})


def _ttl(config: dict) -> int:
    try:
        return min(max(int(config.get("ttl_s") or DEFAULT_TTL_S), MIN_TTL_S), MAX_TTL_S)
    except (TypeError, ValueError):
        return DEFAULT_TTL_S


# ----------------------------------------------------------------------------- static
async def _static(conn, config: dict, secret: dict) -> Credential:
    if not secret:
        raise CredentialError("the stored login cannot be read (the encryption key is missing): enter it again")
    return Credential(secret.get("username", ""), secret.get("password") or None, secret.get("private_key") or None, secret.get("passphrase") or None, source="static")


# ----------------------------------------------------------------------------- the Netlens CA
def ca_load(conn) -> asyncssh.SSHKey | None:
    from app.db import get_setting

    text = get_setting(conn, CA_KEY)
    if not text:
        return None
    try:
        return asyncssh.import_private_key(text)
    except (asyncssh.Error, ValueError):
        return None


def ca_create(conn) -> str:
    """A new CA key (the old one stops being trusted as soon as the hosts get the new public key). Returns the public key line."""
    from app.db import set_setting

    key = asyncssh.generate_private_key("ssh-ed25519", comment="netlens-ca")
    set_setting(conn, CA_KEY, key.export_private_key("openssh").decode())
    conn.commit()
    return ca_public(conn) or ""


def ca_public(conn) -> str | None:
    key = ca_load(conn)
    return key.export_public_key("openssh").decode().strip() if key else None


def _key_id(certificate: str) -> str | None:
    """The certificate's own id: the host's sshd writes it to its log when the certificate is used, so a login there can be matched to a line in the audit log."""
    try:
        return str(asyncssh.import_certificate(certificate)._key_id)         # asyncssh offers no public name for it
    except (asyncssh.Error, ValueError, AttributeError):
        return None


def make_certificate(ca: asyncssh.SSHKey, username: str, ttl_s: int, force_command: str | None = None, now: float | None = None) -> tuple[str, str, float]:
    """(private key, certificate, expires) for one run: a fresh key pair signed by `ca`, valid for ttl_s seconds (and 60 s before, for clocks that differ)."""
    now = now if now is not None else time.time()
    user_key = asyncssh.generate_private_key("ssh-ed25519")
    cert = ca.generate_user_certificate(user_key, f"netlens-probe-{int(now)}", principals=[username], valid_after=int(now) - 60, valid_before=int(now) + ttl_s,
                                        force_command=force_command, permit_pty=False, permit_x11_forwarding=False, permit_agent_forwarding=False,
                                        permit_port_forwarding=False, permit_user_rc=False)
    return user_key.export_private_key("openssh").decode(), cert.export_certificate("openssh").decode().strip(), now + ttl_s


async def _netlens_ca(conn, config: dict, secret: dict) -> Credential:
    ca = ca_load(conn)
    if ca is None:
        raise CredentialError("the Netlens certificate authority has not been created yet (Settings → Host probes)")
    username = config.get("username") or secret.get("username") or "netlens-ro"
    key, cert, expires = make_certificate(ca, username, _ttl(config))
    return Credential(username, private_key=key, certificate=cert, expires=expires, source="netlens_ca", meta={"key_id": _key_id(cert)})


# ----------------------------------------------------------------------------- Vault / OpenBao
def _post(url: str, body: dict, headers: dict, timeout: float = 10.0) -> dict:
    from app import safenet

    try:
        safenet.check_url(url, what="the address of the secrets server")
    except safenet.BlockedAddress as exc:
        raise CredentialError(str(exc)) from None
    request = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", **headers}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:      # noqa: S310 - the address is the administrator's own setting
            return json.loads(response.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = "; ".join(json.loads(exc.read().decode()).get("errors") or [])
        except (ValueError, OSError):
            pass
        raise CredentialError(f"the secrets service refused the request ({exc.code}{': ' + detail if detail else ''})") from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise CredentialError(f"cannot reach the secrets service: {getattr(exc, 'reason', exc)}") from None


def _vault_sign_sync(config: dict, username: str, public_key: str) -> str:
    base = str(config.get("url") or "").rstrip("/")
    if not base.startswith(("http://", "https://")):
        raise CredentialError("the address of the secrets service is missing")
    headers = {"X-Vault-Namespace": config["namespace"]} if config.get("namespace") else {}
    token = config.get("token")
    if not token and config.get("role_id") and config.get("secret_id"):
        login = _post(f"{base}/v1/auth/{config.get('approle_mount') or 'approle'}/login", {"role_id": config["role_id"], "secret_id": config["secret_id"]}, headers)
        token = (login.get("auth") or {}).get("client_token")
    if not token:
        raise CredentialError("no token or AppRole is set for the secrets service")
    answer = _post(f"{base}/v1/{config.get('mount') or 'ssh'}/sign/{config.get('role') or 'netlens'}",
                   {"public_key": public_key, "valid_principals": username, "cert_type": "user", "ttl": f"{_ttl(config)}s"}, {**headers, "X-Vault-Token": token})
    signed = (answer.get("data") or {}).get("signed_key")
    if not signed:
        raise CredentialError("the secrets service did not return a certificate")
    return signed.strip()


async def _vault_ssh(conn, config: dict, secret: dict) -> Credential:
    username = config.get("username") or secret.get("username") or "netlens-ro"
    user_key = asyncssh.generate_private_key("ssh-ed25519")
    public = user_key.export_public_key("openssh").decode().strip()
    signed = await asyncio.to_thread(_vault_sign_sync, config, username, public)
    return Credential(username, private_key=user_key.export_private_key("openssh").decode(), certificate=signed, expires=time.time() + _ttl(config), source="vault_ssh", meta={"key_id": _key_id(signed)})


register("static", _static)
register("netlens_ca", _netlens_ca)
register("vault_ssh", _vault_ssh)
