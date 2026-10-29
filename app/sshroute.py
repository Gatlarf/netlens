"""SSH through a bastion or a PAM session proxy.

A stored login can carry a **route**. Two kinds, because customers have two kinds of gateway:

  jump    a plain SSH bastion (ProxyJump): Netlens signs in to the bastion with its own login, opens a channel to the target through it, and signs in to the target
          there. The target's host key is checked as usual (the bastion cannot swap it unnoticed); the bastion's key can be pinned with its fingerprint.
  proxy   a PAM session proxy (CyberArk PSM for SSH, BeyondTrust, Delinea and others): Netlens connects to the proxy only, with a user name that names the target
          (a template such as `{user}@{target}` or `{user}@account@{target}`); the proxy opens the session to the target and records it.

A route is data on the stored login, never code: host, port, kind, template, the bastion's fingerprint and (jump) the id of the stored login to use at the bastion. The
routes of a login reach the code that connects as a plain dict, `{"mode", "host", "port", "template", "fingerprint", "login": {...}}`.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Callable

import asyncssh

MODES = ("jump", "proxy")
_TEMPLATE_KEYS = ("user", "target", "port")
_HOST_RE = re.compile(r"^[A-Za-z0-9._:\-\[\]]{1,253}$")
_FP_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}=?$")


class RouteError(ValueError):
    """A sentence the user can act on."""


def validate(fields: dict[str, Any]) -> None:
    """For the credential store: complain early about a route that could never work."""
    mode = str(fields.get("route_mode") or "")
    if not mode:
        return
    if mode not in MODES:
        raise RouteError("a route is a jump host or a PAM session proxy")
    host = str(fields.get("route_host") or "").strip()
    if not _HOST_RE.match(host):
        raise RouteError("the address of the bastion or proxy is missing or not valid")
    try:
        port = int(fields.get("route_port") or 22)
    except (TypeError, ValueError):
        raise RouteError("the port of the bastion or proxy is not a number") from None
    if not 1 <= port <= 65535:
        raise RouteError("the port of the bastion or proxy must be between 1 and 65535")
    fp = str(fields.get("route_fingerprint") or "").strip()
    if fp and not _FP_RE.match(fp):
        raise RouteError("the host key fingerprint of the bastion looks like SHA256:… (as printed by ssh-keygen -lf)")
    if mode == "jump" and not fields.get("route_login"):
        raise RouteError("choose the stored login to use at the bastion")
    template = str(fields.get("route_template") or "")
    if mode == "proxy":
        if not template:
            raise RouteError("give the user name template of the proxy, for example {user}@{target}")
        unknown = set(re.findall(r"\{(\w*)\}", template)) - set(_TEMPLATE_KEYS)
        if unknown or re.sub(r"\{\w*\}", "", template).count("{") or "}" in re.sub(r"\{\w*\}", "", template):
            raise RouteError("the template may only use {user}, {target} and {port}")
        if len(template) > 200 or re.search(r"[\x00-\x1f\x7f\s]", template):
            raise RouteError("the template may not contain spaces or control characters")


def username_for(template: str, user: str, target: str, port: int) -> str:
    """The proxy user name. Values are inserted as they are (a user name or an address cannot add a control character), and the result is checked."""
    for value in (user, target):
        if re.search(r"[\x00-\x1f\x7f\s]", str(value)):
            raise RouteError("the user name or the address of the target contains a space or control character, which a proxy user name cannot carry")
    text = template.replace("{user}", user).replace("{target}", target).replace("{port}", str(port))
    if not text or len(text) > 256:
        raise RouteError("the proxy user name came out empty or too long")
    return text


def _keys(login: dict) -> list | None:
    if not login.get("private_key"):
        return None
    try:
        return [asyncssh.import_private_key(login["private_key"], login.get("passphrase") or None)]
    except (asyncssh.Error, ValueError):
        raise RouteError("the private key of the login for the bastion cannot be read") from None


def _pinning(route: dict, seen: dict) -> Callable[[], asyncssh.SSHClient]:
    class Client(asyncssh.SSHClient):
        def validate_host_public_key(self, host, addr, port, key) -> bool:
            seen["fp"] = key.get_fingerprint("sha256")
            return not route.get("fingerprint") or seen["fp"] == route["fingerprint"]

    return Client


async def connect(host: str, port: int, *, username: str, route: dict | None, connect_args: dict[str, Any], timeout: float) -> tuple[asyncssh.SSHClientConnection, list[asyncssh.SSHClientConnection]]:
    """An SSH connection to the target, directly or through the route. Returns the connection and the connections that must be closed with it.

    `connect_args` are the asyncssh arguments for the target (client_factory, password, client_keys, known_hosts, ...). Errors are asyncssh's own, so the callers' error
    handling stays as it is; a problem with the route itself is a RouteError."""
    if not route:
        return await asyncssh.connect(host, port=port, username=username, **connect_args), []
    mode = route.get("mode")
    rhost, rport = str(route["host"]), int(route.get("port") or 22)
    if mode == "proxy":
        user = username_for(str(route.get("template") or ""), username, host, port)
        args = dict(connect_args)
        base = args.get("client_factory") or asyncssh.SSHClient
        pinned = route.get("fingerprint")

        class ProxyClient(base):                         # the caller's own host key handling, plus the pin for the proxy when there is one
            def validate_host_public_key(self, host, addr, port, key) -> bool:
                ok = super().validate_host_public_key(host, addr, port, key)
                return ok and (not pinned or key.get_fingerprint("sha256") == pinned)

        args["client_factory"] = ProxyClient
        return await asyncssh.connect(rhost, port=rport, username=user, **args), []
    if mode == "jump":
        login = route.get("login") or {}
        if not login.get("username"):
            raise RouteError("the login for the bastion has no user name")
        seen = {}
        try:
            bastion = await asyncio.wait_for(asyncssh.connect(rhost, port=rport, username=login["username"], password=login.get("password") or None, client_keys=_keys(login),
                                                              client_factory=_pinning(route, seen), known_hosts=(), agent_path=None, config=None, login_timeout=timeout), timeout + 2)
        except asyncssh.HostKeyNotVerifiable:
            raise RouteError(f"the host key of the bastion is not the one that was pinned (it is {seen.get('fp', 'unknown')})") from None
        except asyncssh.PermissionDenied:
            raise RouteError("the bastion refused the login chosen for it") from None
        except (asyncssh.Error, OSError, asyncio.TimeoutError) as exc:
            raise RouteError(f"cannot reach the bastion: {exc.__class__.__name__}") from None
        try:
            conn = await asyncssh.connect(host, port=port, username=username, tunnel=bastion, **connect_args)
        except BaseException:
            bastion.close()
            raise
        return conn, [bastion]
    raise RouteError("unknown kind of route")
