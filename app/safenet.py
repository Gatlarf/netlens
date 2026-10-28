"""Outbound requests to an address somebody typed (a webhook, a language model, an identity provider, a secrets server) must not be a way to reach what the machine can
reach and the person cannot: the cloud metadata service, other link-local services, or a file.

`check_url` refuses, before anything is sent:
  * a scheme other than http or https (no file:, ftp:, gopher: ...);
  * an address with a user name or password in it (they end up in logs);
  * a host that is, or resolves to, a link-local address (169.254.0.0/16, fe80::/10: this includes the metadata service of AWS, Azure, GCP and OpenStack), an unspecified,
    multicast or reserved address, or the metadata address of Alibaba Cloud, and the well-known metadata host names.
Private and loopback addresses stay allowed: a webhook to Home Assistant, a model on the next machine, or a check of a local service is the normal use of Netlens.

`install_redirect_guard` makes every redirect of the standard library's urlopen go through the same check, so an allowed address cannot send the request on to a blocked one.
The name is resolved once more at the moment of use, so a name that was fine when it was saved and points to the metadata service later is caught.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse
import urllib.request

METADATA_HOSTS = {"metadata.google.internal", "metadata", "instance-data", "instance-data.ec2.internal", "metadata.azure.internal"}
METADATA_ADDRESSES = {ipaddress.ip_address("100.100.100.200"), ipaddress.ip_address("fd00:ec2::254")}


class BlockedAddress(ValueError):
    """The address is not allowed as the target of an outbound request."""


def _blocked(ip: ipaddress._BaseAddress) -> str | None:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip in METADATA_ADDRESSES:
        return "the metadata service of a cloud provider"
    if ip.is_link_local:
        return "a link-local address (this is where the cloud metadata service lives)"
    if ip.is_unspecified:
        return "an unspecified address"
    if ip.is_multicast:
        return "a multicast address"
    if ip.is_reserved:
        return "a reserved address"
    return None


def check_host(host: str, resolve: bool = True) -> None:
    name = (host or "").strip().strip("[]").lower().rstrip(".")
    if not name:
        raise BlockedAddress("the address has no host name")
    if name in METADATA_HOSTS:
        raise BlockedAddress("that is the metadata service of a cloud provider")
    try:
        literal = ipaddress.ip_address(name)
    except ValueError:
        literal = None
    if literal is not None:
        why = _blocked(literal)
        if why:
            raise BlockedAddress(f"that is {why}")
        return
    if not resolve:
        return
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return                                  # it cannot be resolved: the request itself will fail with a better message
    for info in infos:
        try:
            why = _blocked(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
        if why:
            raise BlockedAddress(f"{name} points to {why}")


def check_url(url: str, *, what: str = "the address", schemes: tuple[str, ...] = ("http", "https"), resolve: bool = True) -> str:
    """The URL (stripped) when it may be the target of an outbound request; BlockedAddress with a sentence otherwise."""
    text = (url or "").strip()
    try:
        parts = urllib.parse.urlsplit(text)
        host = parts.hostname
    except ValueError:
        raise BlockedAddress(f"{what} is not a valid address") from None
    if parts.scheme.lower() not in schemes:
        raise BlockedAddress(f"{what} must start with {' or '.join(s + '://' for s in schemes)}")
    if parts.username is not None or parts.password is not None:
        raise BlockedAddress(f"{what} must not contain a user name or password (use the fields for them)")
    try:
        check_host(host or "", resolve)
    except BlockedAddress as exc:
        raise BlockedAddress(f"{what} is refused: {exc}") from None
    return text


class _RedirectGuard(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urljoin(req.full_url, newurl)
        try:
            check_url(target, what="a redirect")
        except BlockedAddress as exc:
            raise urllib.error.HTTPError(req.full_url, code, f"redirect refused: {exc}", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def install_redirect_guard() -> None:
    """Every redirect that urllib.request.urlopen follows is checked (call once at start-up)."""
    urllib.request.install_opener(urllib.request.build_opener(_RedirectGuard))
