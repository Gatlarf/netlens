"""Built-in HTTPS, for installations that have no reverse proxy.

Netlens serves HTTPS itself when it finds a certificate and a key: from `NETLENS_TLS_CERT` and `NETLENS_TLS_KEY` (files, for a certificate that your own tooling renews), or
in `<data>/tls/server.crt` and `server.key` (made or uploaded under Settings -> HTTPS). The settings page can make a self-signed certificate (fine for a first look and for
a lab; a browser warns about it) or take a certificate and key from your own CA. The server reads them at start, so a change is applied by restarting Netlens (the page
offers it; the container's restart policy brings it back).

Safety: the key file is written readable by its owner only; an encrypted key or a key that does not belong to the certificate is refused; the key is never returned by the
API; TLS 1.2 is the oldest version offered (the Python default).
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import ssl
import tempfile
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DIR_NAME = "tls"
CERT_FILE, KEY_FILE = "server.crt", "server.key"


class TlsError(ValueError):
    """A sentence the user can act on."""


def paths(data_dir: Path) -> tuple[Path, Path] | None:
    """The certificate and key in use, or None (plain http)."""
    env_cert, env_key = os.environ.get("NETLENS_TLS_CERT", "").strip(), os.environ.get("NETLENS_TLS_KEY", "").strip()
    if env_cert and env_key:
        return Path(env_cert), Path(env_key)
    cert, key = Path(data_dir) / DIR_NAME / CERT_FILE, Path(data_dir) / DIR_NAME / KEY_FILE
    return (cert, key) if cert.is_file() and key.is_file() else None


def source(data_dir: Path) -> str:
    return "environment" if os.environ.get("NETLENS_TLS_CERT", "").strip() else "settings"


def _names(names: list[str]) -> list[x509.GeneralName]:
    out: list[x509.GeneralName] = []
    for raw in names:
        text = str(raw).strip()
        if not text:
            continue
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(text)))
        except ValueError:
            if len(text) > 253 or not all(c.isalnum() or c in "-._*" for c in text):
                raise TlsError(f"{text!r} is not a host name or address") from None
            out.append(x509.DNSName(text))
    if not out:
        raise TlsError("give at least one host name or address the certificate is for")
    if len(out) > 20:
        raise TlsError("at most 20 names")
    return out


def _write(data_dir: Path, cert_pem: bytes, key_pem: bytes) -> None:
    target = Path(data_dir) / DIR_NAME
    target.mkdir(parents=True, exist_ok=True)
    for name, data, mode in ((KEY_FILE, key_pem, 0o600), (CERT_FILE, cert_pem, 0o644)):
        fd, tmp = tempfile.mkstemp(dir=target, prefix=".new-")
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, target / name)


def make_self_signed(data_dir: Path, names: list[str], days: int = 825) -> dict[str, Any]:
    """A new key and a self-signed certificate for these names (ECDSA P-256)."""
    alt = _names(names)
    if not 1 <= days <= 3650:
        raise TlsError("the certificate may last 1 to 3650 days")
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    first = str(names[0]).strip()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, first[:64]), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Netlens (self-signed)")])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(alt), critical=False).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).sign(key, hashes.SHA256()))
    _write(data_dir, cert.public_bytes(serialization.Encoding.PEM), key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return info(data_dir)


def install(data_dir: Path, cert_pem: str, key_pem: str) -> dict[str, Any]:
    """Take a certificate (with its chain) and its private key from the user. Checked: PEM, the key is not encrypted, and it belongs to the first certificate."""
    if len(cert_pem) > 100_000 or len(key_pem) > 20_000:
        raise TlsError("that is too large for a certificate and a key")
    try:
        chain = x509.load_pem_x509_certificates(cert_pem.encode())
    except ValueError:
        raise TlsError("the certificate is not valid PEM text (-----BEGIN CERTIFICATE-----)") from None
    try:
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    except TypeError:
        raise TlsError("the key is protected by a password: Netlens needs it without one (openssl pkey -in key.pem -out key-plain.pem)") from None
    except ValueError:
        raise TlsError("the private key is not valid PEM text") from None
    pub = lambda k: k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)       # noqa: E731
    if pub(chain[0].public_key()) != pub(key.public_key()):
        raise TlsError("the key does not belong to the first certificate in the file (the server certificate must come first, then the chain)")
    now = datetime.datetime.now(datetime.timezone.utc)
    if chain[0].not_valid_after_utc < now:
        raise TlsError("that certificate has already expired")
    _write(data_dir, cert_pem.strip().encode() + b"\n", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return info(data_dir)


def remove(data_dir: Path) -> None:
    for name in (CERT_FILE, KEY_FILE):
        try:
            (Path(data_dir) / DIR_NAME / name).unlink()
        except FileNotFoundError:
            pass


def info(data_dir: Path, running: bool | None = None) -> dict[str, Any]:
    """What is configured (never the key): names, issuer, expiry, whether it is self-signed, and where it comes from."""
    found = paths(data_dir)
    if found is None:
        return {"configured": False, "running": bool(running)}
    try:
        cert = x509.load_pem_x509_certificates(found[0].read_bytes())[0]
    except (OSError, ValueError):
        return {"configured": True, "valid": False, "source": source(data_dir), "running": bool(running), "problem": "the certificate file cannot be read"}
    try:
        san = [str(n.value) for n in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
    except x509.ExtensionNotFound:
        san = []
    end = cert.not_valid_after_utc
    return {"configured": True, "valid": True, "source": source(data_dir), "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(), "names": san,
            "expires": end.strftime("%Y-%m-%dT%H:%M:%SZ"), "days_left": (end - datetime.datetime.now(datetime.timezone.utc)).days, "self_signed": cert.issuer == cert.subject,
            "fingerprint": cert.fingerprint(hashes.SHA256()).hex(), "running": bool(running)}


def uvicorn_options(data_dir: Path) -> dict[str, Any]:
    """Arguments for uvicorn.run: the certificate and key, or nothing. A pair that cannot be loaded is reported and ignored (Netlens then starts on plain http rather than not at all)."""
    found = paths(data_dir)
    if found is None:
        return {}
    try:
        ssl.create_default_context(ssl.Purpose.CLIENT_AUTH).load_cert_chain(str(found[0]), str(found[1]))
    except (ssl.SSLError, OSError) as exc:
        import logging

        logging.getLogger("netlens").error("HTTPS is configured but the certificate and key cannot be loaded (%s): starting on plain http", exc)
        return {}
    return {"ssl_certfile": str(found[0]), "ssl_keyfile": str(found[1])}
