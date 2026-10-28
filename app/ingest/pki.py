"""Certificates for the agent ingest: the dedicated CA, the listener's server certificate, short-lived client certificates signed from a CSR, and the
customer's own CA bundle.

Rules that keep this safe:
  * the ingest CA is used for nothing else (the SSH CA of the host probes is a different key), and it only signs certificates with the client-authentication purpose;
  * a client certificate is built here from the CSR's public key only: the subject, extensions and validity in the CSR are ignored;
  * the private key of an agent never exists on Netlens (the agent sends a CSR);
  * only strong keys are accepted (EC P-256/P-384/P-521, Ed25519, RSA from 3072 bits).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import re
import secrets

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_NAME = "Netlens agent ingest CA"
CA_YEARS = 10
SERVER_DAYS = 397
CLIENT_DAYS = 30
MAX_CSR_BYTES = 8192
MAX_BUNDLE_BYTES = 65536
MAX_BUNDLE_CERTS = 10
NAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


class PkiError(ValueError):
    """A sentence the administrator can act on."""


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def key_pem(key) -> str:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()


def load_cert(text: str) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(text.encode())
    except (ValueError, TypeError):
        raise PkiError("that is not a PEM certificate") from None


def create_ca() -> tuple[str, str]:
    """(certificate PEM, private key PEM) of a new ingest CA: EC P-256, ten years, may sign end certificates only."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{CA_NAME} {secrets.token_hex(4)}")])      # unique: two CAs with one name confuse the chain building
    now = _now()
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=365 * CA_YEARS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return pem(cert), key_pem(key)


def check_names(names: list[str]) -> list[str]:
    out: list[str] = []
    for raw in names:
        n = str(raw).strip().lower().rstrip(".")
        if not n:
            continue
        try:
            ipaddress.ip_address(n)
        except ValueError:
            if not NAME_RE.match(n):
                raise PkiError(f"'{raw}' is not a host name or an IP address")
        if n not in out:
            out.append(n)
    if len(out) > 20:
        raise PkiError("at most 20 names")
    return out


def issue_server(ca_pem: str, ca_key_pem: str, names: list[str]) -> tuple[str, str]:
    """The listener's own certificate (server authentication), for the names the agents will connect to."""
    names = check_names(names)
    if not names:
        raise PkiError("give at least one host name or IP address that the agents connect to")
    ca = load_cert(ca_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem.encode(), None)
    key = ec.generate_private_key(ec.SECP256R1())
    sans: list[x509.GeneralName] = []
    for n in names:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            sans.append(x509.DNSName(n))
    now = _now()
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0][:64])])).issuer_name(ca.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=SERVER_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return pem(cert), key_pem(key)


def check_csr(text: str) -> x509.CertificateSigningRequest:
    if len(text) > MAX_CSR_BYTES:
        raise PkiError("the certificate request is too large")
    try:
        csr = x509.load_pem_x509_csr(text.encode())
    except (ValueError, TypeError):
        raise PkiError("that is not a PEM certificate request") from None
    if not csr.is_signature_valid:
        raise PkiError("the signature of the certificate request is not valid")
    k = csr.public_key()
    if isinstance(k, ec.EllipticCurvePublicKey):
        if k.curve.name not in ("secp256r1", "secp384r1", "secp521r1"):
            raise PkiError("use an EC key on P-256, P-384 or P-521")
    elif isinstance(k, rsa.RSAPublicKey):
        if k.key_size < 3072:
            raise PkiError("an RSA key must be at least 3072 bits")
    elif not isinstance(k, ed25519.Ed25519PublicKey):
        raise PkiError("use an EC, Ed25519 or RSA (3072 bits or more) key")
    return csr


def sign_csr(ca_pem: str, ca_key_pem: str, csr_text: str, common_name: str, days: int = CLIENT_DAYS) -> tuple[str, str, str]:
    """(certificate PEM, SHA-256 fingerprint, not-after as ISO text). Only the public key of the request is used."""
    csr = check_csr(csr_text)
    ca = load_cert(ca_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem.encode(), None)
    now = _now()
    end = now + dt.timedelta(days=days)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name[:64])])).issuer_name(ca.subject)
            .public_key(csr.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(end)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return pem(cert), fingerprint(cert.public_bytes(serialization.Encoding.DER)), end.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_bundle(text: str) -> list[x509.Certificate]:
    """The customer's CA certificates. Each must be a CA and not expired, so a leaf certificate or a stale file cannot be trusted by mistake."""
    if len(text) > MAX_BUNDLE_BYTES:
        raise PkiError("the CA file is too large")
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", text, re.S)
    if not blocks:
        raise PkiError("no PEM certificate found in the CA file")
    if len(blocks) > MAX_BUNDLE_CERTS:
        raise PkiError(f"at most {MAX_BUNDLE_CERTS} certificates")
    out = []
    now = _now()
    for b in blocks:
        cert = load_cert(b)
        try:
            ok = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except x509.ExtensionNotFound:
            ok = False
        if not ok:
            raise PkiError("a certificate in the file is not a CA certificate (it must have the CA flag)")
        if cert.not_valid_after_utc < now:
            raise PkiError("a CA certificate in the file has expired")
        if cert.not_valid_before_utc > now + dt.timedelta(minutes=5):
            raise PkiError("a CA certificate in the file is not valid yet")
        out.append(cert)
    return out


def check_server_pair(cert_text: str, key_text: str) -> list[str]:
    """An uploaded server certificate and key: they must belong together and the certificate must be valid for server use. Returns its names."""
    cert = load_cert(cert_text.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----")
    try:
        key = serialization.load_pem_private_key(key_text.encode(), None)
    except (ValueError, TypeError):
        raise PkiError("the private key could not be read (it must be PEM without a password)") from None
    pub = lambda k: k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)      # noqa: E731
    if pub(key.public_key()) != pub(cert.public_key()):
        raise PkiError("the private key does not belong to the certificate")
    now = _now()
    if cert.not_valid_after_utc < now:
        raise PkiError("the server certificate has expired")
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
            raise PkiError("the certificate is not meant for server use")
    except x509.ExtensionNotFound:
        pass
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return [str(n) for n in san.get_values_for_type(x509.DNSName)] + [str(n) for n in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        return []


def identities(der: bytes) -> list[str]:
    """What a client certificate says about itself: `dns:<name>`, `uri:<uri>` (from the SAN) and `cn:<name>`. Used to match a customer-issued certificate to an agent."""
    cert = x509.load_der_x509_certificate(der)
    out: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        out += [f"dns:{n.lower()}" for n in san.get_values_for_type(x509.DNSName)]
        out += [f"uri:{n}" for n in san.get_values_for_type(x509.UniformResourceIdentifier)]
    except x509.ExtensionNotFound:
        pass
    for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        out.append(f"cn:{attr.value}")
    return out


def valid_identity(text: str) -> str:
    """`dns:host.example.com`, `uri:spiffe://x/y` or `cn:name`."""
    t = str(text or "").strip()
    m = re.match(r"^(dns|uri|cn):(.{1,200})$", t)
    if not m:
        raise PkiError("an identity looks like dns:host.example.com, uri:spiffe://example/host or cn:name")
    kind, value = m.group(1), m.group(2).strip()
    if kind == "dns":
        value = value.lower()
        if not NAME_RE.match(value):
            raise PkiError("that is not a valid DNS name")
    if re.search(r"[\x00-\x1f\x7f]", value):
        raise PkiError("the identity contains control characters")
    if kind == "cn" and value.lower().startswith("netlens-agent-"):
        raise PkiError("names starting with netlens-agent- are reserved for certificates issued by Netlens")
    return f"{kind}:{value}"


def signature_ok(cert: x509.Certificate, ca: x509.Certificate) -> bool:
    try:
        ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, *( (ec.ECDSA(cert.signature_hash_algorithm),) if isinstance(ca.public_key(), ec.EllipticCurvePublicKey) else () ))
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False
