"""Retrieve and inspect the validity metadata of a server leaf certificate."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm


@dataclass(slots=True)
class CertificateResult:
    subject: str
    issuer: str
    serial_number: int
    not_valid_before: datetime
    not_valid_after: datetime
    days_remaining: float
    expired: bool
    not_yet_valid: bool
    san_dns_names: list[str]
    signature_hash_algorithm: str | None


def fetch_certificate(
    host: str,
    port: int,
    timeout: float = 5.0,
) -> bytes:
    """Fetch the peer leaf certificate without validating its trust chain.

    Disabling verification here is intentional: it lets the scanner inspect
    expired or self-signed certificates. It must not be interpreted as a trust
    or hostname validation result.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                certificate = tls_sock.getpeercert(binary_form=True)
                if not certificate:
                    raise ValueError("Server did not provide a certificate")
                return certificate
    except (ssl.SSLError, OSError, TimeoutError) as exc:
        raise ConnectionError(
            f"Unable to retrieve certificate: {type(exc).__name__}: {exc}"
        ) from exc


def parse_certificate(certificate_der: bytes) -> CertificateResult:
    certificate = x509.load_der_x509_certificate(certificate_der)
    now = datetime.now(timezone.utc)

    not_valid_before = certificate.not_valid_before_utc
    not_valid_after = certificate.not_valid_after_utc
    days_remaining = (not_valid_after - now).total_seconds() / 86400

    expired = now >= not_valid_after
    not_yet_valid = now < not_valid_before

    try:
        san_extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        san_dns_names = san_extension.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_dns_names = []

    try:
        signature_hash = certificate.signature_hash_algorithm
    except UnsupportedAlgorithm:
        signature_hash = None

    return CertificateResult(
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        serial_number=certificate.serial_number,
        not_valid_before=not_valid_before,
        not_valid_after=not_valid_after,
        days_remaining=days_remaining,
        expired=expired,
        not_yet_valid=not_yet_valid,
        san_dns_names=san_dns_names,
        signature_hash_algorithm=(signature_hash.name if signature_hash else None),
    )


def scan_certificate(
    host: str,
    port: int,
    timeout: float = 5.0,
) -> CertificateResult:
    return parse_certificate(fetch_certificate(host, port, timeout=timeout))


def certificate_status(certificate: CertificateResult) -> str:
    """Report date validity only; chain and hostname trust are not checked."""
    if certificate.not_yet_valid:
        return "NOT_YET_VALID"
    if certificate.expired:
        return "EXPIRED"
    if certificate.days_remaining < 30:
        return "EXPIRING_SOON"
    return "DATE_VALID"
