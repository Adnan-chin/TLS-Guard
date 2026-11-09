"""TLS 1.2 cipher-suite probing and classification."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from enum import Enum


class CipherStatus(str, Enum):
    SUPPORTED = "supported"
    NOT_SUPPORTED = "not_supported"
    NOT_TESTABLE = "not_testable"
    ERROR = "error"


@dataclass(slots=True)
class CipherResult:
    name: str
    protocol: str
    status: CipherStatus
    bits: int | None = None
    error: str | None = None


WEAK_PATTERNS = (
    "NULL",
    "ANON",
    "EXPORT",
    "RC4",
    "3DES",
    "DES-CBC",
    "RC2",
    "MD5",
)

# This is a deliberately documented probe set, not an exhaustive enumeration
# of every cipher suite supported by every TLS implementation.
TLS12_CIPHERS_TO_TEST = (
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "AES256-SHA",
    "AES128-SHA",
    "DES-CBC3-SHA",
    "ECDHE-RSA-AES256-SHA",
    "ECDHE-RSA-AES128-SHA",
)


def _classify_cipher_ssl_error(exc: ssl.SSLError) -> CipherStatus:
    reason = str(getattr(exc, "reason", "") or "").upper()
    message = str(exc).lower()
    if reason in {"NO_SHARED_CIPHER", "NO_CIPHER_MATCH"}:
        return CipherStatus.NOT_SUPPORTED
    if "no shared cipher" in message or "no ciphers available" in message:
        return CipherStatus.NOT_SUPPORTED
    # Generic handshake_failure is not enough evidence: client/server policy,
    # certificates, or other negotiation constraints may be responsible.
    return CipherStatus.NOT_TESTABLE


def probe_cipher_tls12(
    host: str,
    port: int,
    cipher_name: str,
    timeout: float = 5.0,
) -> CipherResult:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        context.set_ciphers(cipher_name)
    except ssl.SSLError as exc:
        return CipherResult(
            name=cipher_name,
            protocol="TLSv1.2",
            status=CipherStatus.NOT_TESTABLE,
            error=f"Cipher unavailable in local client: {exc}",
        )

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                negotiated = tls_sock.cipher()
                if negotiated is None:
                    return CipherResult(
                        name=cipher_name,
                        protocol="TLSv1.2",
                        status=CipherStatus.ERROR,
                        error="TLS handshake completed without cipher details",
                    )

                negotiated_name, _protocol, bits = negotiated
                if negotiated_name.casefold() != cipher_name.casefold():
                    return CipherResult(
                        name=cipher_name,
                        protocol="TLSv1.2",
                        status=CipherStatus.ERROR,
                        error=(
                            f"Requested {cipher_name}, but negotiated "
                            f"{negotiated_name}"
                        ),
                    )

                return CipherResult(
                    name=negotiated_name,
                    protocol="TLSv1.2",
                    status=CipherStatus.SUPPORTED,
                    bits=bits,
                )
    except ssl.SSLError as exc:
        return CipherResult(
            name=cipher_name,
            protocol="TLSv1.2",
            status=_classify_cipher_ssl_error(exc),
            error=str(exc),
        )
    except (OSError, TimeoutError) as exc:
        return CipherResult(
            name=cipher_name,
            protocol="TLSv1.2",
            status=CipherStatus.ERROR,
            error=f"{type(exc).__name__}: {exc}",
        )


def scan_tls12_ciphers(
    host: str,
    port: int,
    timeout: float = 5.0,
) -> list[CipherResult]:
    return [
        probe_cipher_tls12(host, port, cipher_name, timeout=timeout)
        for cipher_name in TLS12_CIPHERS_TO_TEST
    ]


def is_weak_cipher(cipher_name: str) -> bool:
    upper_name = cipher_name.upper()
    return any(pattern in upper_name for pattern in WEAK_PATTERNS)


def classify_cipher(cipher_name: str) -> str:
    """Classify a negotiated suite using conservative name-based heuristics."""
    upper_name = cipher_name.upper()

    if is_weak_cipher(upper_name):
        return "WEAK"

    if "GCM" in upper_name or "CHACHA20" in upper_name or "POLY1305" in upper_name:
        return "MODERN"

    # CBC suites and static-RSA suites are considered legacy. OpenSSL's short
    # names AES128-SHA / AES256-SHA are static-RSA CBC suites.
    if "CBC" in upper_name or upper_name.startswith("TLS_RSA_"):
        return "LEGACY"
    if upper_name.startswith(("AES128-SHA", "AES256-SHA")) or upper_name.endswith(("-SHA", "-SHA1", "-SHA256", "-SHA384")):
        return "LEGACY"

    return "UNKNOWN"
