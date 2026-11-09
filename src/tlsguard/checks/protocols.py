"""TLS protocol probing with explicit, conservative result states."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from enum import Enum


class ProtocolStatus(str, Enum):
    SUPPORTED = "supported"
    NOT_SUPPORTED = "not_supported"
    NOT_TESTABLE = "not_testable"
    ERROR = "error"


@dataclass(slots=True)
class ProtocolResult:
    protocol: str
    status: ProtocolStatus
    negotiated_version: str | None = None
    error: str | None = None

    @property
    def supported(self) -> bool:
        """Backward-friendly convenience property for callers."""
        return self.status is ProtocolStatus.SUPPORTED


def _classify_protocol_ssl_error(exc: ssl.SSLError) -> ProtocolStatus:
    """Only label a protocol unsupported when the peer explicitly rejects it."""
    reason = str(getattr(exc, "reason", "") or "").upper()
    message = str(exc).lower()
    if reason == "TLSV1_ALERT_PROTOCOL_VERSION" or (
        "alert protocol version" in message
    ):
        return ProtocolStatus.NOT_SUPPORTED
    # Handshake failure, unsupported protocol, and local OpenSSL policy errors
    # are ambiguous: they do not prove that the remote endpoint rejects a version.
    return ProtocolStatus.NOT_TESTABLE


def probe_protocol(
    host: str,
    port: int,
    version: ssl.TLSVersion,
    timeout: float = 5.0,
) -> ProtocolResult:
    protocol_name = version.name
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = version
    context.maximum_version = version
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Old protocols can be disabled by the local OpenSSL security level.
    # Lowering the level is limited to this isolated probe; it does not alter
    # the host machine's global OpenSSL policy.
    if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
        try:
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError as exc:
            return ProtocolResult(
                protocol=protocol_name,
                status=ProtocolStatus.NOT_TESTABLE,
                error=f"Client cannot configure legacy TLS: {exc}",
            )

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                return ProtocolResult(
                    protocol=protocol_name,
                    status=ProtocolStatus.SUPPORTED,
                    negotiated_version=tls_sock.version(),
                )
    except ssl.SSLError as exc:
        return ProtocolResult(
            protocol=protocol_name,
            status=_classify_protocol_ssl_error(exc),
            error=str(exc),
        )
    except (OSError, TimeoutError) as exc:
        return ProtocolResult(
            protocol=protocol_name,
            status=ProtocolStatus.ERROR,
            error=f"{type(exc).__name__}: {exc}",
        )


def scan_protocols(
    host: str,
    port: int,
    timeout: float = 5.0,
) -> list[ProtocolResult]:
    versions = (
        ssl.TLSVersion.TLSv1,
        ssl.TLSVersion.TLSv1_1,
        ssl.TLSVersion.TLSv1_2,
        ssl.TLSVersion.TLSv1_3,
    )
    return [
        probe_protocol(host, port, version, timeout=timeout)
        for version in versions
    ]
