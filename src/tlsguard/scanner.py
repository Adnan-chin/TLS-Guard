"""Orchestrates TLSGuard checks and builds a structured scan result."""

from __future__ import annotations

import math
import ssl

from tlsguard.checks.certificate import CertificateResult, scan_certificate
from tlsguard.checks.ciphers import CipherStatus, scan_tls12_ciphers
from tlsguard.checks.protocols import ProtocolStatus, scan_protocols
from tlsguard.models.report import ScanResult
from tlsguard.rules.engine import evaluate_all
from tlsguard.scoring import calculate_score


class TLSScanner:
    def __init__(
        self,
        host: str,
        port: int = 443,
        timeout: float = 5.0,
    ) -> None:
        if not host or host != host.strip():
            raise ValueError("Host must be a non-empty hostname or IP address")
        if not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Timeout must be greater than zero")

        self.host = host
        self.port = port
        self.timeout = timeout

    def run(self) -> ScanResult:
        protocols = scan_protocols(self.host, self.port, timeout=self.timeout)

        certificate: CertificateResult | None
        certificate_error: str | None = None
        try:
            certificate = scan_certificate(
                self.host,
                self.port,
                timeout=self.timeout,
            )
        except (ConnectionError, OSError, ssl.SSLError, ValueError) as exc:
            certificate = None
            certificate_error = f"{type(exc).__name__}: {exc}"

        ciphers = scan_tls12_ciphers(
            self.host,
            self.port,
            timeout=self.timeout,
        )

        findings = evaluate_all(
            protocols=protocols,
            certificate=certificate,
            ciphers=ciphers,
        )

        protocol_checks_complete = all(
            result.status in (ProtocolStatus.SUPPORTED, ProtocolStatus.NOT_SUPPORTED)
            for result in protocols
        )
        cipher_checks_complete = all(
            result.status in (CipherStatus.SUPPORTED, CipherStatus.NOT_SUPPORTED)
            for result in ciphers
        )
        assessment_complete = (
            certificate is not None
            and protocol_checks_complete
            and cipher_checks_complete
        )
        security_score = calculate_score(
            findings,
            assessment_complete=assessment_complete,
        )

        return ScanResult(
            host=self.host,
            port=self.port,
            protocols=protocols,
            certificate=certificate,
            certificate_error=certificate_error,
            ciphers=ciphers,
            findings=findings,
            security_score=security_score,
        )
