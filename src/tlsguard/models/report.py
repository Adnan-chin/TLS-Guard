from dataclasses import dataclass

from tlsguard.checks.certificate import CertificateResult
from tlsguard.checks.ciphers import CipherResult
from tlsguard.checks.protocols import ProtocolResult
from tlsguard.models.finding import Finding
from tlsguard.scoring import SecurityScore


@dataclass(slots=True)
class ScanResult:
    host: str
    port: int
    protocols: list[ProtocolResult]
    certificate: CertificateResult | None
    certificate_error: str | None
    ciphers: list[CipherResult]
    findings: list[Finding]
    security_score: SecurityScore
