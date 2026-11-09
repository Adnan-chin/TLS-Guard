from tlsguard.checks.certificate import CertificateResult
from tlsguard.checks.ciphers import CipherResult
from tlsguard.checks.protocols import ProtocolResult
from tlsguard.models.finding import Finding
from tlsguard.rules.certificate_rules import evaluate_certificate
from tlsguard.rules.cipher_rules import evaluate_ciphers
from tlsguard.rules.protocol_rules import evaluate_protocols


def evaluate_all(
    protocols: list[ProtocolResult],
    certificate: CertificateResult | None,
    ciphers: list[CipherResult],
) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(evaluate_protocols(protocols))
    if certificate is not None:
        findings.extend(evaluate_certificate(certificate))
    findings.extend(evaluate_ciphers(ciphers))
    return findings
