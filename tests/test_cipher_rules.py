from tlsguard.checks.ciphers import CipherResult, CipherStatus
from tlsguard.models.finding import Severity
from tlsguard.rules.cipher_rules import evaluate_ciphers


def test_cipher_findings_aggregate_suites_by_category():
    results = [
        CipherResult("DES-CBC3-SHA", "TLSv1.2", CipherStatus.SUPPORTED, 112),
        CipherResult("RC4-SHA", "TLSv1.2", CipherStatus.SUPPORTED, 128),
        CipherResult("AES256-SHA", "TLSv1.2", CipherStatus.SUPPORTED, 256),
        CipherResult("ECDHE-RSA-AES128-SHA", "TLSv1.2", CipherStatus.SUPPORTED, 128),
        CipherResult("AES128-SHA", "TLSv1.2", CipherStatus.NOT_SUPPORTED),
        CipherResult("AES256-SHA", "TLSv1.2", CipherStatus.NOT_TESTABLE),
    ]

    findings = evaluate_ciphers(results)
    assert len(findings) == 2

    weak = next(item for item in findings if item.id == "TLS-006")
    legacy = next(item for item in findings if item.id == "TLS-007")

    assert weak.severity is Severity.HIGH
    assert "DES-CBC3-SHA" in weak.evidence
    assert "RC4-SHA" in weak.evidence
    assert legacy.severity is Severity.MEDIUM
    assert "AES256-SHA" in legacy.evidence
    assert "ECDHE-RSA-AES128-SHA" in legacy.evidence


def test_cipher_errors_do_not_create_findings():
    results = [
        CipherResult("DES-CBC3-SHA", "TLSv1.2", CipherStatus.ERROR, error="timeout"),
        CipherResult("AES256-SHA", "TLSv1.2", CipherStatus.NOT_TESTABLE),
    ]
    assert evaluate_ciphers(results) == []
