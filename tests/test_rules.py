from datetime import datetime, timezone

from tlsguard.checks.certificate import CertificateResult
from tlsguard.checks.protocols import ProtocolResult, ProtocolStatus
from tlsguard.models.finding import Severity
from tlsguard.rules.certificate_rules import evaluate_certificate
from tlsguard.rules.protocol_rules import evaluate_protocols


def make_certificate(**overrides):
    values = {
        "subject": "CN=test.local",
        "issuer": "CN=Test CA",
        "serial_number": 123,
        "not_valid_before": datetime(2020, 1, 1, tzinfo=timezone.utc),
        "not_valid_after": datetime(2021, 1, 1, tzinfo=timezone.utc),
        "days_remaining": -2000,
        "expired": True,
        "not_yet_valid": False,
        "san_dns_names": ["test.local"],
        "signature_hash_algorithm": "sha256",
    }
    values.update(overrides)
    return CertificateResult(**values)


def test_tls10_creates_high_finding():
    results = [
        ProtocolResult("TLSv1", ProtocolStatus.SUPPORTED, "TLSv1")
    ]
    findings = evaluate_protocols(results)
    assert len(findings) == 1
    assert findings[0].id == "TLS-001"
    assert findings[0].severity == Severity.HIGH


def test_expired_certificate_creates_critical():
    findings = evaluate_certificate(make_certificate())
    assert len(findings) == 1
    assert findings[0].id == "TLS-004"
    assert findings[0].severity == Severity.CRITICAL


def test_no_modern_tls_finding_requires_explicit_rejection():
    results = [
        ProtocolResult("TLSv1_2", ProtocolStatus.NOT_SUPPORTED, error="protocol alert"),
        ProtocolResult("TLSv1_3", ProtocolStatus.NOT_SUPPORTED, error="protocol alert"),
    ]
    findings = evaluate_protocols(results)
    assert any(item.id == "TLS-008" for item in findings)


def test_network_errors_do_not_create_no_modern_tls_finding():
    results = [
        ProtocolResult("TLSv1_2", ProtocolStatus.ERROR, error="timeout"),
        ProtocolResult("TLSv1_3", ProtocolStatus.ERROR, error="timeout"),
    ]
    findings = evaluate_protocols(results)
    assert not any(item.id == "TLS-008" for item in findings)


def test_generic_handshake_failure_does_not_create_no_modern_tls_finding():
    results = [
        ProtocolResult("TLSv1_2", ProtocolStatus.NOT_TESTABLE),
        ProtocolResult("TLSv1_3", ProtocolStatus.NOT_TESTABLE),
    ]
    findings = evaluate_protocols(results)
    assert not any(item.id == "TLS-008" for item in findings)
