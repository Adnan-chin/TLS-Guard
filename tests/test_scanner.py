from datetime import datetime, timezone

from tlsguard.checks.certificate import CertificateResult
from tlsguard.checks.ciphers import CipherResult, CipherStatus
from tlsguard.checks.protocols import ProtocolResult, ProtocolStatus
from tlsguard.scanner import TLSScanner


def make_certificate():
    return CertificateResult(
        subject="CN=example.test",
        issuer="CN=Test CA",
        serial_number=1,
        not_valid_before=datetime(2025, 1, 1, tzinfo=timezone.utc),
        not_valid_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        days_remaining=60,
        expired=False,
        not_yet_valid=False,
        san_dns_names=["example.test"],
        signature_hash_algorithm="sha256",
    )


def test_timeout_is_forwarded_to_all_scans(monkeypatch):
    calls = {}

    def fake_protocols(host, port, timeout):
        calls["protocols"] = timeout
        return [ProtocolResult("TLSv1_3", ProtocolStatus.SUPPORTED, "TLSv1.3")]

    def fake_certificate(host, port, timeout):
        calls["certificate"] = timeout
        return make_certificate()

    def fake_ciphers(host, port, timeout):
        calls["ciphers"] = timeout
        return [CipherResult("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", CipherStatus.NOT_TESTABLE)]

    monkeypatch.setattr("tlsguard.scanner.scan_protocols", fake_protocols)
    monkeypatch.setattr("tlsguard.scanner.scan_certificate", fake_certificate)
    monkeypatch.setattr("tlsguard.scanner.scan_tls12_ciphers", fake_ciphers)

    result = TLSScanner("example.test", port=8443, timeout=2.5).run()
    assert calls == {"protocols": 2.5, "certificate": 2.5, "ciphers": 2.5}
    assert result.security_score.score is None
    assert result.security_score.risk_level == "INCOMPLETE"


def test_certificate_failure_keeps_partial_scan(monkeypatch):
    monkeypatch.setattr(
        "tlsguard.scanner.scan_protocols",
        lambda host, port, timeout: [
            ProtocolResult("TLSv1_3", ProtocolStatus.SUPPORTED, "TLSv1.3")
        ],
    )

    def fail_certificate(host, port, timeout):
        raise ConnectionError("certificate unavailable")

    monkeypatch.setattr("tlsguard.scanner.scan_certificate", fail_certificate)
    monkeypatch.setattr(
        "tlsguard.scanner.scan_tls12_ciphers",
        lambda host, port, timeout: [],
    )

    result = TLSScanner("example.test").run()
    assert result.certificate is None
    assert "certificate unavailable" in result.certificate_error
    assert result.security_score.score is None
