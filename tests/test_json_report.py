import json
from datetime import datetime, timezone

from tlsguard.checks.certificate import CertificateResult
from tlsguard.checks.ciphers import CipherResult, CipherStatus
from tlsguard.checks.protocols import ProtocolResult, ProtocolStatus
from tlsguard.json_report import build_report, export_json
from tlsguard.models.report import ScanResult
from tlsguard.scoring import calculate_score


def make_scan_result():
    certificate = CertificateResult(
        subject="CN=example.test",
        issuer="CN=Test CA",
        serial_number=42,
        not_valid_before=datetime(2025, 1, 1, tzinfo=timezone.utc),
        not_valid_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        days_remaining=60,
        expired=False,
        not_yet_valid=False,
        san_dns_names=["example.test"],
        signature_hash_algorithm="sha256",
    )
    return ScanResult(
        host="example.test",
        port=443,
        protocols=[ProtocolResult("TLSv1_3", ProtocolStatus.SUPPORTED, "TLSv1.3")],
        certificate=certificate,
        certificate_error=None,
        ciphers=[CipherResult("AES256-SHA", "TLSv1.2", CipherStatus.SUPPORTED, 256)],
        findings=[],
        security_score=calculate_score([]),
    )


def test_build_report_has_expected_fields():
    report = build_report(make_scan_result())
    assert report["target"] == {"host": "example.test", "port": 443}
    assert report["security_score"]["score"] == 100
    assert report["protocols"][0]["status"] == "supported"
    assert report["certificate"]["serial_number"] == 42


def test_export_json_writes_valid_json(tmp_path):
    output = tmp_path / "reports" / "scan.json"
    export_json(make_scan_result(), output)
    loaded = json.loads(output.read_text(encoding="utf-8"))
    assert loaded["target"]["host"] == "example.test"
    assert loaded["certificate"]["not_valid_after"].startswith("2027-")


def test_report_supports_missing_certificate():
    result = make_scan_result()
    result.certificate = None
    result.certificate_error = "ConnectionError: no certificate"
    result.security_score = calculate_score([], assessment_complete=False)
    report = build_report(result)
    assert report["certificate"] is None
    assert report["certificate_error"].startswith("ConnectionError")
    assert report["security_score"]["score"] is None
