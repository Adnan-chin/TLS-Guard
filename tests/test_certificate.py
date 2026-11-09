from datetime import datetime, timezone

from tlsguard.checks.certificate import CertificateResult, certificate_status


def make_certificate(**overrides):
    values = {
        "subject": "CN=test.local",
        "issuer": "CN=Test CA",
        "serial_number": 123456,
        "not_valid_before": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "not_valid_after": datetime(2027, 1, 1, tzinfo=timezone.utc),
        "days_remaining": 60.0,
        "expired": False,
        "not_yet_valid": False,
        "san_dns_names": ["test.local"],
        "signature_hash_algorithm": "sha256",
    }
    values.update(overrides)
    return CertificateResult(**values)


def test_certificate_date_validity():
    assert certificate_status(make_certificate()) == "DATE_VALID"


def test_expired_certificate_status():
    cert = make_certificate(expired=True, days_remaining=-1)
    assert certificate_status(cert) == "EXPIRED"


def test_not_yet_valid_certificate_status():
    cert = make_certificate(not_yet_valid=True)
    assert certificate_status(cert) == "NOT_YET_VALID"


def test_certificate_expiring_soon_status():
    cert = make_certificate(days_remaining=10)
    assert certificate_status(cert) == "EXPIRING_SOON"
