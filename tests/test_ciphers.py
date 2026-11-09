import socket
import ssl

from tlsguard.checks.ciphers import (
    CipherStatus,
    _classify_cipher_ssl_error,
    classify_cipher,
    is_weak_cipher,
    probe_cipher_tls12,
)


def test_null_cipher_is_weak():
    assert is_weak_cipher("TLS_RSA_WITH_NULL_MD5")


def test_rc4_cipher_is_weak():
    assert is_weak_cipher("ECDHE-RSA-RC4-SHA")


def test_3des_cipher_is_weak():
    assert is_weak_cipher("DES-CBC3-SHA")


def test_modern_cipher_is_not_weak():
    assert not is_weak_cipher("ECDHE-RSA-AES256-GCM-SHA384")
    assert classify_cipher("ECDHE-RSA-AES256-GCM-SHA384") == "MODERN"


def test_openssl_aes_sha_short_name_is_legacy():
    assert classify_cipher("AES256-SHA") == "LEGACY"


def test_cbc_suite_is_legacy():
    assert classify_cipher("ECDHE-RSA-AES128-SHA") == "LEGACY"
    assert classify_cipher("ECDHE-RSA-AES128-SHA256") == "LEGACY"


def test_generic_handshake_failure_is_not_testable():
    assert (
        _classify_cipher_ssl_error(ssl.SSLError("handshake failure"))
        is CipherStatus.NOT_TESTABLE
    )


def test_dns_error_is_error_not_not_supported(monkeypatch):
    def fail_connection(*args, **kwargs):
        raise socket.gaierror("name not known")

    monkeypatch.setattr(socket, "create_connection", fail_connection)
    result = probe_cipher_tls12(
        "invalid.example",
        443,
        "ECDHE-RSA-AES128-GCM-SHA256",
        timeout=1,
    )
    assert result.status is CipherStatus.ERROR
    assert "gaierror" in result.error


def test_scan_ciphers_forwards_timeout(monkeypatch):
    from tlsguard.checks.ciphers import TLS12_CIPHERS_TO_TEST, scan_tls12_ciphers

    received = []

    def fake_probe(host, port, cipher_name, timeout):
        received.append(timeout)
        return type("Result", (), {"name": cipher_name})()

    monkeypatch.setattr("tlsguard.checks.ciphers.probe_cipher_tls12", fake_probe)
    scan_tls12_ciphers("example.test", 443, timeout=4.5)
    assert received == [4.5] * len(TLS12_CIPHERS_TO_TEST)
