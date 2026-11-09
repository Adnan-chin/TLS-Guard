import socket
import ssl

from tlsguard.checks.protocols import (
    ProtocolResult,
    ProtocolStatus,
    _classify_protocol_ssl_error,
    probe_protocol,
)


def test_protocol_result_exposes_supported_property():
    result = ProtocolResult(
        protocol="TLSv1_3",
        status=ProtocolStatus.SUPPORTED,
        negotiated_version="TLSv1.3",
    )
    assert result.supported is True
    assert result.status is ProtocolStatus.SUPPORTED


def test_generic_handshake_failure_is_not_testable():
    result = _classify_protocol_ssl_error(ssl.SSLError("handshake failure"))
    assert result is ProtocolStatus.NOT_TESTABLE


def test_protocol_version_alert_is_not_supported():
    result = _classify_protocol_ssl_error(
        ssl.SSLError("tlsv1 alert protocol version")
    )
    assert result is ProtocolStatus.NOT_SUPPORTED


def test_dns_error_is_reported_as_error(monkeypatch):
    def fail_connection(*args, **kwargs):
        raise socket.gaierror("name not known")

    monkeypatch.setattr(socket, "create_connection", fail_connection)
    result = probe_protocol(
        "invalid.example",
        443,
        ssl.TLSVersion.TLSv1_2,
        timeout=1,
    )
    assert result.status is ProtocolStatus.ERROR
    assert "gaierror" in result.error


def test_scan_protocols_forwards_timeout(monkeypatch):
    from tlsguard.checks.protocols import scan_protocols

    received = []

    def fake_probe(host, port, version, timeout):
        received.append(timeout)
        return ProtocolResult(version.name, ProtocolStatus.NOT_TESTABLE)

    monkeypatch.setattr("tlsguard.checks.protocols.probe_protocol", fake_probe)
    scan_protocols("example.test", 443, timeout=3.25)
    assert received == [3.25, 3.25, 3.25, 3.25]
