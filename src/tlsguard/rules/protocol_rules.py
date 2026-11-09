from tlsguard.checks.protocols import ProtocolResult, ProtocolStatus
from tlsguard.models.finding import Finding, Severity


def evaluate_protocols(results: list[ProtocolResult]) -> list[Finding]:
    findings: list[Finding] = []
    by_protocol = {result.protocol: result for result in results}

    tls12 = by_protocol.get("TLSv1_2")
    tls13 = by_protocol.get("TLSv1_3")

    # Do not infer that modern TLS is disabled from a timeout, local OpenSSL
    # restriction, generic handshake failure, or an unreachable host.
    if (
        tls12 is not None
        and tls13 is not None
        and tls12.status is ProtocolStatus.NOT_SUPPORTED
        and tls13.status is ProtocolStatus.NOT_SUPPORTED
    ):
        findings.append(
            Finding(
                id="TLS-008",
                title="No modern TLS protocol available",
                severity=Severity.CRITICAL,
                description=(
                    "The endpoint explicitly rejected TLS 1.2 and TLS 1.3 "
                    "during protocol-version negotiation."
                ),
                evidence=(
                    f"TLS 1.2: {tls12.error or 'rejected'}; "
                    f"TLS 1.3: {tls13.error or 'rejected'}."
                ),
                recommendation="Enable TLS 1.2 and preferably TLS 1.3.",
            )
        )

    for result in results:
        if result.status is not ProtocolStatus.SUPPORTED:
            continue

        if result.protocol == "TLSv1":
            findings.append(
                Finding(
                    id="TLS-001",
                    title="Deprecated TLS 1.0 enabled",
                    severity=Severity.HIGH,
                    description=(
                        "The server accepts TLS 1.0 connections. TLS 1.0 is "
                        "deprecated and should not be used for modern secure communications."
                    ),
                    evidence="TLS 1.0 handshake succeeded.",
                    recommendation="Disable TLS 1.0 and use TLS 1.2 or TLS 1.3.",
                )
            )
        elif result.protocol == "TLSv1_1":
            findings.append(
                Finding(
                    id="TLS-002",
                    title="Deprecated TLS 1.1 enabled",
                    severity=Severity.HIGH,
                    description=(
                        "The server accepts TLS 1.1 connections. TLS 1.1 is "
                        "deprecated and should not be used for modern secure communications."
                    ),
                    evidence="TLS 1.1 handshake succeeded.",
                    recommendation="Disable TLS 1.1 and use TLS 1.2 or TLS 1.3.",
                )
            )

    return findings
