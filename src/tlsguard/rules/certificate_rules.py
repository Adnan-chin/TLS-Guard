from tlsguard.checks.certificate import CertificateResult
from tlsguard.models.finding import Finding, Severity


def evaluate_certificate(
    certificate: CertificateResult,
) -> list[Finding]:

    findings: list[Finding] = []

    if certificate.not_yet_valid:

        findings.append(
            Finding(
                id="TLS-003",
                title="Certificate is not yet valid",
                severity=Severity.HIGH,
                description=(
                    "The server certificate is outside its "
                    "validity period because its start date "
                    "is in the future."
                ),
                evidence=(
                    f"Certificate valid from "
                    f"{certificate.not_valid_before.isoformat()}."
                ),
                recommendation=(
                    "Verify the server clock and certificate "
                    "deployment date."
                ),
            )
        )

    if certificate.expired:

        findings.append(
            Finding(
                id="TLS-004",
                title="Certificate expired",
                severity=Severity.CRITICAL,
                description=(
                    "The server presents an expired X.509 "
                    "certificate."
                ),
                evidence=(
                    f"Certificate expired on "
                    f"{certificate.not_valid_after.isoformat()}."
                ),
                recommendation=(
                    "Replace the expired certificate with a "
                    "currently valid certificate."
                ),
            )
        )

    elif certificate.days_remaining < 30:

        findings.append(
            Finding(
                id="TLS-005",
                title="Certificate expires soon",
                severity=Severity.MEDIUM,
                description=(
                    "The certificate is approaching its "
                    "expiration date."
                ),
                evidence=(
                    f"Approximately "
                    f"{certificate.days_remaining:.1f} days "
                    "remain before expiration."
                ),
                recommendation=(
                    "Renew the certificate before it expires "
                    "and verify the deployment process."
                ),
            )
        )

    return findings