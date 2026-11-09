from tlsguard.checks.ciphers import (
    CipherResult,
    CipherStatus,
    classify_cipher,
)
from tlsguard.models.finding import Finding, Severity


def evaluate_ciphers(results: list[CipherResult]) -> list[Finding]:
    """Create one finding per cipher risk category, with all suites as evidence."""
    weak_suites: list[str] = []
    legacy_suites: list[str] = []

    for result in results:
        # Failed or unavailable probes are not evidence that a suite is enabled.
        if result.status is not CipherStatus.SUPPORTED:
            continue

        classification = classify_cipher(result.name)
        if classification == "WEAK":
            weak_suites.append(result.name)
        elif classification == "LEGACY":
            legacy_suites.append(result.name)

    findings: list[Finding] = []

    if weak_suites:
        findings.append(
            Finding(
                id="TLS-006",
                title="Weak cipher suite supported",
                severity=Severity.HIGH,
                description=(
                    "The endpoint accepted one or more cipher suites "
                    "classified as weak by TLSGuard."
                ),
                evidence="Negotiated weak cipher suites: " + ", ".join(sorted(set(weak_suites))),
                recommendation=(
                    "Disable the weak cipher suites and prefer modern "
                    "AEAD-based cipher suites."
                ),
            )
        )

    if legacy_suites:
        findings.append(
            Finding(
                id="TLS-007",
                title="Legacy cipher suite supported",
                severity=Severity.MEDIUM,
                description=(
                    "The endpoint accepted one or more legacy cipher suites "
                    "that should be reviewed."
                ),
                evidence="Negotiated legacy cipher suites: " + ", ".join(sorted(set(legacy_suites))),
                recommendation=(
                    "Review the TLS configuration and prefer modern "
                    "AEAD-based cipher suites."
                ),
            )
        )

    return findings
