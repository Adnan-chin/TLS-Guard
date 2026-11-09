"""Transparent heuristic scoring for completed TLS assessments."""

from dataclasses import dataclass

from tlsguard.models.finding import Finding, Severity


PENALTIES = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 25,
    Severity.MEDIUM: 10,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


@dataclass(slots=True)
class SecurityScore:
    score: int | None
    risk_level: str
    total_penalty: int
    assessment_complete: bool = True


def calculate_score(
    findings: list[Finding],
    *,
    assessment_complete: bool = True,
) -> SecurityScore:
    total_penalty = sum(PENALTIES.get(finding.severity, 0) for finding in findings)

    if not assessment_complete:
        return SecurityScore(
            score=None,
            risk_level="INCOMPLETE",
            total_penalty=total_penalty,
            assessment_complete=False,
        )

    score = max(0, 100 - total_penalty)
    if score >= 90:
        risk_level = "LOW"
    elif score >= 70:
        risk_level = "MEDIUM"
    elif score >= 40:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    return SecurityScore(
        score=score,
        risk_level=risk_level,
        total_penalty=total_penalty,
        assessment_complete=True,
    )
