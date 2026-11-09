from tlsguard.models.finding import Finding, Severity
from tlsguard.scoring import calculate_score


def make_finding(severity: Severity) -> Finding:
    return Finding(
        id="TEST-001",
        title="Test finding",
        severity=severity,
        description="Test description",
        evidence="Test evidence",
        recommendation="Test recommendation",
    )


def test_no_findings_gives_100():
    result = calculate_score([])
    assert result.score == 100
    assert result.risk_level == "LOW"
    assert result.assessment_complete is True


def test_high_and_medium_findings():
    result = calculate_score([
        make_finding(Severity.HIGH),
        make_finding(Severity.MEDIUM),
    ])
    assert result.score == 65
    assert result.risk_level == "HIGH"
    assert result.total_penalty == 35


def test_score_never_goes_below_zero():
    result = calculate_score([
        make_finding(Severity.CRITICAL),
        make_finding(Severity.CRITICAL),
        make_finding(Severity.HIGH),
    ])
    assert result.score == 0
    assert result.risk_level == "CRITICAL"


def test_incomplete_assessment_has_no_numeric_score():
    result = calculate_score([], assessment_complete=False)
    assert result.score is None
    assert result.risk_level == "INCOMPLETE"
    assert result.assessment_complete is False
