def calculate_compliance_score(
    violations: list,
    code_findings_count: int,
    gaps_count: int
) -> dict:
    """
    Score from 0 to 100.  S = max(0, 100 − 15·|CRITICAL| − 8·|HIGH| − 4·|MEDIUM|)
    100 = fully compliant
    0   = critically non-compliant

    Note: gap count is passed in for reporting purposes only — it is NOT
    subtracted from the score.  Gaps are already represented as Section 5 /
    Section 6(1) CRITICAL or HIGH violations by the rule engine, so
    double-penalising them would distort the metric.
    """

    # Start at 100, deduct for violations by severity
    score = 100
    for v in violations:
        if v.severity == "critical":
            score -= 15
        elif v.severity == "high":
            score -= 8
        elif v.severity == "medium":
            score -= 4

    # Floor at 0
    score = max(0, score)

    # Determine rating band
    if score >= 80:
        rating = "Good"
        color  = "#28a745"
    elif score >= 60:
        rating = "Moderate"
        color  = "#fd7e14"
    elif score >= 40:
        rating = "Poor"
        color  = "#dc3545"
    else:
        rating = "Critical"
        color  = "#6f0000"

    return {
        "score":  score,
        "rating": rating,
        "color":  color,
        "total_violations":  len(violations),
        "critical_count": sum(1 for v in violations if v.severity == "critical"),
        "high_count":     sum(1 for v in violations if v.severity == "high"),
        "medium_count":   sum(1 for v in violations if v.severity == "medium"),
    }
