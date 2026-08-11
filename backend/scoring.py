def calculate_compliance_score(
    violations: list,
    code_findings_count: int,
    gaps_count: int
) -> dict:
    """
    Score from 0 to 100.
    100 = fully compliant
    0   = critically non-compliant
    """

    # Start at 100, deduct for violations
    score = 100

    # Deduct per violation by severity
    for v in violations:
        if v.severity == "critical":
            score -= 15
        elif v.severity == "high":
            score -= 8
        elif v.severity == "medium":
            score -= 4

    # Deduct for each consent gap
    score -= gaps_count * 5

    # Floor at 0
    score = max(0, score)

    # Determine rating
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
    }