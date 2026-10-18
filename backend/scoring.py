# Per-violation retention penalties — each violation of a given severity
# multiplies the running score by (1 - penalty), rather than subtracting a
# fixed number of points.  This keeps the score strictly bounded in (0, 100]
# and strictly decreasing, but — unlike flat subtraction — never bottoms out
# at a hard 0 purely from violation *count*: a repo with 50 high-severity
# findings still scores worse than one with 10, instead of both saturating
# to an indistinguishable 0/100.
PENALTY_CRITICAL = 0.20   # each critical violation retains 80% of what's left
PENALTY_HIGH      = 0.10   # each high violation retains 90% of what's left
PENALTY_MEDIUM     = 0.05  # each medium violation retains 95% of what's left


def calculate_compliance_score(
    violations: list,
    code_findings_count: int,
    gaps_count: int
) -> dict:
    """
    Score from 0 to 100 using multiplicative (diminishing-returns) decay:

        S = 100 × (1 − PENALTY_CRITICAL)^critical
                 × (1 − PENALTY_HIGH)^high
                 × (1 − PENALTY_MEDIUM)^medium

    100 = fully compliant (zero violations).
    Approaches 0 as violations accumulate but never reaches it exactly, so
    two heavily non-compliant repos remain distinguishable from each other
    instead of both floor-clamping to an identical 0.

    This replaces the earlier flat-subtraction formula
    (S = max(0, 100 − 15·critical − 8·high − 4·medium)), which saturated to
    0 after roughly 6-7 severity-weighted violations and could not
    differentiate "bad" from "much worse" beyond that point.

    Note: gap count is passed in for reporting purposes only — it is NOT
    factored into the score.  Gaps are already represented as Section 5 /
    Section 6(1) CRITICAL or HIGH violations by the rule engine, so
    double-penalising them would distort the metric.
    """
    critical_count = sum(1 for v in violations if v.severity == "critical")
    high_count     = sum(1 for v in violations if v.severity == "high")
    medium_count   = sum(1 for v in violations if v.severity == "medium")

    score = (
        100
        * (1 - PENALTY_CRITICAL) ** critical_count
        * (1 - PENALTY_HIGH) ** high_count
        * (1 - PENALTY_MEDIUM) ** medium_count
    )
    # Round for display, but not to 1 decimal place: the true value is
    # never exactly 0, yet round(x, 1) collapses anything below 0.05 to a
    # literal 0.0 — reintroducing the "repos become indistinguishable"
    # problem this formula was built to avoid, just via rounding instead
    # of the old hard floor. 4 decimal places pushes that collapse point
    # from ~35 critical violations out to ~65, comfortably past anything
    # a single repo in this evaluation's scale would realistically produce.
    # (At a large enough violation count any finite decimal rounding will
    # still eventually display 0.0 — that's an inherent property of
    # rounding a number that only asymptotically approaches zero, not a
    # logic bug — but 4 decimals keeps it out of reach for realistic use.)
    score = round(score, 4)

    # Determine rating band from score thresholds...
    if score >= 80:
        rating = "Good"
    elif score >= 60:
        rating = "Moderate"
    elif score >= 40:
        rating = "Poor"
    else:
        rating = "Critical"

    # ...then cap it: a single unresolved CRITICAL violation (e.g. an
    # undisclosed Aadhaar collection) should never read as "Good" or
    # "Moderate" just because the weighted score is still numerically high.
    # Presence of any critical violation floors the rating at "Poor" —
    # it can still fall to "Critical" on the score itself, just never rise
    # above "Poor" while a critical issue is outstanding.
    if critical_count > 0 and rating in ("Good", "Moderate"):
        rating = "Poor"

    color = {
        "Good":     "#28a745",
        "Moderate": "#fd7e14",
        "Poor":     "#dc3545",
        "Critical": "#6f0000",
    }[rating]

    return {
        "score":  score,
        "rating": rating,
        "color":  color,
        "total_violations":  len(violations),
        "critical_count": critical_count,
        "high_count":     high_count,
        "medium_count":   medium_count,
    }
