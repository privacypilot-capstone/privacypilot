"""
Compliance Scoring Formula
===========================
Tests backend/scoring.py's calculate_compliance_score() directly, aimed at
three specific problems a review raised against the PREVIOUS formula
(S = max(0, 100 - 15*critical - 8*high - 4*medium), with gap count also
subtracted separately):

  1. A zero-violation ("compliant") repo scored 48/100 "Poor" instead of
     100/100 "Good" -- impossible for a repo with no violations at all.
  2. The formula double-counted: each gap category was both (a) already
     represented as a violation by the rule engine AND (b) penalised
     again directly via the gap count.
  3. The flat subtraction floored at a hard 0 after ~6-7 severity-weighted
     violations, so two very different "bad" repos became indistinguishable.

scoring.py replaced this with a multiplicative decay formula. No test
previously existed for this file at all. While writing these tests, a
4th, more subtle version of problem 3 turned up: the new formula's true
value never hits exactly 0, but round(score, 1) did, at ~35+ critical
violations -- silently reintroducing the same "repos become
indistinguishable" symptom through rounding instead of a hard floor.
Fixed by rounding to 4 decimal places instead of 1 (pushes the collapse
point out to ~65 violations). These tests check a REALISTIC range (real
repos in this evaluation have at most a handful of violations, not
dozens) and separately document -- rather than hide -- that any finite
decimal rounding must eventually collapse an asymptotically-decaying
value to a displayed 0.0 at a large enough count; that's an inherent
property of rounding, not something to pretend is fully eliminated.
"""

import sys
sys.path.insert(0, "/app")

from scoring import calculate_compliance_score


class _FakeViolation:
    def __init__(self, severity):
        self.severity = severity


def _violations(critical=0, high=0, medium=0, low=0):
    return (
        [_FakeViolation("critical") for _ in range(critical)]
        + [_FakeViolation("high") for _ in range(high)]
        + [_FakeViolation("medium") for _ in range(medium)]
        + [_FakeViolation("low") for _ in range(low)]
    )


print("=" * 55)
print("Compliance Scoring Formula")
print("=" * 55)

all_pass = True

# ── Problem 1: a genuinely compliant repo must score 100, not 48 ─────────
print("\n--- A zero-violation repo must score exactly 100 ---")
result = calculate_compliance_score(violations=[], code_findings_count=12, gaps_count=0)
ok = result["score"] == 100.0 and result["rating"] == "Good"
print(f"  [{'PASS' if ok else 'FAIL'}]  score={result['score']}, rating={result['rating']}")
all_pass &= ok

# ── Problem 2: gaps must not be double-counted ────────────────────────────
print("\n--- gaps_count must not change the score (no double-counting) ---")
result_with_gaps = calculate_compliance_score(violations=[], code_findings_count=12, gaps_count=7)
ok = result_with_gaps["score"] == 100.0
print(f"  [{'PASS' if ok else 'FAIL'}]  score with gaps_count=7 -> {result_with_gaps['score']} (expected 100.0)")
all_pass &= ok

# ── Problem 3: distinguishable, non-floored scores across a REALISTIC
# range of violation counts (this evaluation's whole synthetic ground
# truth is 15 planted violations total, across FIVE repos -- a single
# repo having even 10-15 is already a worst case for this project) ───────
print("\n--- Realistic-scale scores must stay nonzero and strictly decreasing ---")
realistic_ns = [0, 1, 2, 5, 10, 15, 20, 30]
scores = []
for n in realistic_ns:
    r = calculate_compliance_score(_violations(critical=n), 0, 0)
    scores.append(r["score"])
    print(f"    {n:3d} critical violations -> score {r['score']}")

ok = all(s > 0 for s in scores)
print(f"  [{'PASS' if ok else 'FAIL'}]  every realistic-scale score stays > 0")
all_pass &= ok

ok = all(scores[i] > scores[i + 1] for i in range(len(scores) - 1))
print(f"  [{'PASS' if ok else 'FAIL'}]  scores are strictly decreasing across 0-30 violations")
all_pass &= ok

# 15 vs 30 critical violations -- comparable to "worst single repo in our
# ground truth" vs "twice that" -- must stay distinguishable.
score_15 = calculate_compliance_score(_violations(critical=15), 0, 0)["score"]
score_30 = calculate_compliance_score(_violations(critical=30), 0, 0)["score"]
ok = score_15 != score_30 and score_15 > 0 and score_30 > 0
print(f"  [{'PASS' if ok else 'FAIL'}]  15 vs 30 critical violations distinguishable: {score_15} != {score_30}")
all_pass &= ok

# ── Documented, not hidden: at an unrealistic violation count far beyond
# anything this project's repos could produce, decimal rounding DOES
# eventually collapse to a displayed 0.0. This is expected and is an
# inherent property of rounding an asymptotic curve, not a regression --
# recorded here so it's an intentional, known boundary, not a surprise.
print("\n--- Documented limit: extreme (unrealistic) counts still round to 0.0 ---")
extreme_score = calculate_compliance_score(_violations(critical=200), 0, 0)["score"]
print(f"    200 critical violations -> score {extreme_score} "
      f"(expected to display as 0.0 -- true value is ~{100 * 0.8**200:.2e}, not literally zero)")

print(f"\n{'SCORING: PASS' if all_pass else 'SCORING: FAIL -- check failures above'}")
