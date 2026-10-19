"""
eval/compute_metrics.py
========================
Grades the scan output from run_eval.py (eval/results/all_results.json)
against a ground-truth file you provide (eval/ground_truth.json), and
reports strict + lenient recall/precision/F1 with Wilson 95% confidence
intervals, plus a per-PII-category breakdown (Table V) and a per-repo
breakdown.

Definitions (matching the paper's own stated methodology, para 96):
  TP      : a planted violation is matched by an actual violation with the
            same rule AND the same PII category.
  Partial : matched by an actual violation with the same rule but a
            DIFFERENT PII category. Counts as TP under lenient scoring,
            as FN under strict scoring.
  FN      : no actual violation matches the planted violation's rule at all.
  FP      : an actual violation left over after every planted violation in
            that repo has been matched (one-to-one — a single actual
            violation can satisfy at most one planted violation, so two
            planted violations of the same kind in one repo need two
            distinct actual detections, not one counted twice).

Usage: python eval/compute_metrics.py
Reads eval/results/all_results.json and eval/ground_truth.json (both must
exist — see eval/ground_truth.example.json for the shape).
"""

import json
import math
from pathlib import Path

HERE = Path(__file__).parent
RESULTS_FILE = HERE / "results" / "all_results.json"
GROUND_TRUTH_FILE = HERE / "ground_truth.json"

# Maps the rule engine's actual dpdp_section strings (as of the current,
# post-fix rule_engine.py) to a stable rule-bucket label a ground-truth
# file can reference without caring about exact section wording.
SECTION_TO_RULE = {
    "Section 5 / Section 6(1)":          "rule_1_notice_gap",
    "Section 5 / Section 8(2)":          "rule_2_third_party",
    "Section 8(2)":                      "rule_2_third_party",  # disclosed-SDK branch
    "Section 8(5)":                      "rule_2_third_party",  # logger-sink branch
    "Section 6(1)":                      "rule_3_purpose_linkage",
    "DPDP Rules 2025, Rule 3(b)(ii)":     "vagueness",
}


def wilson_ci(successes: int, total: int, z: float = 1.959963984540054):
    """95% Wilson score interval for a proportion. Returns (lower, upper),
    both in [0, 1]. Far more honest than a bare point estimate on small n —
    e.g. 14/15 has a much wider real interval than "93.3%" suggests."""
    if total == 0:
        return (0.0, 0.0)
    p = successes / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    margin = (z / denom) * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))
    return (max(0.0, center - margin), min(1.0, center + margin))


def rule_of(dpdp_section: str) -> str:
    return SECTION_TO_RULE.get(dpdp_section, f"unknown:{dpdp_section}")


def match_repo(planted: list[dict], actual: list[dict]) -> dict:
    """One-to-one matching for a single repo. Returns counts plus the
    leftover (unmatched) actual violations, which are this repo's FPs.

    Two passes, so the result does not depend on the order of the planted
    list: every EXACT match (same rule + same PII category) is made first,
    and only then are the remaining planted violations allowed a PARTIAL
    match (same rule, other category). A single greedy pass let an earlier
    planted violation take, as a partial match, the detection that exactly
    matched a later one — turning a strict TP into a strict FN.
    """
    remaining_actual = list(actual)  # each: {"rule":..., "pii_category":...}
    outcome: list[str | None] = [None] * len(planted)

    # Pass 1: exact matches
    for i, gt in enumerate(planted):
        idx = next(
            (j for j, a in enumerate(remaining_actual)
             if a["rule"] == gt["rule"] and a["pii_category"] == gt["pii_category"]),
            None,
        )
        if idx is not None:
            remaining_actual.pop(idx)
            outcome[i] = "TP"

    # Pass 2: partial matches for whatever is still unmatched
    for i, gt in enumerate(planted):
        if outcome[i] is not None:
            continue
        idx = next(
            (j for j, a in enumerate(remaining_actual) if a["rule"] == gt["rule"]),
            None,
        )
        if idx is not None:
            remaining_actual.pop(idx)
            outcome[i] = "PARTIAL"
        else:
            outcome[i] = "MISSED"

    strict_tp  = outcome.count("TP")
    lenient_tp = strict_tp + outcome.count("PARTIAL")
    fn         = outcome.count("PARTIAL") + outcome.count("MISSED")  # strict FN
    details    = [{**gt, "outcome": o} for gt, o in zip(planted, outcome)]

    fp = len(remaining_actual)
    return {
        "strict_tp": strict_tp, "lenient_tp": lenient_tp, "fn": fn, "fp": fp,
        "leftover_actual_fp": remaining_actual, "details": details,
    }


def main():
    if not RESULTS_FILE.exists():
        print(f"Missing {RESULTS_FILE} — run eval/run_eval.py first.")
        return
    if not GROUND_TRUTH_FILE.exists():
        print(f"Missing {GROUND_TRUTH_FILE} — copy eval/ground_truth.example.json "
              f"to eval/ground_truth.json and fill in the 15 planted violations.")
        return

    results = json.loads(RESULTS_FILE.read_text())
    ground_truth = json.loads(GROUND_TRUTH_FILE.read_text())

    totals = {"strict_tp": 0, "lenient_tp": 0, "fn": 0, "fp": 0}
    per_category: dict[str, dict] = {}
    per_repo_report = {}

    for repo in ground_truth["repos"]:
        label = repo["label"]
        planted = repo["violations"]
        scan_result = results.get(label, {})
        if "error" in scan_result:
            print(f"WARNING: {label} scan errored ({scan_result['error']}) — "
                  f"all {len(planted)} planted violations count as FN for this repo.")
            actual = []
        else:
            actual = [
                {"rule": rule_of(v["dpdp_section"]), "pii_category": v["pii_category"]}
                for v in scan_result.get("violations", [])
            ]

        m = match_repo(planted, actual)
        per_repo_report[label] = m
        for k in ("strict_tp", "lenient_tp", "fn", "fp"):
            totals[k] += m[k]

        # Per-PII-category rollup (Table V), driven by the ground truth's
        # own categories plus any leftover-FP categories.
        for d in m["details"]:
            cat = d["pii_category"]
            per_category.setdefault(cat, {"strict_tp": 0, "lenient_tp": 0, "fn": 0, "fp": 0})
            if d["outcome"] == "TP":
                per_category[cat]["strict_tp"] += 1
                per_category[cat]["lenient_tp"] += 1
            elif d["outcome"] == "PARTIAL":
                per_category[cat]["lenient_tp"] += 1
                per_category[cat]["fn"] += 1
            else:
                per_category[cat]["fn"] += 1
        for fp_item in m["leftover_actual_fp"]:
            cat = fp_item["pii_category"]
            per_category.setdefault(cat, {"strict_tp": 0, "lenient_tp": 0, "fn": 0, "fp": 0})
            per_category[cat]["fp"] += 1

    def prf(tp, fn, fp):
        recall    = tp / (tp + fn) if (tp + fn) else 0.0
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        return recall, precision, f1

    print("=" * 70)
    print("OVERALL")
    print("=" * 70)
    for mode, tp_key in (("STRICT", "strict_tp"), ("LENIENT", "lenient_tp")):
        tp = totals[tp_key]
        fn = totals["fn"] if mode == "STRICT" else (totals["fn"] - (totals["lenient_tp"] - totals["strict_tp"]))
        fp = totals["fp"]
        total_planted = tp + fn
        recall, precision, f1 = prf(tp, fn, fp)
        r_lo, r_hi = wilson_ci(tp, total_planted)
        p_lo, p_hi = wilson_ci(tp, tp + fp)
        print(f"\n{mode}:")
        print(f"  TP={tp}  FN={fn}  FP={fp}  (planted total={total_planted})")
        print(f"  Recall:    {recall:.1%}   (Wilson 95% CI: {r_lo:.1%}-{r_hi:.1%})")
        print(f"  Precision: {precision:.1%}   (Wilson 95% CI: {p_lo:.1%}-{p_hi:.1%})")
        print(f"  F1:        {f1:.1%}")

    print("\n" + "=" * 70)
    print("PER-REPO")
    print("=" * 70)
    for label, m in per_repo_report.items():
        print(f"  {label}: strict_tp={m['strict_tp']} lenient_tp={m['lenient_tp']} "
              f"fn={m['fn']} fp={m['fp']}")

    print("\n" + "=" * 70)
    print("PER-PII-CATEGORY (Table V)")
    print("=" * 70)
    for cat, c in sorted(per_category.items()):
        recall, precision, f1 = prf(c["strict_tp"], c["fn"], c["fp"])
        print(f"  {cat:12s}  strict_tp={c['strict_tp']}  lenient_tp={c['lenient_tp']}  "
              f"fn={c['fn']}  fp={c['fp']}  recall={recall:.1%}  precision={precision:.1%}")

    out = {
        "totals": totals,
        "per_repo": per_repo_report,
        "per_category": per_category,
    }
    (HERE / "metrics_output.json").write_text(json.dumps(out, indent=2, default=str))
    print(f"\nFull breakdown written to {HERE / 'metrics_output.json'}")


if __name__ == "__main__":
    main()
