"""
eval/run_eval.py
=================
Drives the PrivacyPilot scan pipeline (via its own HTTP API, exactly as the
frontend does) against a list of repos, and saves the full, real result
for each one to eval/results/<label>.json.

This replaces re-deriving precision/recall/F1 by hand or asserting them in
the paper: it runs the ACTUAL corrected pipeline (post Rule-2-disclosure
fix, post-Verhoeff, post-bullet-parsing-verification, post-scoring-fix) and
captures whatever it actually finds, for compute_metrics.py to grade
against a ground-truth file you provide.

Usage
-----
1. Make sure the stack is running:  docker-compose up
2. Fill in eval/repos.json with your repo_url/policy_url pairs (see
   eval/repos.example.json for the shape).
3. Run:  python eval/run_eval.py
4. Results land in eval/results/<label>.json and eval/results/all_results.json

This does NOT know what the "correct" answer is for any repo — it only
records what the scanner found. Grading against ground truth is
compute_metrics.py's job, kept separate on purpose so the raw scan output
is never silently shaped around the expected answer.
"""

import json
import os
import sys
import time
from pathlib import Path

import requests

API = os.getenv("PRIVACYPILOT_API", "http://localhost:8000")
HERE = Path(__file__).parent
REPOS_FILE = HERE / "repos.json"
RESULTS_DIR = HERE / "results"

POLL_INTERVAL_SEC = 5
# No overall time limit — a large repository just takes longer. Give up only
# if the scan's progress (phase / files scanned) has not moved for this long.
# The server applies the same rule and marks a stalled scan "failed".
STALL_TIMEOUT_SEC = 20 * 60


def run_one_scan(repo_url: str, policy_url: str, github_token: str | None) -> dict:
    """POST /scan, poll /scans/{id}/status until complete/failed, then
    return the full /scans/{id}/result payload."""
    # Field names match backend/main.py's ScanRequest pydantic model exactly
    # (github_repo_url / privacy_policy_url / github_token) -- these do NOT
    # match the result payload's own field names (repo_url / policy_url),
    # which is a real naming inconsistency in the API worth flagging on its
    # own, but not one to paper over silently here.
    payload = {
        "github_repo_url":    repo_url,
        "privacy_policy_url": policy_url,
        "github_token":       github_token or "",
    }

    resp = requests.post(f"{API}/scan", json=payload, timeout=30)
    resp.raise_for_status()
    scan_id = resp.json()["scan_id"]
    print(f"    scan_id={scan_id} enqueued, polling status...")

    status_payload, last_marker, last_change = {}, None, time.time()
    while True:
        s = requests.get(f"{API}/scans/{scan_id}/status", timeout=15)
        s.raise_for_status()
        status_payload = s.json()
        status = status_payload.get("status")
        prog = status_payload.get("progress") or {}
        marker = (status, prog.get("phase"), prog.get("files_done"))
        if marker != last_marker:
            last_marker, last_change = marker, time.time()
            files = (f" {prog.get('files_done')}/{prog.get('files_total')} files"
                     if prog.get("files_total") is not None else "")
            print(f"      status={status} phase={prog.get('phase')}{files}")
        if status in ("complete", "failed"):
            break
        if time.time() - last_change > STALL_TIMEOUT_SEC:
            raise TimeoutError(
                f"scan {scan_id} made no progress for {STALL_TIMEOUT_SEC // 60} minutes")
        time.sleep(POLL_INTERVAL_SEC)

    if status == "failed":
        err = status_payload.get("error_message") or "(no error_message recorded)"
        raise RuntimeError(f"scan {scan_id} failed — {err}")

    r = requests.get(f"{API}/scans/{scan_id}/result", timeout=30)
    r.raise_for_status()
    return r.json()


def main():
    if not REPOS_FILE.exists():
        print(f"Missing {REPOS_FILE}. Copy eval/repos.example.json to "
              f"eval/repos.json and fill in your 5 repo/policy URLs first.")
        sys.exit(1)

    repos = json.loads(REPOS_FILE.read_text())
    RESULTS_DIR.mkdir(exist_ok=True)

    all_results = {}
    for entry in repos:
        label = entry["label"]
        print(f"\n=== {label} ===")
        print(f"  repo:   {entry['repo_url']}")
        print(f"  policy: {entry['policy_url']}")
        try:
            result = run_one_scan(
                entry["repo_url"], entry["policy_url"], entry.get("github_token")
            )
        except Exception as e:
            print(f"  ERROR: {e}")
            result = {"error": str(e)}

        out_path = RESULTS_DIR / f"{label}.json"
        out_path.write_text(json.dumps(result, indent=2))
        print(f"  saved -> {out_path}")
        all_results[label] = result

    (RESULTS_DIR / "all_results.json").write_text(json.dumps(all_results, indent=2))
    print(f"\nAll results written to {RESULTS_DIR / 'all_results.json'}")
    print("Send that file (or the eval/results/ folder) back and I'll compute "
          "strict/lenient recall, precision, F1, Wilson CIs, and the per-PII-"
          "category Table V breakdown from it.")


if __name__ == "__main__":
    main()
