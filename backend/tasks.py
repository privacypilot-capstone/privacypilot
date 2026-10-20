import os
from dotenv import load_dotenv
load_dotenv()   # must be first — loads .env before any os.getenv() calls

from celery import Celery

# ── Celery application ────────────────────────────────────────────────────────
# Both broker and result backend point at the Redis container (or localhost in
# local dev).  REDIS_URL can be overridden in .env or docker-compose environment.
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

# Time the code scan may use before it stops starting new files. Leaves
# room under the 540 s soft limit for the policy models, the rule engine
# and saving results, so a large repository returns a partial (and
# labelled) result instead of being killed at the 600 s hard limit.
CODE_SCAN_BUDGET_S = 420

celery_app = Celery(
    "privacypilot",
    broker=REDIS_URL,
    backend=REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,          # STARTED state visible before SUCCESS
    worker_prefetch_multiplier=1,     # fair dispatch for long-running scan tasks
    task_soft_time_limit=540,         # 9 min soft limit — raises SoftTimeLimitExceeded
    task_time_limit=600,              # 10 min hard limit — kills the worker process
)


# ── Scan task ─────────────────────────────────────────────────────────────────

@celery_app.task(bind=True, name="tasks.run_scan_task")
def run_scan_task(self, scan_id: int, repo_url: str, token: str, policy_url: str):
    """
    Background scan pipeline.

    Receives a pre-created scan_id (created by the HTTP handler with
    status='queued') so the HTTP response can return immediately.
    The frontend polls GET /scans/{scan_id}/status for DB-level status,
    or GET /scan/status/{task_id} for Celery-level state.

    Security: the GitHub token is stored transiently in Redis while the task
    is queued / running; it is never written to the database.
    """
    # ── Deferred heavy imports ────────────────────────────────────────────────
    # Imported here (not at module top) so the worker process can import this
    # module at startup without triggering the full scanner import chain.
    import json
    import time as _time
    from database import SessionLocal, Scan, Finding, Violation
    from scanners.code_scanner import scan_github_repo, coverage_note
    from scanners.policy_parser import parse_privacy_policy
    from dpdp.rule_engine import run_dpdp_rules
    from scoring import calculate_compliance_score

    db = SessionLocal()
    scan = None
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan is None:
            raise ValueError(f"Scan {scan_id} not found in database")

        # Transition queued → running
        scan.status = "running"
        db.commit()
        print(f"[task] Scan {scan_id} running — repo: {repo_url}")

        # ── Steps 1+2: Code scan and policy fetch — run IN PARALLEL ─────────
        # These two are fully independent: kick both off in a thread pool and
        # join them.  Total time = max(scan_time, policy_time) instead of sum.
        # Not a `with` block: on an error (incl. Celery's SoftTimeLimitExceeded)
        # `with` would wait for the still-running scan threads, the except
        # below would never run, and the hard limit would kill the worker
        # leaving the scan stuck at "running".
        import concurrent.futures as _cf
        _deadline = _time.monotonic() + CODE_SCAN_BUDGET_S
        _pool = _cf.ThreadPoolExecutor(max_workers=2)
        try:
            _code_fut   = _pool.submit(scan_github_repo, repo_url, token, _deadline)
            _policy_fut = _pool.submit(parse_privacy_policy, policy_url, token)
            code_findings, usage_map, coverage                             = _code_fut.result()
            policy_claims, purpose_map, vagueness_warnings, disclosed_sdks = _policy_fut.result()
        finally:
            _pool.shutdown(wait=False, cancel_futures=True)

        print(f"[task] Scan {scan_id} — {len(code_findings)} code findings")
        print(f"[task] Scan {scan_id} — {len(policy_claims)} policy claims")

        # ── Step 3: Detect notice gaps ────────────────────────────────────────
        code_pii       = {f.pii_category for f in code_findings}
        policy_pii     = {f.pii_category for f in policy_claims}
        gap_categories = code_pii - policy_pii

        # ── Step 4: Run DPDP Rule Engine ──────────────────────────────────────
        violations = run_dpdp_rules(
            code_findings,
            policy_claims,
            gap_categories,
            usage_map=usage_map,
            purpose_map=purpose_map,
            vagueness_warnings=vagueness_warnings,
            disclosed_sdks=disclosed_sdks,
        )

        # ── Step 5: Compliance score ──────────────────────────────────────────
        compliance = calculate_compliance_score(
            violations, len(code_findings), len(gap_categories)
        )

        # ── Step 6: Persist to database ───────────────────────────────────────
        scan.findings_count   = len(code_findings)
        scan.policy_count     = len(policy_claims)
        scan.gaps_count       = len(gap_categories)
        scan.gap_categories   = json.dumps(sorted(c.value for c in gap_categories))
        scan.violations_count = len(violations)
        scan.status           = "complete"
        # Partial-coverage note (None when every source file was scanned);
        # shown to the user as a warning on a completed scan.
        scan.error_message    = coverage_note(coverage)

        for f in code_findings[:200]:
            db.add(Finding(
                scan_id         = scan_id,
                source          = f.source,
                file_path       = f.file_path,
                line_number     = f.line_number,
                raw_text        = f.raw_text,
                field_name      = f.field_name,
                pii_category    = f.pii_category.value,
                sensitivity     = f.sensitivity.value,
                third_party_sdk = f.third_party_sdk,
                is_gap          = f.pii_category in gap_categories,
            ))

        for v in violations:
            db.add(Violation(
                scan_id        = scan_id,
                dpdp_section   = v.dpdp_section,
                section_title  = v.section_title,
                severity       = v.severity,
                pii_category   = v.pii_category,
                evidence       = v.evidence,
                recommendation = v.recommendation,
            ))

        db.commit()
        print(
            f"[task] Scan {scan_id} complete — "
            f"{len(violations)} violations, score {compliance.get('score', '?')}"
        )

        # Return value stored in Redis result backend and visible via AsyncResult
        return {
            "scan_id":          scan_id,
            "status":           "complete",
            "violations_count": len(violations),
            "compliance_score": compliance.get("score"),
            "gaps_count":       len(gap_categories),
            "coverage":         coverage,
        }

    except Exception as exc:
        # Mark scan as failed in DB before re-raising so the frontend can
        # surface a meaningful error rather than spinning on "running".
        if scan is not None:
            try:
                db.refresh(scan)
                scan.status = "failed"
                scan.error_message = str(exc)[:2000]
                db.commit()
            except Exception:
                db.rollback()
        print(f"[task] Scan {scan_id} FAILED: {exc}")
        # Re-raise so Celery records the task with state=FAILURE
        raise

    finally:
        db.close()
