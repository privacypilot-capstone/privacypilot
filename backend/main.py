from dotenv import load_dotenv
from pathlib import Path
load_dotenv(Path(__file__).parent / ".env")  # explicit path

import asyncio
import re
import os
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from scanners.policy_parser import parse_privacy_policy
from dpdp.rule_engine import run_dpdp_rules
from database import (create_tables, migrate_tables, get_db, scan_gap_categories,
                       describe_database_url, database_instance_id,
                       Scan, Finding, Violation, ChatSession, ChatMessage, DemoRequest)
from scoring import calculate_compliance_score
from report_generator import generate_report_html
from models.dataflow import PIICategory
from llm_client import generate_report_summary, chat_completion, LLMNotConfiguredError
from security import seal, redact_secrets, install_log_redaction

install_log_redaction()   # tokens and API keys never reach a log line

app = FastAPI(title="PrivacyPilot API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    # Any port on this machine: Vite moves to 5174, 5175 … when 5173 is busy,
    # and a fixed list made the browser block the API with a CORS error.
    # Extra origins (a deployed frontend): CORS_ORIGINS=https://a,https://b
    allow_origins=[o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()],
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_methods=["*"],
    allow_headers=["*"],
)


def _iso_utc(dt):
    """Serialize a datetime as ISO-8601 with an explicit UTC offset.

    Our DB columns store naive UTC datetimes (SQLAlchemy `DateTime` with
    `default=datetime.utcnow`). `datetime.isoformat()` on a naive value
    omits any timezone marker, so a client in a non-UTC timezone (e.g.
    IST, UTC+5:30) parses it as *local* time instead of UTC — shifting
    every timestamp by the client's own UTC offset. Attaching UTC
    tzinfo before formatting makes the offset explicit for any client,
    regardless of what timezone it's in.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()

# A scan is declared dead only when NOTHING is moving, never because it is
# big. Every finished chunk (and the repository download) records a
# heartbeat in last_progress_at. A scan has stalled when neither it NOR any
# other running scan has made progress for STALE_SCAN_AFTER — the second
# condition matters because a scan queued behind another large scan makes no
# progress of its own while the workers are busy, yet nothing is wrong.
STALE_SCAN_AFTER = timedelta(minutes=15)
# GitHub rate-limit resets are at most an hour away; a scan waiting for one
# is not stalled.
RATE_LIMIT_WAIT_MAX = timedelta(minutes=75)


def _expire_if_stale(scan, db) -> None:
    if scan.status not in ("queued", "running"):
        return
    now = datetime.utcnow()
    own = scan.last_progress_at or scan.created_at
    if own is None:
        return
    limit = RATE_LIMIT_WAIT_MAX if (scan.phase or "").startswith("waiting") else STALE_SCAN_AFTER
    if now - own <= limit:
        return
    from sqlalchemy import func
    latest_any = (db.query(func.max(Scan.last_progress_at))
                    .filter(Scan.status == "running").scalar())
    if latest_any is not None and now - latest_any <= STALE_SCAN_AFTER:
        return      # workers are busy with other scans; this one is queued behind them
    scan.status = "failed"
    scan.phase = "failed"
    scan.error_message = (
        f"The scan stopped making progress (no work for {int(limit.total_seconds() // 60)} "
        "minutes): no worker is running or it crashed. Check that the worker "
        "container is up, then start the scan again."
    )
    db.commit()


def _check_task_failure(scan, db) -> None:
    """
    A worker that cannot write to this scan's row (wrong database, crash
    before its first update) can still record its failure in Celery's result
    backend. Read it from there so the scan shows the real error at once,
    instead of "stopped making progress" 15 minutes later.
    """
    if scan.status not in ("queued", "running") or not getattr(scan, "task_id", None):
        return
    try:
        from tasks import celery_app
        res = celery_app.AsyncResult(scan.task_id)
        state = res.state
    except Exception:
        return                       # Redis unreachable: the stall check still applies
    if state != "FAILURE":
        return
    scan.status = "failed"
    scan.phase = "failed"
    scan.error_message = redact_secrets(f"The scan worker failed: {res.result}")[:2000]
    db.commit()


def _load_findings(db, scan, limit: int | None = None) -> list:
    """
    A scan's stored findings, application code first (that is the order
    complete_scan stores them in). Every finding is stored now, so pages
    that only show a sample read `limit` rows instead of all of them. Scans
    saved before gap_categories existed need all rows for the gap fallback
    (they stored at most 200).
    """
    q = db.query(Finding).filter(Finding.scan_id == scan.id).order_by(Finding.id)
    if limit is None or not scan.gap_categories:
        return q.all()
    return q.limit(limit).all()


def _coverage_summary(scan) -> dict | None:
    import json as _json
    if not scan.coverage:
        return None
    c = _json.loads(scan.coverage)
    return {
        "total_source_files": c.get("total_source_files"),
        "scanned":            c.get("scanned"),
        "failed_files":       sorted((c.get("failed") or {}).keys()),
        # Files scanned per origin, e.g. {"first_party": 812, "third_party": 4120, "generated": 37}
        "origins":            c.get("origins", {}),
        "duplicates_reused":  c.get("duplicates_reused", 0),
        "findings_by_origin": c.get("findings_by_origin", {}),
        "vagueness_scope":    c.get("vagueness_scope"),     # None for scans made before this was recorded
    }


def _progress(scan) -> dict:
    total = scan.files_total
    done = min(scan.files_done or 0, total) if total is not None else None
    return {
        "phase":       scan.phase or scan.status,
        "files_total": total,
        "files_done":  done,
        "percent":     (round(100 * done / total, 1) if total else None),
    }


@app.on_event("startup")
def startup():
    create_tables()
    migrate_tables()
    database_instance_id(create=True)
    print(f"[db] Tables ready — {describe_database_url()}")


class ScanRequest(BaseModel):
    github_repo_url:    str
    privacy_policy_url: str
    github_token:       str

    def __repr__(self):
        # Security: token is always redacted from logs and error traces
        return (
            f"ScanRequest("
            f"repo={self.github_repo_url!r}, "
            f"policy={self.privacy_policy_url!r}, "
            f"token=***REDACTED***)"
        )

    def __str__(self):
        return self.__repr__()


def _component_status() -> dict:
    """
    Which optional components are actually installed. Several checks degrade
    silently when a package is missing (e.g. no sentence-transformers → no
    Rule 3(b)(ii) vagueness check), so /health reports them explicitly.
    """
    from importlib.util import find_spec
    return {
        "celery (scan queue)":                    find_spec("celery") is not None,
        "redis (scan queue)":                     find_spec("redis") is not None,
        "en_core_web_lg (Presidio NER, spaCy)":   find_spec("en_core_web_lg") is not None,
        "sentence_transformers (Rule 3, vagueness)": find_spec("sentence_transformers") is not None,
        "tree_sitter_javascript (JS taint)":      find_spec("tree_sitter_javascript") is not None,
        "reportlab (PDF reports)":                find_spec("reportlab") is not None,
    }


@app.on_event("startup")
def _warn_missing_components():
    missing = [name for name, ok in _component_status().items() if not ok]
    if missing:
        print(
            "[startup] WARNING: missing components — "
            + ", ".join(missing)
            + ". Run `pip install -r requirements.txt` in backend/."
        )


# Worker database check (see tasks.worker_databases). Cached briefly so that
# submitting several scans in a row does not wait for the reply each time.
_WORKER_DB_CACHE: dict = {"at": None, "value": None}
_WORKER_DB_TTL = timedelta(seconds=60)


def _redis_reachable():
    """True, or a short reason. A direct 2-second ping: much faster and
    clearer than letting Celery retry a connection to a Redis that is down."""
    try:
        import redis
        from tasks import REDIS_URL
        redis.Redis.from_url(REDIS_URL, socket_connect_timeout=2, socket_timeout=2).ping()
        return True
    except Exception as e:
        try:
            from tasks import REDIS_URL
            where = REDIS_URL.split("@")[-1]          # never show a password
        except Exception:
            where = "REDIS_URL"
        return f"Redis at {where} is not reachable: {e}"


def _worker_db_check(force: bool = False) -> dict:
    """
    Can the running workers complete a scan queued by this API?

    {"api_database", "api_code_version", "workers": {host: {...}},
     "ok": True | False | None, "problem": str | None}

    ok is None when no worker answered (none running, or Redis unreachable):
    the scan is queued and waits for one. ok is False when a worker
      - runs older code than the API (it was not restarted after the code
        changed: Celery never reloads code), or
      - uses a different database. Databases are compared by the instance
        id stored in them, not by URL, so localhost:15432 (API on the host)
        and db:5432 (worker in Docker) are correctly the same Postgres.
    """
    from code_version import compute as code_version
    now = datetime.utcnow()
    cached = _WORKER_DB_CACHE
    if not force and cached["at"] and now - cached["at"] < _WORKER_DB_TTL:
        return cached["value"]
    api_db, api_id = describe_database_url(), database_instance_id(create=True)
    api_ver = code_version()
    broker_ok = _redis_reachable()
    try:
        if broker_ok is not True:
            raise ConnectionError(broker_ok)
        from tasks import worker_databases
        workers = worker_databases(timeout=1.0)
    except Exception as e:
        workers, err = {}, e
    else:
        err = None

    report, outdated, other_db = {}, [], []
    for host, w in workers.items():
        if "database" not in w:
            # Reply {"error": "KeyError('privacypilot_database')"}: the worker
            # predates this check, i.e. it is running old code.
            outdated.append(host)
            report[host] = {"status": "running older code (restart it)",
                            "detail": w.get("error")}
            continue
        entry = {"database": w.get("database"), "code_version": w.get("code_version")}
        if w.get("code_version") != api_ver:
            outdated.append(host)
            entry["status"] = "running older code (restart it)"
        elif not api_id or w.get("instance_id") != api_id:
            other_db.append(host)
            entry["status"] = ("different database" if w.get("instance_id")
                               else "different database (never used by this API)")
        else:
            entry["status"] = "ok"
        report[host] = entry

    problems = []
    if not api_id:
        problems.append(f"The API cannot read its own database ({api_db}).")
    if outdated:
        problems.append(
            "The scan worker is running older code than the API ("
            + ", ".join(outdated) + "). A Celery worker does not reload code "
            "after it changes; restart it: `docker compose restart worker`.")
    if other_db:
        problems.append(
            f"The API uses {api_db} but worker(s) use a different database: "
            + ", ".join(f"{report[h]['database']} ({h})" for h in other_db)
            + ". Set the same DATABASE_URL for both (see README).")
    if not workers:
        value = {"api_database": api_db, "api_code_version": api_ver, "workers": {},
                 "ok": None, "redis_reachable": broker_ok is True,
                 "problem": (f"{broker_ok}. Start Redis or fix REDIS_URL." if broker_ok is not True
                             else "No scan worker answered"
                             + (f" ({err})" if err else "")
                             + ". Scans will wait in the queue until a worker is started.")}
    else:
        value = {"api_database": api_db, "api_code_version": api_ver, "workers": report,
                 "ok": not problems, "redis_reachable": True, "problem": " ".join(problems) or None}
    cached["at"], cached["value"] = now, value
    return value


@app.get("/health")
def health():
    components = _component_status()
    db_check = _worker_db_check(force=True)
    return {
        "status":     ("ok" if all(components.values()) and db_check["ok"] else "degraded"),
        "message":    "PrivacyPilot is running",
        "components": components,
        # e.g. {"api_database": "postgresql://localhost:15432/privacypilot",
        #       "workers": {"celery@abc": "postgresql://db:5432/privacypilot"}, ...}
        # No user names or passwords are included.
        "database":   db_check,
    }


# ── Demo requests ─────────────────────────────────────────────────────────────
# Version of the notice shown in the "See demo" consent step
# (frontend/src/legalNotice.js). Bump both together when the notice text changes.
DEMO_NOTICE_VERSION = "2026-10-29"
DEMO_RETENTION_DAYS = 365   # stated in the notice
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class DemoRequestIn(BaseModel):
    name: str
    email: str
    organisation: str = ""
    role: str = ""
    use_case: str = ""
    accepted_terms: bool = False
    consent_contact: bool = False
    consent_updates: bool = False
    notice_version: str = ""


@app.post("/demo-requests", status_code=201)
def create_demo_request(req: DemoRequestIn, db: Session = Depends(get_db)):
    """Record a demo request and the consent given for it.

    Consent must be specific and given by a clear affirmative action, so both
    the terms and the contact consent must be ticked and the notice version
    must be the current one; otherwise nothing is stored.
    """
    name, email = req.name.strip(), req.email.strip().lower()
    errors = {}
    if not 1 <= len(name) <= 100:
        errors["name"] = "Please enter your name (up to 100 characters)."
    if len(email) > 254 or not _EMAIL_RE.match(email):
        errors["email"] = "Please enter a valid e-mail address."
    if len(req.organisation) > 120 or len(req.role) > 80 or len(req.use_case) > 1000:
        errors["details"] = "One of the fields is too long."
    if not (req.accepted_terms and req.consent_contact):
        errors["consent"] = "Please accept the terms and the processing consent to watch the demo."
    if req.notice_version != DEMO_NOTICE_VERSION:
        errors["notice_version"] = "The notice has changed; please reload the page."
    if errors:
        raise HTTPException(status_code=422, detail=errors)
    row = DemoRequest(name=name, email=email,
                      organisation=req.organisation.strip() or None,
                      role=req.role.strip() or None,
                      use_case=req.use_case.strip() or None,
                      accepted_terms=True, consent_contact=True,
                      consent_updates=bool(req.consent_updates),
                      notice_version=DEMO_NOTICE_VERSION)
    db.add(row)
    # The notice promises deletion after 12 months; purge expired rows here.
    db.query(DemoRequest).filter(
        DemoRequest.consented_at < datetime.utcnow() - timedelta(days=DEMO_RETENTION_DAYS)
    ).delete(synchronize_session=False)
    db.commit()
    return {"id": row.id, "notice_version": DEMO_NOTICE_VERSION}


@app.post("/scan")
async def run_scan(req: ScanRequest, db: Session = Depends(get_db)):
    """
    Enqueue a scan job and return immediately (async via Celery).

    Returns {task_id, scan_id, status: "queued"}.
    Poll GET /scans/{scan_id}/status for DB-level progress
    or  GET /scan/status/{task_id} for Celery-level state.

    Security: the GitHub token is never written to the database; it travels (encrypted)
    only in the transient Redis task payload.
    """
    # Security: never log the GitHub token
    print(f"[scan] Enqueuing scan — repo: {req.github_repo_url}")
    print(f"[scan] Policy URL:      {req.privacy_policy_url}")

    # ── Refuse a scan that cannot complete ────────────────────────────────
    # If the workers that answered all use a different database from this
    # API, the scan row created below is invisible to them and the scan could
    # never finish (this is what produced "ForeignKeyViolation … scan_chunks"
    # and a scan that sat "running" until the stall detector failed it).
    db_check = _worker_db_check()
    if db_check.get("redis_reachable") is False:
        _WORKER_DB_CACHE["at"] = None
        raise HTTPException(status_code=503,
                            detail=f"Could not queue the scan: {db_check['problem']}")
    # (No worker answering is not refused: one may be starting. The worker
    # also re-checks that it can see the scan row before it starts.)
    if db_check["ok"] is False:
        _WORKER_DB_CACHE["at"] = None        # re-check on the next attempt
        raise HTTPException(status_code=503, detail=db_check["problem"])

    # ── Pre-create scan record with status=queued ─────────────────────────
    scan = Scan(
        repo_url   = req.github_repo_url,
        policy_url = req.privacy_policy_url,
        status     = "queued",
        phase      = "queued",
        files_done = 0,
        last_progress_at = datetime.utcnow(),
    )
    db.add(scan)
    db.commit()
    scan_id = scan.id
    print(f"[scan] Scan {scan_id} created with status=queued")

    # ── Enqueue background task ───────────────────────────────────────────
    # Lazy import so a missing celery package returns 503 instead of crashing
    # the whole server on startup.
    try:
        from tasks import run_scan_task
        task = run_scan_task.delay(
            scan_id,
            req.github_repo_url,
            seal(req.github_token),   # encrypted in the task message (security.py)
            req.privacy_policy_url,
        )
    except ImportError as e:
        scan.status = "failed"
        scan.phase = "failed"
        scan.error_message = f"Import error: {e}"
        db.commit()
        raise HTTPException(
            status_code=503,
            detail=f"Import error: {e}",
        )
    except Exception as e:
        # Typically Redis is not reachable (wrong REDIS_URL, container down).
        # Without this the scan row stayed "queued" until the stall detector.
        from tasks import REDIS_URL
        where = REDIS_URL.split("@")[-1]       # never show a Redis password
        scan.status = "failed"
        scan.phase = "failed"
        scan.error_message = redact_secrets(f"Could not queue the scan: Redis at {where} is not reachable ({e}).")
        db.commit()
        raise HTTPException(status_code=503, detail=scan.error_message)

    scan.task_id = task.id
    db.commit()
    print(f"[scan] Task {task.id} enqueued for scan {scan_id}")
    return {
        "task_id": task.id,
        "scan_id": scan_id,
        "status":  "queued",
        "message": (
            f"Scan enqueued. "
            f"Poll /scans/{scan_id}/status for progress or "
            f"/scan/status/{task.id} for Celery state."
        ),
    }


@app.get("/scans")
def get_all_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    for s in scans:
        _check_task_failure(s, db)
        _expire_if_stale(s, db)
    return [{
        "id":               s.id,
        "repo_url":         s.repo_url,
        "created_at":       _iso_utc(s.created_at),
        "findings_count":   s.findings_count,
        "violations_count": s.violations_count,
        "gaps_count":       s.gaps_count,
        "status":           s.status,
        "progress":         _progress(s),
    } for s in scans]


@app.get("/scans/{scan_id}/status")
def get_scan_status(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    _check_task_failure(scan, db)
    _expire_if_stale(scan, db)
    return {
        "scan_id":  scan_id,
        "status":   scan.status,
        "repo_url": scan.repo_url,
        "error_message": scan.error_message,
        # e.g. {"phase": "scanning", "files_total": 5210, "files_done": 1840, "percent": 35.3}
        "progress": _progress(scan),
    }

@app.get("/scan/status/{task_id}")
def get_task_status(task_id: str):
    """
    Celery-level task state for an async scan.

    States: PENDING → STARTED → SUCCESS | FAILURE | RETRY
    For the DB-level status (queued/running/complete/failed) use
    GET /scans/{scan_id}/status instead.
    """
    try:
        from tasks import celery_app
        result = celery_app.AsyncResult(task_id)
    except ImportError:
        raise HTTPException(status_code=503, detail="Celery not available")

    resp: dict = {
        "task_id": task_id,
        "state":   result.state,   # PENDING | STARTED | SUCCESS | FAILURE | RETRY
    }
    if result.state == "SUCCESS":
        resp["result"] = result.result   # dict returned by run_scan_task
    elif result.state in ("FAILURE", "RETRY"):
        resp["error"] = str(result.info)
    return resp




def _violation_locations(v) -> list:
    from database import violation_locations
    return violation_locations(v)


@app.get("/scans/{scan_id}/violations")
def get_violations(scan_id: int, db: Session = Depends(get_db)):
    violations = db.query(Violation).filter(
        Violation.scan_id == scan_id
    ).all()
    return [{
        "dpdp_section":   v.dpdp_section,
        "section_title":  v.section_title,
        "severity":       v.severity,
        "pii_category":   v.pii_category,
        "evidence":       v.evidence,
        "recommendation": v.recommendation,
        "recipient":      getattr(v, "recipient", None),
        "locations":      _violation_locations(v),
    } for v in violations]



@app.get("/scans/{scan_id}/result")
def get_scan_result(scan_id: int, db: Session = Depends(get_db)):
    """
    Return the full scan result including violations, findings, and compliance score.
    Call this after polling /scans/{scan_id}/status shows status='complete'.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in ("complete", "failed"):
        raise HTTPException(
            status_code=202,
            detail=f"Scan is still {scan.status}. Poll /scans/{scan_id}/status first.",
        )

    violations = db.query(Violation).filter(Violation.scan_id == scan_id).all()
    findings   = _load_findings(db, scan, limit=30)

    class _FakeV:
        def __init__(self, s): self.severity = s

    compliance = calculate_compliance_score(
        [_FakeV(v.severity) for v in violations],
        scan.findings_count or 0,
        scan.gaps_count or 0,
    )

    return {
        "scan_id":          scan_id,
        "repo_url":         scan.repo_url,
        "policy_url":       scan.policy_url,
        "status":           scan.status,
        "findings_count":   scan.findings_count or 0,
        "violations_count": scan.violations_count or 0,
        "gaps_count":       scan.gaps_count or 0,
        "gaps_detected": scan_gap_categories(scan, findings),
        # e.g. "Partial scan: 250 of 1014 source files were scanned (…)"
        # e.g. "Scan coverage: 2 of 5210 source files could not be scanned (…)"
        "warning":       scan.error_message if scan.status == "complete" else None,
        "coverage":      _coverage_summary(scan),
        "compliance": compliance,
        "violations": [
            {
                "dpdp_section":   v.dpdp_section,
                "section_title":  v.section_title,
                "severity":       v.severity,
                "pii_category":   v.pii_category,
                "evidence":       v.evidence,
                "recommendation": v.recommendation,
                "recipient":      getattr(v, "recipient", None),
                "locations":      _violation_locations(v),
            }
            for v in violations
        ],
        "sample_findings": [
            {
                "pii_category": f.pii_category,
                "file_path":    f.file_path,
                "line_number":  f.line_number,
                "source":       f.source,
                "raw_text":     f.raw_text,
                "origin":       f.origin or "first_party",
            }
            for f in findings[:30]
        ],
    }

@app.get("/scans/{scan_id}/findings")
def get_scan_findings(
    scan_id: int,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    category: str | None = None,
    origin: str | None = Query(None, pattern="^(first_party|third_party|generated)$"),
    sensitivity: str | None = None,
    transmitted: bool = False,
    q: str | None = Query(None, max_length=200),
    db: Session = Depends(get_db),
):
    """
    Every finding of a completed scan, one page at a time.

    A large repository can have tens of thousands of findings, so the
    results page reads them in pages (offset/limit) and filters on the
    server: category, origin (first_party / third_party / generated),
    sensitivity, transmitted=true (only findings whose line sends data to a
    third-party SDK / HTTP / queue / logger sink), and q (substring of the
    file path or the matched code). `facets` counts the WHOLE scan (not the
    current filter) by category and by origin, for the filter controls.
    """
    from sqlalchemy import func, or_
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    base = db.query(Finding).filter(Finding.scan_id == scan_id)
    filt = base
    if category:
        filt = filt.filter(Finding.pii_category == category)
    if origin:
        # Scans stored before origins existed have NULL = their own code.
        filt = filt.filter(Finding.origin == origin) if origin != "first_party" else \
               filt.filter(or_(Finding.origin == "first_party", Finding.origin.is_(None)))
    if sensitivity:
        filt = filt.filter(Finding.sensitivity == sensitivity)
    if transmitted:
        filt = filt.filter(Finding.third_party_sdk.isnot(None))
    if q:
        like = f"%{q}%"
        filt = filt.filter(or_(Finding.file_path.ilike(like), Finding.raw_text.ilike(like)))

    total = filt.count()
    rows = filt.order_by(Finding.id).offset(offset).limit(limit).all()

    def _counts(col):
        return {(k or "first_party"): n for k, n in
                db.query(col, func.count(Finding.id))
                  .filter(Finding.scan_id == scan_id).group_by(col).all()}

    by_origin: dict = {}
    for k, n in _counts(Finding.origin).items():
        by_origin[k] = by_origin.get(k, 0) + n

    return {
        "scan_id": scan_id,
        "total":   total,
        "offset":  offset,
        "limit":   limit,
        "items": [{
            "id":              f.id,
            "pii_category":    f.pii_category,
            "sensitivity":     f.sensitivity,
            "file_path":       f.file_path,
            "line_number":     f.line_number,
            "source":          f.source,
            "raw_text":        f.raw_text,
            "field_name":      f.field_name,
            "third_party_sdk": f.third_party_sdk,
            "is_gap":          bool(f.is_gap),
            "origin":          f.origin or "first_party",
        } for f in rows],
        "facets": {
            "category":    _counts(Finding.pii_category),
            "origin":      by_origin,
            "sensitivity": _counts(Finding.sensitivity),
            "transmitted": base.filter(Finding.third_party_sdk.isnot(None)).count(),
        },
    }


@app.get("/report/{scan_id}")
def get_report(
    scan_id: int,
    format: str = "html",
    db: Session = Depends(get_db)
):
    """
    Generate the compliance report for a completed scan.

    Fetches (or lazily generates) the LLM executive summary and embeds it
    as a plain-English narrative section in both the HTML and PDF outputs.
    If no LLM key is configured the report is still generated without it.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    violations = db.query(Violation).filter(Violation.scan_id == scan_id).all()
    # EVERY finding: the report lists them all (the LLM narrative still gets
    # a sample of 10, as context only).
    findings   = _load_findings(db, scan)

    class FakeV:
        def __init__(self, s):
            self.severity = s

    compliance = calculate_compliance_score(
        [FakeV(v.severity) for v in violations],
        scan.findings_count,
        scan.gaps_count,
    )

    # ── Fetch or generate the LLM narrative ──────────────────────────────────
    # Use the cached ai_summary if available; otherwise generate on-the-fly
    # and cache it so future downloads are instant.
    narrative: str | None = scan.ai_summary
    if narrative is None:
        try:
            scan_data = {
                "scan_id":             scan_id,
                "repo_url":            scan.repo_url,
                "policy_url":          scan.policy_url,
                "code_findings_count": scan.findings_count or 0,
                "gaps_detected":       scan_gap_categories(scan, findings),
                "compliance":          compliance,
                "violations": [
                    {
                        "dpdp_section":   v.dpdp_section,
                        "section_title":  v.section_title,
                        "severity":       v.severity,
                        "pii_category":   v.pii_category,
                        "evidence":       v.evidence,
                        "recommendation": v.recommendation,
                        "recipient":      getattr(v, "recipient", None),
                        "locations":      _violation_locations(v),
                    }
                    for v in violations
                ],
                "sample_findings": [
                    {
                        "pii_category": f.pii_category,
                        "file_path":    f.file_path,
                        "line_number":  f.line_number,
                        "source":       f.source,
                    }
                    for f in findings[:10]
                ],
            }
            narrative = generate_report_summary(scan_data)
            # Cache for future report downloads
            scan.ai_summary = narrative
            db.commit()
            print(f"[report] LLM narrative generated and cached for scan {scan_id}")
        except LLMNotConfiguredError:
            print(f"[report] No LLM key configured — report will omit narrative section")
            narrative = None
        except Exception as e:
            print(f"[report] LLM narrative generation failed: {e} — continuing without it")
            narrative = None

    # ── Build and return the report ───────────────────────────────────────────
    if format == "pdf":
        try:
            from pdf_generator import generate_pdf
            pdf_bytes = generate_pdf(scan, violations, findings, compliance, narrative=narrative)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f"attachment; filename=report_{scan_id}.pdf"
                },
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"PDF error: {e}")

    html = generate_report_html(scan, violations, findings, compliance, narrative=narrative)
    return HTMLResponse(content=html)


# ── Full exports (CSV) ───────────────────────────────────────────────────────
# Every violation / every finding of a scan, unpaged, for spreadsheets and
# evaluation. Finding rows are streamed so a scan with tens of thousands of
# findings is not built in memory first.

def _csv_response(rows, header, filename):
    import csv, io
    from fastapi.responses import StreamingResponse

    def gen():
        buf = io.StringIO()
        w = csv.writer(buf)
        buf.write("\ufeff")                   # BOM: Excel opens UTF-8 correctly
        w.writerow(header)
        for r in rows:
            w.writerow(r)
            if buf.tell() > 64 * 1024:
                yield buf.getvalue(); buf.seek(0); buf.truncate(0)
        yield buf.getvalue()

    return StreamingResponse(gen(), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f"attachment; filename={filename}"})


@app.get("/scans/{scan_id}/violations.csv")
def export_violations_csv(scan_id: int, db: Session = Depends(get_db)):
    """Every violation, one row each; locations as 'file:line' (code) or
    'privacy policy statement N' (policy) joined by '; '."""
    from database import location_short
    if not db.query(Scan).filter(Scan.id == scan_id).first():
        raise HTTPException(status_code=404, detail="Scan not found")
    vs = db.query(Violation).filter(Violation.scan_id == scan_id).order_by(Violation.id).all()

    def rows():
        for v in vs:
            locs = _violation_locations(v)
            yield [v.dpdp_section, v.section_title, v.severity, v.pii_category,
                   getattr(v, "recipient", None) or "", len(locs),
                   "; ".join(location_short(l) for l in locs),
                   v.evidence, v.recommendation]

    return _csv_response(rows(), ["dpdp_section", "title", "severity", "pii_category",
                                  "recipient", "location_count", "locations",
                                  "evidence", "recommendation"],
                         f"violations_{scan_id}.csv")


@app.get("/scans/{scan_id}/findings.csv")
def export_findings_csv(scan_id: int, db: Session = Depends(get_db)):
    """Every finding of the scan, one row each, in stored order."""
    if not db.query(Scan).filter(Scan.id == scan_id).first():
        raise HTTPException(status_code=404, detail="Scan not found")
    # The rows are read while the response streams, after this request's
    # session may already be closed, so the generator opens its own.
    bind = db.get_bind()

    def rows():
        from sqlalchemy.orm import Session as _Session
        own = _Session(bind=bind)
        try:
            q = (own.query(Finding).filter(Finding.scan_id == scan_id)
                    .order_by(Finding.id).yield_per(2000))
            for f in q:
                yield [f.pii_category, f.sensitivity, f.file_path, f.line_number,
                       f.origin or "first_party", f.third_party_sdk or "",
                       bool(f.is_gap), f.source, f.field_name, f.raw_text]
        finally:
            own.close()

    return _csv_response(rows(), ["pii_category", "sensitivity", "file_path", "line_number",
                                  "origin", "sent_to", "is_gap", "detected_by",
                                  "field_name", "code"],
                         f"findings_{scan_id}.csv")


# ── LLM Report Summary ────────────────────────────────────────────────────────

@app.get("/scans/{scan_id}/summary")
def get_scan_summary(scan_id: int, db: Session = Depends(get_db)):
    """Return (or lazily generate) an LLM executive summary for a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Return cached summary if available
    if scan.ai_summary:
        return {"scan_id": scan_id, "summary": scan.ai_summary, "cached": True}

    # Build a minimal scan_data dict from DB rows
    violations = db.query(Violation).filter(Violation.scan_id == scan_id).all()
    findings   = _load_findings(db, scan, limit=10)

    from scoring import calculate_compliance_score
    class _FakeV:
        def __init__(self, s): self.severity = s

    compliance = calculate_compliance_score(
        [_FakeV(v.severity) for v in violations],
        scan.findings_count or 0,
        scan.gaps_count or 0,
    )

    scan_data = {
        "scan_id":              scan_id,
        "repo_url":             scan.repo_url,
        "policy_url":           scan.policy_url,
        "code_findings_count":  scan.findings_count or 0,
        "gaps_detected":        scan_gap_categories(scan, findings),
        "compliance":           compliance,
        "violations":           [
            {
                "dpdp_section":  v.dpdp_section,
                "section_title": v.section_title,
                "severity":      v.severity,
                "pii_category":  v.pii_category,
                "evidence":      v.evidence,
                "recommendation":v.recommendation,
                "recipient":     getattr(v, "recipient", None),
                "locations":     _violation_locations(v),
            }
            for v in violations
        ],
        "sample_findings": [
            {
                "pii_category": f.pii_category,
                "file_path":    f.file_path,
                "line_number":  f.line_number,
                "source":       f.source,
            }
            for f in findings[:10]
        ],
    }

    try:
        summary = generate_report_summary(scan_data)
    except LLMNotConfiguredError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"LLM error: {e}")

    # Cache in DB
    scan.ai_summary = summary
    db.commit()
    return {"scan_id": scan_id, "summary": summary, "cached": False}


# ── Compliance Chatbot ────────────────────────────────────────────────────────

class ChatMessageRequest(BaseModel):
    content: str


@app.post("/chat/sessions")
def create_chat_session(scan_id: int, db: Session = Depends(get_db)):
    """Create a new chat session bound to a specific scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    session = ChatSession(scan_id=scan_id)
    db.add(session)
    db.commit()
    db.refresh(session)
    return {"session_id": session.id, "scan_id": scan_id}


@app.post("/chat/sessions/{session_id}/message")
def send_chat_message(
    session_id: int,
    req: ChatMessageRequest,
    db: Session = Depends(get_db),
):
    """
    Send a user message and receive an LLM compliance advisor response.

    The full conversation history is sent to the LLM on each turn, providing
    session-persistent, context-aware dialogue (not just one-shot Q&A).
    """
    session = db.query(ChatSession).filter(ChatSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Chat session not found")

    # Persist the user message
    user_msg = ChatMessage(session_id=session_id, role="user", content=req.content)
    db.add(user_msg)
    db.commit()

    # Build the full conversation history for the LLM
    history = db.query(ChatMessage).filter(
        ChatMessage.session_id == session_id
    ).order_by(ChatMessage.id).all()

    messages = [{"role": m.role, "content": m.content} for m in history]

    # Reconstruct scan_data context from DB
    scan = session.scan if hasattr(session, "scan") else            db.query(Scan).filter(Scan.id == session.scan_id).first()
    violations = db.query(Violation).filter(Violation.scan_id == scan.id).all()
    findings   = _load_findings(db, scan, limit=10)

    from scoring import calculate_compliance_score
    class _FakeV:
        def __init__(self, s): self.severity = s

    compliance = calculate_compliance_score(
        [_FakeV(v.severity) for v in violations],
        scan.findings_count or 0,
        scan.gaps_count or 0,
    )

    scan_data = {
        "scan_id":             scan.id,
        "repo_url":            scan.repo_url,
        "policy_url":          scan.policy_url,
        "code_findings_count": scan.findings_count or 0,
        "gaps_detected":       scan_gap_categories(scan, findings),
        "compliance":          compliance,
        "violations": [
            {
                "dpdp_section":  v.dpdp_section,
                "section_title": v.section_title,
                "severity":      v.severity,
                "pii_category":  v.pii_category,
                "evidence":      v.evidence,
                "recommendation":v.recommendation,
                "recipient":     getattr(v, "recipient", None),
                "locations":     _violation_locations(v),
            }
            for v in violations
        ],
        "sample_findings": [
            {
                "pii_category": f.pii_category,
                "file_path":    f.file_path,
                "line_number":  f.line_number,
                "source":       f.source,
            }
            for f in findings[:10]
        ],
    }

    try:
        reply = chat_completion(messages, scan_data)
    except LLMNotConfiguredError as e:
        reply = (
            "⚠️ The AI advisor is not configured. "
            "Please set GEMINI_API_KEY or OPENAI_API_KEY in the server environment."
        )
    except Exception as e:
        reply = f"⚠️ LLM error: {e}"

    # Persist assistant reply
    assistant_msg = ChatMessage(session_id=session_id, role="assistant", content=reply)
    db.add(assistant_msg)
    db.commit()

    return {
        "session_id":   session_id,
        "role":         "assistant",
        "content":      reply,
        "message_count": len(history) + 1,
    }


@app.get("/chat/sessions/{session_id}/history")
def get_chat_history(session_id: int, db: Session = Depends(get_db)):
    """Return the full message history for a chat session."""
    session = db.query(ChatSession).filter(ChatSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Chat session not found")

    messages = db.query(ChatMessage).filter(
        ChatMessage.session_id == session_id
    ).order_by(ChatMessage.id).all()

    return {
        "session_id": session_id,
        "scan_id":    session.scan_id,
        "messages":   [
            {
                "id":         m.id,
                "role":       m.role,
                "content":    m.content,
                "created_at": _iso_utc(m.created_at),
            }
            for m in messages
        ],
    }

