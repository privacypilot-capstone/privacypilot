from dotenv import load_dotenv
from pathlib import Path
load_dotenv(Path(__file__).parent / ".env")  # explicit path

import asyncio
from datetime import timezone

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from scanners.code_scanner import scan_github_repo
from scanners.policy_parser import parse_privacy_policy
from dpdp.rule_engine import run_dpdp_rules
from database import (create_tables, migrate_tables, get_db, scan_gap_categories,
                       Scan, Finding, Violation, ChatSession, ChatMessage)
from scoring import calculate_compliance_score
from report_generator import generate_report_html
from models.dataflow import PIICategory
from llm_client import generate_report_summary, chat_completion, LLMNotConfiguredError

app = FastAPI(title="PrivacyPilot API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174"],
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

@app.on_event("startup")
def startup():
    create_tables()
    migrate_tables()
    print("[db] Tables ready")


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


@app.get("/health")
def health():
    components = _component_status()
    return {
        "status":     "ok" if all(components.values()) else "degraded",
        "message":    "PrivacyPilot is running",
        "components": components,
    }


@app.post("/scan")
async def run_scan(req: ScanRequest, db: Session = Depends(get_db)):
    """
    Enqueue a scan job and return immediately (async via Celery).

    Returns {task_id, scan_id, status: "queued"}.
    Poll GET /scans/{scan_id}/status for DB-level progress
    or  GET /scan/status/{task_id} for Celery-level state.

    Security: the GitHub token is never written to the database; it travels
    only in the transient Redis task payload.
    """
    # Security: never log the GitHub token
    print(f"[scan] Enqueuing scan — repo: {req.github_repo_url}")
    print(f"[scan] Policy URL:      {req.privacy_policy_url}")

    # ── Pre-create scan record with status=queued ─────────────────────────
    scan = Scan(
        repo_url   = req.github_repo_url,
        policy_url = req.privacy_policy_url,
        status     = "queued",
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
            req.github_token,
            req.privacy_policy_url,
        )
    except ImportError as e:
        scan.status = "failed"
        db.commit()
        raise HTTPException(
            status_code=503,
            detail=f"Import error: {e}",
        )

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
    return [{
        "id":               s.id,
        "repo_url":         s.repo_url,
        "created_at":       _iso_utc(s.created_at),
        "findings_count":   s.findings_count,
        "violations_count": s.violations_count,
        "gaps_count":       s.gaps_count,
        "status":           s.status,
    } for s in scans]


@app.get("/scans/{scan_id}/status")
def get_scan_status(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id":  scan_id,
        "status":   scan.status,
        "repo_url": scan.repo_url,
        "error_message": scan.error_message,
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
    findings   = db.query(Finding).filter(Finding.scan_id == scan_id).all()

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
        "compliance": compliance,
        "violations": [
            {
                "dpdp_section":   v.dpdp_section,
                "section_title":  v.section_title,
                "severity":       v.severity,
                "pii_category":   v.pii_category,
                "evidence":       v.evidence,
                "recommendation": v.recommendation,
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
            }
            for f in findings[:30]
        ],
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
    findings   = db.query(Finding).filter(Finding.scan_id == scan_id).all()

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
    html = generate_report_html(scan, violations, findings, compliance, narrative=narrative)

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

    return HTMLResponse(content=html)


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
    findings   = db.query(Finding).filter(Finding.scan_id == scan_id).all()

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
    findings   = db.query(Finding).filter(Finding.scan_id == scan.id).all()

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

