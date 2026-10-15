import asyncio

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from scanners.code_scanner import scan_github_repo
from scanners.policy_parser import parse_privacy_policy
from dpdp.rule_engine import run_dpdp_rules
from database import (create_tables, migrate_tables, get_db,
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


@app.get("/health")
def health():
    return {"status": "ok", "message": "PrivacyPilot is running"}


@app.post("/scan")
async def run_scan(req: ScanRequest, db: Session = Depends(get_db)):

    # Security: never log the GitHub token
    print(f"[scan] Starting scan — repo: {req.github_repo_url}")
    print(f"[scan] Policy URL: {req.privacy_policy_url}")

    # ── Pre-create scan record with status=running ────────────────────────
    scan = Scan(
        repo_url   = req.github_repo_url,
        policy_url = req.privacy_policy_url,
        status     = "running",
    )
    db.add(scan)
    db.commit()
    scan_id = scan.id
    print(f"[scan] Scan {scan_id} created with status=running")

    try:
        # ── Steps 1 + 2: Concurrent I/O — code scan and policy fetch ──────
        # scan_github_repo  (GitHub API + regex/NER + AST) and
        # parse_privacy_policy (HTTP fetch + regex) are independent I/O-bound
        # operations.  asyncio.gather runs them concurrently; each is wrapped
        # in asyncio.to_thread so the synchronous/blocking libraries
        # (PyGitHub, requests) don't block the event loop.
        (
            (code_findings, usage_map),
            (policy_claims, purpose_map, vagueness_warnings),
        ) = await asyncio.gather(
            asyncio.to_thread(scan_github_repo,
                              req.github_repo_url, req.github_token),
            asyncio.to_thread(parse_privacy_policy,
                              req.privacy_policy_url),
        )

        # ── Step 3: Detect notice gaps ────────────────────────────────────
        code_pii       = {f.pii_category for f in code_findings}
        policy_pii     = {f.pii_category for f in policy_claims}
        gap_categories = code_pii - policy_pii

        # ── Step 4: Run DPDP Rule Engine ──────────────────────────────────
        # Rule 1 uses gap_categories; Rule 2 uses third_party_sdk on findings;
        # Rule 3 uses usage_map ↔ purpose_map cross-reference;
        # Vagueness uses vagueness_warnings from policy_parser.
        violations = run_dpdp_rules(
            code_findings,
            policy_claims,
            gap_categories,
            usage_map=usage_map,
            purpose_map=purpose_map,
            vagueness_warnings=vagueness_warnings,
        )

        # ── Step 5: Compliance score ──────────────────────────────────────
        # S = max(0, 100 − 15·|CRITICAL| − 8·|HIGH| − 4·|MEDIUM|)
        # gap penalty removed — gaps are already captured as violations
        compliance = calculate_compliance_score(
            violations, len(code_findings), len(gap_categories)
        )

        # ── Step 6: Persist to database ───────────────────────────────────
        scan.findings_count   = len(code_findings)
        scan.policy_count     = len(policy_claims)
        scan.gaps_count       = len(gap_categories)
        scan.violations_count = len(violations)
        scan.status           = "complete"

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
        print(f"[db] Scan {scan_id} complete — {len(violations)} violations")

        # ── Step 7: Return response ───────────────────────────────────────
        return {
            "scan_id":             scan_id,
            "code_findings_count": len(code_findings),
            "policy_claims_count": len(policy_claims),
            "gaps_detected":       sorted({g.value for g in gap_categories}),
            "gaps_count":          len(gap_categories),
            "violations_count":    len(violations),
            "violations":          [v.to_dict() for v in violations],
            "sample_findings":     [f.model_dump() for f in code_findings[:5]],
            "compliance":          compliance,
            # Surface derived data for UI / debugging
            "purpose_map":         {k.value: list(v) for k, v in purpose_map.items()},
            "usage_map":           {k.value: list(v) for k, v in usage_map.items()},
            "vagueness_warnings":  vagueness_warnings,
        }

    except Exception as e:
        try:
            scan.status = "failed"
            db.commit()
            print(f"[db] Scan {scan_id} marked as failed")
        except Exception:
            db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scans")
def get_all_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    return [{
        "id":               s.id,
        "repo_url":         s.repo_url,
        "created_at":       s.created_at.isoformat(),
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
    }


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


@app.get("/report/{scan_id}")
def get_report(
    scan_id: int,
    format: str = "html",
    db: Session = Depends(get_db)
):
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

    html = generate_report_html(scan, violations, findings, compliance)

    if format == "pdf":
        try:
            from pdf_generator import generate_pdf
            pdf_bytes = generate_pdf(scan, violations, findings, compliance)
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
        "gaps_detected":        list({f.pii_category for f in findings if f.is_gap}),
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
        "gaps_detected":       list({f.pii_category for f in findings if f.is_gap}),
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
            "Please set GEMINI_API_KEY or ANTHROPIC_API_KEY in the server environment."
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
                "created_at": m.created_at.isoformat(),
            }
            for m in messages
        ],
    }

