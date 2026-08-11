from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from scanners.code_scanner import scan_github_repo
from scanners.policy_parser import parse_privacy_policy
from dpdp.rule_engine import run_dpdp_rules
from database import create_tables, get_db, Scan, Finding, Violation
from scoring import calculate_compliance_score
from report_generator import generate_report_html
from models.dataflow import PIICategory

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
    print("[db] Tables ready")


class ScanRequest(BaseModel):
    github_repo_url:    str
    privacy_policy_url: str
    github_token:       str


@app.get("/health")
def health():
    return {"status": "ok", "message": "PrivacyPilot is running"}


@app.post("/scan")
def run_scan(req: ScanRequest, db: Session = Depends(get_db)):
    try:
        code_findings = scan_github_repo(req.github_repo_url, req.github_token)
        policy_claims = parse_privacy_policy(req.privacy_policy_url)

        code_pii       = {f.pii_category for f in code_findings}
        policy_pii     = {f.pii_category for f in policy_claims}
        gap_categories = code_pii - policy_pii

        violations = run_dpdp_rules(code_findings, policy_claims, gap_categories)
        compliance = calculate_compliance_score(
            violations, len(code_findings), len(gap_categories)
        )

        scan = Scan(
            repo_url         = req.github_repo_url,
            policy_url       = req.privacy_policy_url,
            findings_count   = len(code_findings),
            policy_count     = len(policy_claims),
            gaps_count       = len(gap_categories),
            violations_count = len(violations),
        )
        db.add(scan)
        db.flush()

        for f in code_findings[:200]:
            db.add(Finding(
                scan_id         = scan.id,
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
                scan_id        = scan.id,
                dpdp_section   = v.dpdp_section,
                section_title  = v.section_title,
                severity       = v.severity,
                pii_category   = v.pii_category,
                evidence       = v.evidence,
                recommendation = v.recommendation,
            ))

        db.commit()
        print(f"[db] Scan {scan.id} saved — {len(violations)} violations")

        return {
            "scan_id":             scan.id,
            "code_findings_count": len(code_findings),
            "policy_claims_count": len(policy_claims),
            "gaps_detected":       [g.value for g in gap_categories],
            "gaps_count":          len(gap_categories),
            "violations_count":    len(violations),
            "violations":          [v.to_dict() for v in violations],
            "sample_findings":     [f.model_dump() for f in code_findings[:5]],
            "compliance":          compliance,
        }

    except Exception as e:
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
    } for s in scans]


@app.get("/scans/{scan_id}/violations")
def get_violations(scan_id: int, db: Session = Depends(get_db)):
    violations = db.query(Violation).filter(Violation.scan_id == scan_id).all()
    return [{
        "dpdp_section":   v.dpdp_section,
        "section_title":  v.section_title,
        "severity":       v.severity,
        "pii_category":   v.pii_category,
        "evidence":       v.evidence,
        "recommendation": v.recommendation,
    } for v in violations]


@app.get("/report/{scan_id}")
def get_report(scan_id: int, format: str = "html", db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    violations = db.query(Violation).filter(Violation.scan_id == scan_id).all()
    findings   = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    class FakeV:
        def __init__(self, s): self.severity = s

    compliance = calculate_compliance_score(
        [FakeV(v.severity) for v in violations],
        scan.findings_count,
        scan.gaps_count
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
                }
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"PDF error: {e}")

    return HTMLResponse(content=html)