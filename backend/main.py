from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scanners.code_scanner import scan_github_repo
from scanners.policy_parser import parse_privacy_policy

app = FastAPI(title="PrivacyPilot API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    github_repo_url:    str
    privacy_policy_url: str
    github_token:       str

@app.get("/health")
def health():
    return {"status": "ok", "message": "PrivacyPilot is running"}

@app.post("/scan")
def run_scan(req: ScanRequest):
    try:
        # Step 1 — scan source code
        code_findings = scan_github_repo(req.github_repo_url, req.github_token)

        # Step 2 — parse privacy policy
        policy_claims = parse_privacy_policy(req.privacy_policy_url)

        # Step 3 — simple gap detection
        code_pii   = {f.pii_category for f in code_findings}
        policy_pii = {f.pii_category for f in policy_claims}
        gaps = code_pii - policy_pii

        return {
            "code_findings_count":  len(code_findings),
            "policy_claims_count":  len(policy_claims),
            "gaps_detected":        [g.value for g in gaps],
            "gaps_count":           len(gaps),
            "code_pii_types":       [p.value for p in code_pii],
            "policy_pii_types":     [p.value for p in policy_pii],
            "sample_findings":      [f.model_dump() for f in code_findings[:5]],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))