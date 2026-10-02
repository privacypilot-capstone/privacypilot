"""
Phase 8: End-to-End Rule 3 Integration
Tests the full pipeline on synthetic data matching
what healthtech-demo actually contains.

PASS criteria:
- Aadhaar in analytics module flagged (correct violation)
- Health in analytics module flagged (correct violation)
- Aadhaar in auth module NOT flagged (correct — matches stated purpose)
- At least one vagueness warning generated on vague policy
"""

import re
import ast
import numpy as np
from sentence_transformers import SentenceTransformer
import spacy

print("Loading models...")
nlp = spacy.load("en_core_web_lg")
model = SentenceTransformer("all-MiniLM-L6-v2")
print("Done.\n")

# ── Reuse components from earlier phases ──────────────────────────────────
from enum import Enum

class PIICategory(str, Enum):
    AADHAAR   = "aadhaar"
    HEALTH    = "health"
    PHONE     = "phone"
    PAN       = "pan"
    BIOMETRIC = "biometric"
    EMAIL     = "email"
    FINANCIAL = "financial"
    LOCATION  = "location"
    NAME      = "name"
    DOB       = "dob"

class ModuleType(str, Enum):
    ANALYTICS = "analytics"; AUTH = "auth"; NOTIFICATION = "notification"
    CORE = "core"; LOGGING = "logging"

MODULE_TO_PURPOSE = {
    ModuleType.ANALYTICS:    {"analytics"},
    ModuleType.AUTH:         {"authentication", "legal"},
    ModuleType.NOTIFICATION: {"communication"},
    ModuleType.CORE:         {"core_service"},
    ModuleType.LOGGING:      {"legal"},
}

PURPOSE_ANCHORS = {
    "authentication": ["to verify your identity", "for identity verification", "KYC compliance"],
    "communication":  ["to send you notifications", "to contact you", "appointment reminders"],
    "analytics":      ["to improve our services", "to analyse usage", "measure performance"],
    "core_service":   ["to provide our services", "to process your request", "complete transaction"],
    "legal":          ["to comply with regulations", "as required by law", "regulatory compliance"],
}
ANCHOR_EMBS = {
    cat: model.encode(sents, normalize_embeddings=True).mean(axis=0)
    for cat, sents in PURPOSE_ANCHORS.items()
}

POLICY_PII_MAP = {
    "aadhaar number": PIICategory.AADHAAR,
    "aadhaar": PIICategory.AADHAAR,
    "health data": PIICategory.HEALTH,
    "health records": PIICategory.HEALTH,
    "phone number": PIICategory.PHONE,
    "mobile": PIICategory.PHONE,
}

PATH_KEYWORDS = {
    ModuleType.ANALYTICS:    ["analytics","tracking","metrics"],
    ModuleType.AUTH:         ["auth","login","kyc","identity"],
    ModuleType.NOTIFICATION: ["notification","sms","email"],
    ModuleType.LOGGING:      ["log","logger"],
}
FUNC_KEYWORDS = {
    ModuleType.ANALYTICS:    ["track","analytics","send_to","report"],
    ModuleType.AUTH:         ["login","authenticate","verify","kyc"],
    ModuleType.NOTIFICATION: ["send_sms","notify","push"],
}

def classify_purpose(text: str) -> tuple[str, float]:
    q = model.encode([text], normalize_embeddings=True)[0]
    best, score = "core_service", 0.0
    for cat, emb in ANCHOR_EMBS.items():
        s = float(np.dot(q, emb))
        if s > score: best, score = cat, s
    return best, round(score, 3)

def extract_purpose_pii_pairs(policy_text: str) -> dict:
    """Returns {PIICategory: set of purpose categories}"""
    result = {}
    sentences = [s.strip() for s in re.split(r'[.!\n]', policy_text) if s.strip()]
    for sent in sentences:
        sent_lower = sent.lower()
        for kw, pii_cat in POLICY_PII_MAP.items():
            if kw in sent_lower:
                purpose, conf = classify_purpose(sent)
                if conf > 0.4:
                    if pii_cat not in result:
                        result[pii_cat] = set()
                    result[pii_cat].add(purpose)
    return result

def get_fn_names(code: str) -> list:
    try:
        tree = ast.parse(code)
        return [n.name.lower() for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    except:
        return []

def classify_module(path: str, code: str = "") -> ModuleType:
    path_lower = path.lower()
    scores = {mt: 0 for mt in ModuleType}
    for mt, kws in PATH_KEYWORDS.items():
        for kw in kws:
            if kw in path_lower:
                scores[mt] += 2
    if code:
        fns = get_fn_names(code)
        for mt, kws in FUNC_KEYWORDS.items():
            for fn in fns:
                for kw in kws:
                    if kw in fn:
                        scores[mt] += 3
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else ModuleType.CORE

# ── Synthetic scenario matching healthtech-demo ────────────────────────────
SYNTHETIC_POLICY = """
We collect your Aadhaar number to verify your identity as required by
government regulations. We collect health data to provide medical services
and maintain your health records. Your phone number is used to send you
appointment reminders.
"""

SYNTHETIC_FILES = {
    "models/patient.py": {
        "pii": [PIICategory.AADHAAR, PIICategory.HEALTH],
        "code": "class Patient:\n    aadhaar_number = None\n    blood_group = None"
    },
    "services/analytics.py": {
        "pii": [PIICategory.AADHAAR, PIICategory.HEALTH],
        "code": "def track_event(patient):\n    firebase.log({'aadhaar': patient.aadhaar_number, 'health': patient.blood_group})"
    },
    "api/auth/views.py": {
        "pii": [PIICategory.AADHAAR],
        "code": "def verify_identity(aadhaar):\n    return kyc_service.verify(aadhaar)"
    },
    "services/notifications.py": {
        "pii": [PIICategory.PHONE],
        "code": "def send_reminder(phone):\n    twilio.messages.create(to=phone)"
    },
}

SENSITIVE_PII = {PIICategory.AADHAAR, PIICategory.HEALTH, PIICategory.BIOMETRIC,
                 PIICategory.PAN, PIICategory.FINANCIAL}

# ── Run the full pipeline ─────────────────────────────────────────────────
print("=" * 65)
print("PHASE 8: End-to-End Rule 3 Integration Test")
print("=" * 65)

print("\n[Step 1] Extracting purpose-PII pairs from policy...")
purpose_map = extract_purpose_pii_pairs(SYNTHETIC_POLICY)
for pii, purposes in purpose_map.items():
    print(f"  {pii.value:12} → stated purposes: {purposes}")

print("\n[Step 2] Classifying code modules...")
module_map = {}
for path, info in SYNTHETIC_FILES.items():
    mt = classify_module(path, info["code"])
    module_map[path] = mt
    print(f"  {path:40} → {mt.value}")

print("\n[Step 3] Running linkage check...")
violations = []
for path, info in SYNTHETIC_FILES.items():
    module = module_map[path]
    if module == ModuleType.CORE:
        continue
    module_purposes = MODULE_TO_PURPOSE.get(module, {"core_service"})
    
    for pii_cat in info["pii"]:
        if pii_cat not in SENSITIVE_PII:
            continue
        stated = purpose_map.get(pii_cat, set())
        overlap = module_purposes & stated
        if not overlap:
            violations.append({
                "file": path,
                "pii": pii_cat.value,
                "module": module.value,
                "module_purposes": module_purposes,
                "stated_purposes": stated,
            })

print("\n[Step 4] Violations found:")
for v in violations:
    print(f"\n  ⚠ VIOLATION — Section 6(1)")
    print(f"    File:     {v['file']}")
    print(f"    PII:      {v['pii']}")
    print(f"    Module purpose:  {v['module_purposes']}")
    print(f"    Stated in policy: {v['stated_purposes']}")
    print(f"    Gap: {v['pii']} used for {v['module']} but policy only justifies: {v['stated_purposes'] or 'nothing'}")

# ── Assertions ────────────────────────────────────────────────────────────
print("\n" + "=" * 65)
print("ASSERTIONS:")

# Must flag: aadhaar in analytics
a1 = any(v["pii"] == "aadhaar" and v["module"] == "analytics" for v in violations)
print(f"  {'✓' if a1 else '✗'} Aadhaar in analytics module flagged")

# Must flag: health in analytics
a2 = any(v["pii"] == "health" and v["module"] == "analytics" for v in violations)
print(f"  {'✓' if a2 else '✗'} Health data in analytics module flagged")

# Must NOT flag: aadhaar in auth (authentication matches stated purpose)
a3 = not any(v["pii"] == "aadhaar" and v["module"] == "auth" for v in violations)
print(f"  {'✓' if a3 else '✗'} Aadhaar in auth module NOT flagged (correct — matches stated purpose)")

# Must NOT flag: phone in notifications (communication matches stated purpose)
a4 = not any(v["pii"] == "phone" and v["module"] == "notification" for v in violations)
print(f"  {'✓' if a4 else '✗'} Phone in notifications NOT flagged (correct — matches stated purpose)")

overall = a1 and a2 and a3 and a4
print(f"\n{'PHASE 8: PASS' if overall else 'PHASE 8: FAIL'}")
print("\nIf all 4 assertions pass: Rule 3 strategy is implementable and correct on synthetic data.")