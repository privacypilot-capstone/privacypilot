"""
Phase 2: Bullet-Point PII Extraction
Tests that the parser finds PII in bullet-pointed lists
without requiring a collection verb in each bullet line.

PASS criteria:
- Finds at least 4 PII categories from the bullet list
- Does not miss Aadhaar, phone, health, financial from bullets
- Regular sentence extraction still works alongside bullet extraction
"""

import re
from enum import Enum

class PIICategory(str, Enum):
    AADHAAR   = "aadhaar"
    PAN       = "pan"
    PHONE     = "phone"
    EMAIL     = "email"
    LOCATION  = "location"
    HEALTH    = "health"
    FINANCIAL = "financial"
    NAME      = "name"
    DOB       = "dob"
    BIOMETRIC = "biometric"

POLICY_PII_MAP = {
    "aadhaar":          PIICategory.AADHAAR,
    "aadhar":           PIICategory.AADHAAR,
    "pan":              PIICategory.PAN,
    "pan card":         PIICategory.PAN,
    "phone":            PIICategory.PHONE,
    "mobile":           PIICategory.PHONE,
    "contact number":   PIICategory.PHONE,
    "email":            PIICategory.EMAIL,
    "location":         PIICategory.LOCATION,
    "address":          PIICategory.LOCATION,
    "health":           PIICategory.HEALTH,
    "medical":          PIICategory.HEALTH,
    "blood group":      PIICategory.HEALTH,
    "diagnosis":        PIICategory.HEALTH,
    "financial":        PIICategory.FINANCIAL,
    "bank account":     PIICategory.FINANCIAL,
    "account number":   PIICategory.FINANCIAL,
    "name":             PIICategory.NAME,
    "full name":        PIICategory.NAME,
    "date of birth":    PIICategory.DOB,
    "dob":              PIICategory.DOB,
    "biometric":        PIICategory.BIOMETRIC,
    "fingerprint":      PIICategory.BIOMETRIC,
}

COLLECTION_VERBS = {
    "collect", "process", "store", "use", "share",
    "disclose", "gather", "obtain", "access", "record"
}

BULLET_PATTERN = re.compile(
    r'^[\s]*(?:[-•*▪◦●]|\d+\.|[a-z]\))\s+(.+)$',
    re.MULTILINE
)

def extract_from_sentences(text: str) -> set:
    """Pass 1 — sentence-level (existing logic)."""
    found = set()
    sentences = re.split(r'[.!?]\s+', text)
    for sent in sentences:
        sent_lower = sent.lower()
        has_verb = any(v in sent_lower for v in COLLECTION_VERBS)
        if not has_verb:
            continue
        for keyword, category in POLICY_PII_MAP.items():
            if keyword in sent_lower:
                found.add(category)
    return found

def extract_from_bullets(text: str) -> set:
    """Pass 2 — bullet-point extraction (new logic)."""
    found = set()
    for match in BULLET_PATTERN.finditer(text):
        line = match.group(1).lower()
        for keyword, category in POLICY_PII_MAP.items():
            if keyword in line:
                found.add(category)
    return found

def parse_policy(text: str) -> set:
    """Combined: Pass 1 + Pass 2."""
    return extract_from_sentences(text) | extract_from_bullets(text)

# ── Test cases ─────────────────────────────────────────────────────────────
print("=" * 55)
print("PHASE 2: Bullet-Point Policy Parser")
print("=" * 55)

# Test 1: Bullet list — Pass 1 alone would miss all of these
BULLET_ONLY_POLICY = """
Privacy Policy

We collect the following personal information:

  • Full name
  • Aadhaar number
  • PAN card
  • Phone number / mobile number
  • Email address
  • Date of birth
  • Health and medical information
  • Financial account details
  • Biometric data (fingerprint)
  • Location / address
"""

print("\n--- Test 1: Bullet list with no verbs ---")
pass1 = extract_from_sentences(BULLET_ONLY_POLICY)
pass2 = extract_from_bullets(BULLET_ONLY_POLICY)
combined = parse_policy(BULLET_ONLY_POLICY)

print(f"Pass 1 (sentence) found:  {sorted(c.value for c in pass1)}")
print(f"Pass 2 (bullet)   found:  {sorted(c.value for c in pass2)}")
print(f"Combined          found:  {sorted(c.value for c in combined)}")

expected = {PIICategory.AADHAAR, PIICategory.PAN, PIICategory.PHONE,
            PIICategory.EMAIL, PIICategory.DOB, PIICategory.HEALTH,
            PIICategory.FINANCIAL, PIICategory.BIOMETRIC, PIICategory.LOCATION}
missing = expected - combined
t1_pass = len(missing) == 0
print(f"\n{'✓ PASS' if t1_pass else '✗ FAIL'} — Expected {len(expected)}, "
      f"found {len(combined)}, missing: {[c.value for c in missing] or 'none'}")

# Test 2: Mixed policy — sentences + bullets
MIXED_POLICY = """
We collect your email address and phone number to contact you.

We also collect:
  - Aadhaar number
  - Health and medical information
  * Financial account number
"""

print("\n--- Test 2: Mixed sentences + bullets ---")
combined2 = parse_policy(MIXED_POLICY)
expected2 = {PIICategory.EMAIL, PIICategory.PHONE,
             PIICategory.AADHAAR, PIICategory.HEALTH, PIICategory.FINANCIAL}
missing2 = expected2 - combined2
t2_pass = len(missing2) == 0
print(f"Found: {sorted(c.value for c in combined2)}")
print(f"{'✓ PASS' if t2_pass else '✗ FAIL'} — missing: {[c.value for c in missing2] or 'none'}")

# Test 3: The false positive case — this was causing 12 FP violations
# A compliant policy that lists PII in bullets SHOULD be detected,
# meaning fewer false positives (previously these bullets were missed
# so they appeared as gaps)
COMPLIANT_BULLET_POLICY = """
We collect the following:
  • Name and email address
  • Phone number

We use this data to provide our services.
"""

print("\n--- Test 3: Previously caused false positive ---")
combined3 = parse_policy(COMPLIANT_BULLET_POLICY)
# name, email, phone should ALL be found — so they're NOT gaps
# previously only sentence-level was used, missing the bullets
t3_pass = PIICategory.EMAIL in combined3 and PIICategory.PHONE in combined3
print(f"Found: {sorted(c.value for c in combined3)}")
print(f"{'✓ PASS' if t3_pass else '✗ FAIL'} — email and phone detected from bullets")

overall = t1_pass and t2_pass and t3_pass
print(f"\n{'PHASE 2: PASS' if overall else 'PHASE 2: FAIL — check failures above'}")