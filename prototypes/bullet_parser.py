"""
Phase 2: Bullet-Point PII Extraction
Tests that the ACTUAL production policy parser (policy_parser.py's
_pass1_extract_pii, which implements Pass 1a sentence-level + Pass 1b
bullet-list extraction) finds PII in bullet-pointed lists without requiring
a collection verb in each bullet line.

This file previously defined its own standalone POLICY_PII_MAP, bullet
regex, and extraction functions, and never imported backend/scanners/*.py
at all -- it tested a simplified reimplementation of the idea, not the
real parser (which additionally has BULLET_PII_MAP's longest-phrase-first
matching, span-overlap tracking, and the _BULLET_EXCLUSIONS false-positive
gate, none of which this file exercised). Rewritten to call the real
function directly.

This is also the "precision fix" the paper's error analysis describes as
"projected to raise precision above 80%" (bullet-point pattern matching
fixing the 12 false positives caused by missed bullet-list PII) -- these
tests confirm that fix is actually implemented and behaves as claimed at
the unit level. The corpus-level re-run (measuring the real precision
number, not asserting one) is a separate, larger step.

PASS criteria:
- Finds at least 4 PII categories from a pure bullet list (no collection verbs)
- Does not miss Aadhaar, PAN, phone, health, financial, biometric from bullets
- Regular sentence extraction still works alongside bullet extraction
- The specific false-positive-reduction case from the paper (PII listed in
  bullets should NOT register as a policy gap) still holds
"""

import re
import sys

from pathlib import Path
# backend/ relative to this file, so the script runs from any checkout
# (it used to work only inside Docker, where backend/ is mounted at /app)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from scanners.policy_parser import _pass1_extract_pii
from models.dataflow import PIICategory


def parse_policy(text: str) -> set:
    """Run the real Pass 1 (sentence + bullet) extraction and return the
    set of PIICategory found, exactly as parse_privacy_policy() would feed
    into Pass 2/3 and the rule engine."""
    full_text_lower  = re.sub(r"\s+", " ", text).lower()
    raw_with_newlines = text  # Pass 1b's bullet regex needs real line breaks
    _findings, seen = _pass1_extract_pii(full_text_lower, raw_with_newlines)
    return seen


print("=" * 55)
print("PHASE 2: Bullet-Point Policy Parser (real production code)")
print("=" * 55)

# Test 1: Bullet list -- Pass 1a (sentence-level, verb-gated) alone would
# miss every one of these, since none of these lines contain a collection
# verb like "collect"/"share"/"store".
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
combined = parse_policy(BULLET_ONLY_POLICY)
print(f"Found: {sorted(c.value for c in combined)}")

expected = {
    PIICategory.NAME, PIICategory.AADHAAR, PIICategory.PAN, PIICategory.PHONE,
    PIICategory.EMAIL, PIICategory.DOB, PIICategory.HEALTH,
    PIICategory.FINANCIAL, PIICategory.BIOMETRIC, PIICategory.LOCATION,
}
missing = expected - combined
t1_pass = len(missing) == 0
print(f"{'PASS' if t1_pass else 'FAIL'} -- expected {len(expected)}, "
      f"found {len(combined)}, missing: {sorted(c.value for c in missing) or 'none'}")

# Test 2: Mixed policy -- sentences + bullets together
MIXED_POLICY = """
We collect your email and phone number to contact you.

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
print(f"{'PASS' if t2_pass else 'FAIL'} -- missing: {sorted(c.value for c in missing2) or 'none'}")

# Test 3: The false-positive case the paper's error analysis is about --
# 12 FPs were traced to the policy parser failing to extract PII from
# bullet lists without a collection verb. A compliant policy that lists
# its PII collection in bullets (common real-world phrasing) must be
# recognised as disclosing that PII, not scored as an undisclosed gap.
COMPLIANT_BULLET_POLICY = """
We collect the following:
  • Name and email address
  • Phone number

We use this data to provide our services.
"""

print("\n--- Test 3: Bullet-disclosed PII must not register as a gap ---")
combined3 = parse_policy(COMPLIANT_BULLET_POLICY)
t3_pass = PIICategory.EMAIL in combined3 and PIICategory.PHONE in combined3
print(f"Found: {sorted(c.value for c in combined3)}")
print(f"{'PASS' if t3_pass else 'FAIL'} -- email and phone detected from bullets")

overall = t1_pass and t2_pass and t3_pass
print(f"\n{'PHASE 2: PASS' if overall else 'PHASE 2: FAIL -- check failures above'}")
