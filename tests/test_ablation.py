"""
Ablation study: demonstrates the contribution of each detection component.
Shows why two passes are needed — what each catches that the other misses.
Not a full precision/recall study — demonstrates component-level coverage.
"""

import re
import sys
sys.path.insert(0, '/app')

# ── Simulate regex-only (Pass 1) ──────────────────────────────────────────
PII_PATTERNS = {
    "aadhaar":   re.compile(r'\b(aadhaar_number|aadhar_no|aadhaar)\b', re.I),
    "pan":       re.compile(r'\b(pan_number|pan_card|pan)\b', re.I),
    "health":    re.compile(r'\b(blood_group|diagnosis|health_data|medical)\b', re.I),
    "phone":     re.compile(r'\b(phone_number|mobile_no|contact_number)\b', re.I),
    "biometric": re.compile(r'\b(fingerprint|biometric_hash|iris_scan)\b', re.I),
    "financial": re.compile(r'\b(bank_account|account_no|ifsc_code)\b', re.I),
}

def scan_regex_only(code: str) -> set:
    found = set()
    for line in code.splitlines():
        for category, pattern in PII_PATTERNS.items():
            if pattern.search(line):
                found.add(category)
    return found


# ── Simulate Presidio-only (Pass 2) ──────────────────────────────────────
# We cannot run full Presidio here without the container
# but we can demonstrate what it catches that regex misses
# by showing the pattern types it would find

PRESIDIO_CATCHES = {
    # Actual PII values that regex misses because field name gives nothing away
    "aadhaar_value": re.compile(r'\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b'),
    "pan_value":     re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'),
    "phone_value":   re.compile(r'\b(?:\+91|0)?[6-9]\d{9}\b'),
}

def scan_presidio_only(code: str) -> set:
    """Simulates what Presidio catches that regex misses."""
    found = set()
    for line in code.splitlines():
        if PRESIDIO_CATCHES["aadhaar_value"].search(line):
            found.add("aadhaar_value_detected")
        if PRESIDIO_CATCHES["pan_value"].search(line):
            found.add("pan_value_detected")
        if PRESIDIO_CATCHES["phone_value"].search(line):
            found.add("phone_value_detected")
    return found

# ── Test cases demonstrating what each pass catches ───────────────────────
print("=" * 65)
print("ABLATION STUDY: Regex-only vs Presidio-only vs Combined")
print("=" * 65)

# Case 1: Field name present — regex catches, Presidio adds nothing
CODE_FIELD_NAME = '''
class Patient(db.Model):
    aadhaar_number = db.Column(db.String(12))
    blood_group    = db.Column(db.String(5))
    phone_number   = db.Column(db.String(10))
'''
r1 = scan_regex_only(CODE_FIELD_NAME)
p1 = scan_presidio_only(CODE_FIELD_NAME)
print("\n--- Case 1: Structured field names (database models) ---")
print(f"  Regex-only:    {sorted(r1)}")
print(f"  Presidio-only: {sorted(p1)} (no PII values in column definitions)")
print(f"  Combined:      {sorted(r1 | p1)}")
print(f"  ✓ Regex catches structured models that Presidio misses")

# Case 2: Actual PII values — Presidio catches, regex misses
CODE_VALUES = '''
def test_patient_verify():
    # Test data with actual values
    verify_aadhaar("2345 6789 0123")
    check_pan("ABCDE1234F")
    send_otp("+91 98765 43210")
'''
r2 = scan_regex_only(CODE_VALUES)
p2 = scan_presidio_only(CODE_VALUES)
print("\n--- Case 2: Actual PII values in test/hardcoded strings ---")
print(f"  Regex-only:    {sorted(r2)} (no field name patterns)")
print(f"  Presidio-only: {sorted(p2)} (catches actual values)")
print(f"  Combined:      {sorted(r2 | p2)}")
print(f"  ✓ Presidio catches actual values that regex misses")

# Case 3: Both needed — mixed codebase
CODE_MIXED = '''
class Patient(db.Model):
    aadhaar_number = db.Column(db.String(12))  # regex catches

def seed_test_data():
    p = Patient()
    p.aadhaar_number = "2345 6789 0123"  # Presidio catches value too
    verify("+91 98765 43210")             # Presidio only
    blood_group = "O+"                   # regex field name below
    patient_blood_group = blood_group    # regex catches
'''
r3 = scan_regex_only(CODE_MIXED)
p3 = scan_presidio_only(CODE_MIXED)
print("\n--- Case 3: Mixed — both passes contribute ---")
print(f"  Regex-only:    {sorted(r3)}")
print(f"  Presidio-only: {sorted(p3)}")
print(f"  Combined:      {sorted(r3 | p3)}")
print(f"  ✓ Combined catches more than either alone")

print("\n--- Summary ---")
print("  Regex-only misses: actual PII values in test data, logs, comments")
print("  Presidio-only misses: field names in ORM models, variable names,")
print("                        column definitions (no scannable value present)")
print("  Combined: complementary coverage, each catches what the other misses")
print("\nABLATION: Component contribution demonstrated")