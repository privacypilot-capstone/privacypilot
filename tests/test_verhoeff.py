"""
Phase 1: Verhoeff Checksum Validation
Tests that the ACTUAL production Aadhaar validation (presidio_scanner.py's
verhoeff_checksum_valid + _extract_valid_aadhaar, and code_scanner.py's
_validate_aadhaar which imports the same shared function) correctly accepts
valid-format numbers and rejects invalid ones.

This file previously defined its own standalone copy of the Verhoeff tables
and never imported backend/scanners/*.py at all -- it could pass forever
while the real implementation had a completely different bug, or diverged
from it entirely. It now imports the real functions, so a regression in the
actual scanner shows up here.

PASS criteria:
- All "should reject" structural cases are rejected
- A genuinely Verhoeff-valid Aadhaar number is accepted
- A tampered (checksum-fail) number is rejected
- The scan_text_with_presidio() entry point (the one code_scanner.py Pass 2
  actually calls) does NOT flag a shape-only, checksum-failing 12-digit
  value as AADHAAR, and DOES flag a genuinely valid one
- code_scanner.py's own _validate_aadhaar (Pass 1 path) agrees
"""

import sys
import types

# presidio_analyzer (+ its spaCy-backed NLP engine) is a heavy optional
# dependency of the NER fallback path. The Verhoeff logic under test here
# never touches it, so it's stubbed rather than required just to run this
# test -- scan_text_with_presidio() already handles the NER engine failing
# to load (see its try/except), so stubbing it doesn't change what we're
# validating.
if "presidio_analyzer" not in sys.modules:
    _fake_pa = types.ModuleType("presidio_analyzer")
    _fake_pa.AnalyzerEngine = object
    _fake_nlp = types.ModuleType("presidio_analyzer.nlp_engine")
    _fake_nlp.NlpEngineProvider = object
    sys.modules["presidio_analyzer"] = _fake_pa
    sys.modules["presidio_analyzer.nlp_engine"] = _fake_nlp

sys.path.insert(0, "/app")  # backend/ is mounted at /app in the Docker image

from scanners.presidio_scanner import verhoeff_checksum_valid, scan_text_with_presidio
from scanners.code_scanner import _validate_aadhaar

print("=" * 55)
print("PHASE 1: Verhoeff Checksum (against real production code)")
print("=" * 55)

all_pass = True

SHOULD_REJECT = [
    ("order_id = 123456789012",   "Starts with 1 -- invalid per UIDAI"),
    ("code = 000000000000",       "Starts with 0 -- invalid"),
    ("pin = 12345",                "Too short"),
    ("ref = 12345678901234",       "Too long"),
    ("id = ABCDEFGHIJKL",          "Non-numeric"),
]

print("\n--- Should REJECT (via scan_text_with_presidio) ---")
for line, reason in SHOULD_REJECT:
    hits = scan_text_with_presidio(line)
    result = "AADHAAR" in hits
    status = "PASS" if not result else "FAIL"
    if result:
        all_pass = False
    print(f"  [{status}]  '{line}'  ({reason})")

VALID_AADHAAR = "234567890124"
TAMPERED      = "234567890125"

print("\n--- Verhoeff checksum itself ---")
ok = verhoeff_checksum_valid(VALID_AADHAAR) is True
print(f"  [{'PASS' if ok else 'FAIL'}]  valid number {VALID_AADHAAR} accepted")
all_pass &= ok

ok = verhoeff_checksum_valid(TAMPERED) is False
print(f"  [{'PASS' if ok else 'FAIL'}]  tampered number {TAMPERED} rejected")
all_pass &= ok

print("\n--- False positive reduction: shape matches, checksum fails ---")
line_fp = f"order_timestamp = {TAMPERED}"
hits = scan_text_with_presidio(line_fp)
result = "AADHAAR" in hits
status = "PASS (correctly rejected)" if not result else "FAIL (false positive)"
if result:
    all_pass = False
print(f"  [{status}]  '{line_fp}'")

print("\n--- True positive: genuinely valid Aadhaar value still detected ---")
line_tp = f"aadhaar_value = {VALID_AADHAAR}"
hits = scan_text_with_presidio(line_tp)
result = "AADHAAR" in hits
status = "PASS" if result else "FAIL (missed a real Aadhaar number)"
if not result:
    all_pass = False
print(f"  [{status}]  '{line_tp}'")

print("\n--- code_scanner.py Pass 1 path agrees (shared implementation) ---")
ok = _validate_aadhaar(f"aadhaar_number = '{VALID_AADHAAR}'") is True
print(f"  [{'PASS' if ok else 'FAIL'}]  valid value -> keyword match stands")
all_pass &= ok

ok = _validate_aadhaar(f"aadhaar_number = '{TAMPERED}'") is False
print(f"  [{'PASS' if ok else 'FAIL'}]  tampered value -> keyword match rejected")
all_pass &= ok

ok = _validate_aadhaar("aadhaar_number = input_value") is True
print(f"  [{'PASS' if ok else 'FAIL'}]  bare field name, no value -> conservatively accepted")
all_pass &= ok

print(f"\n{'PHASE 1: PASS' if all_pass else 'PHASE 1: FAIL -- check failures above'}")
