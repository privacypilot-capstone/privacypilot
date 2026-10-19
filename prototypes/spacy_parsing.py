"""
Phase 3: spaCy Dependency Parsing
Tests that spaCy correctly extracts purpose verbs from
different sentence structures found in real privacy policies.

PASS criteria:
- Extracts a purpose token from at least 4 of 6 sentence types
- Identifies the correct verb/noun as purpose signal
- Fallback to root verb works when no purpose clause found
"""

import spacy

print("Loading spaCy model (may take 10-15 seconds)...")
nlp = spacy.load("en_core_web_lg")
print("Model loaded.")

def find_purpose_token(sentence: str):
    """
    Returns (purpose_token_text, dependency_type, method_used)
    or None if no purpose found.
    """
    doc = nlp(sentence)
    
    # Find root
    roots = [t for t in doc if t.dep_ == "ROOT"]
    if not roots:
        return None
    root = roots[0]
    
    # Pass 1: advcl/xcomp — "to verify", "to provide"
    for child in root.children:
        if child.dep_ in ("advcl", "xcomp"):
            return (child.text, child.dep_, "Pass1-advcl/xcomp")
    
    # Pass 2: prep phrase — "for identity verification", "for KYC"
    for child in root.children:
        if child.dep_ == "prep" and child.text.lower() in ("for", "to"):
            for pobj in child.children:
                if pobj.dep_ in ("pobj", "pcomp"):
                    return (pobj.text, pobj.dep_, "Pass2-prep")
    
    # Pass 3: relcl — relative clause "which verifies"
    for token in doc:
        if token.dep_ in ("relcl",):
            return (token.text, token.dep_, "Pass3-relcl")
    
    # Fallback: root verb
    return (root.text, root.dep_, "Fallback-root")

# ── Test sentences covering the 6 structure types ─────────────────────────
print("\n" + "=" * 65)
print("PHASE 3: spaCy Dependency Parsing")
print("=" * 65)

SENTENCES = [
    # (sentence, expected_purpose_contains, structure_type)
    (
        "We collect your Aadhaar number to verify your identity.",
        "verify",
        "Type 1: Active infinitive (ideal case)"
    ),
    (
        "Your Aadhaar number is collected for identity verification purposes.",
        "verification",
        "Type 2: Passive + prepositional phrase"
    ),
    (
        "We process Aadhaar data for KYC and regulatory compliance.",
        "KYC",
        "Type 3: Noun phrase purpose (no verb)"
    ),
    (
        "Your phone number is used to send you appointment reminders.",
        "send",
        "Type 4: Passive root with active purpose clause"
    ),
    (
        "We use health data to provide medical services.",
        "provide",
        "Type 5: Simple active"
    ),
    (
        "Your date of birth is required to comply with regulatory requirements.",
        "comply",
        "Type 6: Required + purpose clause"
    ),
    (
        "We use your personal information to improve our services.",
        "improve",
        "Type 7: Vague statement (should still find token)"
    ),
    (
        "Your location data may be used if unusual activity is detected.",
        None,  # conditional — no clear purpose, fallback expected
        "Type 8: Conditional (fallback expected)"
    ),
]

passed = 0
for sentence, expected_contains, label in SENTENCES:
    result = find_purpose_token(sentence)
    
    if result:
        token_text, dep_type, method = result
        if expected_contains:
            found = expected_contains.lower() in token_text.lower()
            status = "✓" if found else "~"
            if found: passed += 1
        else:
            status = "~"  # fallback — just show what was found
            passed += 0.5
    else:
        token_text, dep_type, method = "NONE", "—", "—"
        status = "✗"
    
    print(f"\n  {status} {label}")
    print(f"    Sentence: \"{sentence[:60]}...\"" if len(sentence) > 60 else f"    Sentence: \"{sentence}\"")
    print(f"    Found: '{token_text}' ({dep_type}) via {method}")

print(f"\n{'='*65}")
print(f"Purpose token extracted from {passed}/{len(SENTENCES)} sentences")
pass_threshold = 5  # at least 5 of 8 must succeed
overall = passed >= pass_threshold
print(f"\n{'PHASE 3: PASS' if overall else 'PHASE 3: FAIL'} "
      f"(threshold: {pass_threshold}/{len(SENTENCES)})")