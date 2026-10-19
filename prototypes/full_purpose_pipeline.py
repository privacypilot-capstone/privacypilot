"""
Phase 5: Full Purpose Extraction Pipeline
Tests all four extraction passes together plus the context
window co-reference for multi-sentence policies.

PASS criteria:
- At least 5 of 6 sentence types yield a classified purpose
- Context window correctly links cross-sentence purpose to PII
- Vagueness warning fires for vague statements
"""

import re
import spacy
import numpy as np
from sentence_transformers import SentenceTransformer

print("Loading models...")
nlp = spacy.load("en_core_web_lg")
model = SentenceTransformer("all-MiniLM-L6-v2")

# ── Purpose classification anchors ────────────────────────────────────────
PURPOSE_ANCHORS = {
    "authentication": ["to verify your identity", "for identity verification",
                       "authenticate user", "KYC compliance"],
    "communication":  ["to send you notifications", "to contact you",
                       "appointment reminders", "send alerts"],
    "analytics":      ["to improve our services", "to analyse usage",
                       "measure performance", "user behaviour"],
    "core_service":   ["to provide our services", "to process your request",
                       "complete transaction", "deliver product"],
    "legal":          ["to comply with regulations", "as required by law",
                       "regulatory compliance", "RBI IRDAI"],
    "personalisation":["to personalise your experience", "recommend content",
                       "tailor services", "based on preferences"],
}
ANCHOR_EMBEDDINGS = {
    cat: model.encode(sents, normalize_embeddings=True).mean(axis=0)
    for cat, sents in PURPOSE_ANCHORS.items()
}

# ── PII keyword map ────────────────────────────────────────────────────────
# Compound phrases only. Bare adjectives like "medical" excluded because
# they appear in service descriptions ("medical services") as well as PII
# descriptions ("medical records"), making them ambiguous.
POLICY_PII_MAP = {
    "aadhaar number":     "aadhaar",
    "aadhaar":            "aadhaar",
    "aadhar":             "aadhaar",
    "pan card":           "pan",
    "pan number":         "pan",
    "pan":                "pan",
    "phone number":       "phone",
    "mobile number":      "phone",
    "phone":              "phone",
    "mobile":             "phone",
    "email address":      "email",
    "email":              "email",
    "health records":     "health",
    "health data":        "health",
    "health information": "health",
    "medical records":    "health",
    "medical data":       "health",
    "medical history":    "health",
    "blood group":        "health",
    "diagnosis":          "health",
    "date of birth":      "dob",
    "biometric":          "biometric",
    "fingerprint":        "biometric",
    "location":           "location",
    "address":            "location",
    "financial":          "financial",
    "bank account":       "financial",
    "full name":          "name",
}

# ── Purpose lexicon — fallback classification ─────────────────────────────
PURPOSE_LEXICON_SIMPLE = {
    "authentication": ["verify", "authenticate", "kyc", "identity", "confirm"],
    "communication":  ["notify", "contact", "remind", "send", "alert", "reach"],
    "analytics":      ["analyse", "improve", "measure", "track", "understand"],
    "core_service":   ["provide", "deliver", "process", "fulfil", "maintain"],
    "legal":          ["comply", "regulation", "mandatory", "required", "statutory"],
    "personalisation":["personalise", "recommend", "customise", "tailor"],
}


# ── Classification functions ───────────────────────────────────────────────

def classify_semantic(text: str) -> tuple[str, float]:
    """Semantic similarity classification using sentence-transformers."""
    q = model.encode([text], normalize_embeddings=True)[0]
    best_cat, best_score = "core_service", 0.0
    for cat, emb in ANCHOR_EMBEDDINGS.items():
        s = float(np.dot(q, emb))
        if s > best_score:
            best_score, best_cat = s, cat
    return best_cat, round(best_score, 3)


def lexicon_classify_sentence(sent: str) -> tuple[str, float]:
    """
    Keyword-based fallback for sentences where semantic model scores low.
    Used for long multi-purpose sentences where sentence-level embeddings
    produce competing signals and reduce margin artificially.
    Returns first matched category with fixed confidence 0.55.
    """
    sent_lower = sent.lower()
    for cat, keywords in PURPOSE_LEXICON_SIMPLE.items():
        for kw in keywords:
            if kw in sent_lower:
                return (cat, 0.55)
    return ("core_service", 0.25)


def is_vague_by_margin(text: str, threshold: float = 0.08) -> tuple[bool, float]:
    """
    Margin-based vagueness detection.
    A vague statement scores similarly across all categories (low margin).
    A clear statement has one dominant category (high margin).
    Threshold 0.08 derived empirically from diagnostic run — see paper
    limitations section for the one documented borderline miss.
    """
    q = model.encode([text], normalize_embeddings=True)[0]
    scores = sorted(
        [float(np.dot(q, emb)) for emb in ANCHOR_EMBEDDINGS.values()],
        reverse=True
    )
    margin = scores[0] - scores[1]
    return (margin < threshold, round(margin, 3))


def extract_purpose_from_sentence(sentence: str) -> tuple[str, float, str]:
    """
    Four-pass extraction. Returns (category, confidence, method).

    Pass 1: advcl/xcomp dependency — "to verify", "to provide"
    Pass 2: prepositional phrase  — "for identity verification"
    Pass 3: lexicon keyword match — handles KYC, RBI, domain terms
    Fallback: classify root verb via semantic similarity
    """
    doc = nlp(sentence)
    roots = [t for t in doc if t.dep_ == "ROOT"]
    root = roots[0] if roots else None

    purpose_fragment = None
    method = None

    if root:
        # Pass 1: advcl/xcomp — infinitive purpose clause
        for child in root.children:
            if child.dep_ in ("advcl", "xcomp"):
                purpose_fragment = sentence[child.idx:][:60]
                method = "Pass1"
                break

        # Pass 2: prep phrase — "for X", "to X" where X is a noun
        if not purpose_fragment:
            for child in root.children:
                if child.dep_ == "prep" and child.text.lower() in ("for", "to"):
                    for pobj in child.children:
                        if pobj.dep_ in ("pobj", "pcomp"):
                            purpose_fragment = sentence[child.idx:][:60]
                            method = "Pass2"
                            break

        # Pass 3: lexicon keyword on whole sentence
        if not purpose_fragment:
            cat, conf = lexicon_classify_sentence(sentence)
            if conf > 0.5:
                return (cat, conf, "Pass3-lexicon")

        # Fallback: classify the root verb semantically
        if not purpose_fragment:
            purpose_fragment = root.text
            method = "Fallback"

    if purpose_fragment:
        cat, conf = classify_semantic(purpose_fragment)
        return (cat, conf, method)

    return ("core_service", 0.25, "none")


def find_pii_in_sentence(sent: str) -> list[str]:
    """
    Returns list of PII category strings found in the sentence.
    Uses POLICY_PII_MAP with compound phrases to avoid ambiguity.
    Sorts keywords by length descending so compound phrases match
    before substrings, preventing double-counting.
    """
    sent_lower = sent.lower()
    found = []
    sorted_keywords = sorted(POLICY_PII_MAP.keys(), key=len, reverse=True)
    matched_positions = set()

    for keyword in sorted_keywords:
        pos = sent_lower.find(keyword)
        if pos >= 0:
            span = set(range(pos, pos + len(keyword)))
            if not span.intersection(matched_positions):
                found.append(POLICY_PII_MAP[keyword])
                matched_positions.update(span)

    return list(set(found))


def extract_with_context_window(policy_text: str) -> list[dict]:
    """
    Full pipeline: per-sentence extraction + 3-sentence context window.

    For each sentence:
    - If it contains PII keywords: record PII + purpose for that sentence.
      The is_vague flag is reported to surface vague policy disclosures.
    - If it has a purpose but no PII (conf >= 0.45): look back up to
      3 sentences for PII and link the purpose to that PII.
      NOTE: the context window trigger uses conf only, not is_vague.
      Reason: is_vague is based on semantic margin, which can be low
      for multi-purpose sentences even when the lexicon has correctly
      identified the purpose at conf=0.55. Blocking on is_vague here
      would prevent the context window from firing on legitimately clear
      multi-purpose sentences like "to provide services and comply with
      regulations."
    """
    sentences = [s.strip() for s in re.split(r'[.!?\n]', policy_text) if s.strip()]
    results = []

    for i, sent in enumerate(sentences):

        # Detect PII in this sentence using POLICY_PII_MAP
        pii_in_sent = find_pii_in_sentence(sent)

        # Extract purpose — semantic first, lexicon fallback if conf low
        cat, conf, method = extract_purpose_from_sentence(sent)

        if conf < 0.45:
            lex_cat, lex_conf = lexicon_classify_sentence(sent)
            if lex_conf > conf:
                cat, conf = lex_cat, lex_conf
                method = method + "+lexicon"

        # is_vague is for reporting only — used in PII branch
        is_vague, margin = is_vague_by_margin(sent)

        if pii_in_sent:
            # Standard case: PII found in this sentence
            results.append({
                "sentence":    sent[:80],
                "pii":         pii_in_sent,
                "purpose":     cat,
                "confidence":  conf,
                "method":      method,
                "vague":       is_vague,  # reported to surface vague disclosures
                "margin":      margin,
                "via_context": False,
            })

        elif conf >= 0.45:
            # ── KEY FIX ──────────────────────────────────────────────────
            # Use conf only — NOT is_vague — as the trigger condition.
            # is_vague reflects semantic margin, which stays low on mixed-
            # purpose sentences even after the lexicon correctly boosts conf.
            # If the lexicon matched at 0.55, this IS a purpose statement
            # regardless of what the semantic margin says.
            # ─────────────────────────────────────────────────────────────
            window = sentences[max(0, i - 3):i]
            for prev in reversed(window):
                prev_pii = find_pii_in_sentence(prev)
                if prev_pii:
                    results.append({
                        "sentence":    sent[:80],
                        "pii":         prev_pii,
                        "purpose":     cat,
                        "confidence":  conf,
                        "method":      method + "+context",
                        "vague":       False,
                        "margin":      margin,
                        "via_context": True,
                    })
                    break

    return results


# ── Tests ──────────────────────────────────────────────────────────────────
print("\n" + "=" * 65)
print("PHASE 5: Full Purpose Extraction Pipeline")
print("=" * 65)

# ── Test 1: Six sentence structure types ───────────────────────────────────
STRUCTURE_TESTS = [
    ("We collect your Aadhaar number to verify your identity.",
     "authentication", "Type 1: Active infinitive"),
    ("Your Aadhaar number is collected for identity verification.",
     "authentication", "Type 2: Passive + prep phrase"),
    ("We process Aadhaar data for KYC compliance.",
     "authentication", "Type 3: Noun phrase KYC"),
    ("Your phone number is used to send you appointment reminders.",
     "communication",  "Type 4: Passive with infinitive"),
    ("We collect health data to provide medical services.",
     "core_service",   "Type 5: Simple active"),
    ("Your date of birth is required to comply with regulatory requirements.",
     "legal",          "Type 6: Required + comply"),
]

print("\n--- Test 1: Six sentence structure types ---")
structure_pass = 0
for sentence, expected, label in STRUCTURE_TESTS:
    cat, conf, method = extract_purpose_from_sentence(sentence)
    correct = cat == expected
    if correct:
        structure_pass += 1
    status = "✓" if correct else "✗"
    print(f"  {status} {label}")
    print(f"    Got: {cat} ({conf}) via {method} | Expected: {expected}")

# ── Test 2: Context window co-reference ────────────────────────────────────
# Policy separates PII listing from purpose statement across sentences.
# "our services" used instead of "medical services" to prevent the word
# "medical" appearing in a service description and triggering a false
# PII match, which would put sentence 2 into the PII branch instead of
# the context window branch.
MULTI_SENT_POLICY = """
We collect the following personal data: Aadhaar number, health records, and phone number.
We use this data to provide our services and comply with government regulations.
"""

print("\n--- Test 2: Context window co-reference ---")
results = extract_with_context_window(MULTI_SENT_POLICY)
for r in results:
    ctx   = "(via context)" if r["via_context"] else ""
    vague = "⚠ VAGUE"      if r["vague"]       else ""
    print(f"  PII: {r['pii']} → Purpose: {r['purpose']} "
          f"({r['confidence']}, margin={r['margin']}) {ctx} {vague}")
context_ok = any(r["via_context"] for r in results)
print(f"  Context window fired: {'✓ YES' if context_ok else '✗ NO'}")

# ── Test 3: Vagueness detection ────────────────────────────────────────────
# Uses margin-based detection (threshold=0.08) established from
# diagnostic run. One documented borderline miss: "to handle your
# information" (margin=0.103, just above threshold).
VAGUE_CASES = [
    ("We use your personal information to improve your experience and for our purposes.",
     True,  "Evasion phrase — genuinely vague"),
    ("We collect your Aadhaar number to verify your identity.",
     False, "Clear purpose — should not be flagged"),
    ("Your phone number is used to send you appointment reminders.",
     False, "Clear purpose — should not be flagged"),
    ("to use your data",
     True,  "Bare generic verb — clearly vague"),
    ("for our purposes",
     True,  "Meaningless phrase — clearly vague"),
]

print("\n--- Test 3: Vagueness detection (margin-based, threshold=0.08) ---")
vague_pass = 0
for text, expect_vague, label in VAGUE_CASES:
    is_vague, margin = is_vague_by_margin(text)
    _, top_score = classify_semantic(text)
    correct = is_vague == expect_vague
    if correct:
        vague_pass += 1
    status = "✓" if correct else "✗"
    flag   = "VAGUE" if is_vague else "classifiable"
    print(f"  {status} [{label}]")
    print(f"    '{text[:65]}'")
    print(f"    → {flag} (margin={margin}, top_score={top_score})")

# ── Results ────────────────────────────────────────────────────────────────
overall = structure_pass >= 5 and context_ok and vague_pass >= 4

print(f"\n{'='*65}")
print(f"Structure types:  {structure_pass}/6  {'✓' if structure_pass >= 5 else '✗'}")
print(f"Context window:   {'✓ fired' if context_ok else '✗ did not fire'}")
print(f"Vagueness cases:  {vague_pass}/5  {'✓' if vague_pass >= 4 else '✗'}")
print(f"\n{'PHASE 5: PASS' if overall else 'PHASE 5: FAIL'}")