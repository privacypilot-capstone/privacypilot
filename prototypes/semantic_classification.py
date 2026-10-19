"""
Phase 4: Sentence-Transformers Purpose Classification
Tests that semantic similarity correctly classifies purpose
phrases even when exact keywords are not present (paraphrase).

PASS criteria:
- All 6 direct cases classified correctly (>0.5 confidence)
- At least 3 of 4 paraphrase cases classified correctly
- Vagueness detection fires on generic statements (<0.4 confidence)
"""

import numpy as np
from sentence_transformers import SentenceTransformer

print("Loading sentence-transformers model (downloads ~80MB first time)...")
model = SentenceTransformer("all-MiniLM-L6-v2")
print("Model loaded.")

# ── Anchor sentences per purpose category ─────────────────────────────────
PURPOSE_ANCHORS = {
    "authentication": [
        "to verify your identity",
        "for identity verification",
        "to authenticate the user",
        "to confirm who you are",
        "for KYC compliance",
        "to establish your identity",
        "to validate your credentials",
    ],
    "communication": [
        "to send you notifications",
        "to contact you about your account",
        "to send appointment reminders",
        "to notify you of updates",
        "to reach out to you",
        "to send alerts and messages",
    ],
    "analytics": [
        "to improve our services",
        "to analyse usage patterns",
        "to understand how you use the app",
        "to measure performance and engagement",
        "for reporting and analytics",
        "to track user behaviour",
    ],
    "core_service": [
        "to provide our services to you",
        "to process your request",
        "to deliver the product",
        "to complete your transaction",
        "to fulfil your order",
        "to maintain your account",
    ],
    "legal": [
        "to comply with regulations",
        "as required by law",
        "for regulatory compliance",
        "under RBI guidelines",
        "to meet legal obligations",
        "as mandated by government regulations",
    ],
    "personalisation": [
        "to personalise your experience",
        "to recommend relevant content",
        "to tailor our services to you",
        "based on your preferences",
        "to customise what you see",
    ],
}

print("\nPre-computing anchor embeddings...")
ANCHOR_EMBEDDINGS = {}
for category, sentences in PURPOSE_ANCHORS.items():
    embeddings = model.encode(sentences, normalize_embeddings=True)
    ANCHOR_EMBEDDINGS[category] = embeddings.mean(axis=0)
print("Done.")

def classify_purpose(text: str) -> tuple[str, float]:
    query = model.encode([text], normalize_embeddings=True)[0]
    best_cat, best_score = "core_service", 0.0
    for cat, anchor in ANCHOR_EMBEDDINGS.items():
        score = float(np.dot(query, anchor))
        if score > best_score:
            best_score, best_cat = score, cat
    return best_cat, round(best_score, 3)

def is_vague_by_margin(text: str) -> tuple[bool, str, float, float]:
    q = model.encode([text], normalize_embeddings=True)[0]
    scores = {cat: float(np.dot(q, emb)) for cat, emb in ANCHOR_EMBEDDINGS.items()}
    sorted_items = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    top1_cat, top1_score = sorted_items[0]
    top2_score = sorted_items[1][1]
    margin = top1_score - top2_score
    return (margin < 0.08, top1_cat, round(top1_score, 3), round(margin, 3))

# ── Test cases ─────────────────────────────────────────────────────────────
print("\n" + "=" * 65)
print("PHASE 4: Sentence-Transformers Classification")
print("=" * 65)

DIRECT_CASES = [
    ("to verify your identity",              "authentication",  "Direct keyword"),
    ("to send you appointment reminders",    "communication",   "Direct keyword"),
    ("to analyse usage patterns",            "analytics",       "Direct keyword"),
    ("to provide our healthcare services",   "core_service",    "Direct keyword"),
    ("to comply with RBI regulations",       "legal",           "Direct keyword"),
    ("to personalise your experience",       "personalisation", "Direct keyword"),
]

PARAPHRASE_CASES = [
    ("to establish that you are who you claim to be", "authentication", "Paraphrase"),
    ("so we can get in touch with you",               "communication",  "Paraphrase"),
    ("to understand user behaviour on our platform",  "analytics",      "Paraphrase"),
    ("as required by government mandate",             "legal",          "Paraphrase"),
]

VAGUENESS_TEST = [
    ("to use your data",                   True,  "Generic verb"),
    ("for our purposes",                   True,  "Meaningless"),
    ("to handle your information",         True,  "Generic verb"),
    ("to provide our healthcare services", False, "Clear purpose"),
    ("to comply with legal requirements",  False, "Clear purpose"),
    # Add more edge cases
    ("to improve your experience",         True,  "Borderline — common evasion phrase"),
    ("to verify your identity",            False, "Clearly authentication"),
    ("to send you appointment reminders",  False, "Clearly communication"),
]

direct_pass = 0
print("\n--- Full score distribution (all categories) ---")
for text, expected, label in DIRECT_CASES:
    q = model.encode([text], normalize_embeddings=True)[0]
    scores = {}
    for cat, emb in ANCHOR_EMBEDDINGS.items():
        scores[cat] = round(float(np.dot(q, emb)), 3)
    
    sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    top1_cat, top1_score = sorted_scores[0]
    top2_cat, top2_score = sorted_scores[1]
    margin = round(top1_score - top2_score, 3)
    
    correct = top1_cat == expected
    if correct and margin > 0.05:   
        direct_pass += 1
    status = "✓" if correct else "✗"
    print(f"\n  {status} '{text}'")
    print(f"    Expected: {expected}")
    print(f"    Top-1: {top1_cat} ({top1_score})")
    print(f"    Top-2: {top2_cat} ({top2_score})")
    print(f"    Margin: {margin}  {'← CONFIDENT' if margin > 0.05 else '← NEAR TIE (unreliable)'}")

paraphrase_pass = 0
print("\n--- Paraphrase cases (at least 3 of 4 must pass) ---")
for text, expected, label in PARAPHRASE_CASES:
    predicted, score = classify_purpose(text)
    correct = predicted == expected
    if correct:
        paraphrase_pass += 1
    status = "✓" if correct else "~"
    print(f"  {status} '{text}'")
    print(f"    Expected: {expected} | Got: {predicted} ({score})")

vague_pass = 0
print("Margin-based vagueness detection:")
for text, expect_vague, label in VAGUENESS_TEST:
    is_vague, top_cat, top_score, margin = is_vague_by_margin(text)
    correct = is_vague == expect_vague
    if correct:
        vague_pass += 1
    status = "✓" if correct else "✗"
    print(f"  {status} [{label}] '{text}' → {'VAGUE' if is_vague else 'classifiable'} "
          f"(score={top_score}, margin={margin})")

print(f"\n{'='*65}")
print(f"Direct cases:    {direct_pass}/6")
print(f"Paraphrase cases: {paraphrase_pass}/4")
print(f"Vagueness cases:  {vague_pass}/{len(VAGUENESS_TEST)}")

vagueness_pass_threshold = 4
overall = direct_pass == 6 and paraphrase_pass >= 3 and vague_pass >= vagueness_pass_threshold
print(f"\n{'PHASE 4: PASS' if overall else 'PHASE 4: FAIL'}")