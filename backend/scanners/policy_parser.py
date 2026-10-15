"""
Privacy Policy Parser
=====================
Two-pass PII extraction + purpose extraction pipeline:

Pass 1a — Sentence-level regex (with collection context verbs)
Pass 1b — Bullet-list sub-pass (without collection verb requirement)
Pass 2  — spaCy dependency parsing + sentence-transformer classification
           → builds purpose_map {PIICategory → set[purpose_label]}
           → fires vagueness detection when margin < 0.08

Returns: (policy_claims, purpose_map, vagueness_warnings)
"""

import re
import socket
import requests
from urllib.parse import urlparse
from models.dataflow import DataFlowObject, PIICategory, Sensitivity

# ── Security: URL Validation ──────────────────────────────────────────────────

ALLOWED_SCHEMES = {"http", "https"}

BLOCKED_DOMAINS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "169.254.169.254",
    "metadata.google.internal",
}

BLOCKED_IP_PREFIXES = (
    "127.", "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "169.254.", "::1",
)


def validate_policy_url(url: str) -> None:
    """
    SSRF protection: blocks RFC 1918, loopback, link-local, cloud metadata.
    Raises ValueError with descriptive message on any failure.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        raise ValueError(f"Malformed URL — could not parse: {url}")

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(
            f"URL scheme '{parsed.scheme}' is not permitted. "
            "Only http and https are allowed."
        )
    if not parsed.netloc:
        raise ValueError("URL has no domain — invalid URL format.")

    domain = parsed.netloc.split(":")[0].lower()
    if domain in BLOCKED_DOMAINS:
        raise ValueError(
            f"Domain '{domain}' is not allowed. "
            "Localhost and internal service URLs are blocked."
        )
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        raise ValueError(
            f"Domain '{domain}' could not be resolved. "
            "Please check the URL is correct and publicly accessible."
        )
    if ip.startswith(BLOCKED_IP_PREFIXES):
        raise ValueError(
            f"URL resolves to a private or internal IP address ({ip}). "
            "Internal network URLs are blocked for security."
        )
    print(f"[security] URL validated: {url[:80]}")


# ── PII detection config ──────────────────────────────────────────────────────

COLLECTION_CONTEXT = [
    'collect', 'process', 'store', 'use', 'share',
    'disclose', 'transfer', 'receive', 'gather', 'obtain',
    'retain', 'record', 'access', 'handle',
]

POLICY_PII_MAP = {
    'name':       PIICategory.NAME,
    'email':      PIICategory.EMAIL,
    'phone':      PIICategory.PHONE,
    'mobile':     PIICategory.PHONE,
    'location':   PIICategory.LOCATION,
    'address':    PIICategory.LOCATION,
    'health':     PIICategory.HEALTH,
    'medical':    PIICategory.HEALTH,
    'aadhaar':    PIICategory.AADHAAR,
    'pan':        PIICategory.PAN,
    'financial':  PIICategory.FINANCIAL,
    'bank':       PIICategory.FINANCIAL,
    'birth':      PIICategory.DOB,
    'dob':        PIICategory.DOB,
    'biometric':  PIICategory.BIOMETRIC,
    'password':   PIICategory.FINANCIAL,
    'contact':    PIICategory.PHONE,
    'identity':   PIICategory.NAME,
    'personal':   PIICategory.NAME,
}

SENSITIVITY_MAP = {
    PIICategory.AADHAAR:   Sensitivity.SENSITIVE,
    PIICategory.PAN:       Sensitivity.SENSITIVE,
    PIICategory.HEALTH:    Sensitivity.SENSITIVE,
    PIICategory.FINANCIAL: Sensitivity.SENSITIVE,
    PIICategory.BIOMETRIC: Sensitivity.SENSITIVE,
    PIICategory.PHONE:     Sensitivity.PERSONAL,
    PIICategory.EMAIL:     Sensitivity.PERSONAL,
    PIICategory.LOCATION:  Sensitivity.PERSONAL,
    PIICategory.NAME:      Sensitivity.PERSONAL,
    PIICategory.DOB:       Sensitivity.PERSONAL,
}

# ── Purpose taxonomy ──────────────────────────────────────────────────────────
# Maps purpose category labels to keyword clusters used by both
# the spaCy pass and the sentence-transformer templates.

PURPOSE_CATEGORIES = {
    "service_delivery": [
        "provide", "deliver", "fulfil", "account", "authenticate",
        "login", "access", "service", "support", "transact",
    ],
    "analytics": [
        "analytic", "statistic", "improve", "personali", "recommend",
        "insight", "measure", "report", "monitor", "trend",
    ],
    "marketing": [
        "market", "advertis", "promot", "campaign", "commercial",
        "offer", "target", "interest-based",
    ],
    "security": [
        "secur", "fraud", "abuse", "prevent", "compliance",
        "legal", "regulat", "audit", "investig",
    ],
    "communication": [
        "notif", "alert", "email", "sms", "message",
        "inform", "remind", "contact",
    ],
    "research": [
        "research", "study", "develop", "innovat", "test",
        "experiment", "academic",
    ],
}

# Sentence-transformer reference sentences for cosine-similarity classification
PURPOSE_TEMPLATES = {
    "service_delivery": "We collect your information to provide and deliver our service and manage your account.",
    "analytics":        "We use your data for analytics, to measure performance, and to improve personalized recommendations.",
    "marketing":        "We use your information for marketing, advertising, and promotional purposes.",
    "security":         "We process your data to ensure security, prevent fraud, and comply with legal obligations.",
    "communication":    "We use your contact information to send notifications, alerts, and service messages.",
    "research":         "We use your data for research and development to improve our products.",
}

# Vagueness threshold: if top-2 cosine scores are within this margin,
# the purpose statement is considered ambiguous (DPDP Rules 2025, Rule 3(b)(ii))
VAGUENESS_MARGIN = 0.08

# ── Lazy-loaded NLP models ────────────────────────────────────────────────────

_nlp = None
_st_model = None
_template_embeddings = None


def _get_nlp():
    global _nlp
    if _nlp is None:
        try:
            import spacy
            _nlp = spacy.load("en_core_web_lg")
            print("[policy] spaCy en_core_web_lg loaded")
        except Exception as e:
            print(f"[policy] spaCy unavailable: {e}")
            _nlp = False  # sentinel — don't retry
    return _nlp if _nlp is not False else None


def _get_st_model():
    global _st_model, _template_embeddings
    if _st_model is None:
        try:
            from sentence_transformers import SentenceTransformer
            import numpy as np
            _st_model = SentenceTransformer("all-MiniLM-L6-v2")
            templates = list(PURPOSE_TEMPLATES.values())
            _template_embeddings = _st_model.encode(templates, normalize_embeddings=True)
            print("[policy] sentence-transformer all-MiniLM-L6-v2 loaded")
        except Exception as e:
            print(f"[policy] sentence-transformer unavailable: {e}")
            _st_model = False
    return (_st_model if _st_model is not False else None), _template_embeddings


# ── HTTP fetch ────────────────────────────────────────────────────────────────

def fetch_policy_text(url: str) -> tuple[str, str]:
    """
    Fetch and strip HTML.
    Returns: (clean_text_lower, raw_text_for_bullets)
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept':     'text/html,application/xhtml+xml,*/*;q=0.8',
    }
    resp = requests.get(url, headers=headers, timeout=15)
    html = resp.text

    # Preserve bullet structure by converting list tags to newlines first
    html_with_breaks = re.sub(r'<li[^>]*>', '\n• ', html, flags=re.IGNORECASE)
    html_with_breaks = re.sub(r'<br\s*/?>', '\n', html_with_breaks, flags=re.IGNORECASE)

    # Strip script / style
    clean = re.sub(r'<script[^>]*>.*?</script>', ' ', html_with_breaks, flags=re.DOTALL)
    clean = re.sub(r'<style[^>]*>.*?</style>',   ' ', clean, flags=re.DOTALL)
    # Strip remaining tags
    clean = re.sub(r'<[^>]+>', ' ', clean)
    # Collapse spaces (but preserve newlines for bullet detection)
    clean = re.sub(r'[ \t]+', ' ', clean)

    raw_with_newlines = clean  # keep newlines for bullet-list pass
    clean_lower = re.sub(r'\s+', ' ', clean).lower()
    return clean_lower, raw_with_newlines


# ── Purpose extraction helpers ────────────────────────────────────────────────

def _keyword_purpose(sentence: str) -> str | None:
    """Fast keyword-based purpose detection (fallback when models unavailable)."""
    s = sentence.lower()
    for purpose, keywords in PURPOSE_CATEGORIES.items():
        if any(kw in s for kw in keywords):
            return purpose
    return None


def _spacy_extract_purposes(sentences: list[str], nlp) -> dict[str, set[str]]:
    """
    4-pass spaCy dependency strategy to extract purpose → purpose_category mappings.
    Returns {sentence_text → set[purpose_label]}
    """
    purpose_for_sent: dict[str, set[str]] = {}

    for sent_text in sentences:
        if len(sent_text) < 15:
            continue
        purposes: set[str] = set()
        doc = nlp(sent_text)

        for token in doc:
            # Pass 1: purpose clause — "for the purpose of X" / "in order to X"
            if token.lower_ in ("purpose", "goal", "objective") and token.dep_ == "pobj":
                # Head verb context
                phrase = " ".join(t.lower_ for t in token.subtree)
                p = _keyword_purpose(phrase)
                if p:
                    purposes.add(p)

            # Pass 2: infinitive "to <verb>" purpose marker
            if token.dep_ == "advcl" and token.tag_ == "VB":
                phrase = " ".join(t.lower_ for t in token.subtree)
                p = _keyword_purpose(phrase)
                if p:
                    purposes.add(p)

            # Pass 3: prepositional "for <noun-phrase>"
            if token.lower_ == "for" and token.dep_ == "prep":
                phrase = " ".join(t.lower_ for t in token.subtree)
                p = _keyword_purpose(phrase)
                if p:
                    purposes.add(p)

            # Pass 4: subject-verb-object — verb is a data-use verb
            DATA_VERBS = {"collect", "use", "process", "store", "share", "transfer"}
            if token.lemma_.lower() in DATA_VERBS and token.pos_ == "VERB":
                for child in token.children:
                    if child.dep_ in ("advcl", "prep", "xcomp", "dobj"):
                        phrase = " ".join(t.lower_ for t in child.subtree)
                        p = _keyword_purpose(phrase)
                        if p:
                            purposes.add(p)

        if purposes:
            purpose_for_sent[sent_text] = purposes

    return purpose_for_sent


def _st_classify_purpose(
    sentence: str,
    st_model,
    template_embeddings,
) -> tuple[str, float, float]:
    """
    Classify a sentence using all-MiniLM-L6-v2 cosine similarity.
    Returns (best_label, best_score, second_score).
    """
    import numpy as np
    keys = list(PURPOSE_TEMPLATES.keys())
    emb = st_model.encode([sentence], normalize_embeddings=True)[0]
    scores = template_embeddings @ emb  # cosine since both normalized
    idx_sorted = scores.argsort()[::-1]
    best  = keys[idx_sorted[0]], float(scores[idx_sorted[0]])
    second = float(scores[idx_sorted[1]]) if len(idx_sorted) > 1 else 0.0
    return best[0], best[1], second


# ── Pass 1: sentence-level regex + bullet-list sub-pass ──────────────────────

def _pass1_extract_pii(
    full_text_lower: str,
    raw_with_newlines: str,
) -> tuple[list[DataFlowObject], set[PIICategory]]:
    """
    Pass 1a: sentence-level matching with collection context verbs.
    Pass 1b: bullet-list sub-pass — matches PII keywords in list items
             WITHOUT requiring a collection verb (fixes false-negative lists).
    Returns (findings, seen_categories).
    """
    findings: list[DataFlowObject] = []
    seen: set[PIICategory] = set()

    # ── Pass 1a: sentence-level ───────────────────────────────────────────
    sentences = re.split(r'[.!?;]', full_text_lower)
    for sentence in sentences:
        sentence = sentence.strip()
        if len(sentence) < 10:
            continue
        has_context = any(word in sentence for word in COLLECTION_CONTEXT)
        for keyword, category in POLICY_PII_MAP.items():
            if keyword in sentence and category not in seen:
                if has_context:
                    seen.add(category)
                    findings.append(DataFlowObject(
                        source="policy_parser",
                        file_path=None,
                        line_number=None,
                        raw_text=sentence[:300],
                        field_name=keyword,
                        pii_category=category,
                        sensitivity=SENSITIVITY_MAP.get(category, Sensitivity.UNKNOWN),
                        third_party_sdk=None,
                    ))

    # ── Pass 1b: bullet-list sub-pass ────────────────────────────────────
    # Many privacy policies list PII types in <li> elements without a verb.
    # We detect lines that start with bullet markers and look for PII keywords
    # without requiring a collection context verb.
    bullet_pattern = re.compile(
        r'^\s*(?:[•\-\*]|\d+[\.\)])\s+(.+)$',
        re.MULTILINE,
    )
    for match in bullet_pattern.finditer(raw_with_newlines):
        item = match.group(1).strip().lower()
        if len(item) < 3 or len(item) > 200:
            continue
        for keyword, category in POLICY_PII_MAP.items():
            if keyword in item and category not in seen:
                seen.add(category)
                findings.append(DataFlowObject(
                    source="policy_parser_bullets",
                    file_path=None,
                    line_number=None,
                    raw_text=item[:300],
                    field_name=keyword,
                    pii_category=category,
                    sensitivity=SENSITIVITY_MAP.get(category, Sensitivity.UNKNOWN),
                    third_party_sdk=None,
                ))

    return findings, seen


# ── Pass 2: purpose extraction ───────────────────────────────────────────────

def _pass2_extract_purposes(
    full_text_lower: str,
    policy_pii_categories: set[PIICategory],
) -> tuple[dict[PIICategory, set[str]], list[dict]]:
    """
    For each PII category found in Pass 1, identify what purpose(s) the policy
    states for processing that data.

    Strategy:
      1. Find sentences that mention the PII category keyword.
      2. Extract purposes from those sentences using:
         a. spaCy dependency parsing (4-pass)
         b. sentence-transformer cosine similarity (all-MiniLM-L6-v2)
         c. Keyword fallback when models unavailable
      3. Flag vagueness when top-2 ST scores are within VAGUENESS_MARGIN.

    Returns:
      purpose_map        : {PIICategory → set[purpose_label]}
      vagueness_warnings : [{"pii_category": ..., "margin": ..., "sentence": ...}]
    """
    purpose_map: dict[PIICategory, set[str]] = {}
    vagueness_warnings: list[dict] = []

    nlp = _get_nlp()
    st_model, template_embeddings = _get_st_model()

    # Split into sentences (preserve case for spaCy)
    raw_sentences = re.split(r'[.!?]', full_text_lower)
    raw_sentences = [s.strip() for s in raw_sentences if len(s.strip()) > 15]

    # Reverse-map: PII keyword → category (multiple keywords per category)
    pii_to_kw: dict[PIICategory, list[str]] = {}
    for kw, cat in POLICY_PII_MAP.items():
        pii_to_kw.setdefault(cat, []).append(kw)

    for cat in policy_pii_categories:
        keywords_for_cat = pii_to_kw.get(cat, [])
        cat_purposes: set[str] = set()

        # Collect sentences mentioning this PII category
        relevant = [
            s for s in raw_sentences
            if any(kw in s for kw in keywords_for_cat)
        ]
        if not relevant:
            continue

        for sent in relevant:
            # ── spaCy dependency pass ──────────────────────────────────────
            if nlp:
                spacy_results = _spacy_extract_purposes([sent], nlp)
                for purposes in spacy_results.values():
                    cat_purposes.update(purposes)

            # ── Sentence-transformer classification ───────────────────────
            if st_model is not None and template_embeddings is not None:
                best_label, best_score, second_score = _st_classify_purpose(
                    sent, st_model, template_embeddings
                )
                if best_score >= 0.30:  # min confidence threshold
                    cat_purposes.add(best_label)
                # Vagueness: margin between top-2 too small
                margin = best_score - second_score
                if margin < VAGUENESS_MARGIN and best_score >= 0.25:
                    vagueness_warnings.append({
                        "pii_category": cat.value,
                        "margin":       round(margin, 4),
                        "sentence":     sent[:200],
                        "top_label":    best_label,
                        "top_score":    round(best_score, 4),
                    })

            # ── Keyword fallback ───────────────────────────────────────────
            if not nlp and (st_model is None):
                p = _keyword_purpose(sent)
                if p:
                    cat_purposes.add(p)

        if cat_purposes:
            purpose_map[cat] = cat_purposes

    # Deduplicate vagueness warnings (keep worst margin per PII category)
    deduped: dict[str, dict] = {}
    for w in vagueness_warnings:
        k = w["pii_category"]
        if k not in deduped or w["margin"] < deduped[k]["margin"]:
            deduped[k] = w
    vagueness_warnings = list(deduped.values())

    print(f"[policy] purpose_map: { {k.value: v for k, v in purpose_map.items()} }")
    if vagueness_warnings:
        print(f"[policy] {len(vagueness_warnings)} vagueness warning(s) fired")

    return purpose_map, vagueness_warnings


# ── Main entry point ──────────────────────────────────────────────────────────

def parse_privacy_policy(
    policy_url: str,
) -> tuple[list[DataFlowObject], dict[PIICategory, set[str]], list[dict]]:
    """
    Fetch and analyse a privacy policy URL.

    Returns
    -------
    policy_claims      : list[DataFlowObject]  — PII types found in policy
    purpose_map        : dict[PIICategory, set[str]]  — what purposes are stated
    vagueness_warnings : list[dict]  — sentences with ambiguous purpose (margin < 0.08)
    """
    # Security: validate URL before any HTTP request
    validate_policy_url(policy_url)

    print(f"[policy] Fetching: {policy_url}")
    full_text_lower, raw_with_newlines = fetch_policy_text(policy_url)
    print(f"[policy] Got {len(full_text_lower)} characters")

    # ── Pass 1: PII extraction ────────────────────────────────────────────
    findings, seen_categories = _pass1_extract_pii(full_text_lower, raw_with_newlines)
    print(f"[policy] Pass 1 — {len(findings)} PII claim(s) from {len(seen_categories)} category/ies")

    # ── Pass 2: Purpose extraction ────────────────────────────────────────
    purpose_map, vagueness_warnings = _pass2_extract_purposes(
        full_text_lower, seen_categories
    )

    return findings, purpose_map, vagueness_warnings
