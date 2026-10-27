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

import ipaddress
import os
import re
import socket
import requests
from urllib.parse import urljoin, urlparse
from models.dataflow import DataFlowObject, PIICategory, Sensitivity
from scanners.sinks import sdks_named_in

# ── Security: URL Validation ──────────────────────────────────────────────────

ALLOWED_SCHEMES = {"http", "https"}

BLOCKED_DOMAINS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "169.254.169.254",
    "metadata.google.internal",
}

def _ip_is_blocked(ip: str) -> bool:
    """
    True for any address that is not a public, globally-routable unicast
    address: loopback, RFC 1918 private, link-local (incl. 169.254.169.254
    cloud metadata), carrier-grade NAT 100.64.0.0/10, unspecified, reserved,
    multicast — for IPv4 and IPv6 (IPv4-mapped IPv6 is unwrapped first).

    Replaces a hand-written IPv4 prefix list that missed IPv6, 100.64/10 and
    0.0.0.0/8.
    """
    try:
        addr = ipaddress.ip_address(ip.split('%')[0])   # drop IPv6 zone id
    except ValueError:
        return True
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return (not addr.is_global) or addr.is_multicast


def validate_policy_url(url: str) -> None:
    """
    SSRF protection: blocks loopback, private, link-local, CGNAT, cloud
    metadata and other non-public addresses, IPv4 and IPv6. Every address
    the host resolves to is checked, not just the first.
    Raises ValueError with descriptive message on any failure.

    fetch_policy_text() calls this again for every redirect hop. Residual
    risk: DNS could still change between this check and the connection
    (DNS rebinding); closing that fully needs connecting to the checked IP.
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

    domain = (parsed.hostname or "").lower()   # handles [IPv6] and user@host
    if not domain:
        raise ValueError("URL has no domain — invalid URL format.")
    if domain in BLOCKED_DOMAINS:
        raise ValueError(
            f"Domain '{domain}' is not allowed. "
            "Localhost and internal service URLs are blocked."
        )
    try:
        infos = socket.getaddrinfo(domain, None)
    except (socket.gaierror, UnicodeError):
        raise ValueError(
            f"Domain '{domain}' could not be resolved. "
            "Please check the URL is correct and publicly accessible."
        )
    for info in infos:
        ip = info[4][0]
        if _ip_is_blocked(ip):
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


# ── Sentence splitting (shared by Pass 1a, Pass 2 and Pass 3) ─────────────────
# A full stop / ! / ? only ends a sentence when followed by whitespace or the
# end of the text, so "segment.com", "v2.1" or "example.co.in" stay intact
# (the old re.split(r'[.!?;]') cut "segment.com" into "segment" + "com", so
# Pass 3 could never see a Segment.com disclosure). A semicolon always splits.
# All three passes use this one splitter so they see the same sentences
# (Pass 2 previously ignored ';' while Pass 1a and Pass 3 split on it).
_SENTENCE_END_RE = re.compile(r'[.!?](?=\s|$)|;')


def _split_sentences(text: str) -> list[str]:
    return [s.strip() for s in _SENTENCE_END_RE.split(text) if s.strip()]


# ── Structure-aware policy units (shared by Pass 1a, Pass 2 and Pass 3) ──────
# Policies are mostly lists: "We use your information to:" followed by
# bullets that carry no full stops. Splitting the whitespace-collapsed text
# on punctuation alone merged a whole section — heading, lead-in and every
# bullet — into one "sentence", so e.g. "Twilio … (phone number only)" and
# "Delivery partners … (name and address only)" became one sentence and
# Twilio counted as a recipient of the name too, and the purpose classifier
# saw several purposes at once (spurious vagueness warnings).
# Units are built line by line instead:
#   - a heading (markdown "#", or an HTML block, see fetch_policy_text)
#     or a blank line ends a paragraph;
#   - each bullet is its own unit, prefixed with the paragraph line that
#     introduced the list when that line ends with ":" ("We use your
#     information to: Process your orders");
#   - paragraph text is split into sentences as before.
_HEADING_LINE_RE = re.compile(r'^#{1,6}\s')
_BULLET_LINE_RE = re.compile(r'^(?:[•\-\*▪◦●→]|\d+[\.\)]|[a-z]\))\s+(.+)$')


def _policy_units(text: str) -> list[str]:
    units: list[str] = []
    lead_in: str | None = None
    para: list[str] = []

    def flush() -> None:
        nonlocal lead_in
        if not para:
            return
        sentences = _split_sentences(re.sub(r'\s+', ' ', ' '.join(para)).strip())
        para.clear()
        units.extend(sentences)
        lead_in = sentences[-1] if sentences and sentences[-1].endswith(':') else None

    for line in text.splitlines():
        s = line.strip()
        if not s:
            flush()
            continue
        if _HEADING_LINE_RE.match(s):
            flush()
            lead_in = None
            continue
        m = _BULLET_LINE_RE.match(s)
        if m:
            flush()
            item = re.sub(r'\s+', ' ', m.group(1)).strip()
            units.extend(_split_sentences(f"{lead_in} {item}" if lead_in else item))
            continue
        para.append(s)
    flush()
    return units


def _verb_forms(verb: str) -> list[str]:
    """collect → collect, collects, collected, collecting; use → use, uses, used, using."""
    forms = {verb, verb + 's'}
    if verb.endswith('e'):
        forms |= {verb + 'd', verb[:-1] + 'ing'}
    else:
        forms |= {verb + 'ed', verb + 'ing', verb + 'es'}
    if verb == 'transfer':
        forms |= {'transferred', 'transferring'}
    return sorted(forms, key=len, reverse=True)


# Whole-word match on the verb forms. The old substring test treated "use"
# inside "because" / "user" / "house" as a collection verb.
_CONTEXT_RE = re.compile(
    r'\b(?:' + '|'.join(f for v in COLLECTION_CONTEXT for f in _verb_forms(v)) + r')\b'
)

# ── Sentence-level PII map (requires collection-context verb in same sentence) ──
# Matched with word boundaries, longest phrase first, so:
#   - "pan" no longer fires inside "expand" / "company" / "japan";
#   - "address" inside "email address" is consumed by EMAIL, not LOCATION;
#   - vague words that do not name a PII category ("personal", "identity",
#     "password", bare "contact") are no longer mapped to one.
POLICY_PII_MAP = {
    # Aadhaar
    'aadhaar number': PIICategory.AADHAAR, 'aadhar number': PIICategory.AADHAAR,
    'aadhaar':        PIICategory.AADHAAR, 'aadhar':        PIICategory.AADHAAR,
    # PAN
    'permanent account number': PIICategory.PAN,
    'pan card': PIICategory.PAN, 'pan number': PIICategory.PAN, 'pan': PIICategory.PAN,
    # Phone
    'phone number': PIICategory.PHONE, 'mobile number': PIICategory.PHONE,
    'telephone number': PIICategory.PHONE, 'contact number': PIICategory.PHONE,
    'phone': PIICategory.PHONE, 'mobile': PIICategory.PHONE, 'telephone': PIICategory.PHONE,
    'whatsapp number': PIICategory.PHONE,
    # Email
    'email address': PIICategory.EMAIL, 'e-mail address': PIICategory.EMAIL,
    'email id': PIICategory.EMAIL, 'email': PIICategory.EMAIL, 'e-mail': PIICategory.EMAIL,
    # Location
    'postal address': PIICategory.LOCATION,
    'home address': PIICategory.LOCATION, 'residential address': PIICategory.LOCATION,
    'billing address': PIICategory.LOCATION, 'shipping address': PIICategory.LOCATION,
    'mailing address': PIICategory.LOCATION, 'geolocation': PIICategory.LOCATION,
    'location': PIICategory.LOCATION, 'address': PIICategory.LOCATION, 'gps': PIICategory.LOCATION,
    'pin code': PIICategory.LOCATION, 'pincode': PIICategory.LOCATION, 'postal code': PIICategory.LOCATION,
    'zip code': PIICategory.LOCATION,
    # Health
    'health information': PIICategory.HEALTH, 'health data': PIICategory.HEALTH,
    'health records': PIICategory.HEALTH, 'medical records': PIICategory.HEALTH,
    'medical information': PIICategory.HEALTH, 'medical history': PIICategory.HEALTH,
    'blood group': PIICategory.HEALTH, 'diagnosis': PIICategory.HEALTH,
    'prescription': PIICategory.HEALTH, 'health': PIICategory.HEALTH, 'medical': PIICategory.HEALTH,
    # Financial
    'financial information': PIICategory.FINANCIAL, 'payment information': PIICategory.FINANCIAL,
    'bank account': PIICategory.FINANCIAL, 'bank details': PIICategory.FINANCIAL,
    'credit card': PIICategory.FINANCIAL, 'debit card': PIICategory.FINANCIAL,
    'account number': PIICategory.FINANCIAL, 'upi id': PIICategory.FINANCIAL,
    'upi': PIICategory.FINANCIAL, 'payment card': PIICategory.FINANCIAL,
    'financial': PIICategory.FINANCIAL,
    # Name
    'full name': PIICategory.NAME, 'first name': PIICategory.NAME, 'last name': PIICategory.NAME,
    'legal name': PIICategory.NAME, 'your name': PIICategory.NAME, 'name': PIICategory.NAME,
    # Date of birth
    'date of birth': PIICategory.DOB, 'birth date': PIICategory.DOB,
    'birthdate': PIICategory.DOB, 'dob': PIICategory.DOB,
    # Biometric
    'facial recognition': PIICategory.BIOMETRIC, 'face recognition': PIICategory.BIOMETRIC,
    'fingerprint': PIICategory.BIOMETRIC, 'iris scan': PIICategory.BIOMETRIC,
    'biometric': PIICategory.BIOMETRIC,
}
_POLICY_PHRASES = sorted(POLICY_PII_MAP.items(), key=lambda kv: len(kv[0]), reverse=True)
_POLICY_PHRASE_RX = [
    (re.compile(r'(?<![a-z0-9])' + re.escape(p) + r'(?![a-z0-9])'), p, c)
    for p, c in _POLICY_PHRASES
]

# ── Bullet-specific PII map: precise multi-word phrases, longest-first ────────
# Used by Pass 1b WITHOUT a collection-verb gate.  Longer phrases must appear
# before any prefix of themselves so the longest match wins first.
# Ambiguous single words ('name', 'pan', 'personal', etc.) are intentionally
# absent — they need verb context and live in POLICY_PII_MAP instead.
BULLET_PII_MAP: list[tuple[str, "PIICategory"]] = [
    # Aadhaar
    ("aadhaar number",          PIICategory.AADHAAR),
    ("aadhaar card",            PIICategory.AADHAAR),
    ("aadhar number",           PIICategory.AADHAAR),
    ("aadhar card",             PIICategory.AADHAAR),
    ("aadhaar",                 PIICategory.AADHAAR),
    ("aadhar",                  PIICategory.AADHAAR),
    # PAN — require phrase to avoid matching "japan", "pandora", etc.
    ("permanent account number",PIICategory.PAN),
    ("pan card",                PIICategory.PAN),
    ("pan number",              PIICategory.PAN),
    # Phone — specific phrases + standalone safe words
    ("contact number",          PIICategory.PHONE),
    ("phone number",            PIICategory.PHONE),
    ("mobile number",           PIICategory.PHONE),
    ("telephone number",        PIICategory.PHONE),
    ("phone",                   PIICategory.PHONE),
    ("mobile",                  PIICategory.PHONE),
    # Email
    ("email address",           PIICategory.EMAIL),
    ("email id",                PIICategory.EMAIL),
    ("email",                   PIICategory.EMAIL),
    # Location — specific address types before bare "address"
    ("home address",            PIICategory.LOCATION),
    ("mailing address",         PIICategory.LOCATION),
    ("residential address",     PIICategory.LOCATION),
    ("postal address",          PIICategory.LOCATION),
    ("billing address",         PIICategory.LOCATION),
    ("shipping address",        PIICategory.LOCATION),
    ("gps location",            PIICategory.LOCATION),
    ("geo location",            PIICategory.LOCATION),
    ("geolocation",             PIICategory.LOCATION),
    ("location",                PIICategory.LOCATION),
    ("pin code",                PIICategory.LOCATION),
    ("pincode",                 PIICategory.LOCATION),
    ("postal code",             PIICategory.LOCATION),
    ("zip code",                PIICategory.LOCATION),
    ("address",                 PIICategory.LOCATION),
    # Health
    ("health information",      PIICategory.HEALTH),
    ("medical information",     PIICategory.HEALTH),
    ("medical records",         PIICategory.HEALTH),
    ("medical record",          PIICategory.HEALTH),
    ("health records",          PIICategory.HEALTH),
    ("blood group",             PIICategory.HEALTH),
    ("blood type",              PIICategory.HEALTH),
    ("diagnosis",               PIICategory.HEALTH),
    ("prescription",            PIICategory.HEALTH),
    ("health",                  PIICategory.HEALTH),
    ("medical",                 PIICategory.HEALTH),
    # Financial
    ("financial information",   PIICategory.FINANCIAL),
    ("payment information",     PIICategory.FINANCIAL),
    ("credit card",             PIICategory.FINANCIAL),
    ("debit card",              PIICategory.FINANCIAL),
    ("bank account",            PIICategory.FINANCIAL),
    ("account number",          PIICategory.FINANCIAL),
    ("payment card",            PIICategory.FINANCIAL),
    ("upi id",                  PIICategory.FINANCIAL),
    ("financial",               PIICategory.FINANCIAL),
    # Name — require qualifier in bullet context; bare "name" excluded
    ("full name",               PIICategory.NAME),
    ("first name",              PIICategory.NAME),
    ("last name",               PIICategory.NAME),
    ("legal name",              PIICategory.NAME),
    ("your name",               PIICategory.NAME),
    # DOB — specific phrases
    ("date of birth",           PIICategory.DOB),
    ("birth date",              PIICategory.DOB),
    ("birthdate",               PIICategory.DOB),
    ("date of birth",           PIICategory.DOB),
    ("dob",                     PIICategory.DOB),
    # Biometric
    ("facial recognition",      PIICategory.BIOMETRIC),
    ("face recognition",        PIICategory.BIOMETRIC),
    ("fingerprint",             PIICategory.BIOMETRIC),
    ("iris scan",               PIICategory.BIOMETRIC),
    ("biometric",               PIICategory.BIOMETRIC),
]

# ── Bullet exclusion: phrases that superficially contain a PII keyword ─────────
# but are definitively NOT about PII collection (e.g. navigation links,
# section headings, company references).  Each is a compiled word-boundary regex.
_BULLET_EXCLUSIONS = [re.compile(p, re.IGNORECASE) for p in [
    r'\bcontact\s+us\b',
    r'\bcontact\s+page\b',
    r'\bcontact\s+form\b',
    r'\bcontact\s+details?\s+of\s+(?:our|the|company|officer|grievance)\b',
    r'\bcompany\s+name\b',
    r'\bbrand\s+name\b',
    r'\bproduct\s+name\b',
    r'\bfile\s+name\b',
    r'\bdomain\s+name\b',
    r'\bapp\s+name\b',
    r'\bbank\s+holiday\b',
    r'\baddress\s+bar\b',
    r'\bpan\s+(?:india|asian|pacific|american|european)\b',
    r'\bmedical\s+(?:disclaimer|advice|professional)\b',
    r'\bhealth\s+(?:tips?|advice|disclaimer|insurance\s+claim)\b',
    r'\bfinancial\s+(?:advice|disclaimer|year|planning\s+tips?)\b',
    # Device and network addresses are not a person's location. The code
    # scanner already excludes ip_address / mac_address / server_address; a
    # policy that discloses IP addresses must not count as disclosing
    # location either, or a real location notice gap is hidden.
    r'\b(?:ip|mac|web|website|url|internet|server|network|device|wallet)\s+address(?:es)?\b',
    # "address" as a verb: "to address your queries", "we will address the issue"
    r'(?<!email )(?<!e-mail )(?<!postal )(?<!home )\baddress(?:es|ed|ing)?\s+(?:your|any|the|such|our|these|this|that|their|its|all|them|it|complaints?|grievances?|queries|concerns|issues|requests?)\b',
    # where servers or data are kept is not the user's location
    r'\b(?:server|servers|storage|hosting|data\s+storage|data\s+cent(?:er|re))\s+locations?\b',
    r'\blocations?\s+of\s+(?:our|the|its)\s+(?:servers?|data\s+cent(?:er|re)s?|offices?|facilities|data)\b',
    # institutions and regulators are not financial data
    r'\bfinancial\s+(?:institutions?|regulators?|services?\s+providers?|partners?|intermediar(?:y|ies)|instruments?|statements?\s+of\s+(?:the|our)\s+company)\b',
    # the device or app, not a phone number
    r'\bmobile\s+(?:app|apps|application|applications|device|devices|version|site|website|browser|platform|operating\s+system|network|operator|carrier)\b',
]]

# Extra exclusions for full sentences (applied together with the bullet ones).
_SENTENCE_EXCLUSIONS = _BULLET_EXCLUSIONS + [re.compile(p, re.IGNORECASE) for p in [
    r'\bmobile\s+(?:app|apps|application|applications|device|devices|version|site|website|browser|platform|operating\s+system)\b',
    r'\bname\s+of\s+(?:the|our|this)\s+(?:company|website|site|app|application|service|product|platform)\b',
    r'\bhealth\s+of\s+(?:the|our)\s+(?:service|services|platform|systems?|website|app)\b',
]]


def _find_policy_pii(text_lower: str, exclusions=None) -> list[tuple[PIICategory, str]]:
    """
    PII categories named in a sentence: whole-word phrases, longest first,
    each character used by at most one phrase, excluded phrases blanked out.
    Returns [(category, phrase), ...] in first-seen order, one per category.
    """
    exclusions = _SENTENCE_EXCLUSIONS if exclusions is None else exclusions
    for exc in exclusions:
        text_lower = exc.sub(lambda m: ' ' * len(m.group(0)), text_lower)
    taken: list[tuple[int, int]] = []
    found: dict[PIICategory, tuple[int, str]] = {}
    for rx, phrase, cat in _POLICY_PHRASE_RX:
        for m in rx.finditer(text_lower):
            if any(m.start() < e and s < m.end() for s, e in taken):
                continue
            taken.append((m.start(), m.end()))
            if cat not in found or m.start() < found[cat][0]:
                found[cat] = (m.start(), phrase)
    return [(c, p) for c, (pos, p) in sorted(found.items(), key=lambda kv: kv[1][0])]

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

# A narrow embedding margin alone is a weak signal: short, specific bullets
# ("Process and fulfil your orders") score low and close against all six
# reference purposes and were flagged as vague. A Rule 3(b)(ii) warning now
# also requires that the unit
#   - actually states a purpose (a "to …" / "for …" purpose marker) — a bare
#     "We collect your email address." states none, which is a Rule 3 gap,
#     not a vague purpose; and
#   - is ambiguous in its own words: it names TWO OR MORE purpose
#     categories ("to provide and improve our services"), or uses stock vague
#     wording ("for business purposes", "other purposes", "legitimate
#     interests", "improve our services"). A unit naming no purpose keyword
#     is NOT treated as vague — the keyword list is small, and specific
#     purposes it does not know ("Verify your identity", "Issue completion
#     certificates") must not be penalised.
_PURPOSE_MARKER_RE = re.compile(r"\b(?:to|for|so that|in order to)\b", re.I)
_VAGUE_PHRASE_RE = re.compile(
    r"\b(?:business purposes?|other purposes|various purposes|any purpose|such purposes"
    r"|(?:improve|enhance)\s+(?:our\s+|the\s+)?(?:services?|platform|products?|experience)"
    r"|legitimate (?:business )?interests?|as (?:necessary|appropriate)"
    r"|including but not limited to)\b",
    re.I,
)


# Clauses that are not purpose statements at all: acceptance of terms,
# consent boilerplate, statements about the policy itself. They often score
# ambiguously against every purpose (they name none), which made the
# classifier flag e.g. "By accessing the Website ... you are accepting the
# terms of our Privacy Policy ... and consent to the collection and use of
# the information ..." as a vague purpose.
_NOT_PURPOSE_STATEMENT_RE = re.compile(
    r"\b(?:accept(?:s|ing|ed)?|agree(?:s|ing|d)?\s+to)\s+(?:the\s+|these\s+|our\s+)?terms"
    r"|\bby\s+(?:accessing|using|visiting|browsing|registering|continuing)\b"
    r"|\blegally\s+(?:competent|binding)\b"
    r"|\b(?:this|our|the)\s+privacy\s+(?:policy|notice)\s+(?:applies|describes|explains|sets\s+out|governs|may\s+be\s+(?:updated|changed|amended))"
    r"|\bwe\s+(?:may|reserve\s+the\s+right\s+to)\s+(?:update|change|amend|modify)\s+(?:this|our)\b",
    re.I,
)
# Purpose statements describe a use: "we use / process / share / collect …
# to …", or a bullet under such a lead-in.
_USE_STATEMENT_RE = re.compile(
    r"\b(?:use|uses|used|using|process|processes|processed|processing|share|shares|shared"
    r"|sharing|disclose|discloses|disclosed|collect|collects|collected|collecting|retain|store"
    r"|stores|stored)\b", re.I)
VAGUE_MAX_WORDS = 40


def is_stock_vague(sentence: str) -> bool:
    """A purpose statement that uses stock vague wording ("improve our
    services", "business purposes", "legitimate interests" …). Such wording
    states no specified purpose, so it is vague whatever the classifier says,
    and it does not count as stating any purpose (see Pass 2)."""
    if sentence.rstrip().endswith(':') or _NOT_PURPOSE_STATEMENT_RE.search(sentence):
        return False
    return bool(_PURPOSE_MARKER_RE.search(sentence) and _VAGUE_PHRASE_RE.search(sentence))


# ── Purpose specificity (Rule 3(b)(ii)) ───────────────────────────────────────
# Rule 3(b)(ii) asks the notice to give "the specified purpose" of processing.
# A purpose is vague when its wording names nothing more specific than the
# fact that data is used for the service or the business: "to provide and
# improve our services", "for business purposes". Whether wording is generic
# is judged from the words themselves, not from how unsure the purpose
# classifier is: two close embedding scores mean the CLASSIFIER cannot choose
# between purposes, not that the sentence is vague ("to administer the
# platform and provide security" is clear to a reader yet sits between the
# security and service-delivery templates).
#
# The generic vocabulary below follows the vague terms reported by Lebanoff &
# Liu, "Automatic Detection of Vague Words and Sentences in Privacy Policies"
# (EMNLP 2018) — "information", "other", "some", "certain", "various",
# "services", "purposes" … — extended with the generic verbs of purpose
# statements ("provide", "improve", "operate", "administer").
_GENERIC_PURPOSE_WORDS = {
    # nouns
    "service", "product", "platform", "experience", "business", "purpose",
    "interest", "operation", "functionality", "feature", "website", "site",
    "app", "application", "offering", "quality", "need", "requirement",
    "activity", "information", "data", "detail", "way", "level", "user",
    "customer", "matter", "thing", "content", "solution", "system", "people",
    "other", "others", "part", "kind", "type", "manner", "extent", "use",
    "related", "connection", "relation", "course", "time", "case", "basis",
    # adjectives / adverbs
    "various", "certain", "some", "such", "general", "overall", "internal",
    "best", "better", "high", "highest", "possible", "new", "more", "relevant",
    "appropriate", "necessary", "legitimate", "efficient", "effective",
    "improved", "enhanced", "existing", "own", "same", "similar", "additional",
    "further", "continued", "ongoing", "smooth", "seamless", "overall", "also",
    # verbs
    "provide", "improve", "enhance", "operate", "run", "manage", "administer",
    "offer", "deliver", "maintain", "support", "help", "enable", "ensure",
    "make", "perform", "carry", "conduct", "facilitate", "develop", "serve",
    "give", "allow", "do", "include", "relate", "require", "optimise",
    "optimize", "upgrade", "evaluate", "review", "process", "handle",
}
_PURPOSE_STOPWORDS = {
    "a", "an", "the", "and", "or", "of", "to", "for", "in", "on", "at", "by",
    "with", "from", "as", "about", "into", "over", "under", "our", "your",
    "their", "its", "his", "her", "we", "us", "you", "they", "it", "this",
    "that", "these", "those", "which", "who", "whom", "what", "be", "is",
    "are", "was", "were", "been", "being", "can", "could", "may", "might",
    "will", "would", "shall", "should", "must", "so", "than", "then", "if",
    "any", "all", "each", "every", "both", "either", "not", "no", "etc",
    "including", "e.g", "eg", "i.e", "ie", "order", "in", "us", "me", "my",
    "time", "from", "upon", "via", "per", "where", "when", "how", "why",
}
# A purpose clause that only points elsewhere ("solely for this purpose",
# "for the purposes described above") states no purpose of its own.
_ANAPHORIC_PURPOSE_RE = re.compile(
    r"^\s*(?:the\s+|these\s+|this\s+|that\s+|such\s+|those\s+|the\s+same\s+|the\s+above\s+)"
    r"(?:purposes?|reasons?)\b(?!\s+(?:of|to)\b)", re.I)
_ANAPHORIC_TAIL_RE = re.compile(
    r"\b(?:purposes?|reasons?)\s+(?:described|set\s+out|listed|mentioned|stated|specified|outlined)\b", re.I)
# Purpose verbs that name a kind of use but no object: listed together over
# a generic object they leave the purpose unspecified.
_SOFT_PURPOSE_STEMS = (
    "personali", "customi", "tailor", "market", "advertis", "promot", "analy",
    "statistic", "insight", "recommend", "measure", "monitor", "improv",
    "enhanc", "optimi", "develop", "innovat", "research",
)
_PURPOSE_WORD_RE = re.compile(r"[a-z][a-z'\-]*", re.I)


def _word_root(w: str) -> str:
    """Crude, deterministic lemmatisation: services → service, improving →
    improve, provided → provide, personalised → personalise."""
    w = w.lower().strip("'-")
    if w in _GENERIC_PURPOSE_WORDS:
        return w
    for suf, rep in (("ies", "y"), ("ing", ""), ("ed", ""), ("es", ""), ("s", "")):
        if w.endswith(suf) and len(w) - len(suf) >= 3:
            root = w[: -len(suf)] + rep
            for cand in (root, root + "e"):
                if cand in _GENERIC_PURPOSE_WORDS:
                    return cand
            if suf in ("s", "es", "ies"):
                return root
            return root + ("e" if (root + "e") in _GENERIC_PURPOSE_WORDS else "")
    return w


def _purpose_part(sentence: str) -> str | None:
    """The text after the first purpose marker ("to", "for", "so that",
    "in order to"), with the personal-data phrases blanked out (they name
    the DATA, not the purpose). None when the unit states no purpose."""
    m = _PURPOSE_MARKER_RE.search(sentence)
    if not m:
        return None
    part = sentence[m.end():]
    low = part.lower()
    for rx, _, _ in _POLICY_PHRASE_RX:
        low = rx.sub(lambda x: " " * len(x.group(0)), low)
    # keep capitalisation information for proper-noun detection
    return "".join(c if low[i] != " " or c == " " else " " for i, c in enumerate(part))


def _content_words(part: str) -> list[tuple[str, bool]]:
    """(root, is_name) for the purpose part's content words. A capitalised
    word that does not start the clause is treated as a name (the company,
    product or app) — a name is not a purpose."""
    out = []
    for i, m in enumerate(_PURPOSE_WORD_RE.finditer(part)):
        w = m.group(0)
        if w.lower() in _PURPOSE_STOPWORDS or len(w) < 2:
            continue
        is_name = w[0].isupper() and i > 0 and not w.isupper()
        out.append((_word_root(w), is_name))
    return out


def vagueness_scope() -> str:
    """'statement' (default): every generic purpose statement is reported.
    'notice': a category is vague only when no statement in the policy gives
    it a specific purpose. Set PRIVACYPILOT_VAGUENESS_SCOPE=notice to use the
    stricter reading; no setting is needed for the default."""
    v = os.getenv("PRIVACYPILOT_VAGUENESS_SCOPE", "statement").strip().lower()
    return v if v in ("notice", "statement") else "statement"


def purpose_statement_kind(sentence: str) -> str:
    """
    Classify one policy unit for Rule 3(b)(ii):
      "none"     — not a purpose statement (no purpose marker or use verb, a
                   list lead-in, terms-acceptance or policy boilerplate, or a
                   clause that only refers to purposes stated elsewhere);
      "stock"    — stock vague wording ("business purposes", "improve our
                   services", "legitimate interests");
      "vague"    — its purpose wording is generic: every content word is
                   generic, or it lists two or more purposes over nothing
                   but generic words ("to provide, personalise and market
                   our services");
      "specific" — it names something specific ("to verify your identity",
                   "to send you payment receipts", "for a loan").
    """
    s = sentence.strip()
    if not s or s.endswith(':') or _NOT_PURPOSE_STATEMENT_RE.search(s):
        return "none"
    if not _PURPOSE_MARKER_RE.search(s):
        return "none"
    if _VAGUE_PHRASE_RE.search(s) and _USE_STATEMENT_RE.search(s):
        return "stock"
    if not _USE_STATEMENT_RE.search(s):
        return "none"
    part = _purpose_part(s)
    if part is None:
        return "none"
    if _ANAPHORIC_PURPOSE_RE.search(part) or _ANAPHORIC_TAIL_RE.search(part):
        return "none"
    words = _content_words(part)
    if not words:
        return "none"
    generic = [w for w, is_name in words if is_name or w in _GENERIC_PURPOSE_WORDS]
    if len(generic) == len(words):
        return "vague"
    # Several purposes coordinated over generic words only ("to provide,
    # personalise and market our services"): every non-generic word is a
    # soft purpose verb with no object of its own. A concrete object
    # ("your account", "security", "OTPs") makes the purpose specific.
    if re.search(r"\b(?:and|or)\b|,|/", part) and len(_keyword_purposes(part)) >= 2:
        rest = [w for w, is_name in words if not (is_name or w in _GENERIC_PURPOSE_WORDS)]
        if rest and all(w.startswith(_SOFT_PURPOSE_STEMS) for w in rest):
            return "vague"
    return "specific"


def _is_vague_wording(sentence: str) -> bool:
    """Whether a unit is a vague purpose statement (stock or generic wording)."""
    return purpose_statement_kind(sentence) in ("stock", "vague")


# ── Lazy-loaded NLP models ────────────────────────────────────────────────────

_nlp = None
_st_model = None
_template_embeddings = None


def _shared_presidio_nlp():
    """Presidio's spaCy Language object, or None if Presidio is unavailable."""
    try:
        from scanners.presidio_scanner import get_analyzer
        analyzer = get_analyzer()
        return analyzer.nlp_engine.nlp["en"] if analyzer else None
    except Exception:
        return None


def _get_nlp():
    global _nlp
    if _nlp is None:
        try:
            # Reuse the en_core_web_lg pipeline Presidio has already loaded
            # (the code scanner loads it in every worker): a second
            # spacy.load() of the same 600 MB model doubled each worker
            # process's memory and start-up time for no benefit.
            _nlp = _shared_presidio_nlp()
            if _nlp is None:
                import spacy
                _nlp = spacy.load("en_core_web_lg")
            print("[policy] spaCy en_core_web_lg ready")
        except Exception as e:
            print(
                f"[policy] WARNING: spaCy en_core_web_lg unavailable ({e}) — "
                "dependency-parse purpose extraction is OFF. "
                "Run `pip install -r requirements.txt`."
            )
            _nlp = False  # sentinel — don't retry
    return _nlp if _nlp is not False else None


def _get_st_model():
    global _st_model, _template_embeddings
    if _st_model is None:
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore[import-untyped]
            import numpy as np
            _st_model = SentenceTransformer("all-MiniLM-L6-v2")
            templates = list(PURPOSE_TEMPLATES.values())
            _template_embeddings = _st_model.encode(templates, normalize_embeddings=True,
                                                    show_progress_bar=False)
            print("[policy] sentence-transformer all-MiniLM-L6-v2 loaded")
        except Exception as e:
            print(
                f"[policy] WARNING: sentence-transformers unavailable ({e}) — "
                "semantic purpose classification and the Rule 3(b)(ii) "
                "vagueness check are OFF. Run `pip install -r requirements.txt`."
            )
            _st_model = False
    return (_st_model if _st_model is not False else None), _template_embeddings


# ── HTTP fetch ────────────────────────────────────────────────────────────────

# GitHub domains it is safe to attach a user-supplied PAT to. The token is
# NEVER sent anywhere else — a privacy policy hosted on an unrelated
# third-party domain never sees it.
_GITHUB_AUTH_DOMAINS = {
    "github.com", "raw.githubusercontent.com",
    "gist.github.com", "gist.githubusercontent.com",
}

# github.com/{owner}/{repo}/blob/{branch}/{path} is the human-facing web UI
# page. It authenticates browsers via session cookies only — it does NOT
# honor an "Authorization: Bearer <token>" header on a plain HTTP request,
# so attaching a perfectly valid PAT to that URL has no effect and a
# private repo still 404s exactly as if no token were sent at all. The
# GitHub REST "contents" API (api.github.com) is the documented endpoint
# that does accept a PAT via the Authorization header for private repos
# (https://docs.github.com/en/rest/repos/contents). When the policy URL is
# a recognizable blob-page URL, rewrite it to that API endpoint before
# fetching — this also returns the raw file text directly, instead of the
# full rendered GitHub web page (nav bar, file-tree sidebar, commit info)
# that the old code had to strip HTML tags out of.
_GITHUB_BLOB_RE = re.compile(
    r'^https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/blob/'
    r'(?P<branch>[^/]+)/(?P<path>.+)$'
)


def _rewrite_github_blob_url(url: str) -> str | None:
    """Convert a github.com blob-page URL to the api.github.com contents
    endpoint. Returns None if `url` doesn't match that pattern (already a
    raw/API URL, or a non-GitHub host) — caller then fetches `url` as-is."""
    m = _GITHUB_BLOB_RE.match(url)
    if not m:
        return None
    from urllib.parse import quote, unquote
    owner, repo, branch, path = m.group("owner", "repo", "branch", "path")
    # Normalize first (unquote then re-quote) so a path/branch that arrived
    # already percent-encoded (e.g. a space as %20, copied straight from the
    # browser's address bar) isn't double-encoded into %2520.
    path = quote(unquote(path), safe="/")
    branch = quote(unquote(branch))
    return f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}"


# Hosts a GitHub token may be sent to (the blob-URL rewrite targets the API).
_TOKEN_HOSTS = _GITHUB_AUTH_DOMAINS | {"api.github.com"}
_REDIRECT_CODES = {301, 302, 303, 307, 308}
_MAX_REDIRECTS = 5


def _get_with_safe_redirects(url: str, headers: dict):
    """
    GET with redirects followed MANUALLY: every hop's target is passed back
    through validate_policy_url(), and the GitHub token is dropped as soon
    as a hop leaves GitHub. requests' automatic redirect-following (the old
    behaviour) fetched whatever a public URL redirected to — including
    http://169.254.169.254/ or localhost — after only the first URL had
    been validated.
    """
    headers = dict(headers)
    for _ in range(_MAX_REDIRECTS + 1):
        resp = requests.get(url, headers=headers, timeout=15, allow_redirects=False)
        location = resp.headers.get("Location") if resp.status_code in _REDIRECT_CODES else None
        if not location:
            return resp
        url = urljoin(url, location)
        validate_policy_url(url)
        if urlparse(url).hostname not in _TOKEN_HOSTS:
            headers.pop("Authorization", None)
    raise ValueError(f"Could not fetch privacy policy — more than {_MAX_REDIRECTS} redirects.")


def fetch_policy_text(url: str, github_token: str | None = None) -> tuple[str, str]:
    """
    Fetch and strip HTML.
    Returns: (clean_text_lower, raw_text_for_bullets)

    If the policy lives in a private GitHub repo (the same repo being
    scanned, for example), an unauthenticated fetch gets a 404 — GitHub
    hides private repos from anonymous requests rather than returning 403.
    When github_token is supplied and the URL's host is a GitHub domain,
    it is attached as a Bearer token so private-repo policy files resolve
    the same way the already-authenticated code scan does.
    """
    from urllib.parse import urlparse

    _api_url = _rewrite_github_blob_url(url)
    fetch_url = _api_url or url

    if _api_url:
        # api.github.com contents endpoint: ask for the raw file bytes
        # directly rather than the default JSON-wrapped+base64 response.
        headers = {
            'User-Agent':           'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept':                'application/vnd.github.raw+json',
            'X-GitHub-Api-Version':  '2022-11-28',
        }
    else:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept':     'text/html,application/xhtml+xml,*/*;q=0.8',
        }
    if github_token and (_api_url or urlparse(url).hostname in _GITHUB_AUTH_DOMAINS):
        headers['Authorization'] = f'Bearer {github_token}'

    resp = _get_with_safe_redirects(fetch_url, headers)

    # The fetch itself succeeding (no exception) does NOT mean the URL
    # pointed at an actual privacy policy. A 404/redirect-to-error page
    # still returns HTML with a 200... or more commonly a non-2xx status
    # that this code previously ignored entirely — silently parsing the
    # site's nav bar / footer / "Page not found" body as if it were policy
    # text. Fail loudly instead, so a wrong policy_url surfaces as a failed
    # scan rather than as bogus PII/purpose/vagueness violations extracted
    # from navigation links.
    if resp.status_code != 200:
        _auth_hint = ""
        if resp.status_code == 404 and urlparse(url).hostname in _GITHUB_AUTH_DOMAINS:
            if not github_token:
                _auth_hint = (
                    " If this is a private repository, provide a GitHub "
                    "token with access to it."
                )
            else:
                _auth_hint = (
                    " A GitHub token was supplied but this still returned "
                    "404 — check that the token has access to this "
                    "repository (private-repo read scope) and that the "
                    "file path and branch name are exactly correct."
                )
        raise ValueError(
            f"Could not fetch privacy policy — {url} returned "
            f"HTTP {resp.status_code}. Check that the URL is correct, "
            f"publicly accessible, and points directly at the policy page "
            f"(not a 404 or a page that redirects to one).{_auth_hint}"
        )

    html = resp.text

    # Even a 200 response can be a "soft 404" (error page served with a 200
    # status) or an unrelated page — but only when the content came from
    # scraping an arbitrary rendered HTML page (the non-API fetch path).
    # There, we can't tell from the response alone whether it's the real
    # policy or an error page that also happens to return 200, so a
    # minimum-length sanity check is the only signal available — real
    # policies are prose documents, soft-404 pages are short boilerplate.
    #
    # The GitHub Contents API path (_api_url truthy) has no such ambiguity:
    # GitHub already told us, via the HTTP status code checked above,
    # whether the exact file at that repo/branch/path exists and was
    # returned (200) or not (a non-200, already raised). There's no
    # "soft 404 disguised as 200" case to guard against here, so a length
    # heuristic has nothing real to detect — it would just be guessing at
    # how long a privacy policy "should" be, which rejects genuinely short
    # (but real) files like a terse student/demo PRIVACY_POLICY.md for no
    # logical reason. The only thing actually worth checking on this path
    # is the one unambiguous failure case a 200 status doesn't rule out:
    # the file existing but being empty.
    # The same reasoning applies to any non-HTML response (a raw
    # .md/.txt file from raw.githubusercontent.com, a gist, a CDN): those
    # hosts return real 404 statuses, not soft-404 pages, so only an empty
    # body is a failure there. Previously a short PRIVACY_POLICY.md fetched
    # by its raw URL was rejected while the same file's blob URL passed.
    _ctype = (resp.headers.get("Content-Type") or "").lower()
    _is_html = "html" in _ctype or (not _ctype and "<html" in html[:2000].lower())
    _stripped_len = len(re.sub(r'<[^>]+>', ' ', html))
    if _api_url or not _is_html:
        if not html.strip():
            raise ValueError(
                f"Could not fetch privacy policy — {url} points to an "
                f"empty file. Check that the file path and branch are "
                f"correct and that the file actually has content."
            )
    elif _stripped_len < 1000:
        raise ValueError(
            f"Could not fetch privacy policy — {url} returned only "
            f"{_stripped_len} characters of text content, far too short to "
            f"be an actual privacy policy. The URL may be wrong or broken."
        )

    # Preserve document structure: block elements become paragraph breaks
    # (so headings and paragraphs are separate policy units), list items
    # become bullet lines.
    html_with_breaks = re.sub(
        r'</?(?:p|div|h[1-6]|ul|ol|tr|table|section|article|header|footer|blockquote)\b[^>]*>',
        '\n\n', html, flags=re.IGNORECASE)
    html_with_breaks = re.sub(r'<li[^>]*>', '\n• ', html_with_breaks, flags=re.IGNORECASE)
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

# Keywords in PURPOSE_CATEGORIES are word STEMS ("advertis", "secur"): each
# must start at a word boundary and may be followed by more letters. A few
# stems collide with unrelated words and get a negative lookahead.
_PURPOSE_STEM_EXCEPTIONS = {
    "inform": r"(?!ation|ative)",     # "inform/informed", not "information"
}
_PURPOSE_KW_RX: list[tuple[re.Pattern, str]] = [
    (re.compile(r'(?<![a-z0-9])' + re.escape(kw) + _PURPOSE_STEM_EXCEPTIONS.get(kw, '')), purpose)
    for purpose, keywords in PURPOSE_CATEGORIES.items()
    for kw in keywords
]

# Multi-word PII phrases ("bank account number", "health information",
# "email address", "contact number") are blanked out before purpose matching:
# they name the DATA, not the purpose, but contain purpose keywords
# ("account", "inform", "email", "contact").
_MULTIWORD_PII_RX = [rx for rx, phrase, _ in _POLICY_PHRASE_RX if ' ' in phrase]


def _keyword_purpose_hits(sentence: str) -> list[tuple[int, str]]:
    """(position, purpose) for every purpose keyword in the sentence, after
    blanking multi-word PII phrases (see _keyword_purpose)."""
    s = sentence.lower()
    for rx in _MULTIWORD_PII_RX:
        s = rx.sub(lambda m: ' ' * len(m.group(0)), s)
    hits = []
    for rx, purpose in _PURPOSE_KW_RX:
        m = rx.search(s)
        if m:
            hits.append((m.start(), purpose))
    return hits


def _keyword_purposes(sentence: str) -> set[str]:
    """All purpose categories the sentence's wording names."""
    return {p for _, p in _keyword_purpose_hits(sentence)}


def _keyword_purpose(sentence: str) -> str | None:
    """
    Keyword-based purpose detection (used by the spaCy passes on purpose
    phrases, and as the fallback when the sentence-transformer is missing).

    Previously this did `kw in s` and returned the first category in dict
    order, so "health information" matched communication ("inform"), "bank
    account number" matched service_delivery ("account"), "latest" matched
    research ("test"), and an earlier category always beat the purpose
    actually stated. Wrong purposes inflate purpose_map and hide genuine
    Rule 3 violations. Now: PII phrases are blanked, stems match at word
    starts only, and the purpose whose keyword appears FIRST in the text wins.
    """
    hits = _keyword_purpose_hits(sentence)
    return min(hits)[1] if hits else None


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
    emb = st_model.encode([sentence], normalize_embeddings=True,
                          show_progress_bar=False)[0]
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
    sentences = [u.lower() for u in _policy_units(raw_with_newlines)]
    for sentence in sentences:
        sentence = sentence.strip()
        if len(sentence) < 10:
            continue
        if not _CONTEXT_RE.search(sentence):
            continue
        for category, keyword in _find_policy_pii(sentence):
            # "We do not collect your Aadhaar number" discloses nothing: a
            # mention governed by a negated collection verb in the same
            # clause is not a disclosure (a notice that denies collecting
            # data the code collects must still yield a notice gap). A
            # negated SHARING verb ("we never sell your email") still
            # implies the data is held, so it does count.
            if _negated_collection(sentence, keyword):
                continue
            if category not in seen:
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

    # ── Pass 1b: bullet-list sub-pass (NLP-enhanced) ────────────────────
    # Many privacy policies list PII types in <li> elements without a verb.
    # We detect lines that start with bullet markers and look for PII keywords
    # without requiring a collection context verb, using the more precise
    # BULLET_PII_MAP (multi-word phrases, ambiguous single words excluded).
    #
    # False-positive gate: each bullet item is checked against BULLET_EXCLUSIONS
    # before any keyword match is accepted.  Word-boundary matching prevents
    # substring matches (e.g. "pan" inside "japan").
    bullet_pattern = re.compile(
        r'^\s*(?:[•\-\*▪◦●→]|\d+[\.\)]|[a-z]\))\s+(.+)$',
        re.MULTILINE,
    )
    for match in bullet_pattern.finditer(raw_with_newlines):
        item = match.group(1).strip()
        item_lower = item.lower()
        if len(item_lower) < 3 or len(item_lower) > 300:
            continue

        # Exclusion gate — skip non-PII bullets that superficially contain keywords
        if any(exc.search(item_lower) for exc in _BULLET_EXCLUSIONS):
            continue

        # Span tracking: prevents shorter phrases (e.g. "address") from
        # re-matching inside an already-consumed longer phrase ("email address").
        consumed_spans: list[tuple[int, int]] = []
        for phrase, category in BULLET_PII_MAP:
            # Use word-boundary regex so "pan" doesn't match inside "japan"
            m = re.search(r'\b' + re.escape(phrase) + r'\b', item_lower)
            if m:
                # Skip if this match overlaps a span already consumed by a longer phrase
                if any(cs[0] < m.end() and m.start() < cs[1] for cs in consumed_spans):
                    continue
                # Consume the span even when the category is already known.
                # Previously an already-seen category was skipped BEFORE its
                # span was recorded, so in the bullet "Email address" (email
                # already found by Pass 1a) the word "address" was left free
                # and wrongly disclosed LOCATION.
                consumed_spans.append((m.start(), m.end()))
                if category in seen:
                    continue
                seen.add(category)
                findings.append(DataFlowObject(
                    source="policy_parser_bullets",
                    file_path=None,
                    line_number=None,
                    raw_text=item_lower[:300],
                    field_name=phrase,
                    pii_category=category,
                    sensitivity=SENSITIVITY_MAP.get(category, Sensitivity.UNKNOWN),
                    third_party_sdk=None,
                ))

    return findings, seen


# ── Pass 2: purpose extraction ───────────────────────────────────────────────

# A purpose statement that refers to the user's data generically ("We use
# your information to: …") names no PII category, so it used to be linked
# to none — and Rule 3 then reported every category as having no stated
# purpose. Such a unit is applied to every category the policy discloses.
# It must be a USE statement (use/process), so sharing, retention or
# "we do not sell your data" sentences are not mistaken for purposes.
_GENERIC_DATA_RE = re.compile(
    r"\b(?:your|personal|the|this|such|all)\s+(?:personal\s+)?(?:information|data|details)\b"
)
_USE_VERB_RE = re.compile(r"\b(?:use|uses|used|using|process|processes|processed|processing)\b")


def _affirmative_part(text: str) -> str:
    """
    The part of a unit before its first negation word: "We use your email
    for login, not for marketing" → "We use your email for login, ". Text
    after a negation states what is NOT done and must not add a purpose.
    """
    m = _NEGATION_RE.search(text.lower())
    return text[:m.start()] if m else text


def _pass2_extract_purposes(
    full_text_lower: str,
    policy_pii_categories: set[PIICategory],
    full_text_raw: str | None = None,
) -> tuple[dict[PIICategory, set[str]], list[dict]]:
    """
    For each PII category found in Pass 1, identify what purpose(s) the policy
    states for processing that data.

    Strategy:
      1. Find sentences that mention the PII category keyword.
      2. Extract purposes from those sentences using:
         a. spaCy dependency parsing (4-pass)
         b. sentence-transformer cosine similarity (all-MiniLM-L6-v2)
         c. Keyword fallback when the sentence-transformer is unavailable
      3. Flag vagueness when top-2 ST scores are within VAGUENESS_MARGIN.

    Returns:
      purpose_map        : {PIICategory → set[purpose_label]}
      vagueness_warnings : [{"pii_category": ..., "margin": ..., "sentence": ...}]
    """
    purpose_map: dict[PIICategory, set[str]] = {}
    vagueness_warnings: list[dict] = []
    # category → statements that state a specific purpose for it
    specific_for: dict[PIICategory, list[str]] = {}

    nlp = _get_nlp()
    st_model, template_embeddings = _get_st_model()

    # Split into sentences, preserving case for spaCy: its tagger and
    # dependency parser are trained on cased text, so the lower-cased copy
    # (which this pass used to receive) degrades the parse. full_text_raw is
    # the same text before lower-casing; whitespace is collapsed the same way
    # fetch_policy_text() does for the lower-cased copy.
    _source = full_text_raw if full_text_raw is not None else full_text_lower
    _units = _policy_units(_source)
    raw_sentences = [s for s in _units if len(s) > 15]
    # Where each statement is in the policy (1-based position among the
    # policy's statements), so a vague-purpose violation can say where.
    statement_no: dict[str, int] = {}
    for i, unit in enumerate(_units, 1):
        statement_no.setdefault(unit, i)

    # Which PII categories each sentence names — same whole-word, longest-
    # phrase matcher as Pass 1 (on the lower-cased sentence), so Pass 2
    # looks at the same sentences.
    sentence_cats = [
        (s, {c for c, _ in _find_policy_pii(s.lower())}) for s in raw_sentences
    ]
    generic_units = [
        s for s, cats in sentence_cats
        if not cats and _GENERIC_DATA_RE.search(s.lower()) and _USE_VERB_RE.search(s.lower())
    ]

    for cat in policy_pii_categories:
        cat_purposes: set[str] = set()

        # Units naming this PII category, plus generic "your information" use
        # statements (which apply to every disclosed category)
        relevant = [s for s, cats in sentence_cats if cat in cats] + generic_units
        if not relevant:
            continue

        for quoted in relevant:
            sent = _affirmative_part(quoted).strip()
            if len(sent) < 10:
                continue
            # Rule 3(b)(ii): a statement whose purpose wording is stock or
            # generic ("Improve our platform", "to provide and improve our
            # services") states no specified purpose. It is a vagueness
            # candidate for this category, and the purposes it seems to name
            # are NOT added to purpose_map (otherwise "improve our platform"
            # made analytics use look disclosed and hid a Rule 3 violation).
            # Whether the CATEGORY is reported as vague is decided below, for
            # the notice as a whole.
            kind = purpose_statement_kind(sent)
            if kind in ("stock", "vague"):
                vagueness_warnings.append({
                    "pii_category": cat.value,
                    "margin":       None,
                    "sentence":     quoted,
                    "statement_no": statement_no.get(quoted),
                    "top_label":    None,
                    "top_score":    None,
                    "reason":       ("stock vague wording" if kind == "stock"
                                     else "generic purpose wording"),
                })
                continue
            if kind == "specific":
                specific_for.setdefault(cat, []).append(quoted)
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
                # (The margin between the top-2 scores is NOT used for
                # vagueness: it measures the classifier's uncertainty, not
                # whether the policy's wording is specific.)

            # ── Keyword fallback ───────────────────────────────────────────
            if st_model is None:
                p = _keyword_purpose(sent)
                if p:
                    cat_purposes.add(p)

        if cat_purposes:
            purpose_map[cat] = cat_purposes

    # Rule 3(b)(ii) concerns the NOTICE: it must state the specified purpose
    # of processing each item of personal data. A category for which some
    # statement does state a specific purpose ("We use your phone number to
    # send you OTPs") has one, even if another statement also uses generic
    # wording ("… and to improve our services"). Only a category whose every
    # purpose statement is generic is reported as vague.
    # The default scope is "statement": every generic statement is reported,
    # whatever else the policy says about the same data.
    # PRIVACYPILOT_VAGUENESS_SCOPE=notice applies the whole-notice reading.
    if vagueness_scope() == "notice":
        vagueness_warnings = [w for w in vagueness_warnings
                              if not specific_for.get(PIICategory(w["pii_category"]))]

    # Deduplicate vagueness warnings: one per (statement, PII category).
    # (It used to keep only the worst statement per category, so a second
    # vague statement about the same data was never reported.)
    deduped: dict[tuple, dict] = {}
    for w in vagueness_warnings:
        k = (" ".join((w.get("sentence") or "").split()).lower(), w["pii_category"])
        m = w["margin"] if w.get("margin") is not None else -1.0
        if k not in deduped or m < (deduped[k]["margin"] if deduped[k].get("margin") is not None else -1.0):
            deduped[k] = w
    vagueness_warnings = list(deduped.values())

    print(f"[policy] purpose_map: { {k.value: v for k, v in purpose_map.items()} }")
    if vagueness_warnings:
        print(f"[policy] {len(vagueness_warnings)} vagueness warning(s) fired")

    return purpose_map, vagueness_warnings


# ── Pass 3: disclosed third-party extraction ──────────────────────────────────
# Rule 2 ("Third-Party Transmission") in the rule engine previously flagged
# every PII+SDK co-location in code as "undisclosed" (Section 5) regardless
# of what the privacy policy actually says — it never consulted the policy
# at all. This pass closes that gap: if the policy names a known SDK/
# processor in the same sentence as a PII category, that category's sharing
# with that SDK is treated as disclosed, and the rule engine downgrades its
# finding instead of repeating a false "undisclosed" claim.
#
# Matching (revised): both the PII category and the SDK are matched as whole
# words/names — the PII side with the same _find_policy_pii() matcher as
# Pass 1 (so "company" is not PAN and "email address" is not location), the
# SDK side with scanners.sinks.sdks_named_in() (so the generic word
# "analytics" or "we segment customers" is not a named SDK).
#
# Negation: a clause such as "we never share your phone number with Twilio"
# does NOT count as disclosure. If the code does send that data to Twilio,
# the notice actively says the opposite of what happens, which is a worse
# notice failure, not a satisfied one — so that pairing stays "undisclosed".
# Only a negation word between the start of the SDK's clause and the SDK
# name is considered; "we share it with Mixpanel and do not sell it" is
# still a disclosure.

_NEGATION_RE = re.compile(
    r"\b(?:not|never|no|neither|nor|don't|doesn't|won't|cannot|can't)\b"
)
_CLAUSE_BREAK_RE = re.compile(r",|\bbut\b|\bhowever\b|\bwhereas\b|\bexcept\b")


_NEGATED_COLLECTION_RE = re.compile(
    r"\b(?:not|never|no\s+longer|neither|nor|don't|doesn't|won't|cannot|can't)\s+"
    r"(?:\w+\s+){0,3}?(?:collect|obtain|gather|store|record|retain|receive|access|ask\s+for|request|require|process|use)\w*\b"
)


def _negated_collection(sentence: str, phrase: str) -> bool:
    """True when the phrase's clause negates a collection verb before it."""
    m = re.search(r'(?<![a-z0-9])' + re.escape(phrase) + r'(?![a-z0-9])', sentence)
    if not m:
        return False
    head = sentence[:m.start()]
    breaks = [b.end() for b in _CLAUSE_BREAK_RE.finditer(head)]
    clause = head[breaks[-1]:] if breaks else head
    return bool(_NEGATED_COLLECTION_RE.search(clause))


def _negated_before(sentence: str, pos: int) -> bool:
    """True if a negation word sits in the same clause, before position `pos`."""
    head = sentence[:pos]
    breaks = [m.end() for m in _CLAUSE_BREAK_RE.finditer(head)]
    clause = head[breaks[-1]:] if breaks else head
    return bool(_NEGATION_RE.search(clause))


def _pass3_extract_disclosed_sdks(
    full_text_lower: str,
    policy_pii_categories: set[PIICategory],
    full_text_raw: str | None = None,
) -> dict[PIICategory, set[str]]:
    """
    Returns {PIICategory → set[sdk_name]} for every (category, SDK) pair
    that co-occurs in the same sentence of the privacy policy — i.e. SDKs
    the policy already names as a recipient of that PII category — unless
    the sentence negates sharing with that SDK.
    """
    from scanners.sinks import SDK_DISCLOSURE_PATTERNS

    disclosed: dict[PIICategory, set[str]] = {}
    if not policy_pii_categories:
        return disclosed

    _source = full_text_raw if full_text_raw is not None else full_text_lower
    sentences = [u.lower() for u in _policy_units(_source)]
    for sentence in sentences:
        sentence = sentence.strip()
        if len(sentence) < 10:
            continue

        named = sdks_named_in(sentence)
        if not named:
            continue
        sdks_in_sentence = {
            sdk for sdk in named
            if not _negated_before(sentence, SDK_DISCLOSURE_PATTERNS[sdk].search(sentence).start())
        }
        if not sdks_in_sentence:
            continue

        cats_in_sentence = {c for c, _ in _find_policy_pii(sentence)}
        for cat in cats_in_sentence & set(policy_pii_categories):
            disclosed.setdefault(cat, set()).update(sdks_in_sentence)

    if disclosed:
        print(f"[policy] disclosed_sdks: { {k.value: v for k, v in disclosed.items()} }")
    return disclosed


# ── Main entry point ──────────────────────────────────────────────────────────

def parse_privacy_policy(
    policy_url: str,
    github_token: str | None = None,
) -> tuple[list[DataFlowObject], dict[PIICategory, set[str]], list[dict], dict[PIICategory, set[str]]]:
    """
    Fetch and analyse a privacy policy URL.

    Returns
    -------
    policy_claims      : list[DataFlowObject]  — PII types found in policy
    purpose_map        : dict[PIICategory, set[str]]  — what purposes are stated
    vagueness_warnings : list[dict]  — sentences with ambiguous purpose (margin < 0.08)
    disclosed_sdks      : dict[PIICategory, set[str]]  — SDKs the policy already
                          names as a recipient of that PII category (Pass 3)
    """
    # Security: validate URL before any HTTP request
    validate_policy_url(policy_url)

    print(f"[policy] Fetching: {policy_url}")
    full_text_lower, raw_with_newlines = fetch_policy_text(policy_url, github_token)
    print(f"[policy] Got {len(full_text_lower)} characters")

    # ── Pass 1: PII extraction ────────────────────────────────────────────
    findings, seen_categories = _pass1_extract_pii(full_text_lower, raw_with_newlines)
    print(f"[policy] Pass 1 — {len(findings)} PII claim(s) from {len(seen_categories)} category/ies")

    # ── Pass 2: Purpose extraction ────────────────────────────────────────
    purpose_map, vagueness_warnings = _pass2_extract_purposes(
        full_text_lower, seen_categories, full_text_raw=raw_with_newlines
    )
    for w in vagueness_warnings:
        w["policy_url"] = policy_url      # the location of a vague statement

    # ── Pass 3: Disclosed third-party extraction ──────────────────────────
    disclosed_sdks = _pass3_extract_disclosed_sdks(
        full_text_lower, seen_categories, full_text_raw=raw_with_newlines
    )

    return findings, purpose_map, vagueness_warnings, disclosed_sdks
