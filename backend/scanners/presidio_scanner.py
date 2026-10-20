from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
import re
import threading

# India-specific regex patterns
INDIA_PATTERNS = {
    "AADHAAR": r"\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b",
    "PAN":     r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
    "PHONE":   r"\b(?:\+91|0)?[6-9][0-9]{9}\b",
}

# ── Verhoeff checksum for Aadhaar validation ──────────────────────────────────
# Aadhaar numbers are 12-digit UIDAI identifiers whose last digit is a
# Verhoeff check digit. A bare 12-digit regex alone has no way to tell a real
# Aadhaar number apart from any other 12-digit sequence that happens to start
# with 2-9 (a timestamp, an order ID, a padded account number, etc.) — the
# Verhoeff checksum is the one structural signal that actually distinguishes
# them, so every Aadhaar-shaped match is run through it before being accepted.
#
# This is the single source of truth for the algorithm: code_scanner.py's
# own regex-based Aadhaar check imports `verhoeff_checksum_valid` from here
# rather than keeping a second copy of these tables, so the two scanning
# passes can never silently drift apart on what counts as a valid number.
_VERHOEFF_D = [
    [0,1,2,3,4,5,6,7,8,9],
    [1,2,3,4,0,6,7,8,9,5],
    [2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7],
    [4,0,1,2,3,9,5,6,7,8],
    [5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2],
    [7,6,5,9,8,2,1,0,4,3],
    [8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0],
]
_VERHOEFF_P = [
    [0,1,2,3,4,5,6,7,8,9],
    [1,5,7,6,2,8,3,0,9,4],
    [5,8,0,3,7,9,6,1,4,2],
    [8,9,1,6,0,4,3,5,2,7],
    [9,4,5,3,1,2,6,8,7,0],
    [4,2,8,6,5,7,3,9,0,1],
    [2,7,9,3,8,0,6,4,1,5],
    [7,0,4,6,9,1,3,2,5,8],
]


def verhoeff_checksum_valid(digits: str) -> bool:
    """
    Return True if `digits` (a 12-character numeric string, no spaces/dashes)
    passes the Verhoeff checksum used by UIDAI for Aadhaar numbers.
    """
    seq = [int(d) for d in reversed(digits)]
    c = 0
    for i, d in enumerate(seq):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][d]]
    return c == 0


def _extract_valid_aadhaar(text: str) -> bool:
    """
    Return True if `text` contains at least one 12-digit candidate matching
    the Aadhaar shape AND passing the Verhoeff checksum. A shape-only match
    (e.g. a timestamp or order ID that happens to start with 2-9) is rejected.
    """
    for m in re.finditer(INDIA_PATTERNS["AADHAAR"], text):
        digits = re.sub(r'\s', '', m.group(0))
        if len(digits) == 12 and verhoeff_checksum_valid(digits):
            return True
    return False

# Lazy-load analyzer so it doesn't crash if spacy not ready.
# None = not tried yet, False = tried and unavailable (don't retry).
_analyzer = None
_analyzer_lock = threading.Lock()   # the code scanner calls this from 40 threads


def get_analyzer():
    """
    Load Presidio once. On failure, remember the failure (sentinel False)
    instead of retrying on every scanned line, and say exactly what is
    missing — previously a missing spaCy model was retried on every line of
    every file and NER was skipped without a clear warning.
    """
    global _analyzer
    if _analyzer is None:
        with _analyzer_lock:
            if _analyzer is None:
                try:
                    provider = NlpEngineProvider(nlp_configuration={
                        "nlp_engine_name": "spacy",
                        "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
                    })
                    nlp_engine = provider.create_engine()
                    _analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
                    print("[presidio] Analyzer loaded")
                except Exception as e:
                    print(
                        f"[presidio] WARNING: Presidio NER disabled — {e}. "
                        "Run `pip install -r requirements.txt` (it installs "
                        "en_core_web_lg). Only the India regexes will run."
                    )
                    _analyzer = False
    return _analyzer or None


# SDK / library proper nouns that Presidio wrongly tags as PERSON entities.
# Extend this list whenever a new false-positive is observed in scan results.
_PERSON_FALSE_POSITIVES = {
    # Analytics / SDK product names
    "mixpanel", "firebase", "amplitude", "segment", "braze", "intercom",
    "hubspot", "salesforce", "twilio", "sendgrid", "mailchimp", "stripe",
    "razorpay", "paytm", "sentry", "datadog", "newrelic", "logstash",
    "elasticsearch", "kafka", "rabbitmq", "celery", "redis", "postgres",
    "mongodb", "dynamodb", "bigquery", "snowflake", "airflow", "fastapi",
    "django", "flask", "sqlalchemy", "pydantic", "boto", "boto3",
    # Auth / login identifiers — spaCy sometimes tags these as PERSON
    "login", "logout", "signin", "signup", "register", "authenticate",
    "authorize", "verify", "verification", "password", "credential",
    "user_id", "userid", "username", "session", "token", "oauth",
    # Generic code-context words
    "admin", "user", "client", "server", "service", "handler", "manager",
    "controller", "request", "response", "payload", "data", "result",
    # Auth-service / header tokens spaCy misidentifies as names
    "otp", "basic", "bearer", "authorization", "authenticated",
    "aadhaar", "aadhar", "login_user", "verify_otp", "hash",
}

# SDK / library names that spaCy sometimes tags as GPE (geopolitical entity)
# which Presidio maps to LOCATION.  Extend when new false-positives appear.
_LOCATION_FALSE_POSITIVES = {
    # Analytics / SDK proper nouns (capital-M "Mixpanel" -> GPE in spaCy)
    "mixpanel", "firebase", "amplitude", "segment", "braze", "intercom",
    "hubspot", "salesforce", "twilio", "sendgrid", "stripe", "razorpay",
    "paytm", "sentry", "datadog", "newrelic", "elasticsearch", "kafka",
    "rabbitmq", "celery", "redis", "postgres", "mongodb", "dynamodb",
    "bigquery", "snowflake", "airflow", "fastapi", "django", "flask",
    # Generic tech tokens spaCy sometimes mis-tags as location
    "analytics", "database", "backend", "frontend", "api", "sdk",
    "server", "client", "service", "handler", "manager", "controller",
    "track_token", "write_key", "api_key", "xxxx",
}


def scan_text_with_presidio(text: str) -> list:
    """
    Scan a block of text and return list of detected PII entity types.
    Falls back gracefully if Presidio not available.

    Returns list of entity-type strings (e.g. ["PERSON", "EMAIL_ADDRESS"]).
    PERSON results are filtered against _PERSON_FALSE_POSITIVES so SDK class
    names like 'Mixpanel' or 'Firebase' are not mistaken for real person names.
    """
    return list({label for label, _, _ in scan_text_with_presidio_spans(text)})


def scan_text_with_presidio_spans(text: str) -> list[tuple[str, int, int]]:
    """
    Same detection as scan_text_with_presidio(), but returns
    (entity_type, start, end) so the caller can check WHERE in a line of
    code an entity was found (the code scanner only accepts PERSON /
    LOCATION hits inside a name-like string literal).
    """
    found: list[tuple[str, int, int]] = []

    # India-specific regex first
    for label, pattern in INDIA_PATTERNS.items():
        for m in re.finditer(pattern, text):
            if label == "AADHAAR":
                # Shape alone isn't enough for Aadhaar — require a Verhoeff
                # pass. PAN/PHONE have no public checksum standard, so they
                # stay shape-only like before.
                digits = re.sub(r'\s', '', m.group(0))
                if not (len(digits) == 12 and verhoeff_checksum_valid(digits)):
                    continue
            found.append((label, m.start(), m.end()))

    # Presidio NER
    analyzer = get_analyzer()
    if analyzer:
        try:
            results = analyzer.analyze(text=text, language="en")
            for r in results:
                if r.score < 0.7:
                    continue
                # For PERSON entities, reject known SDK / library names so they
                # are not flagged as name PII.
                if r.entity_type == "PERSON":
                    matched = text[r.start:r.end].strip().lower()
                    if matched in _PERSON_FALSE_POSITIVES:
                        continue
                # For LOCATION entities, reject SDK names that spaCy tags as
                # GPE (geopolitical entity) — e.g. capitalised "Mixpanel".
                if r.entity_type == "LOCATION":
                    matched = text[r.start:r.end].strip().lower()
                    if matched in _LOCATION_FALSE_POSITIVES:
                        continue
                found.append((r.entity_type, r.start, r.end))
        except Exception as e:
            print(f"[presidio] Analysis error: {e}")

    return found