from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
import re

# India-specific regex patterns
INDIA_PATTERNS = {
    "AADHAAR": r"\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b",
    "PAN":     r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
    "PHONE":   r"\b(?:\+91|0)?[6-9][0-9]{9}\b",
}

# Lazy-load analyzer so it doesn't crash if spacy not ready
_analyzer = None

def get_analyzer():
    global _analyzer
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
            print(f"[presidio] Could not load: {e}")
            _analyzer = None
    return _analyzer


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
    found = []

    # India-specific regex first
    for label, pattern in INDIA_PATTERNS.items():
        if re.search(pattern, text):
            found.append(label)

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
                found.append(r.entity_type)
        except Exception as e:
            print(f"[presidio] Analysis error: {e}")

    return list(set(found))