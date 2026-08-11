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


def scan_text_with_presidio(text: str) -> list:
    """
    Scan a block of text and return list of detected PII entity types.
    Falls back gracefully if Presidio not available.
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
                if r.score >= 0.7:
                    found.append(r.entity_type)
        except Exception as e:
            print(f"[presidio] Analysis error: {e}")

    return list(set(found))