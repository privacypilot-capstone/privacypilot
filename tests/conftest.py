"""
pytest configuration for PrivacyPilot.

- Puts backend/ on sys.path so tests import the PRODUCTION modules
  (scanners.code_scanner, dpdp.rule_engine, …) rather than re-implementing
  them.
- Heavy NLP back-ends are switched off inside tests so results are
  deterministic and fast: Presidio NER (the India regexes still run) and the
  spaCy / sentence-transformer purpose models (the keyword fallback runs).
"""

import sys
import types
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))


def _stub_if_missing(name: str, **attrs):
    """Provide a tiny stand-in module only when the real package is absent."""
    try:
        __import__(name)
    except ImportError:
        mod = types.ModuleType(name)
        for k, v in attrs.items():
            setattr(mod, k, v)
        sys.modules[name] = mod


class _Unavailable:
    def __init__(self, *a, **k):
        raise RuntimeError("stubbed in tests")


_stub_if_missing("github", Github=_Unavailable)
_stub_if_missing("presidio_analyzer", AnalyzerEngine=_Unavailable)
_stub_if_missing("presidio_analyzer.nlp_engine", NlpEngineProvider=_Unavailable)


@pytest.fixture(autouse=True)
def _no_heavy_models(monkeypatch):
    from scanners import presidio_scanner, policy_parser
    monkeypatch.setattr(presidio_scanner, "get_analyzer", lambda: None)
    monkeypatch.setattr(policy_parser, "_get_nlp", lambda: None)
    monkeypatch.setattr(policy_parser, "_get_st_model", lambda: (None, None))
