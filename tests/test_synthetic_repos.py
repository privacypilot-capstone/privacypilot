"""
End-to-end check on the five synthetic evaluation repositories
(github.com/privacypilot-capstone/*, snapshots in tests/fixtures/synthetic,
commit hashes in SOURCES.txt).

The whole production pipeline runs offline — code scanner, policy parser,
gap detection, rule engine — and the result is compared with ground truth
taken from the PLANTED VIOLATION / TRAP comments in each repo and from
reading its code and privacy policy.

Asserted EXACTLY (so both misses and false positives fail the test):
  * consent gaps (Rule 1)
  * every third-party transmission (Section 8(2)) and logger leak
    (Section 8(5)) as (kind, PII category, sink)
Not asserted: Rule 3 purpose linkage and Rule 3(b)(ii) vagueness, because
in production they come from the spaCy / sentence-transformer models, which
the test suite switches off (see conftest.py).

These repos are also the paper's evaluation set: the fixes this test
guards are generic code-pattern fixes, but report detection figures from a
held-out repository too, to avoid tuning to this set.
"""

import os
import re

import pytest

from models.dataflow import PIICategory as P
from scanners import code_scanner as cs
from scanners import policy_parser as pp
from dpdp.rule_engine import run_dpdp_rules

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "synthetic")

UNDISCLOSED, CONTRACT, LOGGER = "8(2) undisclosed", "8(2) contract unverified", "8(5) logger"


class _Content:
    def __init__(self, text): self.decoded_content = text.encode()


class _LocalRepo:
    def __init__(self, root): self.root = root
    def get_contents(self, path):
        with open(os.path.join(self.root, path), encoding="utf-8") as fh:
            return _Content(fh.read())


class _File:
    def __init__(self, path): self.path, self.type = path, "blob"


class _Resp:
    def __init__(self, text): self.status_code, self.text, self.headers = 200, text, {"Content-Type": "text/plain"}


def run_pipeline(repo, policy_file, monkeypatch):
    root = os.path.join(FIXTURES, repo)
    findings, usage = [], {}
    for dirpath, _, files in os.walk(root):
        for fn in sorted(files):
            rel = os.path.relpath(os.path.join(dirpath, fn), root).replace("\\", "/")
            if rel.endswith(cs.SCAN_EXTS):
                f, u = cs._scan_single_file(_LocalRepo(root), _File(rel))
                findings += f
                for k, v in u.items():
                    usage.setdefault(k, set()).update(v)

    with open(os.path.join(root, policy_file), encoding="utf-8") as fh:
        policy = fh.read()
    monkeypatch.setattr(pp, "validate_policy_url", lambda url: None)
    monkeypatch.setattr(pp.requests, "get", lambda url, **kw: _Resp(policy))
    claims, purpose_map, vague, disclosed = pp.parse_privacy_policy(
        f"https://github.com/privacypilot-capstone/{repo}/blob/main/{policy_file}")

    gaps = {f.pii_category for f in findings} - {c.pii_category for c in claims}
    violations = run_dpdp_rules(findings, claims, gaps, usage_map=usage,
                                purpose_map=purpose_map, vagueness_warnings=vague,
                                disclosed_sdks=disclosed)

    transmissions = set()
    for v in violations:
        if v.dpdp_section == "Section 8(5)":
            transmissions.add((LOGGER, v.pii_category,
                               re.search(r"at (\S+) line", v.evidence).group(1)))
        elif v.dpdp_section == "Section 8(2)":
            kind = CONTRACT if "Contract Unverified" in v.section_title else UNDISCLOSED
            transmissions.add((kind, v.pii_category,
                               re.search(r"transmitted to '([^']+)'", v.evidence).group(1)))
    return findings, {g.value for g in gaps}, transmissions


# ── Ground truth ──────────────────────────────────────────────────────────────

EXPECTED = {
    # No planted violations. Twilio is disclosed for the phone number, so
    # phone → Twilio only needs the processor contract confirmed. The SMS
    # body also contains user.full_name (notifications.py:18) while the
    # policy says Twilio gets the "phone number only" → name is undisclosed.
    "compliant-demo": ("PRIVACY_POLICY.md", set(), {
        (CONTRACT, "phone", "twilio"),
        (UNDISCLOSED, "name", "twilio"),
    }),
    # V1 date_of_birth and V2 location not in the policy; V3 student data
    # sent to Mixpanel through the `mp` client (the policy says no data goes
    # to analytics companies).
    "edtech-demo": ("PRIVACY_PILOT.md", {"date_of_birth", "location"}, {
        (UNDISCLOSED, "email", "mixpanel"),
        (UNDISCLOSED, "name", "mixpanel"),
        (UNDISCLOSED, "phone", "mixpanel"),
        (UNDISCLOSED, "location", "mixpanel"),
    }),
    # V1 PAN, V2 bank account, V3 Aadhaar not in the policy; V4 financial
    # data (and contact data on login) sent to Segment, imported as
    # `analytics`; spread over multi-line calls.
    "fintech-demo": ("PRIVACY_POLICY.md", {"aadhaar", "financial", "pan"}, {
        (UNDISCLOSED, c, "segment") for c in ("email", "pan", "financial", "aadhaar", "phone", "name")
    }),
    # V1 Aadhaar, V2 blood group, V3 fingerprint, V6 DOB, V7 PAN not in the
    # policy; V4 health + Aadhaar sent to Firebase (analytics.log_event and
    # requests.post) through a payload dict; V5 phone (and name / diagnosis
    # in the message body) to Twilio via `client`; Mixpanel via `mp`.
    # V8 (GPS tracking) is not a gap: "Home address" discloses LOCATION —
    # a known limit of the single location category.
    "healthtech-demo": ("PRIVACY_POLICY.md", {"aadhaar", "biometric", "date_of_birth", "health", "pan"}, {
        (UNDISCLOSED, "aadhaar", "firebase"), (UNDISCLOSED, "health", "firebase"),
        (UNDISCLOSED, "phone", "firebase"),
        (UNDISCLOSED, "aadhaar", "requests.post"), (UNDISCLOSED, "health", "requests.post"),
        (UNDISCLOSED, "phone", "requests.post"),
        (UNDISCLOSED, "email", "mixpanel"), (UNDISCLOSED, "phone", "mixpanel"),
        (UNDISCLOSED, "location", "mixpanel"),
        (UNDISCLOSED, "name", "twilio"), (UNDISCLOSED, "phone", "twilio"),
        (UNDISCLOSED, "health", "twilio"),
    }),
    # V1 email + phone to Segment via requests.post; V2 diagnosis to Firebase
    # via requests.post; V3 Aadhaar in a logger; V4 location and V6 email to
    # Mixpanel; V5 biometric not in the policy. Aadhaar sent to UIDAI
    # (uidai.gov.in) is verification with the government, not a processor.
    "dpdp-synthetic-test": ("privacy_policy.html", {"aadhaar", "biometric", "health", "location"}, {
        (UNDISCLOSED, "email", "requests.post"), (UNDISCLOSED, "phone", "requests.post"),
        (UNDISCLOSED, "health", "requests.post"),
        (UNDISCLOSED, "location", "mixpanel"), (UNDISCLOSED, "email", "mixpanel"),
        (LOGGER, "aadhaar", "services/auth_service.py"),
    }),
}


@pytest.mark.parametrize("repo", sorted(EXPECTED))
def test_synthetic_repo_matches_ground_truth(repo, monkeypatch):
    policy_file, expected_gaps, expected_tx = EXPECTED[repo]
    _, gaps, transmissions = run_pipeline(repo, policy_file, monkeypatch)
    assert gaps == expected_gaps
    assert transmissions == expected_tx


def test_synthetic_traps_produce_no_findings(monkeypatch):
    """FP2–FP5 (PII / SDK words in docstrings and comments) and TN1/TN3 in
    dpdp-synthetic-test produce no finding; TN2/TN3 code produces no
    transmission."""
    findings, _, _ = run_pipeline("dpdp-synthetic-test", "privacy_policy.html", monkeypatch)
    lines = {(f.file_path, f.line_number) for f in findings}
    trap_lines = (
        {("services/health_service.py", n) for n in (18, 20, 21, 22, 23, 24, 28, 29, 30)}
        | {("services/auth_service.py", n) for n in (21, 22, 23, 24, 25, 26, 30, 31)}
        | {("services/user_service.py", 23)}
    )
    assert not lines & trap_lines
    assert not any(f.third_party_sdk for f in findings if f.file_path == "utils/validators.py")
