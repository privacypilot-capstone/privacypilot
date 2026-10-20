"""
Production test suite — every test imports and runs the real backend code.

Run from the project root:   pytest -q tests
Each test is tagged with the defect ID (D1–D14) from the implementation
audit that it guards against, so a regression points straight at the fix.
"""

import pytest

from models.dataflow import DataFlowObject, PIICategory as P, Sensitivity
from scanners import code_scanner as cs
from scanners import policy_parser as pp
from scanners import presidio_scanner as ps
from scanners.sinks import canonical_sink, sink_kind
from dpdp.rule_engine import run_dpdp_rules
from scoring import calculate_compliance_score


# ── helpers ───────────────────────────────────────────────────────────────────

class _Content:
    def __init__(self, text): self.decoded_content = text.encode()

class _Repo:
    def __init__(self, files): self.files = files
    def get_contents(self, path): return _Content(self.files[path])

class _File:
    def __init__(self, path): self.path, self.type = path, "blob"


def scan(path: str, source: str):
    """Run the real per-file scanner on an in-memory file."""
    findings, usage = cs._scan_single_file(_Repo({path: source}), _File(path))
    return findings, usage


def cats(findings, source=None):
    return {f.pii_category for f in findings if source is None or f.source == source}


def finding(cat, sdk=None, raw="x", path="app.py", line=1):
    return DataFlowObject(source="t", file_path=path, line_number=line, raw_text=raw,
                          field_name=cat.value, pii_category=cat,
                          sensitivity=Sensitivity.PERSONAL, third_party_sdk=sdk)


def sections(violations):
    return [v.dpdp_section for v in violations]


def make_aadhaar(base11: str) -> str:
    """Append the Verhoeff check digit to an 11-digit base."""
    c = 0
    for i, d in enumerate(int(x) for x in reversed(base11)):
        c = ps._VERHOEFF_D[c][ps._VERHOEFF_P[(i + 1) % 8][d]]
    return base11 + str([0, 4, 3, 2, 1, 9, 8, 7, 6, 5][c])


VALID = make_aadhaar("23456789012")                       # 234567890124
INVALID = VALID[:-1] + str((int(VALID[-1]) + 1) % 10)     # last digit changed


# ── Verhoeff / Aadhaar (D13) ──────────────────────────────────────────────────

def test_verhoeff_accepts_valid_and_rejects_tampered():
    assert ps.verhoeff_checksum_valid(VALID)
    assert not ps.verhoeff_checksum_valid(INVALID)


def test_D13_keyword_line_with_invalid_number_is_not_readded_by_pass2():
    f, _ = scan("a.py", f'aadhaar = "{INVALID}"\n')
    assert P.AADHAAR not in cats(f)


def test_D13_value_only_invalid_number_is_rejected():
    spaced = f"{INVALID[:4]} {INVALID[4:8]} {INVALID[8:]}"
    f, _ = scan("a.py", f'ref_id = "{spaced}"  # customer reference\n')
    assert P.AADHAAR not in cats(f)


def test_D13_value_only_valid_number_is_detected():
    spaced = f"{VALID[:4]} {VALID[4:8]} {VALID[8:]}"
    f, _ = scan("a.py", f'ref_id = "{spaced}"  # customer reference\n')
    assert P.AADHAAR in cats(f, "presidio_scanner")


# ── Pass 1 coverage (D2, D3) ──────────────────────────────────────────────────

def test_D2_js_camelcase_fields_are_detected():
    src = ("const phoneNumber = user.phoneNumber;\n"
           "const aadhaarNumber = req.body.aadhaarNumber;\n"
           "const dateOfBirth = form.dateOfBirth;\n")
    f, _ = scan("src/profile.js", src)
    assert {P.PHONE, P.AADHAAR, P.DOB} <= cats(f)


def test_D2_jsx_files_are_scanned():
    assert ".jsx" in cs.SCAN_EXTS and ".tsx" in cs.SCAN_EXTS


def test_D3_every_category_on_a_line_is_reported():
    f, _ = scan("m.py", "user = dict(email=email, phone=phone, aadhaar=aadhaar)\n")
    assert {P.EMAIL, P.PHONE, P.AADHAAR} <= cats(f)


def test_D3_overlapping_identifier_counts_once():
    f, _ = scan("m.py", "email_address = form.get('x')\n")
    assert cats(f) == {P.EMAIL}          # not also LOCATION via "address"


def test_D3_pan_value_detected_with_valid_structure_only():
    good, _ = scan("a.py", 'tax_identifier = "ABCPE1234F"  # value\n')
    bad, _ = scan("a.py", 'tax_identifier = "ABCDE1234F"  # value\n')
    assert P.PAN in cats(good)
    assert P.PAN not in cats(bad)        # 4th letter D is not a PAN holder type


# ── Sink labels (D4, D5, D6) ──────────────────────────────────────────────────

@pytest.mark.parametrize("text,label,kind", [
    ("requests.post(", "requests.post", "http"),
    ('axios.post("https://x.io", {c})', "axios.post", "http"),
    ("fetch(", "fetch", "http"),
    ("kafka_producer.send(", "kafka", "queue"),
    ("process_health.delay(", "celery", "queue"),
    ("redis_client.publish(", "redis.publish", "queue"),
    ("mixpanel.track(", "mixpanel", "sdk"),
    ("twilio.messages.create(", "twilio", "sdk"),
    ("print(", "print", "logger"),
    ("self.logger.warning(", "logger", "logger"),
    ("logging.info(", "logging", "logger"),
    ("console.log(", "console.log", "logger"),
])
def test_canonical_sink_labels(text, label, kind):
    assert canonical_sink(text) == label
    assert sink_kind(label) == kind


@pytest.mark.parametrize("text", [
    "read_fingerprint(", "Blueprint(", "user_segment = 3", "catalog.items(", "logging.getLogger(",
])
def test_D5_lookalikes_are_not_sinks(text):
    assert canonical_sink(text) is None


PY_TAINT = '''email = request.form["email"]
contact = email
print(contact)
self.logger.warning(contact)
requests.post(URL, json=contact)
kafka_producer.send(contact)
enqueue_job.delay(contact)
'''


def test_D6_python_taint_reaches_print_and_self_logger():
    f, _ = scan("svc/handler.py", PY_TAINT)
    sinks = {x.third_party_sdk for x in f if x.source == "taint_analysis"}
    assert {"print", "logger", "requests.post", "kafka", "celery"} <= sinks


def test_D4_D6_python_sinks_raise_the_right_rule():
    f, _ = scan("svc/handler.py", PY_TAINT)
    v = run_dpdp_rules(f, f, set())
    secs = sections(v)
    assert "Section 8(5)" in secs                 # print / logger
    assert "Section 8(2)" in secs     # requests / kafka / celery
    sdks = {v_.evidence.split("transmitted to '")[1].split("'")[0]
            for v_ in v if v_.dpdp_section == "Section 8(2)"}
    assert {"requests.post", "kafka", "celery"} <= sdks


def test_D4_js_http_sinks_raise_rule_2a():
    pytest.importorskip("tree_sitter_javascript")
    src = ('const email = req.body.email;\n'
           'const c = email;\n'
           'axios.post("https://x.io", { c });\n'
           'fetch("/api/save", { body: JSON.stringify({ c }) });\n')
    f, _ = scan("svc/a.js", src)
    sinks = {x.third_party_sdk for x in f if x.source == "taint_analysis"}
    assert {"axios.post", "fetch"} <= sinks
    assert "Section 8(2)" in sections(run_dpdp_rules(f, f, set()))


def test_D2_js_camelcase_taint_to_firebase():
    pytest.importorskip("tree_sitter_javascript")
    src = ("function processPatient(patient) {\n"
           "    const data   = patient.bloodGroup;\n"
           "    const record = data;\n"
           "    firebase.log(record);\n"
           "}\n")
    f, _ = scan("src/patient.js", src)
    assert any(x.source == "taint_analysis" and x.third_party_sdk == "firebase"
               and x.pii_category == P.HEALTH for x in f)


def test_D5_sdk_call_with_fingerprint_is_8_2_not_8_5():
    v = run_dpdp_rules([finding(P.BIOMETRIC, "mixpanel", "mixpanel.track('scan', fingerprint)")], [], set())
    assert sections(v) == ["Section 8(2)"]


def test_D5_blueprint_line_is_not_a_logger_finding():
    f, _ = scan("routes.py", "auth_bp = Blueprint('location', __name__)\n")
    assert all(x.third_party_sdk is None for x in f)


def test_legacy_raw_call_text_label_still_routes():
    # labels stored by the old scanner (raw call text) are still understood
    v = run_dpdp_rules([finding(P.EMAIL, 'axios.post("https://x.io", { c })')], [], set())
    assert sections(v) == ["Section 8(2)"]


# ── Module classifier (D7) ────────────────────────────────────────────────────

@pytest.mark.parametrize("path,src,expected", [
    ("app/login.py",          "def get_user(): pass\n",                 {"authentication"}),
    ("app/profile.py",        "def get_user(): pass\n",                 set()),
    ("app/blog/catalog.py",   "def get_user(): pass\n",                 set()),
    ("utils/review.py",       "def get_user(): pass\n",                 set()),
    ("api/views.py",          "def get(self, request): pass\n",         {"api"}),
    ("services/analytics.py", "def track_event(u): pass\n",             {"analytics"}),
    ("utils.py",              "def track_event(u): pass\n",             {"analytics"}),
    ("services/notifications.py", "def send_sms(p): pass\n",            {"notification"}),
    ("core/logs/writer.py",   "def write(x): pass\n",                   {"logging"}),
])
def test_D7_module_classifier_uses_whole_tokens(path, src, expected):
    assert cs.classify_module(path, src) == expected


def test_D7_login_module_no_longer_triggers_rule_3():
    usage = {P.EMAIL: cs.classify_module("app/login.py", "def get_user(): pass\n")}
    v = run_dpdp_rules([finding(P.EMAIL)], [finding(P.EMAIL)], set(),
                       usage_map=usage, purpose_map={P.EMAIL: {"service_delivery"}})
    assert v == []


# ── Rule 3 coverage (D8, D10) ─────────────────────────────────────────────────

def test_D8_rule_3_runs_when_policy_states_no_purposes():
    v = run_dpdp_rules([finding(P.HEALTH)], [finding(P.HEALTH)], set(),
                       usage_map={P.HEALTH: {"analytics"}}, purpose_map={})
    assert sections(v) == ["Section 6(1)"]
    assert "none found" in v[0].evidence


def test_D10_undisclosed_category_is_reported_once():
    v = run_dpdp_rules([finding(P.HEALTH)], [], {P.HEALTH},
                       usage_map={P.HEALTH: {"analytics"}}, purpose_map={})
    assert sections(v) == ["Section 5 / Section 6(1)"]


# ── Policy parser (D9 + the bullet-exclusion regex fix) ───────────────────────

def policy_cats(text):
    findings, seen = pp._pass1_extract_pii(text.lower(), text)
    return seen


@pytest.mark.parametrize("text,expected", [
    ("We collect your email address to create your account.", {P.EMAIL}),
    ("We use cookies to expand our features and to process personal data.", set()),
    ("Our company is based in Japan and we process data there.", set()),
    ("We store your password securely.", set()),
    ("We use your mobile app activity to improve the service.", set()),
    ("Because users like it, we offer a dark theme for your phone.", set()),   # no collection verb
    ("We collect your name, phone number and date of birth.", {P.NAME, P.PHONE, P.DOB}),
    ("We use your PAN card details for tax filing.", {P.PAN}),
    ("We process refunds on every bank holiday.", set()),   # exclusion now works
])
def test_D9_policy_sentence_matching(text, expected):
    assert policy_cats(text) == expected


def test_bullet_exclusions_now_match():
    # These regexes contained literal backspace characters and never matched.
    assert any(rx.search("contact us") for rx in pp._BULLET_EXCLUSIONS)
    assert any(rx.search("pan india") for rx in pp._BULLET_EXCLUSIONS)


def test_bullets_still_detected():
    text = "We collect:\n• Aadhaar number\n• Phone number\n• IP address\n• Fingerprint scans\n"
    assert {P.AADHAAR, P.PHONE, P.LOCATION, P.BIOMETRIC} <= policy_cats(text)


# ── End-to-end Rule 3 on the healthtech scenario (production code) ────────────

def test_end_to_end_rule_3_healthtech_scenario():
    files = {
        "models/patient.py":
            "class Patient:\n    aadhaar_number = None\n    blood_group = None\n",
        "services/analytics.py":
            "def track_event(patient):\n"
            "    firebase.log({'aadhaar': patient.aadhaar_number, 'health': patient.blood_group})\n",
        "services/notifications.py":
            "def send_reminder(phone):\n    twilio.messages.create(to=phone)\n",
    }
    findings, usage = [], {}
    for path, src in files.items():
        f, u = scan(path, src)
        findings += f
        for k, mods in u.items():
            usage.setdefault(k, set()).update(mods)

    policy = ("We collect your Aadhaar number to verify your identity as required by "
              "government regulations. We collect health data to provide medical services "
              "and maintain your health records. Your phone number is used to send you "
              "appointment reminders.")
    claims, seen = pp._pass1_extract_pii(policy.lower(), policy)
    purpose_map, vague = pp._pass2_extract_purposes(policy.lower(), seen)
    gaps = {f.pii_category for f in findings} - seen

    v = run_dpdp_rules(findings, claims, gaps, usage_map=usage, purpose_map=purpose_map)
    r3 = {x.pii_category: x.evidence for x in v if x.dpdp_section == "Section 6(1)"}
    assert "analytics" in r3.get("aadhaar", "")      # Aadhaar sent to analytics
    assert "analytics" in r3.get("health", "")       # health sent to analytics
    assert "phone" not in r3                         # reminders match stated purpose
    assert any(x.dpdp_section == "Section 8(2)" for x in v)   # firebase / twilio


# ── Score / rating (D14 backend contract) ─────────────────────────────────────

class _V:
    def __init__(self, s): self.severity = s


def test_D14_single_critical_caps_rating_at_poor():
    c = calculate_compliance_score([_V("critical")], 1, 1)
    assert c["score"] == 80.0
    assert c["rating"] == "Poor"      # the dashboard now shows this, not "Good"


# ── Pass 3: SDKs the policy names (new upstream feature, D15 fixes) ───────────

def disclosed(text):
    every = set(P) - {P.UNKNOWN}
    return pp._pass3_extract_disclosed_sdks(text.lower(), every)


@pytest.mark.parametrize("text,expected", [
    ("We share your email address with Mixpanel for product analytics.", {P.EMAIL: {"mixpanel"}}),
    ("We use Google Firebase to store your phone number.",               {P.PHONE: {"firebase"}}),
    ("We use Google Analytics to measure how your email is used.",       {P.EMAIL: {"analytics"}}),
    # generic words are not SDK names
    ("We use analytics to improve our service and may email you updates.", {}),
    ("We segment customers by location for regional offers.",             {}),
    # negation is not disclosure
    ("We never share your phone number with Twilio or any other provider.", {}),
    ("We share your email address with Mixpanel and do not sell it.",     {P.EMAIL: {"mixpanel"}}),
    # D9 matching: "company" is not PAN, "email address" is not location
    ("Our company sends your email address to Mixpanel.",                 {P.EMAIL: {"mixpanel"}}),
])
def test_D15_pass3_disclosure_matching(text, expected):
    assert disclosed(text) == expected


def test_rule_2_disclosed_sdk_is_downgraded_to_8_2_medium():
    f = [finding(P.EMAIL, "mixpanel", "mixpanel.track('signup', email)")]
    v = run_dpdp_rules(f, f, set(), disclosed_sdks={P.EMAIL: {"mixpanel"}})
    assert [(x.dpdp_section, x.severity) for x in v] == [("Section 8(2)", "medium")]


def test_rule_2_http_sink_is_never_treated_as_disclosed():
    f = [finding(P.EMAIL, "requests.post", "requests.post(URL, json=email)")]
    v = run_dpdp_rules(f, f, set(), disclosed_sdks={P.EMAIL: {"requests.post"}})
    assert [(x.dpdp_section, x.section_title, x.severity) for x in v] == \
        [("Section 8(2)", "Third-Party Transmission — Undisclosed Data Processor", "high")]


def test_vagueness_is_low_severity():
    w = [{"pii_category": "email", "margin": 0.02, "top_label": "analytics", "sentence": "to improve services"}]
    v = run_dpdp_rules([], [], set(), vagueness_warnings=w)
    assert [(x.dpdp_section, x.severity) for x in v] == [("DPDP Rules 2025, Rule 3(b)(ii)", "low")]


def test_score_display_is_one_decimal():
    from scoring import format_score
    assert format_score(43.0467) == "43.0"
    assert format_score(0.0123) == "0.0123"
    assert calculate_compliance_score([], 0, 0)["score_display"] == "100.0"


# ══════════════════════════════════════════════════════════════════════════════
# Audit round 2 (A1–A20). Each test reproduces a defect found in the October
# code review; the number matches the review list.
# ══════════════════════════════════════════════════════════════════════════════

# ── A1: sentence splitting must not break "segment.com" ───────────────────────

def test_A1_segment_dot_com_is_a_disclosure():
    assert disclosed("We share your email address with Segment.com for analytics.") \
        == {P.EMAIL: {"segment"}}


def test_A1_sentence_splitter_keeps_domains_and_splits_semicolons():
    assert pp._split_sentences("Visit segment.com today. Next one; third!") \
        == ["Visit segment.com today", "Next one", "third"]


# ── A2: taint seeding must not taint receiver objects ─────────────────────────

def test_A2_receiver_object_on_pii_line_is_not_tainted():
    f, _ = scan("svc/view.py", 'email = request.form["email"]\nprint(request.method)\n')
    assert not [x for x in f if x.source == "taint_analysis"]


def test_A2_assigned_variable_is_still_tainted():
    f, _ = scan("svc/view.py", 'contact = request.form["email"]\nprint(contact)\n')
    assert any(x.source == "taint_analysis" and x.line_number == 2
               and x.pii_category == P.EMAIL for x in f)


# ── A3: PII words inside trailing comments are not findings ───────────────────

@pytest.mark.parametrize("path,src", [
    ("a.py", "x = compute()  # TODO store user email later\n"),
    ("a.js", "const x = compute(); // TODO store user email later\n"),
])
def test_A3_trailing_comment_is_not_pii(path, src):
    f, _ = scan(path, src)
    assert P.EMAIL not in cats(f)


# ── A4: '//' and '#' inside string literals are not comments ──────────────────

def test_A4_js_url_in_string_does_not_hide_sink():
    f, _ = scan("a.js", 'const u = "https://example.com/address"; console.log(u)\n')
    assert any(x.pii_category == P.LOCATION and x.third_party_sdk == "console.log" for x in f)


def test_A4_python_hash_in_string_does_not_hide_sink():
    f, _ = scan("a.py", 'tag = "#"; logger.info(email)\n')
    assert any(x.pii_category == P.EMAIL and x.third_party_sdk == "logger" for x in f)


def test_A4_comment_after_string_is_still_stripped():
    assert cs._strip_inline_comment('x = "a#b"  # note', "py") == 'x = "a#b"  '
    assert cs._strip_inline_comment("f('//x') // note", "js") == "f('//x') "


# ── A5: purpose keywords match whole words, not substrings of PII phrases ─────

@pytest.mark.parametrize("sentence,expected", [
    ("we collect health information about you", None),             # "inform" ⊂ "information"
    ("we store your bank account number securely", "security"),     # "account" ⊂ "bank account"
    ("we use your email address to send appointment reminders", "communication"),
    ("we use your phone number to send marketing offers and support your account", "marketing"),
    ("we use the latest techniques", None),                          # "test" ⊂ "latest"
])
def test_A5_keyword_purpose_whole_words(sentence, expected):
    assert pp._keyword_purpose(sentence) == expected


# ── A17: a taint hit is kept even if Pass 1 found another category on the line ─

def test_A17_taint_kept_alongside_other_category_on_same_line():
    f, _ = scan("svc/a.py", 'contact = request.form["email"]\nprint(contact, phone)\n')
    line2 = {(x.pii_category, x.third_party_sdk) for x in f if x.line_number == 2}
    assert (P.PHONE, "print") in line2
    assert (P.EMAIL, "print") in line2


# ── A18: docstrings are found with ast, not by toggling on triple quotes ──────

def test_A18_code_after_multiline_string_constant_is_scanned():
    src = 'QUERY = """\nSELECT email FROM users\n"""\nprint(phone)\n'
    f, _ = scan("a.py", src)
    assert P.PHONE in cats(f)            # was skipped: closing """ re-opened "docstring" mode
    assert P.EMAIL in cats(f)            # SQL selecting email is real data handling


def test_A18_prefixed_docstring_is_skipped():
    src = 'def f():\n    r"""Docstring mentions aadhaar\n    and email here\n    """\n    return 1\n'
    f, _ = scan("a.py", src)
    assert f == []


# ── A6: gap categories are persisted, not rebuilt from the first 200 findings ─

from types import SimpleNamespace as _NS
from datetime import datetime as _dt


def _fake_scan(**kw):
    base = dict(id=1, repo_url="https://github.com/a/b", policy_url="https://x/p",
                created_at=_dt(2026, 10, 19, 12, 0), findings_count=1,
                violations_count=1, gaps_count=1, gap_categories=None)
    base.update(kw)
    return _NS(**base)


def _fake_violation(evidence="e", recommendation="r", severity="high"):
    return _NS(dpdp_section="Section 6(1)", section_title="t", severity=severity,
               pii_category="email", evidence=evidence, recommendation=recommendation)


def test_A6_scan_has_gap_categories_column():
    from database import Scan
    assert "gap_categories" in Scan.__table__.columns


def test_A6_persisted_gaps_win_over_stored_findings():
    from database import scan_gap_categories
    scan_ = _fake_scan(gap_categories='["email", "pan"]')
    assert scan_gap_categories(scan_, []) == ["email", "pan"]


def test_A6_old_scans_fall_back_to_findings():
    from database import scan_gap_categories
    rows = [_NS(pii_category="pan", is_gap=True), _NS(pii_category="email", is_gap=False),
            _NS(pii_category="pan", is_gap=True)]
    assert scan_gap_categories(_fake_scan(), rows) == ["pan"]


def test_A6_html_report_uses_persisted_gaps():
    from report_generator import generate_report_html
    html = generate_report_html(_fake_scan(gap_categories='["pan"]'), [], [], {})
    assert 'class="gap-tag">pan<' in html


# ── A7: report output is escaped ──────────────────────────────────────────────

def test_A7_html_report_escapes_evidence_and_narrative():
    from report_generator import generate_report_html
    v = _fake_violation(evidence='The flagged clause: "<script>alert(1)</script>"')
    html = generate_report_html(_fake_scan(), [v], [], {},
                                narrative="**Bold** <img src=x onerror=alert(1)>")
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html
    assert "<img src=x" not in html
    assert "<strong>Bold</strong>" in html


@pytest.mark.parametrize("evidence", ["<b>unclosed", "x <img src=x onerror=1>", "a < b & c"])
def test_A7_pdf_builds_with_markup_like_evidence(evidence):
    pytest.importorskip("reportlab")
    from pdf_generator import generate_pdf
    pdf = generate_pdf(_fake_scan(), [_fake_violation(evidence=evidence)], [],
                       {"color": "#28a745"}, narrative="**x** <b>y")
    assert pdf[:5] == b"%PDF-"


# ── A8: SSRF — every resolved address checked, redirects re-validated ─────────

@pytest.mark.parametrize("ip,blocked", [
    ("127.0.0.1", True), ("10.1.2.3", True), ("169.254.169.254", True),
    ("100.64.1.1", True), ("0.0.0.0", True), ("::1", True), ("fe80::1", True),
    ("::ffff:127.0.0.1", True), ("8.8.8.8", False),
])
def test_A8_ip_blocklist(ip, blocked):
    assert pp._ip_is_blocked(ip) is blocked


@pytest.mark.parametrize("url", ["http://[::1]/p", "http://100.64.0.5/p"])
def test_A8_validate_rejects_ipv6_loopback_and_cgnat(url):
    with pytest.raises(ValueError):
        pp.validate_policy_url(url)


class _Resp:
    def __init__(self, status, text="", headers=None):
        self.status_code, self.text, self.headers = status, text, headers or {}


def test_A8_redirect_to_internal_address_is_refused(monkeypatch):
    calls = []
    def fake_get(url, **kw):
        calls.append(kw)
        return _Resp(302, headers={"Location": "http://127.0.0.1/admin"})
    monkeypatch.setattr(pp.requests, "get", fake_get)
    with pytest.raises(ValueError):
        pp.fetch_policy_text("https://example.com/policy")
    assert len(calls) == 1 and calls[0].get("allow_redirects") is False


def test_A8_token_not_forwarded_off_github_on_redirect(monkeypatch):
    seen = []
    def fake_get(url, headers=None, **kw):
        seen.append((url, dict(headers or {})))
        if len(seen) == 1:
            return _Resp(302, headers={"Location": "https://8.8.8.8/policy.txt"})
        return _Resp(200, "We collect your email address.", {"Content-Type": "text/plain"})
    monkeypatch.setattr(pp.requests, "get", fake_get)
    pp.fetch_policy_text("https://raw.githubusercontent.com/a/b/main/P.md", github_token="T")
    assert "Authorization" in seen[0][1]
    assert "Authorization" not in seen[1][1]


# ── A9: short plain-text policies (raw GitHub URLs) are accepted ──────────────

def test_A9_short_plain_text_policy_is_accepted(monkeypatch):
    monkeypatch.setattr(pp.requests, "get", lambda url, **kw: _Resp(
        200, "We collect your email address to create your account.",
        {"Content-Type": "text/plain; charset=utf-8"}))
    text, _ = pp.fetch_policy_text("https://raw.githubusercontent.com/a/b/main/P.md")
    assert "email address" in text


def test_A9_short_html_page_is_still_rejected(monkeypatch):
    monkeypatch.setattr(pp.requests, "get", lambda url, **kw: _Resp(
        200, "<html><body>Page not found</body></html>", {"Content-Type": "text/html"}))
    with pytest.raises(ValueError):
        pp.fetch_policy_text("https://example.com/privacy")


# ── A10–A14: legal wording matches the Act's text ─────────────────────────────

def _undisclosed(cat=P.EMAIL):
    return run_dpdp_rules([finding(cat, "mixpanel", "mixpanel.track('x', v)")], [], set())


def test_A10_undisclosed_processor_is_cited_under_8_2_only():
    v = _undisclosed()
    assert [(x.dpdp_section, x.section_title) for x in v] == \
        [("Section 8(2)", "Third-Party Transmission — Undisclosed Data Processor")]
    # Section 5(1) does not require the notice to name recipients
    assert "Section 5 requires" not in v[0].evidence


def test_A10_disclosed_branch_does_not_claim_section_5_requires_recipients():
    f = [finding(P.EMAIL, "mixpanel", "mixpanel.track('signup', email)")]
    v = run_dpdp_rules(f, f, set(), disclosed_sdks={P.EMAIL: {"mixpanel"}})
    assert "Section 5" not in v[0].evidence


def test_A11_section_8_2_wording_is_valid_contract():
    for v in (_undisclosed()[0],
              run_dpdp_rules([finding(P.EMAIL, "mixpanel")], [], set(),
                             disclosed_sdks={P.EMAIL: {"mixpanel"}})[0]):
        assert "valid contract" in v.evidence
        assert "same DPDP obligations" not in v.evidence + v.recommendation


def test_A12_section_8_5_wording_is_reasonable_security_safeguards():
    v = run_dpdp_rules([finding(P.EMAIL, "logger", "logger.info(email)")], [], set())[0]
    assert v.dpdp_section == "Section 8(5)"
    assert "reasonable security safeguards" in v.evidence
    assert "appropriate technical" not in v.evidence
    assert "Rule 6(1)(a)" in v.recommendation


def test_A13_recommendations_do_not_invent_legal_requirements():
    sens = _undisclosed(P.AADHAAR)[0]
    assert "obtain separate explicit consent" not in sens.recommendation.lower()
    gap = run_dpdp_rules([finding(P.PAN)], [], {P.PAN})[0]
    assert "retained" not in gap.recommendation


def test_A14_llm_prompt_matches_the_act():
    import llm_client
    p = llm_client._SYSTEM_PROMPT
    assert "and third parties" not in p
    assert "distinct sensitivity" not in p
    assert "valid contract" in p
    assert "reasonable security safeguards" in p


# ── A16: spaCy receives the policy in its original case ───────────────────────

class _SpyNLP:
    def __init__(self): self.seen = []
    def __call__(self, text):
        self.seen.append(text)
        return []


def test_A16_spacy_gets_original_case(monkeypatch):
    spy = _SpyNLP()
    monkeypatch.setattr(pp, "_get_nlp", lambda: spy)
    raw = "We collect your Aadhaar number to verify your identity under Indian law."
    pp._pass2_extract_purposes(raw.lower(), {P.AADHAAR}, full_text_raw=raw)
    assert spy.seen and "Aadhaar" in spy.seen[0]


def test_A16_parse_privacy_policy_passes_raw_text_to_pass2(monkeypatch):
    raw = "We collect your Aadhaar number\nto verify your identity under Indian law."
    monkeypatch.setattr(pp, "validate_policy_url", lambda url: None)
    monkeypatch.setattr(pp, "fetch_policy_text", lambda url, tok=None: (" ".join(raw.split()).lower(), raw))
    spy = _SpyNLP()
    monkeypatch.setattr(pp, "_get_nlp", lambda: spy)
    pp.parse_privacy_policy("https://example.com/p")
    assert any("Aadhaar" in s for s in spy.seen)


# ── A19: Gemini tries the next model on timeouts and malformed responses ──────

def test_A19_gemini_falls_through_on_timeout_and_bad_payload(monkeypatch):
    import requests, llm_client
    monkeypatch.setattr(llm_client, "_GEMINI_KEY", "k")
    monkeypatch.setattr(llm_client, "_GEMINI_MODELS", ["m1", "m2", "m3"])
    calls = []

    class _R:
        def __init__(self, payload): self.status_code, self._p = 200, payload
        def raise_for_status(self): pass
        def json(self): return self._p

    def fake_post(url, **kw):
        calls.append(url)
        if len(calls) == 1:
            raise requests.Timeout("slow")
        if len(calls) == 2:
            return _R({"candidates": []})        # e.g. a safety-blocked reply
        return _R({"candidates": [{"content": {"parts": [{"text": " ok "}]}}]})

    monkeypatch.setattr(llm_client.requests, "post", fake_post)
    assert llm_client._call_gemini("sys", [{"role": "user", "content": "hi"}]) == "ok"
    assert len(calls) == 3


# ══════════════════════════════════════════════════════════════════════════════
# Audit round 3 (B1–B9): defects found by running the five synthetic repos.
# ══════════════════════════════════════════════════════════════════════════════

# ── B5: a phrase already counted for its category still consumes its span ────

def test_B5_email_address_bullet_does_not_disclose_location():
    assert policy_cats("We collect your email address.\n• Email address\n") == {P.EMAIL}


# ── B7: policies are split into units at bullets and headings ─────────────────

_LIST_POLICY = (
    "## 2. How We Use Your Information\n\n"
    "We use your personal information to:\n"
    "- Process and fulfil your orders\n"
    "- Send updates via SMS\n\n"
    "## 3. Data Sharing\n\n"
    "We share your information only with:\n"
    "- Twilio — for SMS order confirmations (phone number only)\n"
    "- Delivery partners — for order fulfilment (name and address only)\n"
)


def test_B7_bullets_become_units_with_their_lead_in():
    units = pp._policy_units(_LIST_POLICY)
    assert "We use your personal information to: Process and fulfil your orders" in units
    assert "We share your information only with: Twilio — for SMS order confirmations (phone number only)" in units
    assert not any("Twilio" in u and "name" in u for u in units)


def test_B7_sdk_disclosed_only_for_the_bullet_that_names_it():
    assert disclosed(_LIST_POLICY) == {P.PHONE: {"twilio"}}


def test_B7_html_block_tags_separate_units(monkeypatch):
    html = ("<h2>Data We Collect</h2><p>We collect your name and email address.</p>"
            "<h2>Third Parties</h2><p>We use Twilio to send SMS to your phone number.</p>")
    monkeypatch.setattr(pp.requests, "get", lambda url, **kw: _Resp(200, html, {"Content-Type": "text/html"}))
    _, raw = pp.fetch_policy_text("https://github.com/o/r/blob/main/p.html")
    units = pp._policy_units(raw)
    assert "We collect your name and email address" in units
    assert "We use Twilio to send SMS to your phone number" in units


# ── B8: generic "We use your information to…" purposes reach every category ──

def _purposes(text):
    _, seen = pp._pass1_extract_pii(text.lower(), text)
    pm, _ = pp._pass2_extract_purposes(text.lower(), seen, full_text_raw=text)
    return pm


def test_B8_generic_use_statement_applies_to_all_disclosed_categories():
    pm = _purposes("We collect your full name and email address.\n\n"
                   "We use your information to:\n- Send appointment reminders\n")
    assert "communication" in pm[P.NAME] and "communication" in pm[P.EMAIL]


def test_B8_negated_clause_contributes_no_purpose():
    pm = _purposes("We use your email address for login, not for marketing.\n")
    assert "marketing" not in pm.get(P.EMAIL, set())
    pm = _purposes("We collect your email address.\n\n"
                   "We use your data to provide the service and never for advertising.\n")
    assert "marketing" not in pm.get(P.EMAIL, set())


# ── B6: Presidio name/location hits only count in name-like string literals ───

class _FakeAnalyzer:
    def __init__(self, target, entity): self.target, self.entity = target, entity
    def analyze(self, text, language):
        i = text.find(self.target)
        return [] if i < 0 else [_NS(entity_type=self.entity, start=i,
                                     end=i + len(self.target), score=0.9)]


@pytest.mark.parametrize("line,target,entity,expected", [
    ('TWILIO_SID   = "ACxxxxxxxxxxxxxxxxxxxx"\n', "ACxxxxxxxxxxxxxxxxxxxx", "PERSON", False),
    ("print(Student.objects.count())\n", "Student", "PERSON", False),
    ("return response.json()\n", "response.json", "PERSON", False),
    ('owner_label = "Ravi Kumar"\n', "Ravi Kumar", "PERSON", True),
    ('city_label = "New Delhi"\n', "New Delhi", "LOCATION", True),
])
def test_B6_presidio_ner_only_in_name_like_strings(monkeypatch, line, target, entity, expected):
    monkeypatch.setattr(ps, "get_analyzer", lambda: _FakeAnalyzer(target, entity))
    f, _ = scan("a.py", line)
    cat = P.NAME if entity == "PERSON" else P.LOCATION
    assert (cat in cats(f)) is expected


# ── B2: SDK clients held in variables / imported under other names ────────────

def _sinks(f):
    return {(x.pii_category, x.third_party_sdk) for x in f if x.third_party_sdk}


def test_B2_sdk_client_variable_is_a_sink():
    src = ("import mixpanel\nmp = mixpanel.Mixpanel('T')\n\n"
           "def f(student):\n    mp.track(student.email, 'x')\n")
    assert (P.EMAIL, "mixpanel") in _sinks(scan("svc/a.py", src)[0])


@pytest.mark.parametrize("imp,body,label", [
    ("from twilio.rest import Client",
     "client = Client('a', 'b')\n    client.messages.create(to=user.phone_number)", "twilio"),
    ("import segment.analytics as analytics", "analytics.track(user.email, 'login')", "segment"),
    ("from firebase_admin import analytics", "analytics.log_event('x', user.email)", "firebase"),
])
def test_B2_imported_sdk_aliases(imp, body, label):
    src = f"{imp}\n\ndef f(user):\n    {body}\n"
    assert any(sdk == label for _, sdk in _sinks(scan("svc/a.py", src)[0]))


def test_B2_B3_js_alias_and_multiline_call():
    pytest.importorskip("tree_sitter_javascript")
    src = ("import mixpanel from 'mixpanel-browser';\n"
           "const mp = mixpanel.init('T');\n"
           "function f(u) {\n"
           "  mp.track('signup', {\n"
           "    email: u.email,\n"
           "    phone: u.phone,\n"
           "  });\n"
           "}\n")
    assert {(P.EMAIL, "mixpanel"), (P.PHONE, "mixpanel")} <= _sinks(scan("src/a.js", src)[0])


# ── B3: PII on continuation lines of a multi-line sink call ───────────────────

def test_B3_pii_on_continuation_lines_gets_the_call_sink():
    src = ("import segment.analytics as analytics\n\n"
           "def f(c):\n"
           "    analytics.track(c.email, 'loan', {\n"
           "        'pan_number': c.pan_number,\n"
           "        'aadhaar': c.aadhaar_number,\n"
           "    })\n")
    assert {(P.EMAIL, "segment"), (P.PAN, "segment"), (P.AADHAAR, "segment")} <= \
        _sinks(scan("svc/a.py", src)[0])


def test_B3_sdk_name_without_a_call_is_not_a_sink():
    f, _ = scan("svc/a.py", 'mixpanel_email_key = "x"\n')
    assert P.EMAIL in cats(f) and not _sinks(f)


# ── B1 / B4: field reads taint; a variable carries every category it holds ────

def test_B1_field_read_taints_the_payload():
    src = ("import requests\n\n"
           "def log_consultation(patient):\n"
           "    payload = {\n"
           "        'event': 'done',\n"
           "        'diagnosis': patient.latest_diagnosis,\n"
           "    }\n"
           "    requests.post(URL, json=payload)\n")
    f, _ = scan("svc/h.py", src)
    assert any(x.source == "taint_analysis" and x.pii_category == P.HEALTH
               and x.third_party_sdk == "requests.post" for x in f)


def test_B4_tainted_variable_carries_every_category():
    src = ("import requests\n\n"
           "def f(user_id, email, phone):\n"
           "    payload = {'email': email, 'phone': phone}\n"
           "    requests.post(URL, json=payload)\n")
    f, _ = scan("svc/u.py", src)
    assert {x.pii_category for x in f if x.source == "taint_analysis" and x.line_number == 5} \
        == {P.EMAIL, P.PHONE}


# ── B9: Aadhaar verification with the government (UIDAI) is not a processor ──

def test_B9_government_endpoint_is_not_a_third_party_processor():
    src = ('import requests\nUIDAI_URL = "https://uidai.gov.in/api/verify"\n\n'
           'def v(aadhaar_number):\n    return requests.post(UIDAI_URL, json={"uid": aadhaar_number})\n')
    assert not _sinks(scan("svc/a.py", src)[0])


def test_B9_ordinary_endpoint_is_still_a_sink():
    src = ('import requests\nAPI_URL = "https://api.example.com/verify"\n\n'
           'def v(aadhaar_number):\n    return requests.post(API_URL, json={"uid": aadhaar_number})\n')
    assert (P.AADHAAR, "requests.post") in _sinks(scan("svc/a.py", src)[0])


def test_B2_local_module_named_analytics_is_not_an_sdk():
    src = ("from services.analytics import track_course_progress\n"
           "from .analytics import helper\n\n"
           "def register(data):\n"
           "    student = Student.objects.create(date_of_birth=data['date_of_birth'])\n"
           "    track_course_progress(student)\n"
           "    helper(student)\n")
    assert not _sinks(scan("api/views.py", src)[0])


def test_B2_js_relative_import_is_not_an_sdk():
    pytest.importorskip("tree_sitter_javascript")
    src = ("import { track } from './analytics';\n"
           "function f(u) {\n  track(u.email);\n}\n")
    assert not _sinks(scan("src/a.js", src)[0])


# ── C1: Rule 3(b)(ii) vagueness needs more than a narrow embedding margin ─────

class _FakeST:
    """Every sentence scores 0.50 vs 0.48 on the top two purposes — the
    'ambiguous' margin short bullets get from all-MiniLM-L6-v2."""
    def encode(self, texts, normalize_embeddings=True):
        import numpy as np
        return np.array([[0.50, 0.48, 0.1, 0.1, 0.1, 0.1]])


def _vague_categories(text, monkeypatch):
    np = pytest.importorskip("numpy")
    monkeypatch.setattr(pp, "_get_st_model", lambda: (_FakeST(), np.eye(6)))
    _, seen = pp._pass1_extract_pii(text.lower(), text)
    _, warnings = pp._pass2_extract_purposes(text.lower(), seen, full_text_raw=text)
    return {w["pii_category"] for w in warnings}


@pytest.mark.parametrize("text,expected", [
    # one clear purpose in the wording → not vague
    ("We collect your email address.\n\nWe use your personal information to:\n"
     "- Process and fulfil your orders\n", set()),
    ("We use your name to personalise your experience.\n", set()),
    # no purpose stated at all → Rule 3 territory, not a vague purpose
    ("We collect your email address.\n", set()),
    # specific purposes outside the keyword vocabulary → not vague
    ("We collect your email address.\n\nWe use your information to:\n"
     "- Verify your identity\n- Issue completion certificates\n", set()),
    ("We collect the following information when you apply for a loan:\n- Email address\n", set()),
    ("Your email address is shared with Twilio solely for this purpose.\n", set()),
    # two purposes / no specific purpose behind "to" / "for" → vague
    ("We collect your email address to provide and improve our services.\n", {"email"}),
    ("We collect your email address for business purposes.\n", {"email"}),
])
def test_C1_vagueness_requires_ambiguous_wording(text, expected, monkeypatch):
    assert _vague_categories(text, monkeypatch) == expected


# ── C2: evidence says when the SDK IS disclosed, just not for this data ───────

def test_C2_partially_disclosed_sdk_evidence():
    v = run_dpdp_rules([finding(P.NAME, "twilio", "body=f'Dear {user.full_name}'")], [], set(),
                       disclosed_sdks={P.PHONE: {"twilio"}})[0]
    assert v.dpdp_section == "Section 8(2)" and v.severity == "high"
    assert "names 'twilio' as a recipient of phone data" in v.evidence
    assert "but not of 'name' data" in v.evidence


# ── C3: a marketing purpose does not cover analytics processing ───────────────

def test_C3_marketing_purpose_does_not_cover_analytics_module():
    v = run_dpdp_rules([finding(P.EMAIL)], [finding(P.EMAIL)], set(),
                       usage_map={P.EMAIL: {"analytics"}},
                       purpose_map={P.EMAIL: {"service_delivery", "marketing"}})
    assert sections(v) == ["Section 6(1)"]
    assert "['analytics']" in v[0].recommendation


def test_C3_stated_analytics_purpose_covers_analytics_module():
    v = run_dpdp_rules([finding(P.EMAIL)], [finding(P.EMAIL)], set(),
                       usage_map={P.EMAIL: {"analytics"}},
                       purpose_map={P.EMAIL: {"analytics"}})
    assert v == []
