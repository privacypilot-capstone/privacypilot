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
    # Queues (kafka, celery) are the application's own infrastructure and
    # requests.post with an unresolved URL has no known recipient: the
    # findings keep their sinks, but none is a Section 8(2) violation.
    assert {"requests.post", "kafka", "celery"} <= {x.third_party_sdk for x in f}
    assert "Section 8(2)" not in secs


def test_D4_js_http_sinks_raise_rule_2a():
    pytest.importorskip("tree_sitter_javascript")
    src = ('const email = req.body.email;\n'
           'const c = email;\n'
           'axios.post("https://x.io", { c });\n'
           'fetch("/api/save", { body: JSON.stringify({ c }) });\n')
    f, _ = scan("svc/a.js", src)
    sinks = {x.third_party_sdk for x in f if x.source == "taint_analysis"}
    # The recipient is named by the URL's host when it is a literal; a
    # relative URL cannot be resolved, so the call keeps its HTTP label.
    assert {"x.io", "fetch"} <= sinks
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
    text = "We collect:\n• Aadhaar number\n• Phone number\n• Home address\n• Fingerprint scans\n"
    assert {P.AADHAAR, P.PHONE, P.LOCATION, P.BIOMETRIC} <= policy_cats(text)
    # an IP address is a device identifier, not a person's location (the
    # code scanner excludes ip_address from location in the same way)
    assert P.LOCATION not in policy_cats("We collect:\n• IP address\n")


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
    f = [finding(P.EMAIL, "api.example.com", "requests.post(URL, json=email)")]
    v = run_dpdp_rules(f, f, set(), disclosed_sdks={P.EMAIL: {"api.example.com"}})
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
    f, _ = scan("a.js", 'const u = "https://example.com/"; console.log(address)\n')
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


def _offline_fetch(monkeypatch, fake_get):
    """Policy-fetch tests run offline: names resolve to a public address, and
    the pinned GET is routed to the fake `requests.get`."""
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])
    monkeypatch.setattr(pp, "_pinned_get", lambda url, ip, headers: fake_get(url, headers=headers, timeout=15, allow_redirects=False))
    monkeypatch.setattr(pp.requests, "get", fake_get)


def test_A8_redirect_to_internal_address_is_refused(monkeypatch):
    calls = []
    def fake_get(url, **kw):
        calls.append(kw)
        return _Resp(302, headers={"Location": "http://127.0.0.1/admin"})
    _offline_fetch(monkeypatch, fake_get)
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
    _offline_fetch(monkeypatch, fake_get)
    pp.fetch_policy_text("https://raw.githubusercontent.com/a/b/main/P.md", github_token="T")
    assert "Authorization" in seen[0][1]
    assert "Authorization" not in seen[1][1]


# ── A9: short plain-text policies (raw GitHub URLs) are accepted ──────────────

def test_A9_short_plain_text_policy_is_accepted(monkeypatch):
    _offline_fetch(monkeypatch, lambda url, **kw: _Resp(
        200, "We collect your email address to create your account.",
        {"Content-Type": "text/plain; charset=utf-8"}))
    text, _ = pp.fetch_policy_text("https://raw.githubusercontent.com/a/b/main/P.md")
    assert "email address" in text


def test_A9_short_html_page_is_still_rejected(monkeypatch):
    _offline_fetch(monkeypatch, lambda url, **kw: _Resp(
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
    _offline_fetch(monkeypatch, lambda url, **kw: _Resp(200, html, {"Content-Type": "text/html"}))
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
    def analyze(self, text, language, **kw):
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
    # The recipient is named by the URL's host.
    assert (P.AADHAAR, "api.example.com") in _sinks(scan("svc/a.py", src)[0])


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
    def encode(self, texts, normalize_embeddings=True, show_progress_bar=None):
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


# ══════════════════════════════════════════════════════════════════════════════
# Large-repository scans (ohcnetwork/care hit Celery's 600 s hard limit)
# ══════════════════════════════════════════════════════════════════════════════

# ── L1: Presidio runs once per file (batched), same results as per line ──────

def test_L1_batched_presidio_matches_per_line(monkeypatch):
    monkeypatch.setattr(ps, "get_analyzer", lambda: _FakeAnalyzer("Ravi Kumar", "PERSON"))
    texts = ['owner = "Ravi Kumar"', "x = compute_total(a, b)", 'ref = "2345 6789 0124"']
    batched = ps.scan_lines_with_presidio_spans(texts)
    assert batched == [ps.scan_text_with_presidio_spans(t) for t in texts]
    assert ("PERSON", 9, 19) in batched[0]


# ── L5: NER only runs on lines whose result could be accepted ────────────────

@pytest.mark.parametrize("line,needed", [
    ('owner = "Ravi Kumar"', True),          # name-like string → PERSON possible
    ('send(to="ops@example.com")', True),    # '@' → EMAIL_ADDRESS
    ("call(9876543210)", True),              # digit run → phone / Aadhaar
    ('pan = "ABCPE1234F"', True),            # PAN shape
    ("total = compute_total(a, b)", False),  # nothing NER could report
    ('status = "active"', False),            # lower-case string: no name
    ("print(Student.objects.count())", False),  # capitalised, but not in a string
])
def test_L5_ner_prefilter(line, needed):
    assert cs._needs_ner(line, "py") is needed


class _RecordingAnalyzer:
    def __init__(self): self.calls = []
    def analyze(self, text, language, **kw):
        self.calls.append((text, kw.get("entities")))
        return []


def test_L5_presidio_only_asked_for_used_entities_on_masked_lines(monkeypatch):
    rec = _RecordingAnalyzer()
    monkeypatch.setattr(ps, "get_analyzer", lambda: rec)
    ps.scan_lines_with_presidio_spans(["a = 1", 'b = "Ravi"'], ner_mask=[False, True])
    assert [t for t, _ in rec.calls] == ['b = "Ravi"']
    assert set(rec.calls[0][1]) == set(ps.NER_ENTITIES)




# ── S1–S8: any repository size — no file cap, no whole-scan deadline ─────────
# The repository is downloaded once (streamed to disk), split into bounded
# chunks, and each chunk is its own Celery task; a scan is failed only when
# progress stops. See tasks.py / scanners/repo_snapshot.py.

import io as _io
import json as _json
import tarfile as _tarfile

from scanners import repo_snapshot as rs


def _tar_bytes(files: dict) -> bytes:
    buf = _io.BytesIO()
    with _tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, text in files.items():
            data = text.encode()
            info = _tarfile.TarInfo(f"o-r-abc123/{path}")
            info.size = len(data)
            tar.addfile(info, _io.BytesIO(data))
    return buf.getvalue()


class _GhResp:
    def __init__(self, status=200, body=b"", js=None, headers=None):
        self.status_code, self._body, self._js = status, body, js
        self.headers = headers or {}
        self.content = body
    def json(self): return self._js
    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")
    def iter_content(self, chunk_size):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i:i + chunk_size]
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _fake_github_http(monkeypatch, files: dict, tarball_ok=True, calls=None):
    """Network double for repo_snapshot: repo metadata, commit, tarball,
    git tree and per-file contents."""
    blob = _tar_bytes(files)
    calls = calls if calls is not None else []

    def get(url, **kw):
        calls.append(url)
        if url.endswith("/repos/o/r"):
            return _GhResp(js={"default_branch": "main"})
        if "/commits/" in url:
            return _GhResp(js={"sha": "abc123"})
        if "/tarball/" in url:
            return _GhResp(body=blob) if tarball_ok else _GhResp(status=502)
        if "/git/trees/" in url:
            return _GhResp(js={"truncated": False, "tree": [
                {"type": "blob", "path": p, "size": len(t)} for p, t in files.items()]})
        if "/contents/" in url:
            path = url.split("/contents/", 1)[1]
            return _GhResp(body=files[path].encode())
        raise AssertionError(f"unexpected URL {url}")
    monkeypatch.setattr(rs.requests, "get", get)
    return calls


@pytest.fixture
def snapshot_root(tmp_path, monkeypatch):
    monkeypatch.setattr(rs, "SNAPSHOT_ROOT", tmp_path / "snapshots")
    return tmp_path / "snapshots"


def test_S1_no_file_count_or_size_caps_remain():
    for name in ("MAX_API_FILES", "MAX_FILES", "MAX_TARBALL_FILES",
                 "MAX_TARBALL_BYTES", "MAX_SOURCE_FILE_BYTES"):
        assert not hasattr(cs, name), name
    import inspect
    assert "deadline" not in inspect.signature(cs.scan_github_repo).parameters


def test_S2_whole_repo_is_scanned_past_the_old_caps(monkeypatch, snapshot_root):
    # 350 files: more than the old 300-file API cap, every one scanned,
    # all from ONE tarball download and no per-file API calls. Bundled
    # third-party and minified files are scanned too (tagged by origin).
    files = {f"app/m{i}.py": "email = request.form['email']\n" for i in range(350)}
    files["node_modules/lib/x.js"] = "const email = req.body.email;\n"
    files["web/vendor.min.js"] = "const email = req.body.email;\n"
    files["README.md"] = "# docs\n"
    calls = _fake_github_http(monkeypatch, files)
    findings, usage, cov = cs.scan_github_repo("https://github.com/o/r", "t")
    assert cov["total_source_files"] == cov["scanned"] == 352
    assert cov["failed"] == {}
    assert cov["origins"] == {"first_party": 350, "third_party": 1, "generated": 1}
    emails = [f for f in findings if f.pii_category == P.EMAIL]
    assert len([f for f in emails if f.origin == "first_party"]) == 350
    assert {f.origin for f in emails if f.file_path == "node_modules/lib/x.js"} == {"third_party"}
    assert {f.origin for f in emails if f.file_path == "web/vendor.min.js"} == {"generated"}
    assert sum("/tarball/" in u for u in calls) == 1
    assert not any("/contents/" in u for u in calls)


def test_S2_large_source_files_are_scanned_not_skipped(monkeypatch, snapshot_root):
    big = "x = 1\n" * 300_000 + "email = request.form['email']\n"   # ~1.8 MB
    _fake_github_http(monkeypatch, {"app/big.py": big})
    findings, _, cov = cs.scan_github_repo("https://github.com/o/r", "t")
    assert cov["scanned"] == 1 and any(f.pii_category == P.EMAIL for f in findings)


def test_S3_snapshot_downloaded_once_and_traversal_rejected(monkeypatch, snapshot_root):
    calls = _fake_github_http(monkeypatch, {"a.py": "x = 1\n", "../evil.py": "bad\n",
                                            "b/c.js": "y()\n"})
    ref = rs.RepoRef("o/r", "abc123")
    m1 = rs.ensure_snapshot(ref, "t")
    m2 = rs.ensure_snapshot(ref, "t")
    assert m1 == m2 and [f["path"] for f in m1["files"]] == ["a.py", "b/c.js"]
    assert sum("/tarball/" in u for u in calls) == 1
    assert not (snapshot_root.parent / "evil.py").exists()


def test_S4_api_fallback_lists_and_fetches_every_file(monkeypatch, snapshot_root):
    files = {f"app/m{i}.py": "email = request.form['email']\n" for i in range(5)}
    calls = _fake_github_http(monkeypatch, files, tarball_ok=False)
    monkeypatch.setattr(rs.time, "sleep", lambda s: None)
    findings, _, cov = cs.scan_github_repo("https://github.com/o/r", "t")
    assert cov["scanned"] == 5
    assert sum("/contents/" in u for u in calls) == 5


def test_S4_rate_limit_is_retried_not_failed(monkeypatch, snapshot_root):
    def get(url, **kw):
        return _GhResp(status=403, headers={"X-RateLimit-Remaining": "0",
                                          "X-RateLimit-Reset": str(int(rs.time.time()) + 30)})
    monkeypatch.setattr(rs.requests, "get", get)
    reader = rs.SnapshotReader(rs.RepoRef("o/r", "abc123"), "t")
    with pytest.raises(rs.RateLimited) as e:
        cs.scan_files(reader, ["app/a.py"])          # propagates to the task's retry
    assert 30 <= e.value.retry_after <= 40


@pytest.mark.parametrize("sizes", [[10] * 1000, [3_000_000, 5, 5], [1] * 7])
def test_S5_chunks_are_bounded_and_cover_every_file_once(sizes):
    files = [{"path": f"f{i}.py", "size": s} for i, s in enumerate(sizes)]
    chunks = rs.make_chunks(files, max_files=200, max_bytes=2 * 1024 * 1024)
    flat = [p for c in chunks for p in c]
    assert sorted(flat) == sorted(f["path"] for f in files)       # each exactly once
    by_size = {f["path"]: f["size"] for f in files}
    for c in chunks:
        assert len(c) <= 200
        assert len(c) == 1 or sum(by_size[p] for p in c) <= 2 * 1024 * 1024


def test_S6_chunk_time_limit_hands_unfinished_files_to_next_round(monkeypatch):
    import tasks
    from celery.exceptions import SoftTimeLimitExceeded
    seen = []

    def fake_scan_files(reader, paths):
        seen.extend(paths)
        if paths[0] == "c.py":
            raise SoftTimeLimitExceeded()
        return [], {}, {"scanned": list(paths), "failed": {}}
    monkeypatch.setattr(cs, "scan_files", fake_scan_files)
    out = tasks.run_chunk(None, ["a.py", "b.py", "c.py", "d.py"])
    assert out["scanned"] == ["a.py", "b.py"]
    assert out["unfinished"] == ["c.py", "d.py"]


@pytest.fixture
def mem_db(monkeypatch):
    """Fresh in-memory database shared by tasks.py and main.py."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    import database, tasks
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    database.Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    monkeypatch.setattr(tasks, "_db", Session)
    return Session


def _policy_payload():
    import tasks
    claim = DataFlowObject(source="policy_parser", raw_text="we collect email",
                           field_name="email", pii_category=P.EMAIL,
                           sensitivity=Sensitivity.PERSONAL)
    return {"claims": tasks._findings_to_json([claim]), "purpose_map": {},
            "vagueness": [], "disclosed": {}}


def test_S7_chunks_merge_across_rounds_into_one_complete_scan(mem_db):
    import tasks, database
    db = mem_db()
    scan = database.Scan(repo_url="https://github.com/o/r", policy_url="p",
                         status="running", files_total=4, files_done=0,
                         coverage=_json.dumps({"total_source_files": 4,
                                               "origins": {"first_party": 4}}))
    db.add(scan); db.commit(); sid = scan.id; db.close()

    def res(scanned, unfinished=(), failed=None, cat=P.EMAIL):
        f = [finding(cat, path=p) for p in scanned]
        return {"findings": f, "usage_map": {cat: {"api"}}, "scanned": list(scanned),
                "failed": failed or {}, "unfinished": list(unfinished)}

    tasks.save_chunk(sid, 0, 1, res(["a.py", "b.py"]))
    tasks.save_chunk(sid, 0, 1, res(["a.py", "b.py"]))          # re-delivered: no double count
    tasks.save_chunk(sid, 1, 1, res([], unfinished=["c.py", "d.py"]))
    tasks.save_chunk(sid, 1_000_000, 2, res(["c.py"], cat=P.PHONE))
    tasks.save_chunk(sid, 1_000_001, 2, res([], unfinished=["d.py"]))

    db = mem_db()
    assert db.query(database.Scan).get(sid).files_done == 3
    db.close()

    out = tasks.complete_scan(sid, _policy_payload())
    db = mem_db()
    scan = db.query(database.Scan).get(sid)
    cov = _json.loads(scan.coverage)
    assert scan.status == "complete" and scan.findings_count == 3
    assert cov["scanned"] == 3 and list(cov["failed"]) == ["d.py"]
    assert "time limit" in cov["failed"]["d.py"]
    assert "1 of 4 source files could not be scanned" in scan.error_message
    assert db.query(database.ScanChunk).count() == 0          # cleaned up
    assert out["coverage"]["failed"] == 1


def test_S8_big_scan_with_recent_progress_is_not_failed(mem_db):
    import main, database
    from datetime import datetime, timedelta
    db = mem_db()
    now = datetime.utcnow()
    long_ago = now - timedelta(hours=3)
    busy = database.Scan(repo_url="r", policy_url="p", status="running", phase="scanning",
                         created_at=long_ago, last_progress_at=now - timedelta(minutes=2))
    queued = database.Scan(repo_url="r", policy_url="p", status="queued", phase="queued",
                           created_at=long_ago, last_progress_at=long_ago)
    db.add_all([busy, queued]); db.commit()
    main._expire_if_stale(busy, db)
    main._expire_if_stale(queued, db)       # waiting behind `busy`, which is moving
    assert busy.status == "running" and queued.status == "queued"


def test_S8_scan_with_no_progress_anywhere_is_failed(mem_db):
    import main, database
    from datetime import datetime, timedelta
    db = mem_db()
    old = datetime.utcnow() - timedelta(minutes=40)
    dead = database.Scan(repo_url="r", policy_url="p", status="running", phase="scanning",
                         created_at=old, last_progress_at=old)
    db.add(dead); db.commit()
    main._expire_if_stale(dead, db)
    assert dead.status == "failed" and "stopped making progress" in dead.error_message


def test_S8_progress_payload():
    import main
    p = main._progress(_NS(phase="scanning", status="running", files_total=5210, files_done=1840,
                           files_seen=0, policy_state="parsing"))
    assert p == {"phase": "scanning", "files_total": 5210, "files_done": 1840,
                 "files_complete": 1840, "policy": "parsing", "percent": 35.3}


def test_S8_live_count_moves_before_a_chunk_is_saved_and_is_capped():
    import main
    # 37 files read inside running chunks, no chunk saved yet
    p = main._progress(_NS(phase="scanning", status="running", files_total=240, files_done=0,
                           files_seen=37, policy_state="queued"))
    assert (p["files_done"], p["files_complete"], p["percent"]) == (37, 0, 15.4)
    # a retried chunk can push files_seen past the total: never shown above it
    p = main._progress(_NS(phase="scanning", status="running", files_total=240, files_done=200,
                           files_seen=260, policy_state="done"))
    assert (p["files_done"], p["files_complete"]) == (240, 200)


def test_S8_run_chunk_reports_files_while_running(monkeypatch):
    import tasks
    import scanners.code_scanner as cs
    monkeypatch.setattr(cs, "scan_files", lambda reader, paths: ([], {}, {"scanned": paths, "failed": {}}))
    monkeypatch.setattr(tasks, "PROGRESS_EVERY_S", 0)
    seen = []
    out = tasks.run_chunk(None, ["a.py", "b.py", "c.py"], on_files=seen.append)
    assert sum(seen) == 3 and out["scanned"] == ["a.py", "b.py", "c.py"]
    # a failing progress callback never fails the chunk
    def boom(n): raise RuntimeError("db down")
    out = tasks.run_chunk(None, ["a.py"], on_files=boom)
    assert out["scanned"] == ["a.py"]



# ── S9–S15: third-party code, duplicates, all findings, worker/DB errors ─────

def test_S9_every_scannable_file_is_kept_with_its_origin():
    c = rs.classify_path
    assert c("src/app.py") == "first_party"
    assert c("node_modules/sdk/index.js") == "third_party"
    assert c("node_modules/sdk/dist/sdk.min.js") == "third_party"   # dependency wins
    assert c("vendor/lib/a.py") == "third_party"
    assert c("dist/app.js") == "generated"
    assert c("static/app.bundle.js") == "generated"
    assert c("types/index.d.ts") == "other"          # declarations: no code
    assert c("pkg/__pycache__/a.py") == "other"
    assert c("README.md") == "other"


def test_S9_usage_map_is_built_from_first_party_files_only():
    class R:
        files = {"analytics/track.py": "email = request.form['email']\n",
                 "node_modules/x/analytics.js": "const email = req.body.email;\n"}
        def get_contents(self, p):
            class C: pass
            c = C(); c.decoded_content = self.files[p].encode(); return c
    findings, usage, st = cs.scan_files(R(), list(R.files))
    assert st["scanned"] == list(R.files)
    assert {f.origin for f in findings} == {"first_party", "third_party"}
    # usage_map has the first-party module type only
    assert usage and all(usage.values())
    tp = [f for f in findings if f.origin == "third_party"]
    assert tp, "third-party file must still produce findings"


def test_S10_identical_bundled_copies_are_scanned_once():
    files = [
        {"path": "app/a.py", "size": 1, "origin": "first_party", "hash": "h1"},
        {"path": "app/b.py", "size": 1, "origin": "first_party", "hash": "h1"},  # first-party: never merged
        {"path": "node_modules/a/u.js", "size": 1, "origin": "third_party", "hash": "h2"},
        {"path": "node_modules/b/node_modules/a/u.js", "size": 1, "origin": "third_party", "hash": "h2"},
        {"path": "node_modules/c/u.ts", "size": 1, "origin": "third_party", "hash": "h2"},  # other language
    ]
    to_scan, dups = rs.plan_unique(files)
    assert [f["path"] for f in to_scan] == ["app/a.py", "app/b.py", "node_modules/a/u.js",
                                            "node_modules/c/u.ts"]
    assert dups == {"node_modules/b/node_modules/a/u.js": "node_modules/a/u.js"}


def test_S10_duplicate_findings_are_restored_at_finalize(mem_db):
    import tasks, database
    db = mem_db()
    dup = "node_modules/b/node_modules/a/u.js"
    scan = database.Scan(repo_url="r", policy_url="p", status="running", files_total=2,
                         files_done=0, coverage=_json.dumps({
                             "total_source_files": 3,
                             "origins": {"first_party": 1, "third_party": 2},
                             "duplicates": {dup: "node_modules/a/u.js"}}))
    db.add(scan); db.commit(); sid = scan.id; db.close()
    f1 = finding(P.EMAIL, path="app/a.py"); f1.origin = "first_party"
    f2 = finding(P.PHONE, path="node_modules/a/u.js"); f2.origin = "third_party"
    tasks.save_chunk(sid, 0, 1, {"findings": [f1, f2], "usage_map": {},
                                 "scanned": ["app/a.py", "node_modules/a/u.js"],
                                 "failed": {}, "unfinished": []})
    tasks.complete_scan(sid, _policy_payload())
    db = mem_db()
    rows = db.query(database.Finding).filter_by(scan_id=sid).all()
    assert sorted(r.file_path for r in rows) == sorted(["app/a.py", "node_modules/a/u.js", dup])
    assert {r.origin for r in rows if r.file_path == dup} == {"third_party"}
    cov = _json.loads(db.query(database.Scan).get(sid).coverage)
    assert cov["scanned"] == 3 and cov["duplicates_reused"] == 1


def test_S11_all_findings_stored_and_rules_scoped_by_origin(mem_db):
    import tasks, database
    db = mem_db()
    scan = database.Scan(repo_url="r", policy_url="p", status="running", files_total=2,
                         files_done=0, coverage=_json.dumps({"total_source_files": 2}))
    db.add(scan); db.commit(); sid = scan.id; db.close()
    many = []
    for i in range(450):                         # well past the old 200-row limit
        f = finding(P.EMAIL, path="app/a.py"); f.line_number = i + 1; f.origin = "first_party"
        many.append(f)
    # PHONE only appears in third-party code, inside a call to an SDK.
    tp = DataFlowObject(source="code_scanner", file_path="node_modules/sdk/i.js", line_number=3,
                        raw_text="mixpanel.track(phone)", field_name="phone",
                        pii_category=P.PHONE, sensitivity=Sensitivity.PERSONAL,
                        third_party_sdk="mixpanel", origin="third_party")
    tasks.save_chunk(sid, 0, 1, {"findings": many + [tp], "usage_map": {},
                                 "scanned": ["app/a.py", "node_modules/sdk/i.js"],
                                 "failed": {}, "unfinished": []})
    policy = _policy_payload()                   # discloses EMAIL only
    tasks.complete_scan(sid, policy)
    db = mem_db()
    scan = db.query(database.Scan).get(sid)
    assert db.query(database.Finding).filter_by(scan_id=sid).count() == 451
    # Rule 1 (notice gap) ignores PII seen only in third-party code ...
    assert _json.loads(scan.gap_categories) == []
    v = db.query(database.Violation).filter_by(scan_id=sid).all()
    assert not any(x.dpdp_section.startswith("Section 5") for x in v)
    # ... while Rule 2 (third-party transmission) reports it, saying where it is.
    r2 = [x for x in v if x.dpdp_section == "Section 8(2)" and x.pii_category == P.PHONE.value]
    assert r2 and "third-party code bundled" in r2[0].evidence


def test_S12_worker_without_the_scan_row_fails_with_the_cause(mem_db):
    import tasks
    with pytest.raises(tasks.ScanRowMissing) as e:
        tasks._require_scan(999)
    assert "different databases" in str(e.value) and "DATABASE_URL" in str(e.value)
    assert "pilot:pilot" not in str(e.value)          # never the credentials


def test_S12_chord_errback_marks_the_scan_failed(mem_db):
    import tasks, database
    db = mem_db()
    scan = database.Scan(repo_url="r", policy_url="p", status="running")
    db.add(scan); db.commit(); sid = scan.id; db.close()
    tasks.scan_failed_errback(None, RuntimeError("boom"), None, sid)
    db = mem_db()
    s = db.query(database.Scan).get(sid)
    assert s.status == "failed" and "boom" in s.error_message


def test_S12_api_reads_a_failed_task_from_celery(mem_db, monkeypatch):
    import main, database, tasks
    db = mem_db()
    scan = database.Scan(repo_url="r", policy_url="p", status="queued", task_id="t-1")
    db.add(scan); db.commit()

    class _Res:
        state = "FAILURE"
        result = tasks.ScanRowMissing("Scan 1 does not exist in the worker's database")
    monkeypatch.setattr(tasks.celery_app, "AsyncResult", lambda tid: _Res())
    main._check_task_failure(scan, db)
    assert scan.status == "failed" and "does not exist in the worker" in scan.error_message


def test_S13_worker_database_is_compared_by_instance_id(monkeypatch):
    import main, tasks
    from code_version import compute
    ver = compute()
    main._WORKER_DB_CACHE["at"] = None
    monkeypatch.setattr(main, "database_instance_id", lambda create=False: "A")
    monkeypatch.setattr(main, "_redis_reachable", lambda: True)
    monkeypatch.setattr(main, "describe_database_url", lambda: "postgresql://localhost:15432/pp")

    def workers(**w):
        monkeypatch.setattr(tasks, "worker_databases", lambda timeout=1.0: w)
        return main._worker_db_check(force=True)

    ok = workers(**{"celery@w1": {"database": "postgresql://db:5432/pp",
                                  "instance_id": "A", "code_version": ver}})
    assert ok["ok"] is True and ok["problem"] is None      # same DB, other host name
    bad = workers(**{"celery@w1": {"database": "sqlite:/app/privacypilot.db",
                                   "instance_id": "B", "code_version": ver}})
    assert bad["ok"] is False and "different database" in bad["problem"]
    fresh = workers(**{"celery@w1": {"database": "postgresql://db:5432/other",
                                     "instance_id": None, "code_version": ver}})
    assert fresh["ok"] is False and "never used by this API" in fresh["workers"]["celery@w1"]["status"]
    assert workers()["ok"] is None
    monkeypatch.setattr(main, "_redis_reachable", lambda: "Redis at redis://h:1/0 is not reachable: x")
    down = workers()
    assert down["redis_reachable"] is False and "Start Redis" in down["problem"]
    main._WORKER_DB_CACHE["at"] = None


def test_S13_worker_on_old_code_is_told_to_restart_not_wrong_database(monkeypatch):
    # The reported error: a worker started before this check existed answers
    # {"error": "KeyError('privacypilot_database')"}; that is old code, not
    # a different database.
    import main, tasks
    from code_version import compute
    monkeypatch.setattr(main, "database_instance_id", lambda create=False: "A")
    monkeypatch.setattr(main, "_redis_reachable", lambda: True)
    for reply in ({"error": "KeyError('privacypilot_database')"},
                  {"database": "postgresql://db:5432/pp", "instance_id": "A",
                   "code_version": "0ld0ld0ld0ld"}):
        monkeypatch.setattr(tasks, "worker_databases",
                            lambda timeout=1.0, r=reply: {"celery@2018e08112cc": r})
        chk = main._worker_db_check(force=True)
        assert chk["ok"] is False
        assert "older code" in chk["problem"] and "docker compose restart worker" in chk["problem"]
        assert "different database" not in chk["problem"]
    main._WORKER_DB_CACHE["at"] = None


def test_S13_code_version_ignores_line_endings(tmp_path, monkeypatch):
    import code_version as cv
    for d in ("scanners", "dpdp", "models"):
        (tmp_path / d).mkdir()
    (tmp_path / "tasks.py").write_bytes(b"a = 1\nb = 2\n")
    monkeypatch.setattr(cv, "_ROOT", tmp_path)
    v1 = cv.compute()
    (tmp_path / "tasks.py").write_bytes(b"a = 1\r\nb = 2\r\n")
    assert cv.compute() == v1
    (tmp_path / "scanners" / "x.py").write_bytes(b"c = 3\n")
    assert cv.compute() != v1


def test_S13_database_description_never_contains_credentials():
    import database
    d = database.describe_database_url("postgresql://pilot:secret@db:5432/privacypilot")
    assert d == "postgresql://db:5432/privacypilot" and "secret" not in d


def test_S14_findings_endpoint_pages_and_filters(mem_db):
    import main, database
    db = mem_db()
    scan = database.Scan(repo_url="r", policy_url="p", status="complete")
    db.add(scan); db.commit()
    for i in range(120):
        db.add(database.Finding(scan_id=scan.id, source="code_scanner", file_path=f"app/f{i}.py",
                                line_number=1, raw_text="x", field_name="email",
                                pii_category="email", sensitivity="personal",
                                origin="first_party"))
    for i in range(30):
        db.add(database.Finding(scan_id=scan.id, source="code_scanner",
                                file_path=f"node_modules/x/{i}.js", line_number=1,
                                raw_text="track(phone)", field_name="phone",
                                pii_category="phone", sensitivity="personal",
                                third_party_sdk="mixpanel", origin="third_party"))
    db.commit()
    page = main.get_scan_findings(scan.id, offset=100, limit=50, category=None, origin=None,
                                  sensitivity=None, transmitted=False, q=None, db=db)
    assert page["total"] == 150 and len(page["items"]) == 50
    assert page["facets"]["origin"] == {"first_party": 120, "third_party": 30}
    assert page["facets"]["transmitted"] == 30
    tp = main.get_scan_findings(scan.id, offset=0, limit=500, category=None,
                                origin="third_party", sensitivity=None, transmitted=False,
                                q=None, db=db)
    assert tp["total"] == 30 and all(i["origin"] == "third_party" for i in tp["items"])
    s = main.get_scan_findings(scan.id, offset=0, limit=50, category="email", origin=None,
                               sensitivity=None, transmitted=False, q="f11", db=db)
    assert {i["file_path"] for i in s["items"]} == {"app/f11.py"} | {f"app/f{n}.py" for n in range(110, 120)}


def test_S15_long_minified_line_is_analysed_in_windows(monkeypatch):
    from scanners import presidio_scanner as ps
    text = ("a" * 4500) + " someone@example.com " + ("b" * 4500)
    wins = ps._windows(text)
    assert all(len(w) <= ps.NER_WINDOW_CHARS for _, w in wins)
    assert "".join(w for _, w in wins[:1]) == text[:ps.NER_WINDOW_CHARS]
    assert wins[-1][0] + len(wins[-1][1]) == len(text)               # reaches the end
    at = text.index("someone@")

    class _R:
        def __init__(self, s, e): self.entity_type, self.start, self.end, self.score = "EMAIL_ADDRESS", s, e, 0.9

    class _A:
        def analyze(self, text, language, entities):
            i = text.find("someone@example.com")
            return [_R(i, i + 19)] if i >= 0 else []
    monkeypatch.setattr(ps, "get_analyzer", lambda: _A())
    import presidio_analyzer
    monkeypatch.setattr(presidio_analyzer, "BatchAnalyzerEngine",
                        lambda **kw: (_ for _ in ()).throw(RuntimeError("no batch")), raising=False)
    out = ps.scan_lines_with_presidio_spans([text], ner_mask=[True])[0]
    assert ("EMAIL_ADDRESS", at, at + 19) in out
    assert len([o for o in out if o[0] == "EMAIL_ADDRESS"]) == 1    # overlap: not doubled


# ── M1–M4: one recipient once, GET transmissions, one vague statement once,
#           metrics unit (23 Oct 2026) ──────────────────────────────────────

def test_M1_recipient_is_named_from_the_url_host():
    from scanners.sinks import recipient_for_url, sink_kind
    assert recipient_for_url("https://healthtrack-india.firebaseio.com/events.json") == "firebase"
    assert recipient_for_url("https://api.segment.io/v1/track") == "segment"
    assert recipient_for_url("https://maps.googleapis.com/maps/api/geocode/json") == "maps.googleapis.com"
    assert recipient_for_url("/api/save") is None and recipient_for_url(None) is None
    assert sink_kind("maps.googleapis.com") == "http" and sink_kind("firebase") == "sdk"


def test_M1_sdk_and_http_to_same_service_are_one_recipient():
    src = ('import requests\nfrom firebase_admin import analytics\n'
           'FIREBASE_URL = "https://demo.firebaseio.com"\n\n'
           'def t(patient):\n'
           '    payload = {"diagnosis": patient.latest_diagnosis}\n'
           '    analytics.log_event("x", payload)\n'
           '    requests.post(f"{FIREBASE_URL}/events.json", json=payload)\n')
    f, _ = scan("svc/a.py", src)
    v = [x for x in run_dpdp_rules(f, [], set()) if x.dpdp_section == "Section 8(2)"]
    assert [(x.pii_category, x.recipient) for x in v] == [("health", "firebase")]


def test_M1_js_url_constant_names_the_recipient():
    pytest.importorskip("tree_sitter_javascript")
    src = ('const SEGMENT_URL = "https://api.segment.io/v1/track";\n'
           'const email = req.body.email;\n'
           'axios.post(SEGMENT_URL, { email });\n'
           'fetch(`${SEGMENT_URL}?x=1`, { body: JSON.stringify({ email }) });\n'
           'axios.post("https://uidai.gov.in/verify", { aadhaarNumber });\n')
    f, _ = scan("svc/a.js", src)
    assert {x.third_party_sdk for x in f if x.third_party_sdk} == {"segment"}


def test_M2_get_request_with_coordinates_is_a_transmission():
    src = ('import requests\n\n'
           'def reverse_geocode(lat, lng):\n'
           '    url = "https://maps.googleapis.com/maps/api/geocode/json"\n'
           '    return requests.get(url, params={\n'
           '        "latlng": f"{lat},{lng}",\n'
           '    })\n')
    f, _ = scan("svc/geo.py", src)
    assert (P.LOCATION, "maps.googleapis.com") in _sinks(f)


def test_M3_vague_statements_are_one_violation_per_category():
    s = "We use your information to provide and improve our services."
    w = [{"pii_category": c, "margin": 0.02, "sentence": s, "top_label": "analytics",
          "statement_no": 3} for c in ("email", "name", "phone")]
    w.append({"pii_category": "email", "margin": 0.05, "sentence": "Other: for business purposes.",
              "top_label": "marketing", "statement_no": 9})
    v = [x for x in run_dpdp_rules([], [], set(), vagueness_warnings=w)
         if x.dpdp_section.startswith("DPDP Rules")]
    assert sorted(x.pii_category for x in v) == ["email", "name", "phone"]   # each category once
    email = next(x for x in v if x.pii_category == "email")
    assert [l["statement"] for l in email.locations] == [3, 9]               # both statements listed
    assert "2 purpose statements" in email.evidence and "0.020" in email.evidence


def _metrics():
    import importlib.util, pathlib
    path = pathlib.Path(__file__).resolve().parents[1] / "eval" / "compute_metrics.py"
    spec = importlib.util.spec_from_file_location("compute_metrics", path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def test_M4_metrics_dedupe_recipient_vagueness_and_contract_option():
    cm = _metrics()
    scan_result = {"violations": [
        {"dpdp_section": "Section 8(2)", "section_title": "Third-Party Transmission — Undisclosed Data Processor",
         "pii_category": "health", "recipient": "firebase"},
        {"dpdp_section": "Section 8(2)", "section_title": "Third-Party Transmission — Undisclosed Data Processor",
         "pii_category": "health", "recipient": "firebase"},                      # duplicate
        {"dpdp_section": "Section 8(2)", "section_title": "Third-Party Transmission — Processor Contract Unverified",
         "pii_category": "phone", "recipient": "twilio"},
        {"dpdp_section": "DPDP Rules 2025, Rule 3(b)(ii)", "section_title": "Vague Purpose Statement",
         "pii_category": "email", "recipient": None},
    ]}
    counted = cm.actual_violations(scan_result, "count")
    ignored = cm.actual_violations(scan_result, "ignore")
    assert len(counted) == 3 and len(ignored) == 2
    gt = [{"rule": "rule_2_third_party", "pii_category": "health", "recipient": "firebase"},
          {"rule": "vagueness", "pii_category": "email"}]
    m = cm.match_repo(gt, ignored)
    assert (m["strict_tp"], m["fn"], m["fp"]) == (2, 0, 0)
    # wrong recipient: only a lenient (PARTIAL) match
    m = cm.match_repo([{"rule": "rule_2_third_party", "pii_category": "health",
                        "recipient": "twilio"}], ignored)
    assert (m["strict_tp"], m["lenient_tp"]) == (0, 1)


# ── N: one violation per issue, every location, nothing hidden ──────────────

def _f(cat, sdk=None, path="app.py", line=1, modules=None, origin=None, source="t"):
    f = finding(cat, sdk, "x", path, line)
    f.module_types = modules
    f.origin = origin
    f.source = source
    return f


def test_N1_every_location_is_listed_and_one_line_counts_once():
    fs = [_f(P.PHONE, "mixpanel", "a.py", 3),
          _f(P.PHONE, "mixpanel", "a.py", 3, source="taint_analysis"),   # same line, 2nd pass
          _f(P.PHONE, "mixpanel", "b.py", 9),
          _f(P.PHONE, "mixpanel", "vendor/x.js", 4, origin="third_party")]
    v = [x for x in run_dpdp_rules(fs, [], set()) if x.dpdp_section == "Section 8(2)"]
    assert len(v) == 1
    v = v[0]
    assert [(l["file"], l["line"]) for l in v.locations] == [("a.py", 3), ("b.py", 9), ("vendor/x.js", 4)]
    assert "3 locations" in v.evidence
    for loc in ("a.py line 3", "b.py line 9", "vendor/x.js line 4 [third-party code]"):
        assert loc in v.evidence
    assert v.to_dict()["locations"] == v.locations


def test_N2_local_log_calls_are_one_recipient():
    fs = [_f(P.EMAIL, "print", "a.py", 1), _f(P.EMAIL, "logger", "b.py", 2),
          _f(P.EMAIL, "console.log", "c.js", 3)]
    v = run_dpdp_rules(fs, [], set())
    assert len(v) == 1 and v[0].dpdp_section == "Section 8(5)"
    assert v[0].recipient == "application logs"
    assert "a.py line 1 (print)" in v[0].evidence and "c.js line 3 (console.log)" in v[0].evidence


def test_N3_external_logging_service_reports_8_5_and_8_2_in_one_violation():
    v = run_dpdp_rules([_f(P.AADHAAR, "sentry", "a.py", 5)], [], set())
    assert len(v) == 1
    v = v[0]
    assert v.dpdp_section == "Section 8(5) / Section 8(2)"
    assert v.recipient == "sentry" and v.severity == "critical"
    assert "does not name 'sentry'" in v.evidence and "Section 8(2)" in v.evidence
    # named in the policy: still both provisions, but the evidence says so
    d = run_dpdp_rules([_f(P.AADHAAR, "sentry", "a.py", 5)], [], set(),
                       disclosed_sdks={P.AADHAAR: {"sentry"}})[0]
    assert "names 'sentry' as a recipient of this data" in d.evidence
    # a local logger and Sentry for the same data are two recipients
    both = run_dpdp_rules([_f(P.AADHAAR, "sentry"), _f(P.AADHAAR, "print", line=2)], [], set())
    assert sorted(x.recipient for x in both) == ["application logs", "sentry"]


def test_N3_policy_naming_sentry_is_read_as_disclosure():
    from scanners.sinks import sdks_named_in
    assert {"sentry", "datadog"} <= sdks_named_in("errors are reported to sentry and datadog.")


def test_N4_notice_gap_states_the_purposes_rule_3_would_have_reported():
    fs = [_f(P.PHONE, None, "services/analytics.py", 4, modules=["analytics"]),
          _f(P.PHONE, None, "api/views.py", 8, modules=["api"])]
    v = run_dpdp_rules(fs, [], {P.PHONE}, usage_map={P.PHONE: {"analytics", "api"}},
                       purpose_map={})
    assert [x.dpdp_section for x in v] == ["Section 5 / Section 6(1)"]   # no separate Rule 3
    e = v[0].evidence
    assert "services/analytics.py line 4 (module: analytics)" in e and "api/views.py line 8 (module: api)" in e
    assert "analytics, service_delivery" in e
    assert "analytics, service_delivery" in v[0].recommendation


def test_N5_purpose_violation_lists_only_locations_in_the_uncovered_modules():
    fs = [_f(P.EMAIL, None, f"svc/a{i}.py", i, modules=["analytics"]) for i in range(1, 6)]
    fs.append(_f(P.EMAIL, None, "auth/login.py", 7, modules=["authentication"]))
    v = run_dpdp_rules(fs, fs, set(), usage_map={P.EMAIL: {"analytics", "authentication"}},
                       purpose_map={P.EMAIL: {"service_delivery"}})
    r3 = [x for x in v if x.dpdp_section == "Section 6(1)"]
    assert len(r3) == 1
    assert len(r3[0].locations) == 5                    # all five, not the first three
    assert "auth/login.py" not in r3[0].evidence        # its purpose IS stated


def test_N6_scanner_records_module_types_on_findings():
    f, _ = scan("services/analytics.py", "def track(user):\n    mixpanel.track('x', user.email)\n")
    assert f and all(x.module_types and "analytics" in x.module_types for x in f)


def test_N7_metrics_map_the_combined_logging_section():
    cm = _metrics()
    assert cm.rule_of("Section 8(5) / Section 8(2)") == "rule_2_third_party"


def test_N8_one_multi_line_call_is_one_location():
    src = ("import mixpanel\n"
           "def f(u):\n"
           "    mp = mixpanel.Mixpanel('t')\n"
           "    mp.track(u['email'], 'login', {\n"
           "        'phone': u['phone_number'],\n"
           "    })\n")
    f, _ = scan("svc/a.py", src)
    phone = [x for x in f if x.pii_category == P.PHONE and x.third_party_sdk == "mixpanel"]
    assert phone and {x.call_line for x in phone} == {4}
    v = [x for x in run_dpdp_rules(f, [], set()) if x.dpdp_section == "Section 8(2)"
         and x.pii_category == "phone"]
    assert len(v) == 1 and [(l["file"], l["line"]) for l in v[0].locations] == [("svc/a.py", 4)]


# ── R: the UI API, reports and exports list everything ───────────────────────

def _stored_scan(mem_db, n_findings=250, n_locs=40):
    import database
    db = mem_db()
    scan = database.Scan(repo_url="https://github.com/o/r", policy_url="p", status="complete",
                         findings_count=n_findings, violations_count=1, gaps_count=0,
                         gap_categories="[]")
    db.add(scan); db.commit()
    locs = [{"file": f"src/m{i}.py", "line": i} for i in range(1, n_locs + 1)]
    db.add(database.Violation(scan_id=scan.id, dpdp_section="Section 8(2)",
                              section_title="Third-Party Transmission — Undisclosed Data Processor",
                              severity="high", pii_category="email", recipient="mixpanel",
                              evidence=f"'email' data is transmitted to 'mixpanel' at {n_locs} locations",
                              recommendation="r", locations=_json.dumps(locs)))
    for i in range(n_findings):
        db.add(database.Finding(scan_id=scan.id, source="code_scanner", file_path=f"src/f{i}.py",
                                line_number=i + 1, raw_text=f"track(email_{i})", field_name="email",
                                pii_category="email", sensitivity="personal", origin="first_party"))
    db.commit()
    sid = scan.id
    db.close()
    return sid


def _client(mem_db):
    from fastapi.testclient import TestClient
    import main, database
    def _get_db():
        db = mem_db()
        try:
            yield db
        finally:
            db.close()
    main.app.dependency_overrides[database.get_db] = _get_db
    return TestClient(main.app), main


def test_R1_reports_list_every_finding_and_every_location(mem_db, monkeypatch):
    sid = _stored_scan(mem_db)
    client, main = _client(mem_db)
    monkeypatch.setattr(main, "generate_report_summary",
                        lambda d: (_ for _ in ()).throw(main.LLMNotConfiguredError()))
    try:
        html = client.get(f"/report/{sid}").text
        assert "All Code Findings (250)" in html
        assert html.count("track(email_") == 250                  # not the first 10
        assert "Locations (40)" in html and "src/m40.py line 40" in html
        pdf = client.get(f"/report/{sid}?format=pdf")
        assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
        res = client.get(f"/scans/{sid}/result").json()
        assert len(res["violations"][0]["locations"]) == 40
    finally:
        main.app.dependency_overrides.clear()


def test_R2_csv_exports_have_every_row(mem_db):
    import csv, io
    sid = _stored_scan(mem_db, n_findings=2500)
    client, main = _client(mem_db)
    try:
        rows = list(csv.reader(io.StringIO(client.get(f"/scans/{sid}/findings.csv").text.lstrip("﻿"))))
        assert rows[0][0] == "pii_category" and len(rows) == 2501
        v = list(csv.DictReader(io.StringIO(client.get(f"/scans/{sid}/violations.csv").text.lstrip("﻿"))))
        assert len(v) == 1 and v[0]["location_count"] == "40"
        assert v[0]["locations"].count(";") == 39
    finally:
        main.app.dependency_overrides.clear()


def test_R3_long_code_lines_and_vague_sentences_are_kept():
    long_line = "x = {'email': user.email, " + ", ".join(f"'k{i}': {i}" for i in range(60)) + "}"
    assert 200 < len(long_line) < cs.RAW_TEXT_MAX
    f, _ = scan("a.py", long_line + "\n")
    assert f and f[0].raw_text == long_line.strip()
    assert cs._snippet("y" * 5000).endswith("…") and len(cs._snippet("y" * 5000)) == cs.RAW_TEXT_MAX + 1


def test_R4_many_locations_are_counted_in_the_evidence_and_all_listed():
    fs = [_f(P.EMAIL, "mixpanel", f"s/{i}.py", i) for i in range(1, 11)]
    v = [x for x in run_dpdp_rules(fs, [], set()) if x.dpdp_section == "Section 8(2)"][0]
    assert "10 locations (all listed under Locations)" in v.evidence
    assert len(v.locations) == 10


# ── W: worker processes and the database ─────────────────────────────────────

def test_W1_each_worker_process_gets_its_own_database_connections(monkeypatch):
    import tasks, database
    calls = []
    monkeypatch.setattr(database.engine, "dispose", lambda close=True: calls.append(close))
    tasks._fresh_db_connections()
    assert calls == [False]          # drop inherited connections, don't close the parent's
    from celery import signals
    assert any(getattr(r[1], "__name__", "") == "_fresh_db_connections" or
               "_fresh_db_connections" in repr(r[1])
               for r in signals.worker_process_init.receivers)


def test_W2_a_transient_database_error_while_saving_is_retried(monkeypatch):
    import tasks
    from sqlalchemy.exc import DatabaseError
    attempts = []
    def flaky(*a):
        attempts.append(a)
        if len(attempts) < 2:
            raise DatabaseError("COMMIT", None, Exception("PGRES_TUPLES_OK and no message"))
    monkeypatch.setattr(tasks, "save_chunk", flaky)
    monkeypatch.setattr(tasks.time, "sleep", lambda s: None)
    tasks._save_with_retry(1, 0, 1, {})
    assert len(attempts) == 2
    # a persistent error still fails the task (and the scan, with the cause)
    monkeypatch.setattr(tasks, "save_chunk",
                        lambda *a: (_ for _ in ()).throw(DatabaseError("x", None, Exception("down"))))
    with pytest.raises(DatabaseError):
        tasks._save_with_retry(1, 0, 1, {})


def test_R5_vague_statement_is_located_in_the_policy():
    import database
    warnings = [{"pii_category": c, "margin": 0.02, "top_label": "service_delivery",
                 "sentence": "We use your information to improve our services.",
                 "statement_no": 14, "policy_url": "https://x.org/privacy"}
                for c in ("email", "phone")]
    v = run_dpdp_rules([], [], set(), vagueness_warnings=warnings)
    assert sorted(x.pii_category for x in v) == ["email", "phone"]
    for x in v:
        assert x.locations == [{"policy": "https://x.org/privacy", "statement": 14,
                                "text": "We use your information to improve our services."}]
    assert database.location_short(v[0].locations[0]) == "privacy policy statement 14"
    assert "statement 14" in database.location_label(v[0].locations[0])


def test_R6_every_vague_statement_is_kept_not_only_the_worst_per_category(monkeypatch):
    text = ("We use your email address to improve our services. "
            "We may use your email address for various business purposes.")
    monkeypatch.setattr(pp, "_get_nlp", lambda: None)
    class FakeST:
        pass
    # force both statements to look vague
    monkeypatch.setattr(pp, "_get_st_model", lambda: (FakeST(), object()))
    monkeypatch.setattr(pp, "_st_classify_purpose", lambda sent, m, t: ("service_delivery", 0.5, 0.48))
    monkeypatch.setattr(pp, "_is_vague_wording", lambda s: True)
    _, vw = pp._pass2_extract_purposes(text.lower(), {P.EMAIL}, full_text_raw=text)
    assert len(vw) == 2
    assert sorted(w["statement_no"] for w in vw) == [1, 2]



# ── I: improvements from the real-world reference set ────────────────────────

def test_I1_test_code_does_not_produce_violations(monkeypatch):
    from scanners.test_paths import is_test_path
    assert is_test_path("tests/test_client.py") and is_test_path("src/_tests_/a.test.ts")
    assert is_test_path("src/app/x.component.spec.ts") and is_test_path("a/b-spec.data.ts")
    assert not is_test_path("src/latest.ts") and not is_test_path("examples/index.js")
    f = [finding(P.AADHAAR, None, "x", "tests/test_customer.py", 3)]
    assert run_dpdp_rules(f, [], {P.AADHAAR}) == []
    monkeypatch.setenv("PRIVACYPILOT_INCLUDE_TEST_CODE", "1")
    assert [v.dpdp_section for v in run_dpdp_rules(f, [], {P.AADHAAR})] == ["Section 5 / Section 6(1)"]


def test_I2_queues_and_unresolved_calls_are_not_processors():
    for sink in ("celery", "kafka", "fetch", "axios.post", "requests.get"):
        assert run_dpdp_rules([finding(P.EMAIL, sink, "x")], [], set()) == [], sink
    v = run_dpdp_rules([finding(P.EMAIL, "api.partner.com", "x")], [], set())
    assert [x.recipient for x in v] == ["api.partner.com"]


def test_I3_new_sinks_are_recognised():
    assert canonical_sink("client = vision.ImageAnnotatorClient()") == "google-cloud-vision"
    assert canonical_sink("FCMPlugin.subscribeToTopic(district)") == "firebase"
    assert canonical_sink("s3.put_object(Bucket=b, Body=doc)") == "aws-s3"
    from scanners.sinks import recipient_for_url
    assert recipient_for_url("https://vision.googleapis.com/v1/images:annotate") == "google-cloud-vision"
    for lbl in ("google-cloud-vision", "aws-s3", "azure-blob", "gcs"):
        assert sink_kind(lbl) == "sdk"
    # sign-in SDKs and reCAPTCHA are not sinks (data comes from them / only a token goes)
    assert canonical_sink("grecaptcha.execute(key)") is None


def test_I4_router_location_ip_address_and_health_checks_are_not_pii():
    norm = lambda t: [c.value for c in cs._pass1_categories(cs._normalise_identifiers(t))]
    assert norm("this.location.back()") == [] and norm("window.location.href = u") == []
    assert norm("const ipAddress = req.ip") == [] and norm('app.get("/health", h)') == []
    assert norm("healthCheckService.check()") == []
    assert norm("user.location = loc") == ["location"] and norm("patient.health_record") == ["health"]
    assert norm("yearOfBirth = 1990") == ["date_of_birth"]


def test_I5_log_message_text_is_not_logged_data():
    f, _ = scan("a.js", 'console.log("email sent");\nconsole.log("found", email);\n')
    assert [(x.line_number, x.pii_category) for x in f if x.third_party_sdk == "console.log"] == [(2, P.EMAIL)]


def test_I6_vague_purpose_detection():
    assert pp.is_stock_vague("We use your information to: Improve our platform")
    assert not pp._is_vague_wording("We use your information to: Provide personalised learning experiences")
    terms = ("By accessing or Using the Website and/or providing your information, you are accepting "
             "the terms of our Privacy Policy and consent to the collection and use of the information")
    assert not pp.is_stock_vague(terms) and not pp._is_vague_wording(terms)
    assert pp._is_vague_wording("We use your data to provide, personalise and market our services")


def test_I7_stock_vague_statement_states_no_purpose(monkeypatch):
    monkeypatch.setattr(pp, "_get_nlp", lambda: None)
    monkeypatch.setattr(pp, "_get_st_model", lambda: (None, None))
    text = "We use your email address to improve our platform."
    purpose_map, vague = pp._pass2_extract_purposes(text.lower(), {P.EMAIL}, full_text_raw=text)
    assert P.EMAIL not in purpose_map                      # no stated purpose
    assert [w["pii_category"] for w in vague] == ["email"] and vague[0]["margin"] is None
    v = run_dpdp_rules([], [], set(), vagueness_warnings=vague)
    assert "stock wording" in v[0].evidence


def test_I8_vendored_libraries_and_parse_artefacts_do_not_log_user_data():
    from scanners.repo_snapshot import classify_path
    assert classify_path("src/assets/libs/semantic.min.js") != "first_party"
    assert classify_path("plugins/x/renderer/libs/pdf.worker.js") == "third_party"
    assert classify_path("lib/razorpay.js") == "first_party"
    f = finding(P.EMAIL, "console.log", "x", "vendor/x.js", 1); f.origin = "third_party"
    assert run_dpdp_rules([f], [], set()) == []
    assert list(cs._sink_lines("console.log", 10, 40)) == [10]
    assert list(cs._sink_lines("console.log", 10, 12)) == [10, 11, 12]
    assert list(cs._sink_lines("mixpanel", 10, 40)) == list(range(10, 41))


def test_I9_device_fingerprint_dea_numbers_and_generic_sdk_words_in_bundles():
    norm = lambda t: [c.value for c in cs._pass1_categories(cs._normalise_identifiers(t))]
    assert norm("private fingerprintInfo: any;") == [] and norm("fingerprint_hash = x") == ["biometric"]
    assert "MEDICAL_LICENSE" not in cs.PRESIDIO_MAP
    from scanners.repo_snapshot import classify_path
    assert classify_path("public/preview/script.min.1.1.js") == "generated"
    f = finding(P.NAME, "segment", "x", "libs/pdf.worker.js", 1); f.origin = "third_party"
    assert run_dpdp_rules([f], [], set()) == []
    g = finding(P.NAME, "mixpanel", "x", "vendor/sdk.js", 1); g.origin = "third_party"
    assert [v.recipient for v in run_dpdp_rules([g], [], set())] == ["mixpanel"]



# ── V: notice-level vagueness, specificity, generic improvements ─────────────

@pytest.mark.parametrize("sentence,kind", [
    ("We collect your email address to provide and improve our services.", "stock"),
    ("We collect your email address for business purposes.", "stock"),
    ("We use your data to operate and maintain the platform.", "vague"),
    ("We use your data to provide, personalise and market our services", "vague"),
    ("We use your name to personalise your experience.", "specific"),
    ("We use your phone number to send you OTPs and transaction alerts.", "specific"),
    ("We use your information to: Verify your identity", "specific"),
    ("We process your PAN to comply with KYC regulations.", "specific"),
    ("Your email address is shared with Twilio solely for this purpose.", "none"),
    ("We collect your email address.", "none"),
    ("By using the Website you agree to the terms of this Privacy Policy and consent "
     "to the use of your information.", "none"),
])
def test_V1_purpose_statement_specificity(sentence, kind):
    assert pp.purpose_statement_kind(sentence) == kind


def test_V2_vagueness_is_judged_for_the_whole_notice(monkeypatch):
    monkeypatch.setenv("PRIVACYPILOT_VAGUENESS_SCOPE", "notice")
    monkeypatch.setattr(pp, "_get_nlp", lambda: None)
    monkeypatch.setattr(pp, "_get_st_model", lambda: (None, None))
    vague_only = "We use your email address to improve our services."
    _, w = pp._pass2_extract_purposes(vague_only.lower(), {P.EMAIL}, full_text_raw=vague_only)
    assert [x["pii_category"] for x in w] == ["email"]
    # the same generic sentence next to a specific purpose for the same data
    both = vague_only + " We use your email address to send you payment receipts."
    _, w = pp._pass2_extract_purposes(both.lower(), {P.EMAIL}, full_text_raw=both)
    assert w == []


def test_V2b_default_scope_reports_every_generic_statement(monkeypatch):
    monkeypatch.delenv("PRIVACYPILOT_VAGUENESS_SCOPE", raising=False)
    monkeypatch.setattr(pp, "_get_nlp", lambda: None)
    monkeypatch.setattr(pp, "_get_st_model", lambda: (None, None))
    assert pp.vagueness_scope() == "statement"
    both = ("We use your email address to improve our services. "
            "We use your email address to send you payment receipts.")
    _, w = pp._pass2_extract_purposes(both.lower(), {P.EMAIL}, full_text_raw=both)
    assert [x["pii_category"] for x in w] == ["email"]


def test_V3_classifier_margin_alone_is_not_vagueness(monkeypatch):
    np = pytest.importorskip("numpy")
    monkeypatch.setattr(pp, "_get_st_model", lambda: (_FakeST(), np.eye(6)))
    text = ("We use this information to administer the account and provide the "
            "highest possible level of security to you.")
    _, w = pp._pass2_extract_purposes(text.lower(), {P.EMAIL}, full_text_raw=text)
    assert w == []          # 'security' and 'account' are specific


def test_V4_policy_disclosure_negation_and_non_personal_senses():
    assert P.AADHAAR not in policy_cats("We do not collect your Aadhaar number.")
    assert P.LOCATION not in policy_cats("We will address your grievances within 30 days.")
    assert P.LOCATION not in policy_cats("We collect your IP address to secure your account.")
    assert P.LOCATION not in policy_cats("We store data in server locations in India.")
    assert P.FINANCIAL not in policy_cats("We share data with banks and financial institutions.")
    assert P.LOCATION in policy_cats("We collect your home address to deliver orders.")


def test_V5_example_code_does_not_produce_violations(monkeypatch):
    from scanners.test_paths import is_example_path, counts_for_rules
    assert is_example_path("examples/index.js") and is_example_path("samples/app/main.py")
    assert not is_example_path("src/example_service.py")
    assert not counts_for_rules("examples/index.js")
    monkeypatch.setenv("PRIVACYPILOT_INCLUDE_EXAMPLE_CODE", "1")
    assert counts_for_rules("examples/index.js")


def test_V6_email_in_a_path_names_data_not_a_notification_module():
    assert "notification" not in cs.classify_module("src/app/signup-email-password/page.ts", "")
    assert "notification" in cs.classify_module("services/email_service.py", "")
    assert "analytics" in cs.classify_module("src/x.ts", "export function trackSignup(u) {}\n")


def test_V7_sink_gives_the_purpose_of_use():
    f, usage = scan("services/user.py", "def on_signup(user):\n    mixpanel.track(user.email, 'signup')\n")
    assert "analytics" in usage[P.EMAIL]
    assert any(x.third_party_sdk == "mixpanel" and "analytics" in x.module_types for x in f)


def test_V8_scoped_and_namespace_packages_resolve_to_their_sdk():
    pytest.importorskip("tree_sitter_javascript")
    src = ("import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';\n"
           "const s3 = new S3Client({});\n"
           "async function up(user) { await s3.send(new PutObjectCommand({Body: user.email})); }\n")
    assert (P.EMAIL, "aws-s3") in _sinks(scan("src/upload.js", src)[0])
    import ast as _ast
    assert cs._python_sdk_aliases(_ast.parse("from google.cloud import vision\n")) == {"vision": "google-cloud-vision"}
    assert cs._python_sdk_aliases(_ast.parse("from services import analytics\n")) == {}


def test_V9_document_analysis_service_receives_the_document_data():
    pytest.importorskip("tree_sitter_javascript")
    src = ('import vision from "@google-cloud/vision";\n'
           "const client = new vision.ImageAnnotatorClient();\n"
           "export async function readAadhaar(image) {\n"
           "  const [res] = await client.textDetection(image);\n"
           "  const aadhaarNumber = parse(res);\n"
           "  return { aadhaarNumber };\n}\n"
           "function other(user) { return user.email; }\n")
    f = scan("src/ocr.ts", src)[0]
    inferred = {(x.pii_category, x.third_party_sdk) for x in f if x.source == "scope_inference"}
    assert inferred == {(P.AADHAAR, "google-cloud-vision")}      # not the e-mail in other()
    v = run_dpdp_rules(f, [], set())
    tx = [x for x in v if x.dpdp_section == "Section 8(2)"]
    assert [x.pii_category for x in tx] == ["aadhaar"] and "inferred" in tx[0].evidence


def test_V10_taint_is_scoped_to_the_function():
    pytest.importorskip("tree_sitter_javascript")
    src = ("function a(user) {\n  const res = api.get(user.email);\n  return res;\n}\n"
           "function b() {\n  const res = load();\n  console.log(res);\n}\n"
           "function c(user) {\n  const res = api.get(user.email);\n  console.log(res);\n}\n")
    logged = {(x.line_number, x.pii_category) for x in scan("src/a.js", src)[0]
              if x.third_party_sdk == "console.log"}
    assert logged == {(11, P.EMAIL)}          # not line 7: b's `res` is another variable


def test_V11_this_is_never_tainted_but_its_fields_are():
    pytest.importorskip("tree_sitter_javascript")
    src = ("class P {\n  load(u) {\n    this.profile = u.phoneNumber;\n  }\n"
           "  show() {\n    console.log(this.title);\n    console.log(this.profile);\n  }\n}\n")
    logged = {(x.line_number, x.pii_category) for x in scan("src/p.ts", src)[0]
              if x.third_party_sdk == "console.log"}
    assert logged == {(7, P.PHONE)}


def test_V12_python_taint_is_scoped_and_follows_self_fields():
    src = ("def a(user):\n    data = user.email\n    return data\n\n"
           "def b():\n    data = load()\n    print(data)\n\n"
           "class S:\n    def set(self, u):\n        self.contact = u.phone_number\n"
           "    def show(self):\n        print(self.contact)\n        print(self.name_of_app)\n")
    logged = {(x.line_number, x.pii_category) for x in scan("svc.py", src)[0]
              if x.third_party_sdk == "print"}
    assert logged == {(13, P.PHONE)}


# ---- TypeScript parsing and chained-call sink labelling --------------------

def _ts_sinks(src, path):
    from scanners import code_scanner as cs
    return cs._js_call_sinks(src, path)


def test_ts_generics_do_not_produce_bogus_sinks():
    src = "const x = new Map<string, Array<number>>();\nfunction f(a: Array<string>) { return a.length; }\n"
    from scanners import code_scanner as cs
    labels = [s for s in (_ts_sinks(src, "a.ts") or [])]
    assert not any("console" in str(l) or "http" in str(l) for l in labels)


def test_chained_call_label_ignores_callback_body():
    from scanners import code_scanner as cs
    import tree_sitter  # noqa: F401
    tree = cs._js_parse("svc.load(r).then(async (d) => { console.log(d); });", "a.ts")
    src = b"svc.load(r).then(async (d) => { console.log(d); });"
    call = tree.root_node.children[0].children[0]
    text = cs._js_callee_text(call.child_by_field_name("function"), src)
    assert "console" not in text and text.endswith(".then")


def test_minified_bundle_scans_in_bounded_time():
    """A one-line bundle with thousands of nested functions must not make the
    taint analysis quadratic (it once exceeded the chunk time limit)."""
    import time
    from scanners import code_scanner as cs
    body = "var email=a.email;" + "".join(
        "function f%d(x){var y%d=x.email;return function(z){return y%d+z}}" % (i, i, i)
        for i in range(3000)) + "console.log(email);"
    src = "(function(){" + body + "})();"
    t = time.time()
    cs._js_taint_analysis(src, "bundle.min.js", [(1, cs.PIICategory.EMAIL)])
    assert time.time() - t < 20


def test_service_health_status_and_embedded_blobs_are_not_pii():
    from scanners import code_scanner as cs
    assert not cs._own_pii("CASSANDRA_HEALTH_FAILED")
    assert cs.PIICategory.HEALTH in cs._own_pii("patient_health")
    blob = "const icon = 'data:image/png;base64," + "aQBANk/IBANvpa+Z" * 40 + "';"
    assert not cs._pass1_categories(cs._normalise_identifiers(cs._blank_encoded_blobs(blob)))
    assert cs.PIICategory.FINANCIAL in cs._pass1_categories(cs._normalise_identifiers("account_number = 1"))


def test_service_health_identifiers_are_not_medical_data():
    from scanners import code_scanner as cs
    for t in ("checkPortalHealth", "checkDatabaseHealth", "portal.health.api", "Health Service is unavailable"):
        assert not cs._own_pii(t), t
    for t in ("patient_health", "healthRecords", "user.health"):
        assert cs.PIICategory.HEALTH in cs._own_pii(t), t


def test_minified_content_is_generated_even_with_ordinary_name():
    from scanners import code_scanner as cs
    class C:  # noqa
        def __init__(s, t): s.decoded_content = t.encode()
    class R:
        def __init__(s, t): s.t = t
        def get_contents(s, p): return C(s.t)
    body = "var a=1;" * 700 + "console.log(user.email);"          # one 5.6 KB line
    ordinary = "const email = user.email;\nconsole.log(email);\n"
    assert cs._looks_minified(body) and not cs._looks_minified(ordinary)
    assert not cs._own_pii("healthResponse") and cs.PIICategory.HEALTH in cs._own_pii("health_data")


# ── H: hardening of PrivacyPilot's own handling of secrets (report Table 22) ──

_GH = "ghp_" + "a" * 36


@pytest.fixture
def _vault(monkeypatch, tmp_path):
    import security
    monkeypatch.delenv("PRIVACYPILOT_TOKEN_KEY", raising=False)
    monkeypatch.setattr(security, "_KEY_FILE", tmp_path / ".token_key")
    monkeypatch.setattr(security, "_fernet", None)
    return security


def test_H1_token_is_encrypted_in_the_task_message(_vault):
    sealed = _vault.seal(_GH)
    assert sealed.startswith("pp1:") and _GH not in sealed
    assert _vault.unseal(sealed) == _GH
    assert _vault.unseal(_GH) == _GH            # an unsealed token (older queue, tests) still works
    assert _vault.seal(None) is None and _vault.unseal("") == ""
    assert (_vault._KEY_FILE.stat().st_mode & 0o077) == 0 or __import__("os").name == "nt"


def test_H1b_sealed_token_expires(_vault, monkeypatch):
    sealed = _vault.seal(_GH)
    monkeypatch.setattr(_vault, "TOKEN_TTL_S", -1)
    with pytest.raises(ValueError, match="expired"):
        _vault.unseal(sealed)


def test_H1c_workers_receive_the_sealed_token_and_use_the_plain_one(_vault, monkeypatch):
    import tasks
    seen = {}
    monkeypatch.setattr(pp, "parse_privacy_policy", lambda url, tok=None: seen.setdefault("tok", tok) and ([], {}, [], {}))
    tasks.parse_policy_task(" https://example.com/p".strip(), _vault.seal(_GH))
    assert seen["tok"] == _GH


def test_H2_secrets_never_reach_logs_or_error_messages(_vault, caplog):
    import logging
    _vault.install_log_redaction()
    sealed = _vault.seal(_GH)
    with caplog.at_level(logging.INFO):
        logging.getLogger("celery").info("Task failed args=[1, '%s', '%s'] Authorization: Bearer %s", sealed, _GH, _GH)
    # caplog's own handler sits below the logger-level filter, so the record is already redacted
    assert _GH not in caplog.text and sealed not in caplog.text and "***REDACTED***" in caplog.text
    assert "AIza" not in _vault.redact_secrets("https://g/v1:generate?key=AIza" + "b" * 35)


def test_H3_llm_receives_no_secrets_or_personal_values(monkeypatch):
    import llm_client
    sent = {}
    monkeypatch.setattr(llm_client, "_llm_call", lambda system, messages: sent.update(system=system, messages=messages) or "ok")
    scan_data = {"violations": [{"severity": "high", "dpdp_section": "Section 8(5)", "section_title": "t",
                                 "pii_category": "email", "evidence": "logs a.b@corp.in and 9876543210 with " + _GH}]}
    llm_client.chat_completion([{"role": "user", "content": "is ABCDE1234F exposed? key " + _GH}], scan_data)
    blob = sent["system"] + str(sent["messages"])
    for leak in ("a.b@corp.in", "9876543210", "ABCDE1234F", _GH):
        assert leak not in blob, leak
    assert "email" in blob                      # the category name is kept: the model needs it


def test_H4_policy_fetch_connects_to_the_validated_address(monkeypatch):
    import socket
    answers = iter([[(2, 1, 6, "", ("93.184.216.34", 0))], [(2, 1, 6, "", ("127.0.0.1", 0))]])
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: next(answers))   # DNS rebinding: public, then loopback
    got = []
    monkeypatch.setattr(pp, "_pinned_get", lambda url, ip, hdrs: got.append(ip) or _Resp(200, "ok"))
    pp._get_with_safe_redirects("https://rebind.example.com/privacy", {})
    assert got == ["93.184.216.34"]             # the second, loopback answer is never used


def test_H4b_pinned_get_sends_the_original_host_header():
    import http.server, threading
    seen = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen["host"] = self.headers["Host"]; self.send_response(200); self.end_headers(); self.wfile.write(b"policy")
        def log_message(self, *a): pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        r = pp._pinned_get(f"http://policy.example.test:{port}/privacy", "127.0.0.1", {})
        assert r.text == "policy" and seen["host"] == f"policy.example.test:{port}"
    finally:
        srv.shutdown()


def test_H5_ablation_switches_turn_components_off(monkeypatch):
    from scanners import code_scanner as cs
    saved = (cs._verhoeff_validate, cs._python_taint_analysis, cs._js_taint_analysis)
    try:
        assert cs._apply_ablation(set()) == set() and cs._verhoeff_validate is saved[0]
        cs._apply_ablation({"verhoeff", "taint"})
        assert cs._verhoeff_validate("123456789012") is True          # no check digit needed
        assert cs._python_taint_analysis("x = 1", "a.py", {}) == [] and cs._js_taint_analysis("x", "a.js", {}) == []
    finally:
        cs._verhoeff_validate, cs._python_taint_analysis, cs._js_taint_analysis = saved


def test_H6_scan_records_and_exposes_the_vagueness_setting(monkeypatch):
    import json, main
    from scanners.policy_parser import vagueness_scope
    monkeypatch.setenv("PRIVACYPILOT_VAGUENESS_SCOPE", "notice")
    assert vagueness_scope() == "notice"
    monkeypatch.delenv("PRIVACYPILOT_VAGUENESS_SCOPE")
    assert vagueness_scope() == "statement"
    class S: coverage = json.dumps({"scanned": 1, "total_source_files": 1, "vagueness_scope": "statement"})
    assert main._coverage_summary(S)["vagueness_scope"] == "statement"
    class Old: coverage = json.dumps({"scanned": 1, "total_source_files": 1})
    assert main._coverage_summary(Old)["vagueness_scope"] is None


# ── Demo requests (landing page "See demo") ───────────────────────────────────

def _demo_payload(main, **over):
    p = {"name": "Asha Rao", "email": "Asha@Example.com", "organisation": "Acme",
         "role": "DPO", "use_case": "Check our app", "accepted_terms": True,
         "consent_contact": True, "consent_updates": False,
         "notice_version": main.DEMO_NOTICE_VERSION}
    p.update(over)
    return p


def test_D1_demo_request_is_stored_with_its_consent(mem_db):
    import database
    client, main = _client(mem_db)
    try:
        r = client.post("/demo-requests", json=_demo_payload(main))
        assert r.status_code == 201, r.text
        db = mem_db()
        row = db.query(database.DemoRequest).one()
        assert row.email == "asha@example.com" and row.consent_contact and row.accepted_terms
        assert row.notice_version == main.DEMO_NOTICE_VERSION and row.consented_at is not None
        db.close()
    finally:
        main.app.dependency_overrides.clear()


def test_D2_demo_request_without_consent_or_valid_email_is_rejected(mem_db):
    import database
    client, main = _client(mem_db)
    try:
        for bad in ({"consent_contact": False}, {"accepted_terms": False},
                    {"email": "not-an-email"}, {"name": "  "}, {"notice_version": "old"}):
            assert client.post("/demo-requests", json=_demo_payload(main, **bad)).status_code == 422
        db = mem_db()
        assert db.query(database.DemoRequest).count() == 0      # nothing stored without consent
        db.close()
    finally:
        main.app.dependency_overrides.clear()


def test_D3_demo_requests_older_than_the_retention_period_are_deleted(mem_db):
    import database
    from datetime import datetime, timedelta
    client, main = _client(mem_db)
    try:
        db = mem_db()
        db.add(database.DemoRequest(name="Old", email="old@example.com", accepted_terms=True,
                                    consent_contact=True, notice_version="2025-01-01",
                                    consented_at=datetime.utcnow() - timedelta(days=main.DEMO_RETENTION_DAYS + 1)))
        db.commit(); db.close()
        assert client.post("/demo-requests", json=_demo_payload(main)).status_code == 201
        db = mem_db()
        assert [r.email for r in db.query(database.DemoRequest).all()] == ["asha@example.com"]
        db.close()
    finally:
        main.app.dependency_overrides.clear()
