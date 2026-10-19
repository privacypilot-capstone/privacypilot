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
    assert "Section 5 / Section 8(2)" in secs     # requests / kafka / celery
    sdks = {v_.evidence.split("transmitted to '")[1].split("'")[0]
            for v_ in v if v_.dpdp_section == "Section 5 / Section 8(2)"}
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
    assert "Section 5 / Section 8(2)" in sections(run_dpdp_rules(f, f, set()))


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
    assert sections(v) == ["Section 5 / Section 8(2)"]


def test_D5_blueprint_line_is_not_a_logger_finding():
    f, _ = scan("routes.py", "auth_bp = Blueprint('location', __name__)\n")
    assert all(x.third_party_sdk is None for x in f)


def test_legacy_raw_call_text_label_still_routes():
    # labels stored by the old scanner (raw call text) are still understood
    v = run_dpdp_rules([finding(P.EMAIL, 'axios.post("https://x.io", { c })')], [], set())
    assert sections(v) == ["Section 5 / Section 8(2)"]


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
    assert any(x.dpdp_section == "Section 5 / Section 8(2)" for x in v)   # firebase / twilio


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
    assert sections(v) == ["Section 5 / Section 8(2)"]


def test_vagueness_is_low_severity():
    w = [{"pii_category": "email", "margin": 0.02, "top_label": "analytics", "sentence": "to improve services"}]
    v = run_dpdp_rules([], [], set(), vagueness_warnings=w)
    assert [(x.dpdp_section, x.severity) for x in v] == [("DPDP Rules 2025, Rule 3(b)(ii)", "low")]


def test_score_display_is_one_decimal():
    from scoring import format_score
    assert format_score(43.0467) == "43.0"
    assert format_score(0.0123) == "0.0123"
    assert calculate_compliance_score([], 0, 0)["score_display"] == "100.0"
