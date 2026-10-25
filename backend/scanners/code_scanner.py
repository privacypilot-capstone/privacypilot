"""
Code Scanner
============
Two-pass PII detection over GitHub source files, extended with:

  Pass 1  — Regex keyword matching (10 PII categories) on identifier tokens;
             camelCase identifiers are normalised to snake_case first, and a
             line may yield several categories (longest match wins overlaps)
  Pass 2  — Microsoft Presidio NER + India regex (for lines missed by regex);
             Aadhaar values must pass Verhoeff, PAN values the PAN structure
  Sinks   — a line's sink is the sink CALL that encloses it (Python `ast`,
             JS/TS tree-sitter), so PII on continuation lines of a
             multi-line call is attributed; SDK clients held in variables or
             imported under other names (`mp = mixpanel.Mixpanel()`,
             `from twilio.rest import Client`) are resolved as aliases;
             government verification endpoints (*.gov.in) are not sinks
  Taint   — AST taint analysis: propagate sets of PII labels through
             assignments (tainted names, PII field reads `p.blood_group`,
             PII keys `d['email']`) to sink call sites
             (Python via `ast`; JS/TS via tree-sitter-javascript)
  Classify— Module classifier: file path tokens + AST function names
             → usage_map {PIICategory → set[module_type]}

Sinks are labelled by scanners/sinks.py (shared with the rule engine), so a
finding's `third_party_sdk` is always a canonical label the engine recognises.

Additional:
  - Verhoeff checksum validation for Aadhaar numbers (both passes;
    shared implementation in presidio_scanner.verhoeff_checksum_valid)
  - Returns (findings, usage_map) for Rule 3 cross-reference

Scale: this module scans a given LIST of files (scan_files). Getting the
repository onto disk (scanners/repo_snapshot.py) and spreading the files over
many short Celery tasks (tasks.py) happen elsewhere, so there is no file-count
cap and no whole-scan deadline here.
"""

import ast
import re

from models.dataflow import DataFlowObject, PIICategory, Sensitivity
from scanners.presidio_scanner import scan_lines_with_presidio_spans, verhoeff_checksum_valid
from scanners.sinks import canonical_sink, sink_kind, recipient_for_url, url_host

# Bare schema / field-declaration lines (Django ORM `field = models.XField(...)`,
# SQLAlchemy `col = Column(...)`, dataclass/pydantic `field: Type = Field(...)`,
# etc.) carry no literal PII *value* — only a field *name* and a type
# constructor call. Pass 1's keyword regex already matches PII-sounding field
# names on these lines; anything Pass 1 doesn't match here has nothing for an
# NLP model to legitimately find, since there is no natural-language content
# or literal data on the line at all. Running spaCy/Presidio NER on these
# lines anyway produces demonstrated false positives — e.g. the bare
# identifier "created_at" gets tagged LOCATION and "is_active" gets tagged
# NRP, purely from the model treating snake_case/camelCase identifiers as
# natural-language tokens. Skip Pass 2 for this line shape.
_BARE_FIELD_DECL_RE = re.compile(r'^\s*[A-Za-z_][A-Za-z0-9_]*\s*[:=]\s*[A-Za-z_][\w.]*\s*\(')

# File types scanned. JSX/TSX and ES-module extensions are included because
# most React / Node front-ends keep their PII-handling code there.
PY_EXTS = ('.py',)
JS_EXTS = ('.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs')
SCAN_EXTS = PY_EXTS + JS_EXTS

# ── PII regex patterns ────────────────────────────────────────────────────────
# Each pattern is matched against the line after camelCase → snake_case
# normalisation and lower-casing (see _normalise_identifiers), with *token*
# boundaries: a keyword may sit between underscores ("customer_email",
# "aadhaar_no", "bank_account_number") but not inside a longer word
# ("expand", "fingerprinter" are not "pan"/"fingerprint" hits on their own).
# Multi-word alternatives are listed so that, when two categories overlap on
# one identifier ("email_address"), the longest match wins.

PII_PATTERNS = {
    PIICategory.AADHAAR:   r'aadhaar_number|aadhar_number|aadhaar_no|aadhar_no|aadhaar|aadhar',
    PIICategory.PAN:       r'pan_number|pan_card|pan_no|pancard',
    PIICategory.PHONE:     r'phone_number|mobile_number|contact_number|mobile_no|phone_no|phone|mobile',
    PIICategory.EMAIL:     r'email_address|user_email|email_id|email',
    # lat / lng / latlng: the usual short names of coordinates (latLng → lat_lng)
    # 'location' is also the browser / router location object
    # (window.location.href, this.location.back()) and 'address' an IP, MAC
    # or server address: those are not a person's location.
    PIICategory.LOCATION:  (r'latitude|longitude|latlng|lat|lng|gps'
                            r'|(?<!window\.)(?<!document\.)location(?!\s*\.\s*(?:href|back|forward|go|path|pathname|reload|replace|hash|search|origin|host|hostname|protocol|assign|port)\b)(?!_?(?:strategy|service|href|path|change|state|listener))'
                            r'|(?<!ip_)(?<!mac_)(?<!server_)(?<!host_)(?<!remote_)(?<!base_)(?<!socket_)(?<!wallet_)address'),
    # 'health' as in health checks, health endpoints and liveness probes is
    # service monitoring, not health data.
    PIICategory.HEALTH:    r'blood_group|(?<!/)(?<!service_)(?<!server_)(?<!system_)(?<!app_)health(?!_?(?:check|z|endpoint|status|probe|ping|service|monitor|route|url|api|handler))|medical|diagnosis|disease',
    PIICategory.FINANCIAL: r'bank_account|account_no|ifsc|credit_card|salary',
    PIICategory.NAME:      r'full_name|first_name|last_name|username',
    PIICategory.DOB:       r'date_of_birth|birth_date|birthdate|dob|year_of_birth|birth_year|yob',
    # A browser / device fingerprint (fingerprint_info, fingerprintjs) is a
    # device identifier, not a biometric.
    PIICategory.BIOMETRIC: r'(?<!device_)(?<!browser_)fingerprint(?!_?(?:info|details?|js|2|components?|v1|v2|id))|iris|face_id|biometric',
}
_TOKEN_L = r'(?<![a-z0-9])'
_TOKEN_R = r'(?![a-z0-9])'
_PII_RX = {
    cat: re.compile(_TOKEN_L + r'(?:' + alts + r')' + _TOKEN_R)
    for cat, alts in PII_PATTERNS.items()
}

_CAMEL_RE_1 = re.compile(r'([a-z0-9])([A-Z])')
_CAMEL_RE_2 = re.compile(r'([A-Z]+)([A-Z][a-z])')


def _normalise_identifiers(line: str) -> str:
    """phoneNumber → phone_number, aadhaarNo → aadhaar_no, then lower-case."""
    line = _CAMEL_RE_2.sub(r'\1_\2', line)
    line = _CAMEL_RE_1.sub(r'\1_\2', line)
    return line.lower()


_STR_LIT_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`')
_INTERP_RE = re.compile(r'\$\{([^}]*)\}|\{([^{}]*)\}')


def _blank_string_literals(code: str) -> str:
    """Replace the text of string literals with nothing, keeping template /
    f-string interpolations (`${email}`, f"{user.email}") because those are
    values written into the string."""
    def repl(m):
        lit = m.group(0)
        keep = " ".join(a or b for a, b in _INTERP_RE.findall(lit)) if lit[0] in "`\"'" else ""
        return '""' + ((" " + keep) if keep else "")
    return _STR_LIT_RE.sub(repl, code)


def _pass1_categories(norm_line: str) -> list[PIICategory]:
    """
    All PII categories on a (normalised) line. Overlapping matches are
    resolved longest-first, so "email_address" is EMAIL only, not also
    LOCATION via "address".
    """
    hits = []
    for cat, rx in _PII_RX.items():
        for m in rx.finditer(norm_line):
            hits.append((m.end() - m.start(), m.start(), m.end(), cat))
    hits.sort(key=lambda h: (-h[0], h[1]))
    taken: list[tuple[int, int]] = []
    cats: list[PIICategory] = []
    for _, s, e, cat in hits:
        if any(s < te and ts < e for ts, te in taken):
            continue
        taken.append((s, e))
        if cat not in cats:
            cats.append(cat)
    return cats


# ── Comment handling ──────────────────────────────────────────────────────────

# Longest code line stored with a finding. Ordinary source lines are kept
# whole; only longer ones (minified bundles, embedded data) are cut, and the
# cut is marked with "…" so a stored line is never mistaken for the full one.
RAW_TEXT_MAX = 1000


def _snippet(text: str) -> str:
    text = (text or "").strip()
    return text if len(text) <= RAW_TEXT_MAX else text[:RAW_TEXT_MAX] + "…"


def _strip_inline_comment(line: str, lang: str) -> str:
    """
    Return the code part of `line`, cutting at a Python `#` or a JS/TS `//`
    only when it sits OUTSIDE a string literal.

    The old `line.split('#')[0]` / `line.split('//')[0]` also cut inside
    strings, so `"https://…"` or `"#"` threw away the rest of the line —
    including any sink call after it (`… "https://x/address"; console.log(u)`
    lost the console.log). Quote state is tracked per line ('  "  and, for
    JS, the template-literal backtick), with backslash escapes honoured.
    """
    quotes = ('"', "'", '`') if lang == 'js' else ('"', "'")
    in_q = None
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if in_q:
            if ch == '\\':
                i += 2
                continue
            if ch == in_q:
                in_q = None
        elif ch in quotes:
            in_q = ch
        elif lang == 'py' and ch == '#':
            return line[:i]
        elif lang == 'js' and ch == '/' and i + 1 < n and line[i + 1] == '/':
            return line[:i]
        i += 1
    return line


def _string_spans(line: str, lang: str) -> list[tuple[int, int]]:
    """(start, end) character ranges of string-literal CONTENTS on a line
    (same quote rules as _strip_inline_comment)."""
    quotes = ('"', "'", '`') if lang == 'js' else ('"', "'")
    spans: list[tuple[int, int]] = []
    in_q, start = None, 0
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if in_q:
            if ch == '\\':
                i += 2
                continue
            if ch == in_q:
                spans.append((start, i))
                in_q = None
        elif ch in quotes:
            in_q, start = ch, i + 1
        elif (lang == 'py' and ch == '#') or (lang == 'js' and line.startswith('//', i)):
            break
        i += 1
    return spans


# Presidio's spaCy NER reads code as prose: it has tagged a Twilio account
# SID ("ACxxxx…"), a class name ("Student") and "response.json" as PERSON.
# On a line of code, a PERSON / LOCATION hit is only kept when it sits
# inside a string literal and looks like a proper name.
_NAME_LIKE_RE = re.compile(r"^[A-Z][a-z]+(?:[ .'\-]+[A-Z][a-z]+)*$")


_NAME_LIKE_TOKEN_RE = re.compile(r"[A-Z][a-z]+")


def _needs_ner(code_part: str, lang: str) -> bool:
    """
    Could Presidio report anything on this line that the scanner would KEEP?
    Running its spaCy pipeline is by far the most expensive step of a scan,
    so lines where no accepted result is possible are skipped. This changes
    no output:
      - PERSON / LOCATION are only kept inside a name-like string literal
        (_plausible_ner_span), so the line needs a string with a
        capitalised word;
      - EMAIL_ADDRESS needs '@';
      - PHONE_NUMBER, IN_AADHAAR and MEDICAL_LICENSE need a run of digits
        (5+ digits on the line is a deliberately loose bound);
      - IN_PAN is only kept when PAN_VALUE_RE matches.
    """
    if '@' in code_part or sum(ch.isdigit() for ch in code_part) >= 5:
        return True
    if PAN_VALUE_RE.search(code_part):
        return True
    return any(_NAME_LIKE_TOKEN_RE.search(code_part[s:e]) for s, e in _string_spans(code_part, lang))


def _plausible_ner_span(line: str, start: int, end: int, lang: str) -> bool:
    if not _NAME_LIKE_RE.match(line[start:end].strip()):
        return False
    return any(s <= start and end <= e for s, e in _string_spans(line, lang))


def _python_docstring_lines(source_text: str) -> set[int]:
    """
    Line numbers covered by bare string-expression statements (docstrings
    and standalone string "comments"), found with `ast`.

    Replaces the old text heuristic that toggled a "docstring" flag on every
    line starting with triple quotes. That heuristic (a) missed prefixed
    docstrings such as r\"\"\" … \"\"\", and (b) inverted after an assigned
    multi-line string (QUERY = \"\"\" … \"\"\"): the closing quotes were
    taken as an opening, so all code below was silently skipped. Assigned
    strings (SQL, templates) are data and ARE scanned. Files that do not
    parse get no docstring skipping.
    """
    try:
        tree = ast.parse(source_text)
    except (SyntaxError, ValueError):
        return set()
    skip: set[int] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            skip.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    return skip


# Aadhaar value pattern (12-digit, possibly spaced)
AADHAAR_VALUE_RE = re.compile(r'\b([2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4})\b')

# PAN structure: AAAAA9999A where the 4th letter is the holder type
# (P person, C company, H HUF, F firm, A AOP, T trust, B BOI, L local
# authority, J artificial juridical person, G government).
PAN_VALUE_RE = re.compile(r'\b[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z]\b')

# ── Sensitivity map ───────────────────────────────────────────────────────────

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

# Labels returned by scan_text_with_presidio(): Presidio entity types plus
# the India-regex labels from presidio_scanner.INDIA_PATTERNS ("AADHAAR",
# "PAN", "PHONE"). Both spellings of each India label are mapped.
PRESIDIO_MAP = {
    "PERSON":           (PIICategory.NAME,      Sensitivity.PERSONAL),
    "PHONE_NUMBER":     (PIICategory.PHONE,     Sensitivity.PERSONAL),
    "PHONE":            (PIICategory.PHONE,     Sensitivity.PERSONAL),
    "EMAIL_ADDRESS":    (PIICategory.EMAIL,     Sensitivity.PERSONAL),
    "AADHAAR":          (PIICategory.AADHAAR,   Sensitivity.SENSITIVE),
    "IN_AADHAAR":       (PIICategory.AADHAAR,   Sensitivity.SENSITIVE),
    "PAN":              (PIICategory.PAN,       Sensitivity.SENSITIVE),
    "IN_PAN":           (PIICategory.PAN,       Sensitivity.SENSITIVE),
    "LOCATION":         (PIICategory.LOCATION,  Sensitivity.PERSONAL),
    # MEDICAL_LICENSE is not mapped: Presidio's recogniser is for US DEA
    # registration numbers (two letters + seven digits), which in Indian code
    # matched document numbers ("AD0725981") and ids, and was reported as
    # health data.
}


# ── Aadhaar value validation ──────────────────────────────────────────────────
# The Verhoeff checksum itself (and its lookup tables) lives in
# presidio_scanner.py — imported above as verhoeff_checksum_valid — so this
# file and the Presidio-NER path can never silently drift apart on what
# counts as a structurally valid Aadhaar number.

# Kept as a name for older callers/tests that import it from here.
_verhoeff_validate = verhoeff_checksum_valid


def _aadhaar_candidates(line: str) -> list[str]:
    return [re.sub(r'\s', '', m.group(1)) for m in AADHAAR_VALUE_RE.finditer(line)]


def _validate_aadhaar(line: str) -> bool:
    """
    Pass 1 (keyword) gate. Return True if the line's Aadhaar keyword match
    should stand.

    - If the line contains a 12-digit candidate value, require at least one
      candidate to pass the Verhoeff checksum. A keyword match whose only
      numeric candidates all fail Verhoeff (timestamps, sequential IDs,
      random digit strings) is rejected — this is the false-positive filter
      described in Section IV-A of the paper.
    - If the line has no 12-digit candidate at all (e.g. a bare field name
      like `aadhaar_number = input_value`), there is nothing to checksum,
      so the keyword match is conservatively allowed to stand.
    """
    candidates = _aadhaar_candidates(line)
    if not candidates:
        return True
    return any(_verhoeff_validate(c) for c in candidates)


def _aadhaar_value_valid(line: str) -> bool:
    """
    Pass 2 (value) gate. A value-only Aadhaar hit has no keyword to fall back
    on, so it stands ONLY if some 12-digit candidate passes Verhoeff.
    (Before this gate, Pass 2 re-added numbers that Pass 1 had just rejected.)
    """
    return any(_verhoeff_validate(c) for c in _aadhaar_candidates(line))


def _pan_value_valid(line: str) -> bool:
    return bool(PAN_VALUE_RE.search(line))


# ── Module classifier ─────────────────────────────────────────────────────────
# Keywords are matched against whole *tokens* of the file path (split on
# / \ . _ - and camelCase), never raw substrings — so "login" is not
# "log", "profile" is not "file", "catalog" is not "log", "review" is not
# "view". A trailing plural "s" is accepted ("views", "models", "logs").

MODULE_PATH_KEYWORDS = {
    'analytics':        ['analytics', 'tracking', 'tracker', 'telemetry', 'metrics', 'stats'],
    'authentication':   ['auth', 'authentication', 'login', 'logout', 'signin', 'signup',
                         'oauth', 'jwt', 'session', 'token', 'kyc'],
    'payment':          ['payment', 'billing', 'invoice', 'stripe', 'razorpay', 'checkout'],
    'notification':     ['notification', 'notify', 'push', 'fcm', 'apns', 'sms', 'email', 'mailer'],
    'database':         ['model', 'schema', 'migration', 'repository', 'dao', 'db'],
    'api':              ['api', 'route', 'router', 'endpoint', 'controller', 'handler', 'view'],
    'storage':          ['storage', 'upload', 's3', 'blob', 'file', 'bucket'],
    'logging':          ['log', 'logger', 'logging', 'audit', 'trace', 'tracing'],
}

# AST function names that indicate module type (Python).
# MODULE_FUNC_TOKENS: keyword token sequences that may appear anywhere in a
#   function name ("send_sms_reminder" contains "send_sms").
# MODULE_FUNC_EXACT: generic verbs that only count when they ARE the whole
#   function name (Django/DRF handlers "def get(self, request)", a "def log()"
#   helper) — as substrings they match almost every function ("get_user").
MODULE_FUNC_TOKENS: dict[str, list[str]] = {
    'analytics':     ['track', 'identify', 'log_event', 'send_event', 'report_event'],
    'authentication':['authenticate', 'login', 'logout', 'register', 'verify_token',
                      'decode_jwt', 'verify_otp', 'generate_otp'],
    'payment':       ['charge', 'create_payment', 'process_payment', 'refund'],
    'notification':  ['send_notification', 'send_sms', 'send_email', 'push_notify', 'notify'],
    'database':      ['upsert', 'bulk_insert'],
    'api':           ['handle_request'],
    'storage':       ['upload', 'download', 'read_file', 'write_file'],
    'logging':       ['audit_log', 'write_log'],
}
MODULE_FUNC_EXACT: dict[str, list[str]] = {
    'database':      ['save', 'create', 'update', 'delete', 'insert'],
    'api':           ['get', 'post', 'put', 'delete', 'patch'],
    'storage':       ['store'],
    'logging':       ['log', 'debug', 'info', 'warning', 'error', 'exception'],
}
# Backwards-compatible view of the function keywords (union of both tables).
MODULE_FUNC_KEYWORDS: dict[str, list[str]] = {
    mt: MODULE_FUNC_TOKENS.get(mt, []) + MODULE_FUNC_EXACT.get(mt, [])
    for mt in MODULE_PATH_KEYWORDS
}


def _tokens(text: str) -> list[str]:
    """Split a path or identifier into lower-case word tokens."""
    text = _CAMEL_RE_2.sub(r'\1_\2', text)
    text = _CAMEL_RE_1.sub(r'\1_\2', text)
    return [t for t in re.split(r'[^A-Za-z0-9]+', text.lower()) if t]


def _token_match(tokens: list[str], keyword: str) -> bool:
    kw = keyword.split('_')
    n = len(kw)
    for i in range(len(tokens) - n + 1):
        window = tokens[i:i + n]
        if window[:-1] == kw[:-1] and window[-1] in (kw[-1], kw[-1] + 's'):
            return True
    return False


def classify_module(file_path: str, source_text: str) -> set[str]:
    """
    Return a set of module-type labels for a file, using:
    1. File path token matching (fast)
    2. Python AST function-name extraction (for .py files)

    Labels: 'analytics', 'authentication', 'payment', 'notification',
            'database', 'api', 'storage', 'logging'
    """
    labels: set[str] = set()
    path_tokens = _tokens(file_path)

    # Path-token pass
    for module_type, keywords in MODULE_PATH_KEYWORDS.items():
        if any(_token_match(path_tokens, kw) for kw in keywords):
            labels.add(module_type)

    # AST function-name pass (Python only)
    if file_path.endswith(PY_EXTS):
        try:
            tree = ast.parse(source_text)
            func_names = {
                node.name
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            for fn in func_names:
                fn_tokens = _tokens(fn)
                fn_whole = '_'.join(fn_tokens)
                for module_type, kws in MODULE_FUNC_TOKENS.items():
                    if any(_token_match(fn_tokens, kw) for kw in kws):
                        labels.add(module_type)
                for module_type, kws in MODULE_FUNC_EXACT.items():
                    if fn_whole in kws:
                        labels.add(module_type)
        except SyntaxError:
            pass

    return labels


# ── AST taint analysis ────────────────────────────────────────────────────────
# Propagates PII labels from assignment LHS through the file to detect whether
# a tainted variable reaches a third-party sink call.

_IDENT_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\b')


# Variable assigned on a line: `x = …`, `x: T = …`, `const/let/var x = …`
# (not `==`, `<=`, `>=`, `!=`, keyword arguments are irrelevant here because
# the pattern is anchored at the start of the statement).
_ASSIGN_LHS_RE = re.compile(
    r'^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*(?::[^=]*)?=(?!=)'
)


def _own_pii(name: str) -> set[PIICategory]:
    """PII categories an identifier / field / key name itself denotes
    (`email`, `phoneNumber`, `latest_diagnosis` …)."""
    return set(_pass1_categories(_normalise_identifiers(name)))


def _seed_taint(
    lines: list[str],
    line_findings: list[tuple[int, PIICategory]],
    lang: str = 'py',
) -> dict[str, set[PIICategory]]:
    """
    Initial tainted names, taken from PII-positive lines. Each name maps to
    the SET of PII categories it may carry.

    Only two kinds of identifier are seeded:
      1. identifiers whose own name is a PII word (`email`, `phoneNumber`,
         `blood_group` …), with that word's categories;
      2. the variable ASSIGNED on the line (`contact = request.form["email"]`
         seeds `contact`), with all of the line's categories.

    Receiver objects such as `request`, `form` or `self` are not seeded
    (seeding every identifier made `print(request.method)` an "email" leak).
    Field reads like `patient.blood_group` are handled where they are USED
    (see _py_expr_cats), so `payload = {"bg": patient.blood_group}` still
    taints `payload`.
    """
    tainted: dict[str, set[PIICategory]] = {}
    line_cats: dict[int, set[PIICategory]] = {}
    for line_num, cat in line_findings:
        line_cats.setdefault(line_num, set()).add(cat)
    for line_num, cats in line_cats.items():
        if not (0 < line_num <= len(lines)):
            continue
        code = _strip_inline_comment(lines[line_num - 1], lang)
        for ident in _IDENT_RE.findall(code):
            own = _own_pii(ident)
            if own:
                tainted.setdefault(ident.lower(), set()).update(own)
        m = _ASSIGN_LHS_RE.match(code)
        if m:
            tainted.setdefault(m.group(1).lower(), set()).update(cats)
    return tainted


# ── SDK aliases and sink calls ────────────────────────────────────────────────
# A sink used to be recognised only when the SDK's name appeared in the
# calling line's text. Real code keeps SDK clients in variables or imports
# them under other names:
#     mp = mixpanel.Mixpanel(TOKEN);              mp.track(email, …)
#     from twilio.rest import Client;  client = Client(…);  client.messages.create(…)
#     import segment.analytics as analytics;      analytics.track(…)
#     from firebase_admin import analytics;       analytics.log_event(…)
# Imported names are mapped to the SDK of their module, assigned variables
# inherit the SDK of the expression they are built from, and a call whose
# root name is such a variable is a call to that SDK.

def _package_sink(name: str) -> str | None:
    """Sink label for an imported package, decided by its TOP-LEVEL name
    only: 'twilio.rest' → twilio, 'segment.analytics' → segment,
    'firebase_admin' → firebase, 'mixpanel-browser' → mixpanel,
    '@segment/analytics-node' → segment, 'firebase/analytics' → firebase.
    A project's own module such as 'services.analytics' or './analytics'
    is not an SDK (its top-level name is 'services' / relative)."""
    if not name or name.startswith(('.', '/')):
        return None
    if name.startswith('@'):
        top = name.split('/')[0][1:]          # npm scope: @segment/… → segment
    else:
        top = re.split(r'[./]', name)[0]
    top = top.replace('-', '.')
    return canonical_sink(top + '(') or canonical_sink(top + '.')


def _py_root_name(node) -> str | None:
    """Leftmost name of an expression: client.messages.create → client."""
    while True:
        if isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
        elif isinstance(node, ast.Name):
            return node.id
        else:
            return None


def _python_sdk_aliases(tree) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                label = _package_sink(a.name)
                if label:
                    aliases[a.asname or a.name.split('.')[0]] = label
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            label = _package_sink(node.module)
            if label:
                for a in node.names:
                    aliases[a.asname or a.name] = label
    for _ in range(5):                       # propagate through assignments
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
                continue
            root = _py_root_name(node.value)
            if not root:
                continue
            label = aliases.get(root)
            if label is None:
                guess = _package_sink(root)
                label = guess if guess and sink_kind(guess) == 'sdk' else None
            if not label:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Name) and t.id not in aliases:
                    aliases[t.id] = label
                    changed = True
        if not changed:
            break
    return aliases


# Government verification endpoints (e.g. UIDAI Aadhaar authentication) are
# not Data Processors engaged by the fiduciary, so a call to them is not a
# Section 8(2) transmission. Only URLs the scanner can resolve statically
# (a literal, an f-string / template literal that starts with one, or a name
# assigned a literal string in the same file) are exempted.
_GOV_HOST_RE = re.compile(r'(?:^|\.)(?:gov\.in|nic\.in)$', re.I)


def _module_str_constants(tree) -> dict[str, str]:
    """Names assigned a literal string anywhere in the module (module level
    or inside a function, e.g. `url = "https://maps…"`). A name assigned two
    different strings is ambiguous and left out."""
    consts: dict[str, str] = {}
    ambiguous: set[str] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    if t.id in consts and consts[t.id] != node.value.value:
                        ambiguous.add(t.id)
                    consts[t.id] = node.value.value
    for name in ambiguous:
        consts.pop(name, None)
    return consts


def _py_url_of(call, constants: dict[str, str]) -> str | None:
    arg = call.args[0] if call.args else next(
        (k.value for k in call.keywords if k.arg == 'url'), None)
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    if isinstance(arg, ast.Name):
        return constants.get(arg.id)
    if isinstance(arg, ast.JoinedStr) and arg.values:
        first = arg.values[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
        if isinstance(first, ast.FormattedValue) and isinstance(first.value, ast.Name):
            return constants.get(first.value.id)
    return None


def _is_gov_url(url: str | None) -> bool:
    host = url_host(url)
    return bool(host and _GOV_HOST_RE.search(host))


def _http_recipient(label: str | None, url: str | None) -> str | None:
    """For an HTTP sink, the recipient named by its URL: None for a
    government verification host (not a transmission), the SDK label for a
    known SDK host, otherwise the host name. Falls back to the HTTP label
    (e.g. "requests.post") when the URL cannot be resolved statically."""
    if not label or sink_kind(label) != 'http':
        return label
    if _is_gov_url(url):
        return None
    return recipient_for_url(url) or label


def _python_call_label(call, aliases: dict[str, str], constants: dict[str, str]) -> str | None:
    try:
        callee = ast.unparse(call.func)
    except Exception:
        return None
    root = _py_root_name(call.func)
    label = aliases[root] if root in aliases else canonical_sink(callee + '(')
    return _http_recipient(label, _py_url_of(call, constants))


_KIND_RANK = {'sdk': 0, 'http': 1, 'queue': 2, 'logger': 3}


def _rank(label: str) -> int:
    return _KIND_RANK.get(sink_kind(label), 9)


# A log call is normally a line or a few. A "log call" spanning dozens of
# lines is almost always a parse artefact (TypeScript read with the
# JavaScript grammar: error recovery can make one console.error(...) appear
# to enclose a whole method), and attributing every line in it to the logger
# reported ordinary code as logged data.
MAX_LOGGER_CALL_LINES = 12


def _sink_lines(label: str, start: int, end: int) -> range:
    if sink_kind(label) == 'logger' and end - start + 1 > MAX_LOGGER_CALL_LINES:
        return range(start, start + 1)
    return range(start, end + 1)


class _LineSinks(dict):
    """{line → sink label} for every line inside a sink call, plus
    `call_line`: {line → the line that call starts on}. A multi-line call is
    ONE transmission, so the rule engine cites it once, at its first line,
    even when PII is found on several of its argument lines."""
    def __init__(self):
        super().__init__()
        self.call_line: dict[int, int] = {}

    def offer(self, ln: int, label: str, start: int) -> None:
        if ln not in self or _rank(label) < _rank(self[ln]):
            self[ln] = label
            self.call_line[ln] = start


def _python_call_sinks(source_text: str) -> dict[int, str] | None:
    """
    {line_number → sink label} for every line inside a sink call, found with
    ast. A multi-line call such as
        analytics.track(c.email, 'loan', {
            'pan_number': c.pan_number,        ← this line is inside the call
        })
    gives the sink to all of its lines; previously only the first line could
    match, so PII on continuation lines never reached Rule 2. Lines that only
    MENTION an SDK (constants, `mixpanel_key = …`) are no longer sinks.
    Returns None when the file does not parse (caller falls back to text).
    """
    try:
        tree = ast.parse(source_text)
    except (SyntaxError, ValueError):
        return None
    aliases = _python_sdk_aliases(tree)
    constants = _module_str_constants(tree)
    by_line = _LineSinks()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        label = _python_call_label(node, aliases, constants)
        if not label:
            continue
        for ln in _sink_lines(label, node.lineno, node.end_lineno or node.lineno):
            by_line.offer(ln, label, node.lineno)
    return by_line


def _py_expr_cats(node, tainted: dict[str, set[PIICategory]]) -> set[PIICategory]:
    """PII categories an expression may carry: tainted variable names, PII
    field reads (`patient.blood_group`) and PII keys (`data['email']`)."""
    out: set[PIICategory] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out |= tainted.get(n.id.lower(), set())
        elif isinstance(n, ast.Attribute):
            out |= _own_pii(n.attr)
        elif isinstance(n, ast.Subscript):
            s = n.slice
            if isinstance(s, ast.Constant) and isinstance(s.value, str):
                out |= _own_pii(s.value)
    return out


def _python_taint_analysis(
    source_text: str,
    file_path: str,
    line_findings: list[tuple[int, PIICategory]],  # (line_num, category) from pass 1/2
) -> list[dict]:
    """
    Python AST taint analysis.

    Propagation: a variable assigned from an expression carrying PII (a
    tainted name, a PII field read or a PII key) becomes tainted with ALL of
    those categories, iterated to a fixed point. A variable used to carry
    only the first category found (chosen at random among several), so
    `payload = {"email": email, "phone": phone}` reported only one of them.

    Sinks: a call whose callee is a sink (by name, or through an SDK alias)
    and whose arguments carry PII yields one finding per category.

    Returns list of {file_path, line_number, pii_category, sink, raw_text}.
    """
    taint_findings: list[dict] = []
    if not line_findings:
        return taint_findings

    lines = source_text.splitlines()
    tainted = _seed_taint(lines, line_findings, 'py')

    try:
        tree = ast.parse(source_text)
    except (SyntaxError, ValueError):
        return taint_findings

    for _ in range(5):
        changed = False
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                value = getattr(node, 'value', None)
                if value is None:
                    continue
                cats = _py_expr_cats(value, tainted)
                if not cats:
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for tgt in targets:
                    if isinstance(tgt, ast.Name):
                        cur = tainted.setdefault(tgt.id.lower(), set())
                        if not cats <= cur:
                            cur |= cats
                            changed = True
        if not changed:
            break

    aliases = _python_sdk_aliases(tree)
    constants = _module_str_constants(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        sink = _python_call_label(node, aliases, constants)
        if not sink:
            continue
        cats: set[PIICategory] = set()
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            cats |= _py_expr_cats(arg, tainted)
        call_line = getattr(node, 'lineno', 0)
        raw = _snippet(lines[call_line - 1] if 0 < call_line <= len(lines) else "")
        for cat in sorted(cats, key=lambda c: c.value):
            taint_findings.append({
                "file_path":    file_path,
                "line_number":  call_line,
                "pii_category": cat,
                "sink":         sink,
                "raw_text":     raw,
            })

    return taint_findings


# ── JavaScript / TypeScript ───────────────────────────────────────────────────

_JS_IMPORT_RE = re.compile(r'''import\s+(.+?)\s+from\s+['"]([^'"]+)['"]''')
_JS_REQUIRE_RE = re.compile(
    r'''(?:const|let|var)\s+(\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)''')
_JS_ASSIGN_RE = re.compile(
    r'''(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:new\s+|await\s+)?([A-Za-z_$][\w$]*)''')
_JS_NAME_RE = re.compile(r'[A-Za-z_$][\w$]*')


def _js_bound_names(clause: str) -> list[str]:
    """Names bound by an import clause / destructuring: `mp`, `* as mp`,
    `{ A, B as C }` → [mp] / [mp] / [A, C]."""
    toks = _JS_NAME_RE.findall(clause)
    out = []
    for i, t in enumerate(toks):
        if t == 'as' or (i + 1 < len(toks) and toks[i + 1] == 'as'):
            continue
        out.append(t)
    return out


def _js_sdk_aliases(source_text: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for rx in (_JS_IMPORT_RE, _JS_REQUIRE_RE):
        for m in rx.finditer(source_text):
            label = _package_sink(m.group(2))
            if label:
                for name in _js_bound_names(m.group(1)):
                    aliases[name] = label
    for _ in range(5):
        changed = False
        for m in _JS_ASSIGN_RE.finditer(source_text):
            target, root = m.group(1), m.group(2)
            if root in aliases and target not in aliases:
                aliases[target] = aliases[root]
                changed = True
        if not changed:
            break
    return aliases


def _js_parse(source_text: str):
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_javascript as tsjs
    except ImportError:
        return None
    try:
        parser = Parser(Language(tsjs.language()))
        return parser.parse(bytes(source_text, "utf-8"))
    except Exception:
        return None


def _ts_walk(node):
    yield node
    for child in node.children:
        yield from _ts_walk(child)


_JS_STR_CONST_RE = re.compile(
    r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:'([^'\n]*)'|"([^"\n]*)"|`([^`$\n]*)`)""")


def _js_str_constants(source_text: str) -> dict[str, str]:
    """`const NAME = "literal"` anywhere in the file; ambiguous names dropped."""
    consts: dict[str, str] = {}
    ambiguous: set[str] = set()
    for m in _JS_STR_CONST_RE.finditer(source_text):
        val = next(g for g in m.groups()[1:] if g is not None)
        if m.group(1) in consts and consts[m.group(1)] != val:
            ambiguous.add(m.group(1))
        consts[m.group(1)] = val
    for name in ambiguous:
        consts.pop(name, None)
    return consts


_JS_TEMPLATE_HEAD_RE = re.compile(r'^`([^`$]*)(?:\$\{\s*([A-Za-z_$][\w$]*)\s*\})?')


def _js_url_of(args_node, src: bytes, consts: dict[str, str]) -> str | None:
    """URL of a call's first argument, when it can be resolved statically."""
    if args_node is None:
        return None
    first = next((c for c in args_node.named_children if c.type != 'comment'), None)
    if first is None:
        return None
    text = src[first.start_byte:first.end_byte].decode('utf-8', 'ignore')
    if first.type == 'string' and len(text) >= 2:
        return text[1:-1]
    if first.type == 'identifier':
        return consts.get(text)
    if first.type == 'template_string':
        m = _JS_TEMPLATE_HEAD_RE.match(text)
        if m:
            if m.group(1):
                return m.group(1)
            if m.group(2):
                return consts.get(m.group(2))
    return None


def _js_call_label(func_text: str, aliases: dict[str, str], url: str | None = None) -> str | None:
    m = _JS_NAME_RE.match(func_text)
    root = m.group(0) if m else None
    label = aliases[root] if root in aliases else canonical_sink(func_text + '(')
    return _http_recipient(label, url)


def _js_call_sinks(source_text: str) -> dict[int, str] | None:
    """JS/TS counterpart of _python_call_sinks (tree-sitter). Returns None
    when tree-sitter is unavailable (caller falls back to text matching)."""
    tree = _js_parse(source_text)
    if tree is None:
        return None
    src = bytes(source_text, "utf-8")
    aliases = _js_sdk_aliases(source_text)
    consts = _js_str_constants(source_text)
    by_line = _LineSinks()
    for node in _ts_walk(tree.root_node):
        if node.type != "call_expression":
            continue
        func = node.child_by_field_name("function")
        if func is None:
            continue
        label = _js_call_label(src[func.start_byte:func.end_byte].decode("utf-8", "ignore"), aliases,
                               _js_url_of(node.child_by_field_name("arguments"), src, consts))
        if not label:
            continue
        for ln in _sink_lines(label, node.start_point[0] + 1, node.end_point[0] + 1):
            by_line.offer(ln, label, node.start_point[0] + 1)
    return by_line


def _js_taint_analysis(
    source_text: str,
    file_path: str,
    line_findings: list[tuple[int, PIICategory]],
) -> list[dict]:
    """
    JS/TS taint analysis using tree-sitter-javascript.
    Falls back gracefully if tree-sitter is not installed.

    Taint propagates through `const x = …` / `x = …` when the right-hand side
    carries PII: a tainted identifier, or an identifier / property whose own
    name is a PII word (string contents are ignored). A variable carries the
    full set of categories. A call is a sink when its callee is recognised by
    scanners/sinks.py or is an SDK alias (`mp.track`); one finding is
    reported per PII category in its arguments.

    Returns list of {file_path, line_number, pii_category, sink, raw_text}.
    """
    taint_findings: list[dict] = []
    if not line_findings:
        return taint_findings

    tree = _js_parse(source_text)
    if tree is None:
        return taint_findings

    src_bytes = bytes(source_text, "utf-8")
    lines = source_text.splitlines()
    tainted = _seed_taint(lines, line_findings, 'js')
    aliases = _js_sdk_aliases(source_text)
    consts = _js_str_constants(source_text)

    def _node_text(node) -> str:
        return src_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

    def _text_cats(text: str) -> set[PIICategory]:
        # blank string contents so words inside literals don't count
        for s, e in reversed(_string_spans(text, 'js')):
            text = text[:s] + ' ' * (e - s) + text[e:]
        out: set[PIICategory] = set()
        for ident in _IDENT_RE.findall(text):
            out |= tainted.get(ident.lower(), set())
            out |= _own_pii(ident)
        return out

    for _ in range(5):
        changed = False
        for node in _ts_walk(tree.root_node):
            if node.type not in ("variable_declarator", "assignment_expression"):
                continue
            lhs = node.child_by_field_name("name") or node.child_by_field_name("left")
            rhs = node.child_by_field_name("value") or node.child_by_field_name("right")
            if lhs is None or rhs is None:
                continue
            cats = _text_cats(_node_text(rhs))
            if not cats:
                continue
            for ident in _IDENT_RE.findall(_node_text(lhs)):
                cur = tainted.setdefault(ident.lower(), set())
                if not cats <= cur:
                    cur |= cats
                    changed = True
        if not changed:
            break

    for node in _ts_walk(tree.root_node):
        if node.type != "call_expression":
            continue
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func is None or args is None:
            continue
        sink = _js_call_label(_node_text(func), aliases, _js_url_of(args, src_bytes, consts))
        if not sink:
            continue
        line_no = node.start_point[0] + 1
        raw = _snippet(lines[line_no - 1] if line_no - 1 < len(lines) else "")
        for cat in sorted(_text_cats(_node_text(args)), key=lambda c: c.value):
            taint_findings.append({
                "file_path":    file_path,
                "line_number":  line_no,
                "pii_category": cat,
                "sink":         sink,
                "raw_text":     raw,
            })

    return taint_findings


def _scan_single_file(
    repo,
    file_obj,
    raise_errors: bool = False,
) -> tuple[list, dict]:
    """
    Scan one file from the git tree.

    Runs Pass 1 (regex), Pass 2 (Presidio NER), and AST taint analysis
    for a single file.  Called by scan_files() for every file of a chunk.

    Returns
    -------
    (file_findings, file_usage_map)
    """
    file_findings:  list = []
    file_usage_map: dict = {}

    try:
        content = repo.get_contents(file_obj.path)
        source_text = content.decoded_content.decode('utf-8', errors='ignore')
        lines = source_text.splitlines()

        # Module type labels for this file
        file_module_types = classify_module(file_obj.path, source_text)

        # Track pass-1/2 findings per line for taint seeding
        line_pii: list[tuple[int, PIICategory]] = []

        is_py = file_obj.path.endswith(PY_EXTS)
        is_js = file_obj.path.endswith(JS_EXTS)

        # Python docstrings / bare string statements, located with ast
        _docstring_lines = _python_docstring_lines(source_text) if is_py else set()
        # Sink of each line = the sink call that ENCLOSES it (ast for Python,
        # tree-sitter for JS/TS), so multi-line calls and SDK aliases work.
        # None when the file can't be parsed → fall back to text matching.
        _call_sinks = (_python_call_sinks(source_text) if is_py
                       else _js_call_sinks(source_text) if is_js else None)
        # JS/TS block comments  /* ... */  and  /** ... */
        _in_block_comment = False

        # Lines that need Pass 2 (NER); analysed in ONE batch after the loop
        _pass2_pending: list[tuple[int, str, str, str | None]] = []

        def _add(source, line_num, raw, field, cat, sens, sink):
            file_findings.append(DataFlowObject(
                source=source,
                file_path=file_obj.path,
                line_number=line_num,
                raw_text=_snippet(raw),
                field_name=field,
                pii_category=cat,
                sensitivity=sens,
                third_party_sdk=sink,
                module_types=sorted(file_module_types),
                call_line=(_call_sinks.call_line.get(line_num)
                           if sink and isinstance(_call_sinks, _LineSinks) else None),
            ))
            line_pii.append((line_num, cat))
            file_usage_map.setdefault(cat, set()).update(file_module_types)

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            # ── Docstring skip (Python only) ──────────────────────────
            # Docstrings name SDKs and PII in prose, not in executable code.
            if is_py and line_num in _docstring_lines:
                continue

            # Skip pure-comment lines (Python # and JS/TS //) ─────────
            if is_py and stripped.startswith('#'):
                continue

            # ── JS/TS block comment skip  /* ... */  /** ... */ ───────
            # Body lines of block comments start with ' * ', not '//',
            # so the // check above misses them — we need state tracking.
            if is_js:
                if _in_block_comment:
                    if '*/' in stripped:
                        _in_block_comment = False
                    continue       # skip every body line
                else:
                    if stripped.startswith('/*'):
                        if '*/' not in stripped[2:]:
                            _in_block_comment = True
                        continue   # skip the opening line itself
                    # Inline  /* comment */  — strip it so SDK names don't fire
                    if '/*' in line and '*/' in line:
                        before = line[:line.index('/*')]
                        after  = line[line.index('*/') + 2:]
                        line    = before + after
                        stripped = line.strip()
                if stripped.startswith('//'):
                    continue   # remaining // comment after block-comment strip

            # Drop a trailing inline comment (string-aware) and use only the
            # code part for PII matching AND sink detection, so comment text
            # neither creates findings nor hides a sink.
            code_part = _strip_inline_comment(line, 'py' if is_py else 'js')
            code_stripped = code_part.strip()

            # Canonical sink on this line (SDK > HTTP > queue > logger),
            # shared label vocabulary with the rule engine.
            line_sink = (_call_sinks.get(line_num) if _call_sinks is not None
                         else canonical_sink(code_part))

            # ── Pass 1: regex on normalised identifiers ───────────────
            # In a log call, a PII word that is only part of the message
            # text ("email sent", 'location updated') logs no personal
            # data; only identifiers and interpolated expressions count.
            _p1_text = (_blank_string_literals(code_part)
                        if line_sink and sink_kind(line_sink) == 'logger' else code_part)
            categories = _pass1_categories(_normalise_identifiers(_p1_text))
            if PIICategory.AADHAAR in categories and not _validate_aadhaar(code_part):
                categories.remove(PIICategory.AADHAAR)   # Verhoeff fails — skip

            for category in categories:
                _add("code_scanner", line_num, line, category.value, category,
                     SENSITIVITY_MAP.get(category, Sensitivity.UNKNOWN), line_sink)

            # ── Pass 2: Presidio NER + India regex (queued) ───────────
            # Skipped for bare field/schema declarations (no literal content
            # for NER to analyze — see _BARE_FIELD_DECL_RE above).
            if not categories and len(code_stripped) > 10 and not _BARE_FIELD_DECL_RE.match(code_part):
                # Pass 2 (NER) reads literals; in a log call the literal is the
                # message ("Max retries exceeded" is not a person), and sample
                # values printed by example programs are not user data.
                if len(_p1_text.strip()) > 10:
                    _pass2_pending.append((line_num, line, _p1_text, line_sink))

        # ── Pass 2: one batched Presidio call for the whole file ──────
        _lang = 'py' if is_py else 'js'
        _p2_results = scan_lines_with_presidio_spans(
            [cp for _, _, cp, _ in _pass2_pending],
            ner_mask=[_needs_ner(cp, _lang) for _, _, cp, _ in _pass2_pending],
        )
        for (line_num, line, code_part, line_sink), hits in zip(_pass2_pending, _p2_results):
            seen_p2: set[PIICategory] = set()
            for hit, h_start, h_end in sorted(hits):
                if hit not in PRESIDIO_MAP:
                    continue
                cat, sens = PRESIDIO_MAP[hit]
                if cat in seen_p2:
                    continue
                if hit in ("PERSON", "LOCATION") and not _plausible_ner_span(
                        code_part, h_start, h_end, _lang):
                    continue
                # Value-level validation: the same checks as Pass 1,
                # so Pass 2 can never re-admit what Pass 1 rejected.
                if cat == PIICategory.AADHAAR and not _aadhaar_value_valid(code_part):
                    continue
                if cat == PIICategory.PAN and not _pan_value_valid(code_part):
                    continue
                seen_p2.add(cat)
                _add("presidio_scanner", line_num, line, hit.lower(), cat, sens, line_sink)

        # ── AST taint analysis ────────────────────────────────────────
        taint_results: list[dict] = []
        if is_py:
            taint_results = _python_taint_analysis(source_text, file_obj.path, line_pii)
        elif is_js:
            taint_results = _js_taint_analysis(source_text, file_obj.path, line_pii)

        # Snapshot pass-1/2 findings ONCE, keyed by (file, line, category):
        # a taint hit is only redundant if pass 1/2 already reported the SAME
        # category on that line. Keying on (file, line) alone dropped e.g. an
        # email reaching print() whenever the same print() line also named
        # a phone number.
        existing_pass12 = {(f.file_path, f.line_number, f.pii_category) for f in file_findings}
        existing_taint_keys: set = set()  # (file_path, line_number, pii_category)

        for tr in taint_results:
            cat = tr["pii_category"]

            # Skip if pass-1/2 already caught this category at the same line
            if (tr["file_path"], tr["line_number"], cat) in existing_pass12:
                continue

            # Skip if taint already reported the same (file, line, category)
            cat_key = (tr["file_path"], tr["line_number"], cat)
            if cat_key in existing_taint_keys:
                continue
            existing_taint_keys.add(cat_key)

            file_findings.append(DataFlowObject(
                source="taint_analysis",
                file_path=tr["file_path"],
                line_number=tr["line_number"],
                raw_text=tr["raw_text"],
                field_name=cat.value,
                pii_category=cat,
                sensitivity=SENSITIVITY_MAP.get(cat, Sensitivity.UNKNOWN),
                third_party_sdk=tr["sink"],   # canonical label from sinks.py
                module_types=sorted(file_module_types),
                call_line=tr["line_number"],  # taint findings sit on the call's first line
            ))
            file_usage_map.setdefault(cat, set()).update(file_module_types)

    except Exception as e:
        if raise_errors:      # scan_github_repo counts it in coverage["failed"]
            raise
        print(f"[scanner] skipped {file_obj.path}: {e}")

    return file_findings, file_usage_map


# ── Main scanner ──────────────────────────────────────────────────────────────

class _LocalFile:
    type = "blob"
    def __init__(self, path: str): self.path = path


def scan_files(reader, paths: list[str]) -> tuple[list, dict, dict]:
    """
    Scan every file in `paths`, one after another, reading each through
    `reader.get_contents(path)` (a repo_snapshot.SnapshotReader in
    production).

    Sequential on purpose: the work is CPU-bound, so threads only contend
    for the GIL. Parallelism comes from running many of these calls in
    separate Celery worker processes, one per chunk of files.

    Returns
    -------
    findings  : list[DataFlowObject]
    usage_map : {PIICategory → set[module_type]} — first-party files only:
                it describes how the APPLICATION uses each category (Rule 3),
                and a bundled library's internals say nothing about that.
    status    : {"scanned": [path...], "failed": {path: reason}}

    Every finding carries `origin` (first_party / third_party / generated,
    from repo_snapshot.classify_path), so third-party code is scanned and
    reported but kept apart where the rules need the application's own code.
    """
    from scanners.repo_snapshot import RateLimited, classify_path
    from scanners.test_paths import counts_for_rules

    findings: list = []
    usage_map: dict = {}
    status = {"scanned": [], "failed": {}}
    for path in paths:
        try:
            file_findings, file_usage = _scan_single_file(reader, _LocalFile(path), raise_errors=True)
        except RateLimited:
            raise                      # the Celery task waits for the reset and retries
        except Exception as e:
            status["failed"][path] = f"{type(e).__name__}: {e}"[:300]
            print(f"[scanner] could not scan {path}: {e}")
            continue
        origin = classify_path(path)
        if origin == "other":           # a path given directly (tests, scripts)
            origin = "first_party"
        for f in file_findings:
            f.origin = origin
        findings.extend(file_findings)
        if origin == "first_party" and counts_for_rules(path):
            for cat, mods in file_usage.items():
                usage_map.setdefault(cat, set()).update(mods)
        status["scanned"].append(path)
    return findings, usage_map, status


def coverage_note(coverage: dict) -> str | None:
    """
    Human-readable note for the result page. Every scannable file is always
    attempted (third-party and generated files included); this only explains
    files that could not be scanned (unreadable or unparseable, or still over
    the per-file time limit after a retry). None when every file was scanned.
    """
    total = coverage.get("total_source_files", 0)
    failed = coverage.get("failed") or {}
    if not failed:
        return None
    return (
        f"Scan coverage: {len(failed)} of {total} source files could not be scanned "
        f"(e.g. {next(iter(failed))}: {next(iter(failed.values()))})."
    )


def scan_github_repo(repo_url: str, github_token: str | None):
    """
    Synchronous whole-repository scan (no file cap, no deadline) for scripts
    and tests. Production scans go through tasks.run_scan_task, which runs
    the same scan_files() over many parallel chunk tasks.

    Returns (findings, usage_map, coverage).
    """
    from scanners import repo_snapshot as rs

    ref = rs.resolve_repo(repo_url, github_token)
    manifest = rs.ensure_snapshot(ref, github_token)
    paths = [f["path"] for f in manifest["files"]]
    findings, usage_map, status = scan_files(rs.SnapshotReader(ref, github_token), paths)
    coverage = {
        "total_source_files": len(paths),
        "scanned": len(status["scanned"]),
        "failed": status["failed"],
        "origins": manifest.get("origins", {}),
    }
    print(f"[scanner] Done — {len(findings)} PII findings; "
          f"{coverage['scanned']}/{coverage['total_source_files']} files")
    return findings, usage_map, coverage
