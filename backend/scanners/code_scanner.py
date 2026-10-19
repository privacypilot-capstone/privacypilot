"""
Code Scanner
============
Two-pass PII detection over GitHub source files, extended with:

  Pass 1  — Regex keyword matching (10 PII categories) on identifier tokens;
             camelCase identifiers are normalised to snake_case first, and a
             line may yield several categories (longest match wins overlaps)
  Pass 2  — Microsoft Presidio NER + India regex (for lines missed by regex);
             Aadhaar values must pass Verhoeff, PAN values the PAN structure
  Taint   — AST taint analysis: propagate PII labels through variable
             assignments to third-party sink call sites
             (Python via `ast`; JS/TS via tree-sitter-javascript)
  Classify— Module classifier: file path tokens + AST function names
             → usage_map {PIICategory → set[module_type]}

Sinks are labelled by scanners/sinks.py (shared with the rule engine), so a
finding's `third_party_sdk` is always a canonical label the engine recognises.

Additional:
  - Verhoeff checksum validation for Aadhaar numbers (both passes;
    shared implementation in presidio_scanner.verhoeff_checksum_valid)
  - Returns (findings, usage_map) for Rule 3 cross-reference
"""

import ast
import concurrent.futures
import re
from github import Github
from models.dataflow import DataFlowObject, PIICategory, Sensitivity
from scanners.presidio_scanner import scan_text_with_presidio, verhoeff_checksum_valid
from scanners.sinks import canonical_sink

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
    PIICategory.LOCATION:  r'latitude|longitude|location|gps|address',
    PIICategory.HEALTH:    r'blood_group|health(?!_?(?:check|z|endpoint|status))|medical|diagnosis|disease',
    PIICategory.FINANCIAL: r'bank_account|account_no|ifsc|credit_card|salary',
    PIICategory.NAME:      r'full_name|first_name|last_name|username',
    PIICategory.DOB:       r'date_of_birth|birth_date|birthdate|dob',
    PIICategory.BIOMETRIC: r'fingerprint|iris|face_id|biometric',
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
    "MEDICAL_LICENSE":  (PIICategory.HEALTH,    Sensitivity.SENSITIVE),
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


def _seed_taint(lines: list[str], line_findings: list[tuple[int, PIICategory]]) -> dict[str, PIICategory]:
    """Identifiers on PII-positive lines become the initial tainted names."""
    tainted: dict[str, PIICategory] = {}
    for line_num, cat in line_findings:
        if line_num - 1 < len(lines):
            for ident in _IDENT_RE.findall(lines[line_num - 1]):
                if len(ident) > 2:
                    tainted.setdefault(ident.lower(), cat)
    return tainted


def _python_taint_analysis(
    source_text: str,
    file_path: str,
    line_findings: list[tuple[int, PIICategory]],  # (line_num, category) from pass 1/2
) -> list[dict]:
    """
    Python AST taint analysis.
    Walks assignments: if the RHS references a name that appears in a PII-positive
    line (from pass 1/2), the LHS variable is tainted.
    Walks calls: if a tainted variable appears as an argument to a sink function,
    report a taint finding. The sink is recognised from the full callee text
    (ast.unparse), so print(x), self.logger.warning(x) and task.delay(x) are
    all seen.

    Returns list of {file_path, line_number, pii_category, sink, raw_text}.
    """
    taint_findings: list[dict] = []
    if not line_findings:
        return taint_findings

    lines = source_text.splitlines()
    tainted_names = _seed_taint(lines, line_findings)

    try:
        tree = ast.parse(source_text)
    except SyntaxError:
        return taint_findings

    # Walk assignments to propagate taint
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value if isinstance(node, ast.Assign) else getattr(node, 'value', None)
            if value is None:
                continue
            rhs_names = {
                n.id.lower()
                for n in ast.walk(value)
                if isinstance(n, ast.Name)
            }
            propagate_cat = next(
                (tainted_names[n] for n in rhs_names if n in tainted_names),
                None,
            )
            if propagate_cat:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for tgt in targets:
                    if isinstance(tgt, ast.Name):
                        tainted_names[tgt.id.lower()] = propagate_cat

    # Walk calls to detect tainted args at sink sites
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        try:
            callee = ast.unparse(node.func)
        except Exception:
            continue
        sink = canonical_sink(callee + '(')
        if not sink:
            continue

        call_line = getattr(node, 'lineno', 0)
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            arg_names = {
                n.id.lower()
                for n in ast.walk(arg)
                if isinstance(n, ast.Name)
            }
            hit = next((a for a in arg_names if a in tainted_names), None)
            if hit:
                taint_findings.append({
                    "file_path":    file_path,
                    "line_number":  call_line,
                    "pii_category": tainted_names[hit],
                    "sink":         sink,
                    "raw_text":     (lines[call_line - 1] if call_line - 1 < len(lines) else "").strip()[:200],
                })
                break  # one report per call site

    return taint_findings


def _js_taint_analysis(
    source_text: str,
    file_path: str,
    line_findings: list[tuple[int, PIICategory]],
) -> list[dict]:
    """
    JS/TS taint analysis using tree-sitter-javascript.
    Falls back gracefully if tree-sitter is not installed.

    Taint propagates through `const x = …` / `x = …` when an identifier on
    the right-hand side is tainted (identifier tokens, not substrings). A
    call is a sink when its callee (the `function` field) is recognised by
    scanners/sinks.py; a tainted identifier anywhere in its arguments —
    including inside object literals and arrays — is reported.

    Returns list of {file_path, line_number, pii_category, sink, raw_text}.
    """
    taint_findings: list[dict] = []
    if not line_findings:
        return taint_findings

    try:
        from tree_sitter import Language, Parser
        import tree_sitter_javascript as tsjs
    except ImportError:
        # tree-sitter not installed — skip JS taint silently
        return taint_findings

    try:
        JS_LANGUAGE = Language(tsjs.language())
        parser = Parser(JS_LANGUAGE)
        tree = parser.parse(bytes(source_text, "utf-8"))
    except Exception:
        return taint_findings

    src_bytes = bytes(source_text, "utf-8")
    lines = source_text.splitlines()
    tainted_names = _seed_taint(lines, line_findings)

    def _node_text(node) -> str:
        return src_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

    def _idents(text: str) -> set[str]:
        return {t.lower() for t in _IDENT_RE.findall(text)}

    def _walk(node):
        yield node
        for child in node.children:
            yield from _walk(child)

    # Propagate taint through variable declarations / assignments
    for node in _walk(tree.root_node):
        if node.type in ("variable_declarator", "assignment_expression"):
            lhs = node.child_by_field_name("name") or node.child_by_field_name("left")
            rhs = node.child_by_field_name("value") or node.child_by_field_name("right")
            if lhs is None or rhs is None:
                continue
            propagate_cat = next(
                (tainted_names[n] for n in _idents(_node_text(rhs)) if n in tainted_names),
                None,
            )
            if propagate_cat:
                for ident in _idents(_node_text(lhs)):
                    tainted_names.setdefault(ident, propagate_cat)

    # Detect tainted args at sink call sites
    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func is None or args is None:
            continue
        sink = canonical_sink(_node_text(func) + '(')
        if not sink:
            continue
        hit = next((a for a in _idents(_node_text(args)) if a in tainted_names), None)
        if hit:
            line_no = node.start_point[0] + 1
            raw = lines[line_no - 1] if line_no - 1 < len(lines) else ""
            taint_findings.append({
                "file_path":    file_path,
                "line_number":  line_no,
                "pii_category": tainted_names[hit],
                "sink":         sink,
                "raw_text":     raw.strip()[:200],
            })

    return taint_findings


def _scan_single_file(
    repo,
    file_obj,
) -> tuple[list, dict]:
    """
    Scan one file from the git tree.

    Runs Pass 1 (regex), Pass 2 (Presidio NER), and AST taint analysis
    for a single file.  Called concurrently by scan_github_repo via
    ThreadPoolExecutor.

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

        # Docstring-tracking state (Python triple-quoted strings)
        _in_docstring    = False
        _docstring_delim = '"""'
        # JS/TS block comments  /* ... */  and  /** ... */
        _in_block_comment = False

        def _add(source, line_num, raw, field, cat, sens, sink):
            file_findings.append(DataFlowObject(
                source=source,
                file_path=file_obj.path,
                line_number=line_num,
                raw_text=raw.strip()[:200],
                field_name=field,
                pii_category=cat,
                sensitivity=sens,
                third_party_sdk=sink,
            ))
            line_pii.append((line_num, cat))
            file_usage_map.setdefault(cat, set()).update(file_module_types)

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            # ── Docstring skip (Python only) ──────────────────────────
            # Triple-quoted strings are docstrings / multi-line literals.
            # They name SDKs and PII in prose, not in executable code.
            if is_py:
                if _in_docstring:
                    if _docstring_delim in stripped:
                        _in_docstring = False
                    continue          # always skip body lines
                else:
                    _hit_delim = None
                    for _delim in ('"""', "'''"):
                        if stripped.startswith(_delim):
                            _hit_delim = _delim
                            rest = stripped[3:]
                            if _delim not in rest:
                                # opening of a multi-line docstring
                                _in_docstring    = True
                                _docstring_delim = _delim
                            break
                    if _hit_delim is not None:
                        continue   # skip the opening/single-line docstring

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

            # For lines with trailing inline comments, use only the code part
            # for sink detection so comment text doesn't trigger false matches.
            code_part = line
            if is_py and '#' in line:
                code_part = line.split('#')[0]
            elif is_js and '//' in line:
                code_part = line.split('//')[0]

            # Canonical sink on this line (SDK > HTTP > queue > logger),
            # shared label vocabulary with the rule engine.
            line_sink = canonical_sink(code_part)

            # ── Pass 1: regex on normalised identifiers ───────────────
            categories = _pass1_categories(_normalise_identifiers(line))
            if PIICategory.AADHAAR in categories and not _validate_aadhaar(line):
                categories.remove(PIICategory.AADHAAR)   # Verhoeff fails — skip

            for category in categories:
                _add("code_scanner", line_num, line, category.value, category,
                     SENSITIVITY_MAP.get(category, Sensitivity.UNKNOWN), line_sink)

            # ── Pass 2: Presidio NER + India regex ────────────────────
            # Skipped for bare field/schema declarations (no literal content
            # for NER to analyze — see _BARE_FIELD_DECL_RE above).
            if not categories and len(stripped) > 10 and not _BARE_FIELD_DECL_RE.match(line):
                seen_p2: set[PIICategory] = set()
                for hit in sorted(scan_text_with_presidio(line)):
                    if hit not in PRESIDIO_MAP:
                        continue
                    cat, sens = PRESIDIO_MAP[hit]
                    if cat in seen_p2:
                        continue
                    # Value-level validation: the same checks as Pass 1,
                    # so Pass 2 can never re-admit what Pass 1 rejected.
                    if cat == PIICategory.AADHAAR and not _aadhaar_value_valid(line):
                        continue
                    if cat == PIICategory.PAN and not _pan_value_valid(line):
                        continue
                    seen_p2.add(cat)
                    _add("presidio_scanner", line_num, line, hit.lower(), cat, sens, line_sink)

        # ── AST taint analysis ────────────────────────────────────────
        taint_results: list[dict] = []
        if is_py:
            taint_results = _python_taint_analysis(source_text, file_obj.path, line_pii)
        elif is_js:
            taint_results = _js_taint_analysis(source_text, file_obj.path, line_pii)

        # Snapshot pass-1/2 findings ONCE so taint results at the same
        # line as each other (different PII categories) are not suppressed.
        existing_pass12 = {(f.file_path, f.line_number) for f in file_findings}
        existing_taint_keys: set = set()  # (file_path, line_number, pii_category)

        for tr in taint_results:
            cat = tr["pii_category"]

            # Skip if pass-1/2 already caught a finding at the same line
            line_key = (tr["file_path"], tr["line_number"])
            if line_key in existing_pass12:
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
            ))
            file_usage_map.setdefault(cat, set()).update(file_module_types)

    except Exception as e:
        print(f"[scanner] skipped {file_obj.path}: {e}")

    return file_findings, file_usage_map


# ── Main scanner ──────────────────────────────────────────────────────────────

def scan_github_repo(
    repo_url: str,
    github_token: str,
) -> tuple[list[DataFlowObject], dict[PIICategory, set[str]]]:
    """
    Scan a GitHub repository for PII.

    Returns
    -------
    findings  : list[DataFlowObject]  — all PII occurrences (pass 1 + pass 2 + taint)
    usage_map : dict[PIICategory, set[str]]  — how each PII category is used
                (e.g. {PIICategory.EMAIL → {'analytics', 'notification'}})
    """
    findings: list[DataFlowObject] = []
    # usage_map accumulates module types per PII category across the whole repo
    usage_map: dict[PIICategory, set[str]] = {}

    repo_name = repo_url.rstrip('/').split('github.com/')[-1]
    g = Github(github_token)
    repo = g.get_repo(repo_name)
    tree = repo.get_git_tree(sha="HEAD", recursive=True).tree

    target_files = [
        f for f in tree
        if f.type == "blob" and f.path.endswith(SCAN_EXTS)
    ]
    target_files = target_files[:300]
    print(f"[scanner] {len(target_files)} files to scan in {repo_name}")

    # ── Parallel file scanning via ThreadPoolExecutor ─────────────────────
    # Each file is fetched from GitHub (I/O-bound) and scanned (CPU-bound)
    # concurrently.  PyGitHub is blocking/thread-safe for reads, so
    # ThreadPoolExecutor is the right primitive (no native async support).
    max_workers = min(40, len(target_files) or 1)  # bumped: I/O-bound GitHub fetches benefit from more threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_file = {
            pool.submit(_scan_single_file, repo, f): f
            for f in target_files
        }
        for future in concurrent.futures.as_completed(future_to_file):
            file_obj = future_to_file[future]
            try:
                file_findings, file_usage_map = future.result()
                findings.extend(file_findings)
                for cat, mods in file_usage_map.items():
                    usage_map.setdefault(cat, set()).update(mods)
            except Exception as exc:
                print(f"[scanner] skipped {file_obj.path}: {exc}")

    print(f"[scanner] Done — {len(findings)} PII findings")
    print(f"[scanner] usage_map: { {k.value: v for k, v in usage_map.items()} }")
    return findings, usage_map
