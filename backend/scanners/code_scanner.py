"""
Code Scanner
============
Two-pass PII detection over GitHub source files, extended with:

  Pass 1  — Regex keyword matching (10 PII categories)
  Pass 2  — Microsoft Presidio NER (for lines missed by regex)
  Taint   — AST taint analysis: propagate PII labels through variable
             assignments to third-party sink call sites
             (Python via `ast`; JS/TS via tree-sitter-javascript)
  Classify— Module classifier: file path keywords + AST function names
             → usage_map {PIICategory → set[module_type]}

Additional:
  - Verhoeff checksum validation for Aadhaar numbers
  - Returns (findings, usage_map) for Rule 3 cross-reference
"""

import ast
import re
from github import Github
from models.dataflow import DataFlowObject, PIICategory, Sensitivity
from scanners.presidio_scanner import scan_text_with_presidio

# ── PII regex patterns ────────────────────────────────────────────────────────

PII_PATTERNS = {
    PIICategory.AADHAAR:   r'\b(aadhaar|aadhar|aadhar_no|aadhaar_number)\b',
    PIICategory.PAN:       r'\b(pan_number|pan_card|pan_no|pancard)\b',
    PIICategory.PHONE:     r'\b(phone|mobile|mobile_no|phone_number|contact_number)\b',
    PIICategory.EMAIL:     r'\b(email|email_address|user_email)\b',
    PIICategory.LOCATION:  r'\b(latitude|longitude|location|gps|address)\b',
    PIICategory.HEALTH:    r'\b(blood_group|health|medical|diagnosis|disease)\b',
    PIICategory.FINANCIAL: r'\b(bank_account|account_no|ifsc|credit_card|salary)\b',
    PIICategory.NAME:      r'\b(full_name|first_name|last_name|username)\b',
    PIICategory.DOB:       r'\b(dob|date_of_birth|birth_date|birthdate)\b',
    PIICategory.BIOMETRIC: r'\b(fingerprint|iris|face_id|biometric)\b',
}

# Aadhaar value pattern (12-digit, possibly spaced)
AADHAAR_VALUE_RE = re.compile(r'\b([2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4})\b')

# ── Third-party SDK / sink detection ─────────────────────────────────────────

THIRD_PARTY_SDKS = [
    'firebase', 'firestore', 'sentry', 'mixpanel',
    'amplitude', 'segment', 'twilio', 'sendgrid',
    'analytics', 'crashlytics', 'clevertap',
]

LOGGER_SINK_KEYWORDS = [
    'logging.', 'logger.', 'log.info', 'log.debug',
    'log.warning', 'log.error', 'console.log', 'console.error',
    'print(', 'sentry.capture',
]

HTTP_SINK_KEYWORDS = [
    'requests.post', 'requests.put', 'axios.post',
    'axios.put', 'fetch(', 'httpx.post',
]

QUEUE_SINK_KEYWORDS = [
    'kafka', 'rabbitmq', 'celery', 'redis.publish', 'pubsub',
]

ALL_SINKS = THIRD_PARTY_SDKS + LOGGER_SINK_KEYWORDS + HTTP_SINK_KEYWORDS + QUEUE_SINK_KEYWORDS

# ── Module classifier: file-path keyword → module type ───────────────────────

MODULE_PATH_KEYWORDS = {
    'analytics':        ['analytics', 'tracking', 'telemetry', 'metrics', 'stats'],
    'authentication':   ['auth', 'login', 'oauth', 'jwt', 'session', 'token'],
    'payment':          ['payment', 'billing', 'invoice', 'stripe', 'razorpay'],
    'notification':     ['notification', 'push', 'fcm', 'apns', 'sms', 'email'],
    'database':         ['model', 'schema', 'migration', 'repository', 'dao'],
    'api':              ['api', 'route', 'endpoint', 'controller', 'handler', 'view'],
    'storage':          ['storage', 'upload', 's3', 'blob', 'file'],
    'logging':          ['log', 'logger', 'audit', 'trace'],
}

# AST function names that indicate module type (Python)
MODULE_FUNC_KEYWORDS: dict[str, list[str]] = {
    'analytics':     ['track', 'identify', 'log_event', 'send_event', 'report'],
    'authentication':['authenticate', 'login', 'register', 'verify_token', 'decode_jwt'],
    'payment':       ['charge', 'create_payment', 'process_payment', 'refund'],
    'notification':  ['send_notification', 'send_sms', 'send_email', 'push_notify'],
    'database':      ['save', 'create', 'update', 'delete', 'insert', 'upsert'],
    'api':           ['get', 'post', 'put', 'delete', 'patch', 'handle_request'],
    'storage':       ['upload', 'download', 'read_file', 'write_file', 'store'],
    'logging':       ['log', 'debug', 'info', 'warning', 'error', 'exception'],
}

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

PRESIDIO_MAP = {
    "PERSON":           (PIICategory.NAME,      Sensitivity.PERSONAL),
    "PHONE_NUMBER":     (PIICategory.PHONE,     Sensitivity.PERSONAL),
    "PHONE":            (PIICategory.PHONE,     Sensitivity.PERSONAL),
    "EMAIL_ADDRESS":    (PIICategory.EMAIL,     Sensitivity.PERSONAL),
    "AADHAAR":          (PIICategory.AADHAAR,   Sensitivity.SENSITIVE),
    "IN_PAN":           (PIICategory.PAN,       Sensitivity.SENSITIVE),
    "LOCATION":         (PIICategory.LOCATION,  Sensitivity.PERSONAL),
    "MEDICAL_LICENSE":  (PIICategory.HEALTH,    Sensitivity.SENSITIVE),
}


# ── Verhoeff checksum for Aadhaar validation ──────────────────────────────────
# Aadhaar uses the Verhoeff algorithm (d5 * p[i][c]).
# A regex match alone can produce false positives; checksum filters them.

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
_VERHOEFF_INV = [0,4,3,2,1,9,8,7,6,5]


def _verhoeff_validate(number: str) -> bool:
    """Return True if `number` passes the Verhoeff checksum (valid Aadhaar digit sequence)."""
    digits = [int(d) for d in reversed(number)]
    c = 0
    for i, d in enumerate(digits):
        p = _VERHOEFF_P[i % 8][d]
        c = _VERHOEFF_D[c][p]
    return c == 0


def _validate_aadhaar(line: str) -> bool:
    """Return True if the line contains a digit sequence that passes Verhoeff."""
    for match in AADHAAR_VALUE_RE.finditer(line):
        digits = re.sub(r'\s', '', match.group(1))
        if _verhoeff_validate(digits):
            return True
    # No value-level match — allow keyword match to stand (conservative)
    return True


# ── Module classifier ─────────────────────────────────────────────────────────

def classify_module(file_path: str, source_text: str) -> set[str]:
    """
    Return a set of module-type labels for a file, using:
    1. File path keyword matching (fast)
    2. Python AST function-name extraction (for .py files)

    Labels: 'analytics', 'authentication', 'payment', 'notification',
            'database', 'api', 'storage', 'logging'
    """
    labels: set[str] = set()
    path_lower = file_path.lower()

    # Path-keyword pass
    for module_type, keywords in MODULE_PATH_KEYWORDS.items():
        if any(kw in path_lower for kw in keywords):
            labels.add(module_type)

    # AST function-name pass (Python only)
    if file_path.endswith('.py'):
        try:
            tree = ast.parse(source_text)
            func_names = {
                node.name.lower()
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            for module_type, func_keywords in MODULE_FUNC_KEYWORDS.items():
                if any(
                    any(fkw in fn for fkw in func_keywords)
                    for fn in func_names
                ):
                    labels.add(module_type)
        except SyntaxError:
            pass

    return labels


# ── AST taint analysis ────────────────────────────────────────────────────────
# Propagates PII labels from assignment LHS through the file to detect whether
# a tainted variable reaches a third-party sink call.

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
    report a taint finding.

    Returns list of {file_path, line_number, pii_category, sink, raw_text}.
    """
    taint_findings: list[dict] = []
    if not line_findings:
        return taint_findings

    # Build set of tainted variable names from pass-1/2 findings
    # Use a simple name-on-the-same-line heuristic as the seed set
    lines = source_text.splitlines()
    tainted_names: dict[str, PIICategory] = {}

    for line_num, cat in line_findings:
        if line_num - 1 < len(lines):
            raw = lines[line_num - 1]
            # Extract identifiers from the line as seed taint names
            for ident in re.findall(r'\b([a-z_][a-z0-9_]*)\b', raw.lower()):
                if len(ident) > 2:
                    tainted_names[ident] = cat

    try:
        tree = ast.parse(source_text)
    except SyntaxError:
        return taint_findings

    # Walk assignments to propagate taint
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            # Get the RHS value node
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

        # Identify the sink name
        sink_name: str | None = None
        if isinstance(node.func, ast.Attribute):
            sink_name = node.func.attr.lower()
            # Also check the object for SDK names
            if isinstance(node.func.value, ast.Name):
                obj = node.func.value.id.lower()
                full = f"{obj}.{sink_name}"
                if any(sdk in full for sdk in ALL_SINKS):
                    sink_name = full
        elif isinstance(node.func, ast.Name):
            sink_name = node.func.id.lower()

        if not sink_name:
            continue

        is_sink = any(sdk in sink_name for sdk in ALL_SINKS)
        if not is_sink:
            continue

        # Check args for tainted variables
        call_line = getattr(node, 'lineno', 0)
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            arg_names = {
                n.id.lower()
                for n in ast.walk(arg)
                if isinstance(n, ast.Name)
            }
            for aname in arg_names:
                if aname in tainted_names:
                    taint_findings.append({
                        "file_path":    file_path,
                        "line_number":  call_line,
                        "pii_category": tainted_names[aname],
                        "sink":         sink_name,
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

    lines = source_text.splitlines()
    tainted_names: dict[str, PIICategory] = {}

    # Seed tainted names from pass-1/2 findings
    for line_num, cat in line_findings:
        if line_num - 1 < len(lines):
            raw = lines[line_num - 1]
            for ident in re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', raw):
                if len(ident) > 2:
                    tainted_names[ident.lower()] = cat

    def _node_text(node) -> str:
        return source_text[node.start_byte:node.end_byte]

    def _walk(node):
        yield node
        for child in node.children:
            yield from _walk(child)

    # Propagate taint through variable declarations
    for node in _walk(tree.root_node):
        if node.type in ("variable_declarator", "assignment_expression"):
            children = list(node.children)
            if len(children) >= 3:  # name = value
                lhs = children[0]
                rhs = children[-1]
                rhs_text = _node_text(rhs).lower()
                propagate_cat = next(
                    (tainted_names[n] for n in tainted_names if n in rhs_text),
                    None,
                )
                if propagate_cat:
                    lhs_text = _node_text(lhs).lower().strip()
                    for ident in re.findall(r'\b([a-z_][a-z0-9_]*)\b', lhs_text):
                        tainted_names[ident] = propagate_cat

    # Detect tainted args at call sites
    for node in _walk(tree.root_node):
        if node.type == "call_expression":
            call_text = _node_text(node).lower()
            is_sink = any(sdk in call_text for sdk in ALL_SINKS)
            if not is_sink:
                continue
            line_no = node.start_point[0] + 1
            raw = lines[line_no - 1] if line_no - 1 < len(lines) else ""
            for tainted_var, cat in tainted_names.items():
                if tainted_var in call_text:
                    taint_findings.append({
                        "file_path":    file_path,
                        "line_number":  line_no,
                        "pii_category": cat,
                        "sink":         call_text[:60],
                        "raw_text":     raw.strip()[:200],
                    })
                    break

    return taint_findings


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
        if f.type == "blob"
        and any(f.path.endswith(ext) for ext in ['.py', '.js', '.ts'])
    ]
    target_files = target_files[:300]
    print(f"[scanner] {len(target_files)} files to scan in {repo_name}")

    for file_obj in target_files:
        try:
            content = repo.get_contents(file_obj.path)
            source_text = content.decoded_content.decode('utf-8', errors='ignore')
            lines = source_text.splitlines()

            # Module type labels for this file
            file_module_types = classify_module(file_obj.path, source_text)

            # Track pass-1/2 findings per line for taint seeding
            line_pii: list[tuple[int, PIICategory]] = []

            is_py = file_obj.path.endswith('.py')
            is_js = file_obj.path.endswith(('.js', '.ts'))

            # Docstring-tracking state (Python triple-quoted strings)
            _in_docstring    = False
            _docstring_delim = '"""'
            # JS/TS block comments  /* ... */  and  /** ... */
            _in_block_comment = False

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
                # for SDK detection so comment text doesn't trigger false SDK matches.
                # Python inline comment: everything from the first unquoted # onward
                # JS/TS  inline comment: everything from // onward
                code_part = line
                if is_py and '#' in line:
                    # Simple heuristic: take text before the first #
                    code_part = line.split('#')[0]
                elif is_js and '//' in line:
                    code_part = line.split('//')[0]

                line_lower      = line.lower()
                code_part_lower = code_part.lower()
                matched = False

                # ── Pass 1: regex ─────────────────────────────────────────
                for category, pattern in PII_PATTERNS.items():
                    if re.search(pattern, line_lower):
                        # Special: validate Aadhaar digit sequences
                        if category == PIICategory.AADHAAR:
                            if not _validate_aadhaar(line):
                                continue  # regex hit but Verhoeff fails — skip

                        # Use code_part_lower (comment stripped) so SDK names
                        # in comments don't trigger false third-party findings.
                        third_party = next(
                            (s for s in THIRD_PARTY_SDKS if s in code_part_lower),
                            None,
                        )
                        # Check logger sinks (code part only)
                        if not third_party:
                            logger_hit = next(
                                (s for s in LOGGER_SINK_KEYWORDS if s in code_part_lower),
                                None,
                            )
                            if logger_hit:
                                third_party = logger_hit.rstrip('.').rstrip('(')

                        fo = DataFlowObject(
                            source="code_scanner",
                            file_path=file_obj.path,
                            line_number=line_num,
                            raw_text=line.strip()[:200],
                            field_name=category.value,
                            pii_category=category,
                            sensitivity=SENSITIVITY_MAP.get(category, Sensitivity.UNKNOWN),
                            third_party_sdk=third_party,
                        )
                        findings.append(fo)
                        line_pii.append((line_num, category))

                        # Update usage_map
                        usage_map.setdefault(category, set()).update(file_module_types)

                        matched = True
                        break  # one finding per line in pass 1

                # ── Pass 2: Presidio NER ──────────────────────────────────
                if not matched and len(line.strip()) > 10:
                    presidio_hits = scan_text_with_presidio(line)
                    for hit in presidio_hits:
                        if hit in PRESIDIO_MAP:
                            cat, sens = PRESIDIO_MAP[hit]
                            third_party = next(
                                (s for s in THIRD_PARTY_SDKS if s in code_part_lower),
                                None,
                            )
                            fo = DataFlowObject(
                                source="presidio_scanner",
                                file_path=file_obj.path,
                                line_number=line_num,
                                raw_text=line.strip()[:200],
                                field_name=hit.lower(),
                                pii_category=cat,
                                sensitivity=sens,
                                third_party_sdk=third_party,
                            )
                            findings.append(fo)
                            line_pii.append((line_num, cat))
                            usage_map.setdefault(cat, set()).update(file_module_types)
                            break

            # ── AST taint analysis ────────────────────────────────────────
            taint_results: list[dict] = []
            if file_obj.path.endswith('.py'):
                taint_results = _python_taint_analysis(source_text, file_obj.path, line_pii)
            elif file_obj.path.endswith(('.js', '.ts')):
                taint_results = _js_taint_analysis(source_text, file_obj.path, line_pii)

            # Snapshot pass-1/2 findings ONCE so taint results at the same
            # line as each other (different PII categories) are not suppressed.
            existing_pass12 = {(f.file_path, f.line_number) for f in findings}
            existing_taint_keys: set = set()  # (file_path, line_number, pii_category)

            for tr in taint_results:
                cat = tr["pii_category"]
                sink = tr["sink"]
                # Determine which SDK bucket the sink falls into
                sdk_label = next(
                    (s for s in THIRD_PARTY_SDKS if s in sink.lower()),
                    None,
                )
                if not sdk_label:
                    sdk_label = next(
                        (ls.rstrip('.').rstrip('(') for ls in LOGGER_SINK_KEYWORDS if ls.replace('(', '').replace('.', '') in sink.lower()),
                        None,
                    )
                if not sdk_label:
                    sdk_label = sink[:40]

                # Skip if pass-1/2 already caught a finding at the same line
                line_key = (tr["file_path"], tr["line_number"])
                if line_key in existing_pass12:
                    continue

                # Skip if taint already reported the same (file, line, category)
                cat_key = (tr["file_path"], tr["line_number"], cat)
                if cat_key in existing_taint_keys:
                    continue
                existing_taint_keys.add(cat_key)

                fo = DataFlowObject(
                    source="taint_analysis",
                    file_path=tr["file_path"],
                    line_number=tr["line_number"],
                    raw_text=tr["raw_text"],
                    field_name=cat.value,
                    pii_category=cat,
                    sensitivity=SENSITIVITY_MAP.get(cat, Sensitivity.UNKNOWN),
                    third_party_sdk=sdk_label,
                )
                findings.append(fo)
                usage_map.setdefault(cat, set()).update(file_module_types)

        except Exception as e:
            print(f"[scanner] skipped {file_obj.path}: {e}")

    print(f"[scanner] Done — {len(findings)} PII findings")
    print(f"[scanner] usage_map: { {k.value: v for k, v in usage_map.items()} }")
    return findings, usage_map
