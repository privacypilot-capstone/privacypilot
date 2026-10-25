"""
DPDP Act 2023 Rule Engine
=========================
Implements three detection rules mapped to the Act's sections:

  Rule 1 — Notice Gap         : Section 5 (Notice) + Section 6(1) (Consent)
  Rule 2 — Third-Party Xmit   : Section 8(2) (processor only under a valid
                                 contract) for SDK / HTTP / queue sinks;
                                 Section 8(5) (security safeguards) for local
                                 logger sinks; both, in one violation, for
                                 external logging services (Sentry, Datadog,
                                 CloudWatch)

One violation per (rule, PII category[, recipient]); each lists every code
location it covers. A finding can still raise several violations when it
breaches several provisions (e.g. a notice gap AND an undisclosed processor).
  Rule 3 — Purpose–PII Linkage: Section 6(1) (specified purpose / necessity)

Section mapping verified against DPDP Act 2023 text:
  Sec 5(1) — notice of (i) the personal data and the purpose of processing,
             (ii) how to exercise rights under s.6(4) and s.13, (iii) how to
             complain to the Board. It does NOT require recipients to be named.
  Sec 6(1) — consent: free, specific, informed, unconditional, unambiguous,
             clear affirmative action; limited to data necessary for the
             specified purpose
  Sec 8(1) — the Data Fiduciary stays responsible for processing done on its
             behalf by a Data Processor
  Sec 8(2) — a Data Processor may be engaged only under a valid contract
  Sec 8(5) — reasonable security safeguards to prevent personal data breach
             (DPDP Rules 2025, Rule 6(1)(a) lists encryption, obfuscation,
             masking and virtual tokens as such measures)
"""

from models.dataflow import DataFlowObject, PIICategory, Sensitivity
from scanners.sinks import (
    sink_kind, SDK_LABELS, HTTP_LABELS, QUEUE_LABELS, LOGGER_LABELS,
    EXTERNAL_LOGGER_LABELS,
)

# ── PII sensitivity tiers ───────────────────────────────────────────────────
SENSITIVE_CATEGORIES = {
    PIICategory.AADHAAR,
    PIICategory.HEALTH,
    PIICategory.BIOMETRIC,
    PIICategory.FINANCIAL,
    PIICategory.PAN,
}

# ── Sink categories for Rule 2 ──────────────────────────────────────────────
# The label vocabulary lives in scanners/sinks.py and is shared with the code
# scanner and the policy parser, so every label the scanner writes is one this
# engine recognises (previously JS / queue taint labels were raw call text
# and never matched).
#   SDK_LABELS    — analytics + communication SDKs  → Section 8(2)
#   HTTP_LABELS   — outbound HTTP                     → Section 8(2)
#   QUEUE_LABELS  — queues / brokers                  → Section 8(2)
#   LOGGER_LABELS — loggers / monitoring              → Section 8(5)
ALL_SDK_SINKS = SDK_LABELS
HTTP_SINKS    = HTTP_LABELS
QUEUE_SINKS   = QUEUE_LABELS
LOGGER_SINKS  = LOGGER_LABELS

# ── Rule 3: module-type → purpose-category mapping ─────────────────────────
# The code scanner's module classifier (scanners/code_scanner.py,
# MODULE_PATH_KEYWORDS / MODULE_FUNC_KEYWORDS) and the policy parser's
# purpose classifier (scanners/policy_parser.py, PURPOSE_CATEGORIES) use two
# independently-named label vocabularies. This table translates each
# module-type label into the purpose-category label(s) it legitimately
# serves, so Rule 3 compares like with like instead of doing a raw
# string-difference between two different taxonomies (which only ever
# agreed on the word "analytics"). Each mapping is grounded in the keyword
# lists the two classifiers already use:
#   - authentication code (auth/login/oauth/session) maps to
#     "service_delivery" (whose keywords include authenticate/login/access)
#     and to "security" (auth is itself a security control).
#   - payment/database/api/storage code all exist to run the product, so
#     they map to "service_delivery".
#   - notification code maps to "communication" (notif/alert/email/sms).
#   - logging code maps to "security" (its own keyword list includes
#     "audit").
#   - analytics code maps to "analytics" only. (It used to map to
#     "marketing" too, on the reasoning that tracking is often monetised;
#     but then any policy sentence the classifier labelled "marketing" made
#     analytics processing look disclosed. Section 6(1) consent is for the
#     SPECIFIED purpose, so analytics use needs an analytics purpose.)
MODULE_TO_PURPOSE: dict[str, set[str]] = {
    'analytics':      {'analytics'},
    'authentication': {'service_delivery', 'security'},
    'payment':        {'service_delivery'},
    'notification':   {'communication'},
    'database':       {'service_delivery'},
    'api':            {'service_delivery'},
    'storage':        {'service_delivery'},
    'logging':        {'security'},
}


class DPDPViolation:
    def __init__(self, section, title, severity, pii_category, evidence, recommendation,
                 recipient=None, locations=None):
        # recipient: for third-party transmission / logging (Rule 2), the SDK,
        # host or logging service the data reaches ("application logs" for
        # local log calls); None for the other rules.
        # locations: every code location behind this violation, as
        # [{"file", "line", "origin"?, "modules"?, "sinks"?}, ...]; the
        # evidence text lists the same locations.
        self.recipient      = recipient
        self.locations      = locations or []
        self.dpdp_section   = section
        self.section_title  = title
        self.severity       = severity
        self.pii_category   = pii_category
        self.evidence       = evidence
        self.recommendation = recommendation

    def to_dict(self):
        return {
            "dpdp_section":   self.dpdp_section,
            "section_title":  self.section_title,
            "severity":       self.severity,
            "pii_category":   self.pii_category,
            "evidence":       self.evidence,
            "recommendation": self.recommendation,
            "recipient":      self.recipient,
            "locations":      self.locations,
        }


def _is_logger_sink(sdk: str | None, raw_text: str = "") -> bool:
    """
    Return True if the finding's sink is a logger (Section 8(5) territory).

    Decided from the sink label alone. The raw line text is deliberately NOT
    substring-searched any more: "fingerprint" contains "print", so
    `mixpanel.track('scan', fingerprint)` used to be filed under 8(5)
    instead of 8(2). `raw_text` is kept as a parameter for compatibility.
    """
    return sink_kind(sdk) == 'logger'


_ORIGIN_NOTE = {
    "third_party": (" This call is inside third-party code bundled in the repository "
                    "(e.g. a vendored SDK or node_modules package); the Data Fiduciary "
                    "is responsible for what the software it ships transmits."),
    "generated":   (" This call is in generated/built code (e.g. dist/ or a minified "
                    "bundle) committed to the repository."),
}


def _origin_note(finding) -> str:
    return _ORIGIN_NOTE.get(getattr(finding, "origin", None) or "", "")


# Recipient name for every local log call (print, logging, logger, log,
# console.log): they all write to the application's own logs, so they are
# one recipient — one violation per category, not one per log function.
LOCAL_LOG_RECIPIENT = "application logs"


def _is_first_party(finding) -> bool:
    return getattr(finding, "origin", None) in (None, "first_party")


def _plural(n: int, word: str) -> str:
    return word if n == 1 else f"{word}s"


def _locations(findings, with_modules: bool = False, with_sink: bool = False,
               by_call: bool = False) -> list[dict]:
    """
    Distinct (file, line) locations of `findings`: the application's own code
    first, then by file and line. Several findings on one line (e.g. the regex
    pass and the taint pass) are one location. With by_call, a finding inside
    a multi-line sink call is placed on the call's first line (call_line), so
    one call carrying PII on several argument lines is ONE location.
    """
    out: dict = {}
    for f in findings:
        line = (getattr(f, "call_line", None) or f.line_number) if by_call else f.line_number
        k = (f.file_path, line)
        loc = out.get(k)
        if loc is None:
            loc = {"file": f.file_path, "line": line}
            origin = getattr(f, "origin", None)
            if origin and origin != "first_party":
                loc["origin"] = origin
            out[k] = loc
        if with_modules and getattr(f, "module_types", None):
            loc["modules"] = sorted(set(loc.get("modules", [])) | set(f.module_types))
        if with_sink and f.third_party_sdk:
            loc["sinks"] = sorted(set(loc.get("sinks", [])) | {f.third_party_sdk})
    return sorted(out.values(), key=lambda l: (
        "origin" in l, l.get("file") or "", l.get("line") or 0))


_ORIGIN_TAG = {"third_party": "third-party code", "generated": "generated code"}


def _location_label(loc: dict) -> str:
    if "policy" in loc:
        from database import location_label
        return location_label(loc)
    s = f"{loc.get('file') or 'unknown file'} line {loc.get('line')}"
    if loc.get("sinks"):
        s += f" ({', '.join(loc['sinks'])})"
    if loc.get("modules"):
        s += f" (module: {', '.join(loc['modules'])})"
    if loc.get("origin") in _ORIGIN_TAG:
        s += f" [{_ORIGIN_TAG[loc['origin']]}]"
    return s


# Up to this many locations are written into the evidence sentence; above
# it the sentence gives the count and the full list is the violation's
# `locations` (shown by the UI, the HTML/PDF reports, the CSV export and the
# API), so a long list is not printed twice.
INLINE_LOCATIONS = 3


def _locations_text(locs: list[dict], prefix: str = "at") -> str:
    """'at a.py line 3', 'at 3 locations: a.py line 3; b.py line 9; c.py line 1'
    or 'at 40 locations (all listed under Locations)'. Every location is
    always reported, so fixing the code at one place cannot be mistaken for
    fixing the violation."""
    if not locs:
        return ""
    if len(locs) == 1:
        return f"{prefix} {_location_label(locs[0])}"
    if len(locs) <= INLINE_LOCATIONS:
        return f"{prefix} {len(locs)} locations: " + "; ".join(_location_label(l) for l in locs)
    return f"{prefix} {len(locs)} locations (all listed under Locations)"


def _origin_notes(findings) -> str:
    """Explain third-party / generated locations (marked in the location list)."""
    findings = list(findings)
    origins = {getattr(f, "origin", None) for f in findings}
    distinct = {(f.file_path, getattr(f, "call_line", None) or f.line_number)
                for f in findings}
    if len(distinct) == 1:
        return _origin_note(findings[0])
    notes = ""
    if "third_party" in origins:
        notes += (" Locations marked [third-party code] are inside third-party "
                  "code bundled in the repository (e.g. a vendored SDK or "
                  "node_modules package); the Data Fiduciary is responsible for "
                  "what the software it ships transmits.")
    if "generated" in origins:
        notes += (" Locations marked [generated code] are in generated/built "
                  "code (e.g. dist/ or a minified bundle) committed to the "
                  "repository.")
    return notes


def _policy_recipient_clause(recipient, cat, is_disclosed, named_for) -> str:
    if is_disclosed:
        return (f"The privacy policy names '{recipient}' as a recipient of this "
                f"data; whether a valid contract with it exists cannot be "
                f"verified from the policy text or source code alone.")
    if named_for:
        return (f"The privacy policy names '{recipient}' as a recipient of "
                f"{', '.join(named_for)} data, but not of '{cat.value}' data.")
    return (f"The privacy policy does not name '{recipient}' as a recipient "
            f"of this data.")


def run_dpdp_rules(
    code_findings: list,
    policy_claims: list,
    gap_categories: set,
    usage_map: dict | None = None,
    purpose_map: dict | None = None,
    vagueness_warnings: list | None = None,
    disclosed_sdks: dict | None = None,
) -> list:
    """
    Parameters
    ----------
    code_findings      : list[DataFlowObject] from code_scanner
    policy_claims      : list[DataFlowObject] from policy_parser
    gap_categories     : set[PIICategory] — PII in code but absent from policy
    usage_map          : {PIICategory → set[str]} module-type labels from code_scanner
                         (populated after Step 4 — module classifier)
    purpose_map        : {PIICategory → set[str]} purpose labels from policy_parser
                         (populated after Step 5 — purpose extraction)
    vagueness_warnings : list[dict] from policy_parser vagueness detector
                         (populated after Step 5)
    disclosed_sdks     : {PIICategory → set[str]} SDKs the privacy policy already
                         names as a recipient of that PII category (policy_parser
                         Pass 3). Used by Rule 2 so it stops treating every
                         PII+SDK pairing as "undisclosed" when the policy already
                         discloses it.

    Third-party and generated code
    ------------------------------
    code_findings may include findings from bundled third-party and generated
    files (finding.origin). Rule 2 uses ALL of them — a vendored SDK sending
    personal data out is a third-party transmission wherever its code lives —
    and says in the evidence when the call is in third-party code. Rules 1
    and 3 concern what the application itself collects and why, so the
    caller computes gap_categories and usage_map from first-party code only.
    Every violation lists ALL of its code locations (evidence text and
    DPDPViolation.locations); pass first-party findings first so they are
    listed first.

    Returns
    -------
    list[DPDPViolation]
    """
    violations = []
    seen = set()

    # ── Rule 1: Notice Gap — Section 5 + Section 6(1) ──────────────────────
    # PII is found in source code but NOT disclosed in the privacy policy.
    # Section 5 requires the data fiduciary to give notice of what data is
    # collected and for what purpose before or at the time of collection.
    # Section 6(1) makes consent invalid without proper prior notice.
    #
    # One violation per category, citing EVERY place the application's own
    # code handles it (third-party code only when there is no first-party
    # occurrence), each with the code modules it sits in. Because the policy
    # does not mention the category at all, none of the purposes those
    # modules serve is stated either: that Section 6(1) purpose gap is
    # reported here, in the same violation, rather than as a separate Rule 3
    # violation for the same category.

    gap_findings: dict = {}
    for finding in code_findings:
        if finding.pii_category in gap_categories:
            gap_findings.setdefault(finding.pii_category, []).append(finding)

    for cat, fs in gap_findings.items():
        key = f"r1_{cat.value}"
        if key in seen:
            continue
        seen.add(key)
        own = [f for f in fs if _is_first_party(f)] or fs
        locs = _locations(own, with_modules=True)
        is_sensitive = cat in SENSITIVE_CATEGORIES
        modules = sorted({m for f in own for m in (f.module_types or [])})
        if usage_map and cat in usage_map:
            modules = sorted(set(modules) | set(usage_map[cat]))
        purposes = sorted({p for m in modules
                           for p in MODULE_TO_PURPOSE.get(m, {m})})
        _purpose_clause = (
            f" The code processes it in {_plural(len(modules), 'module')} "
            f"{', '.join(modules)} (purpose(s) these modules typically serve: "
            f"{', '.join(purposes)}); none of these purposes is stated, because "
            f"the policy does not mention this data at all."
            if modules else ""
        )
        violations.append(DPDPViolation(
            section="Section 5 / Section 6(1)",
            title="Notice Gap — Undisclosed Data Collection",
            severity="critical" if is_sensitive else "high",
            pii_category=cat.value,
            evidence=(
                f"'{cat.value}' data is collected or processed by the code "
                f"{_locations_text(locs)} but is absent from the privacy "
                f"policy.{_purpose_clause} Section 5 of the "
                f"DPDP Act 2023 requires the data fiduciary to give notice of "
                f"the personal data collected and the purpose of processing. "
                f"Without this disclosure, consent under Section 6(1) cannot "
                f"be free, specific, or informed."
            ),
            recommendation=(
                f"1. Add an explicit entry for '{cat.value}' data to the "
                f"privacy policy, describing what is collected and the "
                f"purpose for which it is processed (Section 5(1)(i))"
                + (f" — the code uses it for: {', '.join(purposes)}" if purposes else "")
                + ". "
                f"2. Present this notice before or at the point of collection. "
                f"3. Implement a consent gate that is gated on disclosure."
            ),
            locations=locs,
        ))

    # ── Rule 2: Third-Party Transmission / Logging ──────────────────────────
    # • SDK / HTTP / queue sinks → Section 8(2): a Data Processor may only be
    #   engaged under a valid contract, which cannot be verified from code.
    #   (Previously also cited as Section 5, on the claim that the notice must
    #   name third parties — Section 5(1) contains no such requirement.)
    # • Local logger sinks (print, logging, logger, console.log …) →
    #   Section 8(5) (security safeguard failure — PII in log files).
    #   All local log calls are ONE recipient ("application logs"), so a
    #   category logged through both print() and logger.info() is one
    #   violation listing both, not two.
    # • External logging / monitoring services (Sentry, Datadog, CloudWatch)
    #   → Section 8(5) AND Section 8(2) in one violation: the data is in logs
    #   and it is also sent to a third party that processes it.
    #
    # One violation per (category, recipient), citing every location.

    groups: dict = {}            # (kind, cat, recipient) → [finding, ...]
    for finding in code_findings:
        sdk = finding.third_party_sdk
        if not sdk:
            continue
        if _is_logger_sink(sdk, finding.raw_text or ""):
            if sdk.lower() in EXTERNAL_LOGGER_LABELS:
                gk = ("extlog", finding.pii_category, sdk.lower())
            else:
                gk = ("log", finding.pii_category, LOCAL_LOG_RECIPIENT)
        elif sink_kind(sdk.lower()) in ('sdk', 'http', 'queue'):
            gk = ("xmit", finding.pii_category, sdk)
        else:
            continue
        groups.setdefault(gk, []).append(finding)

    for (kind, cat, recipient), fs in groups.items():
        is_sensitive = cat in SENSITIVE_CATEGORIES
        locs = _locations(fs, with_sink=(kind == "log"), by_call=True)
        where = _locations_text(locs)
        notes = _origin_notes(fs)
        rec_lower = recipient.lower()
        _disclosed_set = {s.lower() for s in (disclosed_sdks or {}).get(cat, set())}
        _named_for = sorted(
            c.value for c, sdks in (disclosed_sdks or {}).items()
            if rec_lower in {s.lower() for s in sdks}
        )

        if kind == "log":
            key = f"r2_log_{cat.value}"
            if key in seen:
                continue
            seen.add(key)
            violations.append(DPDPViolation(
                section="Section 8(5)",
                title="Security Safeguard — PII in Logger Output",
                recipient=recipient,
                severity="critical" if is_sensitive else "high",
                pii_category=cat.value,
                evidence=(
                    f"'{cat.value}' data appears in log/print statements "
                    f"{where}.{notes} Logging personal data exposes it in log "
                    f"files, monitoring dashboards, and log-aggregation "
                    f"services. Section 8(5) requires the Data Fiduciary to "
                    f"take reasonable security safeguards to prevent personal "
                    f"data breach."
                ),
                recommendation=(
                    f"Remove or mask '{cat.value}' from all log statements "
                    f"(masking and obfuscation are safeguards listed in DPDP "
                    f"Rules 2025, Rule 6(1)(a)). Use structured logging with a "
                    f"PII-scrubbing filter. Treat log sinks as untrusted "
                    f"channels for personal data."
                ),
                locations=locs,
            ))
            continue

        if kind == "extlog":
            key = f"r2_extlog_{cat.value}_{rec_lower}"
            if key in seen:
                continue
            seen.add(key)
            is_disclosed = rec_lower in _disclosed_set
            _policy_clause = _policy_recipient_clause(recipient, cat, is_disclosed, _named_for)
            violations.append(DPDPViolation(
                section="Section 8(5) / Section 8(2)",
                title="Security Safeguard — PII Sent to External Logging Service",
                recipient=recipient,
                severity="critical" if is_sensitive else "high",
                pii_category=cat.value,
                evidence=(
                    f"'{cat.value}' data is sent to the logging/monitoring "
                    f"service '{recipient}' {where}.{notes} Logging personal "
                    f"data exposes it in log files and dashboards; Section 8(5) "
                    f"requires reasonable security safeguards to prevent "
                    f"personal data breach. '{recipient}' is also a third party "
                    f"processing the data on the Data Fiduciary's behalf. "
                    f"{_policy_clause} Section 8(2) permits a Data Processor "
                    f"to be engaged only under a valid contract, and under "
                    f"Section 8(1) the Data Fiduciary remains responsible for "
                    f"its processing."
                ),
                recommendation=(
                    f"1. Remove or mask '{cat.value}' before it reaches "
                    f"'{recipient}' (masking and obfuscation are safeguards "
                    f"listed in DPDP Rules 2025, Rule 6(1)(a)); configure the "
                    f"service's PII scrubbing. "
                    f"2. Confirm a valid contract (Data Processing Agreement) "
                    f"with '{recipient}' is in place"
                    + ("." if is_disclosed else
                       f" and name '{recipient}' as a processor in the privacy "
                       f"policy for transparency.")
                ),
                locations=locs,
            ))
            continue

        # kind == "xmit": SDK / HTTP / queue sink — Section 8(2)
        key = f"r2_sdk_{cat.value}_{recipient}"
        if key in seen:
            continue
        seen.add(key)
        # Has the privacy policy already named this SDK as a recipient of
        # this PII category (policy_parser Pass 3)? Only the named-company
        # sink lists (ALL_SDK_SINKS) are checkable this way — HTTP_SINKS /
        # QUEUE_SINKS are generic code patterns ('requests.post', 'kafka'),
        # not names a policy would plausibly disclose by string match, so
        # they always fall through to the undisclosed branch.
        is_disclosed = (sink_kind(rec_lower) == 'sdk' and rec_lower in _disclosed_set)
        if is_disclosed:
            # The policy already names the recipient for this data, so it is
            # not flagged as undisclosed. What remains unverifiable from the
            # policy text or source code alone is Section 8(2): whether a
            # valid processor contract exists. Flag that at medium severity.
            violations.append(DPDPViolation(
                section="Section 8(2)",
                title="Third-Party Transmission — Processor Contract Unverified",
                recipient=recipient,
                severity="medium",
                pii_category=cat.value,
                evidence=(
                    f"'{cat.value}' data is transmitted to '{recipient}' "
                    f"{where}.{notes} "
                    f"The privacy policy already names '{recipient}' as a "
                    f"recipient of this data. Section 8(2) permits a Data "
                    f"Processor to be engaged only under a valid contract, "
                    f"and under Section 8(1) the Data Fiduciary remains "
                    f"responsible for its processing — whether such a "
                    f"contract exists cannot be verified from the policy "
                    f"text or source code alone."
                ),
                recommendation=(
                    f"Confirm a valid, signed contract (Data Processing "
                    f"Agreement) with '{recipient}' is in place, including the "
                    f"security safeguards it must apply (DPDP Rules 2025, "
                    f"Rule 6(1)(f))."
                ),
                locations=locs,
            ))
        else:
            # Recipient not named in the policy for THIS data. If the policy
            # names it for other categories, say so — otherwise readers (and
            # the LLM summary) take it to mean it is missing altogether.
            _policy_clause = _policy_recipient_clause(recipient, cat, False, _named_for)
            violations.append(DPDPViolation(
                section="Section 8(2)",
                title="Third-Party Transmission — Undisclosed Data Processor",
                recipient=recipient,
                severity="critical" if is_sensitive else "high",
                pii_category=cat.value,
                evidence=(
                    f"'{cat.value}' data is transmitted to '{recipient}' "
                    f"{where}.{notes} "
                    f"{_policy_clause} Section 8(2) permits a Data "
                    f"Processor to be engaged only under a valid contract, "
                    f"and under Section 8(1) the Data Fiduciary remains "
                    f"responsible for its processing."
                ),
                recommendation=(
                    f"1. Execute a valid contract (Data Processing Agreement) "
                    f"with '{recipient}', including the security safeguards it must "
                    f"apply (DPDP Rules 2025, Rule 6(1)(f)). "
                    f"2. Name '{recipient}' as a processor in the privacy policy for "
                    f"transparency. "
                    f"3. '{cat.value}' is treated as high-risk by PrivacyPilot "
                    f"(a project severity tier, not a category defined in the "
                    f"Act): minimise or tokenise it before sharing."
                    if is_sensitive else
                    f"1. Execute a valid contract (Data Processing Agreement) "
                    f"with '{recipient}'. "
                    f"2. Name '{recipient}' as a processor in the privacy policy for "
                    f"transparency."
                ),
                locations=locs,
            ))

    # ── Rule 3: Purpose–PII Linkage — Section 6(1) ──────────────────────────
    # Cross-reference usage_map (how code uses each PII category, e.g. 'analytics')
    # with purpose_map (what the policy claims PII is used for, e.g. 'service_delivery').
    # A mismatch means data is processed for a purpose not disclosed → Section 6(1)
    # consent cannot be "specific" or "informed".
    #
    # This rule runs whenever the code side (usage_map) is available. An empty
    # purpose_map is NOT a reason to skip it: a policy that states no purpose
    # at all is the worst case, and every module use then lacks a stated
    # purpose (previously the rule was skipped exactly then).
    #
    # Categories reported by Rule 1 (absent from the policy entirely) are
    # skipped here: the Rule 1 violation already states the purposes the code
    # uses them for, so a second violation would duplicate it.

    if usage_map:
        purpose_map = purpose_map or {}
        for cat, code_uses in usage_map.items():
            if cat in gap_categories:
                continue   # reported, with its purposes, by Rule 1
            policy_purposes = purpose_map.get(cat, set())

            # Translate each module-type label into the purpose category(ies)
            # it legitimately serves (MODULE_TO_PURPOSE above), then flag any
            # module type whose translated purposes have no overlap with the
            # policy's stated purposes for this PII category.
            uncovered_modules: set[str] = set()
            inferred_purposes: set[str] = set()
            for module_type in code_uses:
                expected = MODULE_TO_PURPOSE.get(module_type)
                if expected is None:
                    # Unknown module-type label (e.g. a new entry added to
                    # MODULE_PATH_KEYWORDS without a matching mapping here):
                    # fail safe with a direct-label comparison rather than
                    # silently skipping it.
                    expected = {module_type}
                inferred_purposes |= expected
                if not (expected & policy_purposes):
                    uncovered_modules.add(module_type)

            if uncovered_modules:
                key = f"r3_{cat.value}"
                if key not in seen:
                    seen.add(key)
                    # Every first-party location of this category that sits
                    # in one of the uncovered modules. A finding without
                    # module labels (older stored scans) cannot be placed,
                    # so it is listed rather than dropped.
                    in_scope = [
                        f for f in code_findings
                        if f.pii_category == cat and _is_first_party(f)
                        and (f.module_types is None
                             or set(f.module_types) & uncovered_modules)
                    ]
                    locs = _locations(in_scope, with_modules=True)
                    _loc_clause = f" ({_locations_text(locs, prefix='found at')})" if locs else ""
                    is_sensitive = cat in SENSITIVE_CATEGORIES
                    violations.append(DPDPViolation(
                        section="Section 6(1)",
                        title="Purpose–PII Linkage — Processing Exceeds Stated Purpose",
                        severity="critical" if is_sensitive else "high",
                        pii_category=cat.value,
                        evidence=(
                            f"'{cat.value}' data is used in code module(s) "
                            f"{sorted(uncovered_modules)}{_loc_clause}, whose "
                            f"typical purpose is not among the privacy "
                            f"policy's stated purposes for this data: "
                            f"{sorted(policy_purposes) or ['none found']}. "
                            f"Section 6(1) requires consent to be specific to the "
                            f"stated purpose; processing for unstated purposes is "
                            f"non-consensual."
                        ),
                        recommendation=(
                            f"Either disclose the purpose(s) "
                            f"{sorted(inferred_purposes - policy_purposes)} in the "
                            f"privacy policy and obtain fresh consent, or restrict "
                            f"'{cat.value}' processing to the already-disclosed "
                            f"purposes: {sorted(policy_purposes) or ['none']}."
                        ),
                        locations=locs,
                    ))

    # ── Vagueness warnings — DPDP Rules 2025, Rule 3(b)(ii) ─────────────────
    # When the purpose classifier's top-2 scores are within 0.08 of each other,
    # the stated purpose is ambiguous and fails the specificity requirement.

    # One violation per PII CATEGORY, like every other rule: it lists every
    # vague statement in the policy that covers that category as its
    # locations. (Previously one violation per statement, so the same
    # category appeared in several violations.) A generic "We use your
    # information to …" statement covers every disclosed category, so it is
    # listed under each of them — as one code line is listed under each
    # category it carries.
    if vagueness_warnings:
        by_cat: dict[str, list[dict]] = {}
        for w in vagueness_warnings:
            by_cat.setdefault(w.get("pii_category") or "unknown", []).append(w)
        for cat, ws in sorted(by_cat.items()):
            key = f"vague_{cat}"
            if key in seen:
                continue
            seen.add(key)
            # One location per distinct statement (policy URL, position
            # among the policy's statements, text), in policy order; the
            # worst (smallest) margin of a statement's warnings is kept.
            stmts: dict[str, dict] = {}
            for w in ws:
                k = " ".join((w.get("sentence") or "").split()).lower()
                if k not in stmts or w.get("margin", 1.0) < stmts[k].get("margin", 1.0):
                    stmts[k] = w
            ordered = sorted(stmts.values(),
                             key=lambda x: (x.get("statement_no") is None, x.get("statement_no") or 0))
            locs = [{"policy": x.get("policy_url"), "statement": x.get("statement_no"),
                     "text": (x.get("sentence") or "").strip()} for x in ordered]
            worst = min(ordered, key=lambda x: x.get("margin", 1.0))
            n = len(ordered)
            if n == 1:
                _sentence = (worst.get("sentence") or "").strip()
                what = (f"The privacy policy's purpose statement covering '{cat}' "
                        f"data is ambiguous")
                quote = f" The flagged clause: \"{_sentence}\"" if _sentence else ""
            else:
                what = (f"{n} purpose statements in the privacy policy covering "
                        f"'{cat}' data are ambiguous (all listed, with their text, "
                        f"under Locations)")
                quote = ""
            violations.append(DPDPViolation(
                section="DPDP Rules 2025, Rule 3(b)(ii)",
                title="Vague Purpose Statement",
                # "low": a language-clarity gap under the subordinate Rules —
                # the purpose IS stated, disclosed and linked, only worded
                # ambiguously — so it sits below the medium "contract
                # unverifiable" case.
                severity="low",
                pii_category=cat,
                evidence=(
                    f"{what}: the classifier margin between the top-2 purpose "
                    f"categories is {worst.get('margin', 0):.3f}"
                    f"{' at its smallest' if n > 1 else ''} (threshold 0.08), "
                    f"closest to '{worst.get('top_label', 'unknown')}'. Rule "
                    f"3(b)(ii) of DPDP Rules 2025 requires the notice to state "
                    f"the specified purpose in clear and plain language.{quote}"
                ),
                recommendation=(
                    f"Rewrite {'this purpose statement' if n == 1 else f'these {n} purpose statements'} "
                    f"to be unambiguous. State exactly what '{cat}' data is used "
                    f"for rather than broad terms like 'improve services'."
                ),
                locations=locs,
            ))

    n_provisions = len({v.dpdp_section for v in violations})
    print(
        f"[dpdp] {len(violations)} DPDP violations across "
        f"{n_provisions} provision(s)"
    )
    return violations
