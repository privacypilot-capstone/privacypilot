"""
DPDP Act 2023 Rule Engine
=========================
Implements three detection rules mapped to the Act's sections:

  Rule 1 — Notice Gap         : Section 5 (Notice) + Section 6(1) (Consent)
  Rule 2 — Third-Party Xmit   : Section 8(2) (processor only under a valid
                                 contract) for SDK / HTTP / queue sinks;
                                 Section 8(5) (security safeguards) for logger sinks
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
    def __init__(self, section, title, severity, pii_category, evidence, recommendation):
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
    Pass first-party findings first so the location each violation cites is
    in the application's own code whenever one exists.

    Returns
    -------
    list[DPDPViolation]
    """
    violations = []
    seen = set()

    # Build a location index: {PIICategory → [(file_path, line_number), ...]}
    # Used by Rule 3 to cite concrete evidence locations in violation messages.
    # Only the application's own code is cited: Rule 3 is about how the
    # application uses the data, not about a bundled library's internals.
    _loc_index: dict = {}
    for _f in code_findings:
        if getattr(_f, "origin", None) not in (None, "first_party"):
            continue
        _loc_index.setdefault(_f.pii_category, []).append(
            (_f.file_path, _f.line_number)
        )

    # ── Rule 1: Notice Gap — Section 5 + Section 6(1) ──────────────────────
    # PII is found in source code but NOT disclosed in the privacy policy.
    # Section 5 requires the data fiduciary to give notice of what data is
    # collected and for what purpose before or at the time of collection.
    # Section 6(1) makes consent invalid without proper prior notice.

    for finding in code_findings:
        cat = finding.pii_category
        loc = f"{finding.file_path} line {finding.line_number}"

        if cat in gap_categories:
            is_sensitive = cat in SENSITIVE_CATEGORIES
            key = f"r1_{cat.value}"
            if key not in seen:
                seen.add(key)
                severity = "critical" if is_sensitive else "high"
                violations.append(DPDPViolation(
                    section="Section 5 / Section 6(1)",
                    title="Notice Gap — Undisclosed Data Collection",
                    severity=severity,
                    pii_category=cat.value,
                    evidence=(
                        f"'{cat.value}' data is collected in source code "
                        f"(e.g. {loc}) but is absent from the privacy policy. "
                        f"Section 5 of the DPDP Act 2023 requires the data "
                        f"fiduciary to give notice of all categories of personal "
                        f"data collected. Without this disclosure, consent under "
                        f"Section 6(1) cannot be free, specific, or informed."
                    ),
                    recommendation=(
                        f"1. Add an explicit entry for '{cat.value}' data to the "
                        f"privacy policy, describing what is collected and the "
                        f"purpose for which it is processed (Section 5(1)(i)). "
                        f"2. Present this notice before or at the point of collection. "
                        f"3. Implement a consent gate that is gated on disclosure."
                    ),
                ))

    # ── Rule 2: Third-Party Transmission ────────────────────────────────────
    # PII is co-located with a third-party SDK call.
    # • SDK / HTTP / queue sinks → Section 8(2): a Data Processor may only be
    #   engaged under a valid contract, which cannot be verified from code.
    #   (Previously also cited as Section 5, on the claim that the notice must
    #   name third parties — Section 5(1) contains no such requirement.)
    # • Logger sinks → Section 8(5) (security safeguard failure — logging PII
    #   risks unauthorised disclosure via log files / monitoring systems).

    for finding in code_findings:
        cat = finding.pii_category
        sdk = finding.third_party_sdk
        loc = f"{finding.file_path} line {finding.line_number}"
        raw = finding.raw_text or ""

        if not sdk:
            continue

        sdk_lower = sdk.lower()

        # Logger-sink path — Section 8(5)
        if _is_logger_sink(sdk, raw):
            key = f"r2_log_{cat.value}_{sdk}"
            if key not in seen:
                seen.add(key)
                is_sensitive = cat in SENSITIVE_CATEGORIES
                violations.append(DPDPViolation(
                    section="Section 8(5)",
                    title="Security Safeguard — PII in Logger Output",
                    severity="critical" if is_sensitive else "high",
                    pii_category=cat.value,
                    evidence=(
                        f"'{cat.value}' data appears in a log/print statement "
                        f"at {loc}.{_origin_note(finding)} Logging personal data exposes it in log files, "
                        f"monitoring dashboards, and log-aggregation services. "
                        f"Section 8(5) requires the Data Fiduciary to take "
                        f"reasonable security safeguards to prevent personal "
                        f"data breach."
                    ),
                    recommendation=(
                        f"Remove or mask '{cat.value}' from all log statements "
                        f"(masking and obfuscation are safeguards listed in DPDP "
                        f"Rules 2025, Rule 6(1)(a)). Use structured logging with a "
                        f"PII-scrubbing filter. Treat log sinks as untrusted "
                        f"channels for personal data."
                    ),
                ))
            continue  # logged → don't also fire SDK rules for same finding

        # SDK / HTTP / Queue sink path — Section 8(2)
        if sink_kind(sdk_lower) in ('sdk', 'http', 'queue'):
            is_sensitive = cat in SENSITIVE_CATEGORIES

            # Has the privacy policy already named this SDK as a recipient
            # of this PII category (policy_parser Pass 3)? Only the named-
            # company sink lists (ALL_SDK_SINKS) are checkable this way —
            # HTTP_SINKS/QUEUE_SINKS are generic code patterns ('requests.post',
            # 'kafka'), not names a policy would plausibly disclose by string
            # match, so they always fall through to the undisclosed branch.
            _disclosed_set = (disclosed_sdks or {}).get(cat, set())
            is_disclosed = (
                sink_kind(sdk_lower) == 'sdk'
                and sdk_lower in {s.lower() for s in _disclosed_set}
            )

            key = f"r2_sdk_{cat.value}_{sdk}"
            if key not in seen:
                seen.add(key)
                if is_disclosed:
                    # The policy already names '{sdk}' as a recipient of this
                    # data, so it is not flagged as undisclosed. What remains
                    # unverifiable from the policy text or source code alone
                    # is Section 8(2): whether a valid processor contract
                    # exists. Flag that narrower gap at medium severity.
                    violations.append(DPDPViolation(
                        section="Section 8(2)",
                        title="Third-Party Transmission — Processor Contract Unverified",
                        severity="medium",
                        pii_category=cat.value,
                        evidence=(
                            f"'{cat.value}' data is transmitted to '{sdk}' at {loc}."
                            f"{_origin_note(finding)} "
                            f"The privacy policy already names '{sdk}' as a "
                            f"recipient of this data. Section 8(2) permits a Data "
                            f"Processor to be engaged only under a valid contract, "
                            f"and under Section 8(1) the Data Fiduciary remains "
                            f"responsible for its processing — whether such a "
                            f"contract exists cannot be verified from the policy "
                            f"text or source code alone."
                        ),
                        recommendation=(
                            f"Confirm a valid, signed contract (Data Processing "
                            f"Agreement) with '{sdk}' is in place, including the "
                            f"security safeguards it must apply (DPDP Rules 2025, "
                            f"Rule 6(1)(f))."
                        ),
                    ))
                else:
                    # Recipient not named in the policy for THIS data. If the
                    # policy names the SDK for other categories, say so —
                    # otherwise readers (and the LLM summary) take it to mean
                    # the SDK is missing from the policy altogether.
                    severity = "critical" if is_sensitive else "high"
                    _named_for = sorted(
                        c.value for c, sdks in (disclosed_sdks or {}).items()
                        if sdk_lower in {s.lower() for s in sdks}
                    )
                    _policy_clause = (
                        f"The privacy policy names '{sdk}' as a recipient of "
                        f"{', '.join(_named_for)} data, but not of '{cat.value}' data."
                        if _named_for else
                        f"The privacy policy does not name '{sdk}' as a recipient "
                        f"of this data."
                    )
                    violations.append(DPDPViolation(
                        section="Section 8(2)",
                        title="Third-Party Transmission — Undisclosed Data Processor",
                        severity=severity,
                        pii_category=cat.value,
                        evidence=(
                            f"'{cat.value}' data is transmitted to '{sdk}' at {loc}."
                            f"{_origin_note(finding)} "
                            f"{_policy_clause} Section 8(2) permits a Data "
                            f"Processor to be engaged only under a valid contract, "
                            f"and under Section 8(1) the Data Fiduciary remains "
                            f"responsible for its processing."
                        ),
                        recommendation=(
                            f"1. Execute a valid contract (Data Processing Agreement) "
                            f"with '{sdk}', including the security safeguards it must "
                            f"apply (DPDP Rules 2025, Rule 6(1)(f)). "
                            f"2. Name '{sdk}' as a processor in the privacy policy for "
                            f"transparency. "
                            f"3. '{cat.value}' is treated as high-risk by PrivacyPilot "
                            f"(a project severity tier, not a category defined in the "
                            f"Act): minimise or tokenise it before sharing."
                            if is_sensitive else
                            f"1. Execute a valid contract (Data Processing Agreement) "
                            f"with '{sdk}'. "
                            f"2. Name '{sdk}' as a processor in the privacy policy for "
                            f"transparency."
                        ),
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
    # Categories already reported by Rule 1 (absent from the policy entirely)
    # are skipped here: the notice gap already covers them, and reporting the
    # same category twice double-penalised it in the compliance score.

    if usage_map:
        purpose_map = purpose_map or {}
        for cat, code_uses in usage_map.items():
            if cat in gap_categories:
                continue   # covered by Rule 1 — avoid double counting
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
                    # Collect up to 3 concrete file+line locations for this category
                    _locs = _loc_index.get(cat, [])
                    _loc_strs = [
                        f"{fp} line {ln}" for fp, ln in _locs[:3]
                    ]
                    _loc_clause = (
                        f" (found at: {'; '.join(_loc_strs)})"
                        if _loc_strs else ""
                    )
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
                    ))

    # ── Vagueness warnings — DPDP Rules 2025, Rule 3(b)(ii) ─────────────────
    # When the purpose classifier's top-2 scores are within 0.08 of each other,
    # the stated purpose is ambiguous and fails the specificity requirement.

    if vagueness_warnings:
        for w in vagueness_warnings:
            key = f"vague_{w.get('pii_category', 'unknown')}"
            if key not in seen:
                seen.add(key)
                # Policy-based violations have no source file/line — the
                # nearest equivalent is the actual ambiguous clause text, so
                # quote it directly rather than leaving the location blank.
                _sentence = (w.get("sentence") or "").strip()
                _quote_clause = (
                    f" The flagged clause: \"{_sentence}\""
                    if _sentence else ""
                )
                violations.append(DPDPViolation(
                    section="DPDP Rules 2025, Rule 3(b)(ii)",
                    title="Vague Purpose Statement",
                    # "low", not "medium": this is a pure language-clarity
                    # gap under the subordinate DPDP Rules 2025, not a gap
                    # in the Act's own notice/consent/processor-contract
                    # obligations. It is the mildest finding the rule
                    # engine raises -- the purpose IS stated, disclosed,
                    # and linked; it's merely worded ambiguously -- so it
                    # sits below the "disclosed-SDK, contract unverifiable"
                    # medium case rather than sharing its severity.
                    severity="low",
                    pii_category=w.get("pii_category", "unknown"),
                    evidence=(
                        f"The privacy policy's purpose statement for "
                        f"'{w.get('pii_category')}' is ambiguous: the classifier "
                        f"margin between top-2 categories is "
                        f"{w.get('margin', 0):.3f} (threshold 0.08), closest to "
                        f"'{w.get('top_label', 'unknown')}'. "
                        f"Rule 3(b)(ii) of DPDP Rules 2025 requires the notice "
                        f"to specify the purpose of processing in clear and "
                        f"plain language.{_quote_clause}"
                    ),
                    recommendation=(
                        f"Rewrite the purpose clause for '{w.get('pii_category')}' "
                        f"to be unambiguous. State exactly what the data is used for "
                        f"rather than broad terms like 'improve services'."
                    ),
                ))

    n_provisions = len({v.dpdp_section for v in violations})
    print(
        f"[dpdp] {len(violations)} DPDP violations across "
        f"{n_provisions} provision(s)"
    )
    return violations
