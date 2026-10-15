"""
DPDP Act 2023 Rule Engine
=========================
Implements three detection rules mapped to the Act's sections:

  Rule 1 — Notice Gap         : Section 5 (Notice) + Section 6(1) (Consent)
  Rule 2 — Third-Party Xmit   : Section 5 (disclosure) + Section 8(2) (processor
                                 contracts) for SDK sinks; Section 8(5) (security
                                 safeguards) for logger sinks
  Rule 3 — Purpose–PII Linkage: Section 6(1) (necessity / proportionality)

Section mapping verified against DPDP Act 2023 text:
  Sec 5   — Notice: what is collected, purpose, right to withdraw consent
  Sec 6(1)— Consent: freely given, specific, informed, unambiguous
  Sec 8(2)— Data processor contracts must bind processor to same obligations
  Sec 8(5)— Technical & organisational measures to prevent unauthorised disclosure
"""

from models.dataflow import DataFlowObject, PIICategory, Sensitivity

# ── PII sensitivity tiers ───────────────────────────────────────────────────
SENSITIVE_CATEGORIES = {
    PIICategory.AADHAAR,
    PIICategory.HEALTH,
    PIICategory.BIOMETRIC,
    PIICategory.FINANCIAL,
    PIICategory.PAN,
}

# ── Sink categories for Rule 2 ──────────────────────────────────────────────
# Analytics / tracking SDKs — secondary-use risk (Section 5 + 8(2))
ANALYTICS_SDKS = {
    'firebase', 'mixpanel', 'amplitude',
    'segment', 'analytics', 'crashlytics', 'clevertap',
}

# Communication SDKs — third-party processor (Section 5 + 8(2))
COMMUNICATION_SDKS = {
    'twilio', 'sendgrid',
}

# Logger sinks — security safeguard risk (Section 8(5))
# Match substrings found in third_party_sdk or raw_text via code_scanner taint
LOGGER_SINKS = {
    'logging', 'logger', 'log.info', 'log.debug', 'log.warning',
    'log.error', 'console.log', 'console.error', 'print', 'sentry',
    'cloudwatch', 'datadog',
}

# Outbound HTTP sinks — data transmission (Section 5 + 8(2))
HTTP_SINKS = {
    'requests.post', 'requests.put', 'axios.post', 'axios.put',
    'fetch', 'httpx.post', 'urllib',
}

# Queue / message broker sinks (Section 5 + 8(2))
QUEUE_SINKS = {
    'kafka', 'rabbitmq', 'celery', 'redis.publish', 'pubsub',
}

ALL_SDK_SINKS = ANALYTICS_SDKS | COMMUNICATION_SDKS


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


def _is_logger_sink(sdk: str | None, raw_text: str) -> bool:
    """Return True if the finding's sink is a logger (Section 8(5) territory)."""
    if sdk and any(ls in sdk.lower() for ls in LOGGER_SINKS):
        return True
    raw_lower = raw_text.lower()
    return any(ls in raw_lower for ls in LOGGER_SINKS)


def run_dpdp_rules(
    code_findings: list,
    policy_claims: list,
    gap_categories: set,
    usage_map: dict | None = None,
    purpose_map: dict | None = None,
    vagueness_warnings: list | None = None,
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

    Returns
    -------
    list[DPDPViolation]
    """
    violations = []
    seen = set()

    policy_pii_types = {f.pii_category for f in policy_claims}

    # Build a location index: {PIICategory → [(file_path, line_number), ...]}
    # Used by Rule 3 to cite concrete evidence locations in violation messages.
    _loc_index: dict = {}
    for _f in code_findings:
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
                        f"privacy policy, describing what is collected, why, and "
                        f"how long it is retained. "
                        f"2. Present this notice before or at the point of collection. "
                        f"3. Implement a consent gate that is gated on disclosure."
                    ),
                ))

    # ── Rule 2: Third-Party Transmission ────────────────────────────────────
    # PII is co-located with a third-party SDK call.
    # • Analytics / communication SDKs → Section 5 (undisclosed sharing) +
    #   Section 8(2) (no evidence of a data-processor contract).
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
                violations.append(DPDPViolation(
                    section="Section 8(5)",
                    title="Security Safeguard — PII in Logger Output",
                    severity="high",
                    pii_category=cat.value,
                    evidence=(
                        f"'{cat.value}' data appears in a log/print statement "
                        f"at {loc}. Logging personal data exposes it in log files, "
                        f"monitoring dashboards, and log-aggregation services. "
                        f"Section 8(5) requires appropriate technical measures to "
                        f"prevent unauthorised disclosure of personal data."
                    ),
                    recommendation=(
                        f"Remove or mask '{cat.value}' from all log statements. "
                        f"Use structured logging with a PII-scrubbing filter. "
                        f"Treat log sinks as untrusted channels for personal data."
                    ),
                ))
            continue  # logged → don't also fire SDK rules for same finding

        # SDK / HTTP / Queue sink path — Section 5 + Section 8(2)
        if sdk_lower in ALL_SDK_SINKS or sdk_lower in HTTP_SINKS or sdk_lower in QUEUE_SINKS:
            is_sensitive = cat in SENSITIVE_CATEGORIES

            # All SDK transmissions: undisclosed third-party sharing (Section 5)
            key = f"r2_sdk_{cat.value}_{sdk}"
            if key not in seen:
                seen.add(key)
                severity = "critical" if is_sensitive else "high"
                violations.append(DPDPViolation(
                    section="Section 5 / Section 8(2)",
                    title="Third-Party Transmission — Undisclosed Data Processor",
                    severity=severity,
                    pii_category=cat.value,
                    evidence=(
                        f"'{cat.value}' data is transmitted to '{sdk}' at {loc}. "
                        f"Section 5 requires the notice to identify third parties "
                        f"that will receive personal data. Section 8(2) requires a "
                        f"contract with every data processor that binds them to the "
                        f"same DPDP obligations as the data fiduciary."
                    ),
                    recommendation=(
                        f"1. Disclose '{sdk}' as a data processor in the privacy policy. "
                        f"2. Execute a Data Processing Agreement with '{sdk}' covering "
                        f"purpose, retention, and security obligations. "
                        f"3. For sensitive category '{cat.value}', obtain separate "
                        f"explicit consent for this third-party share."
                        if is_sensitive else
                        f"1. Disclose '{sdk}' as a data processor in the privacy policy. "
                        f"2. Execute a Data Processing Agreement with '{sdk}'."
                    ),
                ))

    # ── Rule 3: Purpose–PII Linkage — Section 6(1) ──────────────────────────
    # Cross-reference usage_map (how code uses each PII category, e.g. 'analytics')
    # with purpose_map (what the policy claims PII is used for, e.g. 'service_delivery').
    # A mismatch means data is processed for a purpose not disclosed → Section 6(1)
    # consent cannot be "specific" or "informed".
    #
    # This rule fires only when both maps are populated (after Steps 4 & 5).

    if usage_map and purpose_map:
        for cat, code_uses in usage_map.items():
            policy_purposes = purpose_map.get(cat, set())
            # Overlap check: any code use not covered by a policy purpose
            uncovered = code_uses - policy_purposes
            if uncovered:
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
                    violations.append(DPDPViolation(
                        section="Section 6(1)",
                        title="Purpose–PII Linkage — Processing Exceeds Stated Purpose",
                        severity="high",
                        pii_category=cat.value,
                        evidence=(
                            f"'{cat.value}' data is used for {sorted(uncovered)} "
                            f"in the codebase{_loc_clause}, but the privacy policy "
                            f"only states purposes: "
                            f"{sorted(policy_purposes) or ['none found']}. "
                            f"Section 6(1) requires consent to be specific to the "
                            f"stated purpose; processing for unstated purposes is "
                            f"non-consensual."
                        ),
                        recommendation=(
                            f"Either add the purpose(s) {sorted(uncovered)} to the "
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
                violations.append(DPDPViolation(
                    section="DPDP Rules 2025, Rule 3(b)(ii)",
                    title="Vague Purpose Statement",
                    severity="medium",
                    pii_category=w.get("pii_category", "unknown"),
                    evidence=(
                        f"The privacy policy's purpose statement for "
                        f"'{w.get('pii_category')}' is ambiguous: the classifier "
                        f"margin between top-2 categories is "
                        f"{w.get('margin', 0):.3f} (threshold 0.08). "
                        f"Rule 3(b)(ii) of DPDP Rules 2025 requires the notice "
                        f"to specify the purpose of processing in clear and plain language."
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
