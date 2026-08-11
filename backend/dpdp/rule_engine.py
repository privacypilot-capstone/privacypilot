from models.dataflow import DataFlowObject, PIICategory, Sensitivity

# ── DPDP Rules ─────────────────────────────────────────────────────────────────
# We implement 3 provisions as per project scope:
# Section 6  — Consent Requirements
# Section 8(3) — Purpose Limitation  
# Section 8(4) — Data Minimisation

SENSITIVE_CATEGORIES = {
    PIICategory.AADHAAR,
    PIICategory.HEALTH,
    PIICategory.BIOMETRIC,
    PIICategory.FINANCIAL,
    PIICategory.PAN,
}

ANALYTICS_SDKS = {
    'firebase', 'mixpanel', 'amplitude',
    'segment', 'analytics', 'crashlytics', 'clevertap'
}

COMMUNICATION_SDKS = {
    'twilio', 'sendgrid'
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


def run_dpdp_rules(
    code_findings: list,
    policy_claims: list,
    gap_categories: set
) -> list:
    """
    Takes code findings, policy claims, and detected gaps.
    Returns a list of DPDPViolation objects.
    """
    violations = []
    seen = set()  # avoid duplicate violations

    policy_pii_types = {f.pii_category for f in policy_claims}

    for finding in code_findings:
        cat = finding.pii_category
        sdk = finding.third_party_sdk
        loc = f"{finding.file_path} line {finding.line_number}"

        # ── Section 6: Consent Requirements ─────────────────────────────────
        # Sensitive PII collected but not mentioned in privacy policy = no consent basis

        if cat in SENSITIVE_CATEGORIES and cat in gap_categories:
            key = f"s6_{cat.value}"
            if key not in seen:
                seen.add(key)
                violations.append(DPDPViolation(
                    section="Section 6",
                    title="Consent Requirements",
                    severity="critical",
                    pii_category=cat.value,
                    evidence=(
                        f"'{cat.value}' data is collected in the codebase "
                        f"(found at {loc}) but is NOT mentioned in the privacy "
                        f"policy. Under Section 6 of the DPDP Act, consent must "
                        f"be obtained before collecting personal data, and the "
                        f"privacy notice must disclose what data is collected."
                    ),
                    recommendation=(
                        f"1. Add explicit disclosure of '{cat.value}' data collection "
                        f"to your privacy policy. "
                        f"2. Implement a consent mechanism before collecting this data. "
                        f"3. Obtain free, specific, and informed consent from users."
                    )
                ))

        # Non-sensitive PII also in gap = Section 6 violation but lower severity
        elif cat not in SENSITIVE_CATEGORIES and cat in gap_categories:
            key = f"s6_low_{cat.value}"
            if key not in seen:
                seen.add(key)
                violations.append(DPDPViolation(
                    section="Section 6",
                    title="Consent Requirements",
                    severity="high",
                    pii_category=cat.value,
                    evidence=(
                        f"'{cat.value}' data is processed in code "
                        f"(found at {loc}) but not disclosed in the privacy policy."
                    ),
                    recommendation=(
                        f"Add '{cat.value}' data collection to your privacy policy "
                        f"and obtain user consent before collecting it."
                    )
                ))

        # ── Section 8(3): Purpose Limitation ────────────────────────────────
        # PII sent to analytics SDKs = being used beyond stated purpose

        if sdk and sdk in ANALYTICS_SDKS:
            key = f"s83_{cat.value}_{sdk}"
            if key not in seen:
                seen.add(key)
                violations.append(DPDPViolation(
                    section="Section 8(3)",
                    title="Purpose Limitation",
                    severity="high",
                    pii_category=cat.value,
                    evidence=(
                        f"'{cat.value}' data is being sent to '{sdk}' "
                        f"(found at {loc}). Analytics and tracking SDKs use data "
                        f"for purposes beyond core service delivery, which likely "
                        f"violates the purpose for which consent was obtained."
                    ),
                    recommendation=(
                        f"1. Do not send '{cat.value}' data to '{sdk}' unless "
                        f"users have specifically consented to analytics use. "
                        f"2. Implement data minimisation before sending to analytics — "
                        f"use anonymised or aggregated data instead. "
                        f"3. Disclose this data sharing in your privacy policy."
                    )
                ))

        # Sensitive PII sent to ANY third party = critical purpose limitation issue
        if sdk and cat in SENSITIVE_CATEGORIES:
            key = f"s83_sensitive_{cat.value}_{sdk}"
            if key not in seen:
                seen.add(key)
                violations.append(DPDPViolation(
                    section="Section 8(3)",
                    title="Purpose Limitation — Sensitive Data",
                    severity="critical",
                    pii_category=cat.value,
                    evidence=(
                        f"SENSITIVE data '{cat.value}' is sent to third-party "
                        f"'{sdk}' at {loc}. Sensitive personal data has stricter "
                        f"processing requirements under the DPDP Act."
                    ),
                    recommendation=(
                        f"Remove '{cat.value}' data from all calls to '{sdk}'. "
                        f"Sensitive personal data must not be shared with third "
                        f"parties without explicit, separate consent for that "
                        f"specific purpose."
                    )
                ))

        # ── Section 8(4): Data Minimisation ─────────────────────────────────
        # Sensitive PII not in policy but in code = collecting more than necessary

        if cat in SENSITIVE_CATEGORIES and cat not in policy_pii_types:
            key = f"s84_{cat.value}"
            if key not in seen:
                seen.add(key)
                violations.append(DPDPViolation(
                    section="Section 8(4)",
                    title="Data Minimisation",
                    severity="high",
                    pii_category=cat.value,
                    evidence=(
                        f"'{cat.value}' is collected in code "
                        f"(found at {loc}) but is NOT mentioned in the privacy "
                        f"policy as a necessary data type. This suggests the "
                        f"organisation may be collecting more data than is "
                        f"necessary for the stated purpose."
                    ),
                    recommendation=(
                        f"Review whether '{cat.value}' data is genuinely necessary "
                        f"for your service. If it is, disclose it in your privacy "
                        f"policy. If it is not essential, stop collecting it."
                    )
                ))

    print(f"[dpdp] {len(violations)} DPDP violations found across 3 provisions")
    return violations