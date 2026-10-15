"""
LLM Client for PrivacyPilot
============================
Provider-agnostic wrapper that exposes two public functions:

  generate_report_summary(scan_data)          → str  (executive summary)
  chat_completion(messages, scan_data)         → str  (chatbot turn)

Provider priority (first key found wins):
  1. GEMINI_API_KEY   → Google Gemini 2.0 Flash   (free tier, default)
  2. ANTHROPIC_API_KEY → Anthropic Claude Haiku    (paid, low-cost)

Both are called via plain HTTP (requests) — no extra package needed.
If neither key is set, raises LLMNotConfiguredError so callers degrade
gracefully (summary = None, chatbot returns a static notice).
"""

import os
import json
import requests

# ── Provider configuration ────────────────────────────────────────────────────

_GEMINI_KEY     = os.getenv("GEMINI_API_KEY")
_ANTHROPIC_KEY  = os.getenv("ANTHROPIC_API_KEY")

_GEMINI_URL     = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-2.0-flash:generateContent?key={key}"
)
_ANTHROPIC_URL  = "https://api.anthropic.com/v1/messages"

_TIMEOUT        = 60          # seconds per LLM call
_MAX_TOKENS     = 1024        # response length cap

# ── DPDP expert system prompt ─────────────────────────────────────────────────

_SYSTEM_PROMPT = """You are PrivacyPilot Advisor — an expert compliance assistant \
specialising in India's Digital Personal Data Protection (DPDP) Act 2023.

Your deep knowledge covers:
• Section 5   — Notice obligations: the data fiduciary must inform data principals \
of all PII categories collected, purposes, and third parties before collection.
• Section 6(1) — Consent: must be free, specific, informed, and unambiguous; \
limited to the stated purpose.
• Section 8(2) — Data Processor contracts: every third-party processor must be \
contractually bound to the same DPDP obligations as the fiduciary.
• Section 8(5) — Security safeguards: appropriate technical measures must prevent \
unauthorised disclosure of personal data (e.g. PII must not appear in logs).
• PII categories under DPDP: name, email, phone, location, aadhaar (national ID), \
health, biometric — each with distinct sensitivity and obligations.

You are answering questions about a SPECIFIC compliance scan of a GitHub repository. \
The full scan context is injected into the first system message. Stay grounded in \
that context — cite exact file paths, line numbers, and DPDP sections when relevant.

Be concise, practical, and actionable. Never fabricate evidence; if something is not \
in the scan data, say so. If asked for legal advice beyond the Act's text, recommend \
consulting a qualified lawyer."""


# ── Helpers ───────────────────────────────────────────────────────────────────

class LLMNotConfiguredError(Exception):
    """Raised when no LLM API key is configured."""


def _scan_context_text(scan_data: dict) -> str:
    """Serialise the structured scan result into a readable context block."""
    lines = [
        f"=== PrivacyPilot Scan Context ===",
        f"Repository : {scan_data.get('repo_url', 'unknown')}",
        f"Policy URL : {scan_data.get('policy_url', 'unknown')}",
        f"Scan ID    : {scan_data.get('scan_id', '?')}",
        f"Score      : {scan_data.get('compliance', {}).get('score', '?')}/100  "
        f"({scan_data.get('compliance', {}).get('rating', '?')} Compliance)",
        f"PII findings in code : {scan_data.get('code_findings_count', 0)}",
        f"Consent gaps         : {', '.join(scan_data.get('gaps_detected', [])) or 'none'}",
        "",
        "--- DPDP Violations ---",
    ]
    for v in scan_data.get("violations", []):
        lines.append(
            f"[{v.get('severity','?').upper()}] {v.get('dpdp_section')} — "
            f"{v.get('section_title')}  |  PII: {v.get('pii_category')}"
        )
        lines.append(f"  Evidence      : {v.get('evidence', '')}")
        lines.append(f"  Recommendation: {v.get('recommendation', '')}")
        lines.append("")

    if scan_data.get("sample_findings"):
        lines.append("--- Sample Code Findings (first 10) ---")
        for f in scan_data["sample_findings"][:10]:
            lines.append(
                f"  {f.get('pii_category')} | {f.get('file_path')} "
                f"line {f.get('line_number')} | detected_by={f.get('source')}"
            )
    return "\n".join(lines)


# ── Provider implementations ──────────────────────────────────────────────────

def _call_gemini(system: str, messages: list[dict]) -> str:
    """Call Gemini generateContent with a turn-based conversation."""
    # Gemini uses 'user'/'model' roles; inject system as a leading user turn
    gemini_contents = [
        {"role": "user",  "parts": [{"text": system}]},
        {"role": "model", "parts": [{"text": "Understood. I am ready to help with DPDP compliance guidance."}]},
    ]
    for m in messages:
        role = "model" if m["role"] == "assistant" else "user"
        gemini_contents.append({"role": role, "parts": [{"text": m["content"]}]})

    payload = {
        "contents": gemini_contents,
        "generationConfig": {
            "maxOutputTokens": _MAX_TOKENS,
            "temperature": 0.3,
        },
    }
    url = _GEMINI_URL.format(key=_GEMINI_KEY)
    resp = requests.post(url, json=payload, timeout=_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    return data["candidates"][0]["content"]["parts"][0]["text"].strip()


def _call_anthropic(system: str, messages: list[dict]) -> str:
    """Call Anthropic Messages API."""
    headers = {
        "x-api-key":         _ANTHROPIC_KEY,
        "anthropic-version": "2023-06-01",
        "content-type":      "application/json",
    }
    payload = {
        "model":      "claude-haiku-4-5",
        "max_tokens": _MAX_TOKENS,
        "system":     system,
        "messages":   messages,
    }
    resp = requests.post(_ANTHROPIC_URL, json=payload, headers=headers, timeout=_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    return data["content"][0]["text"].strip()


def _llm_call(system: str, messages: list[dict]) -> str:
    """Route to whichever provider has a key configured."""
    if _GEMINI_KEY:
        return _call_gemini(system, messages)
    if _ANTHROPIC_KEY:
        return _call_anthropic(system, messages)
    raise LLMNotConfiguredError(
        "No LLM API key found. Set GEMINI_API_KEY or ANTHROPIC_API_KEY."
    )


# ── Public API ────────────────────────────────────────────────────────────────

def generate_report_summary(scan_data: dict) -> str:
    """
    Generate a 3-paragraph executive summary for a compliance scan report.

    Parameters
    ----------
    scan_data : dict   — the /scan response payload (violations, compliance, etc.)

    Returns
    -------
    str  — markdown-formatted executive summary
    """
    context = _scan_context_text(scan_data)
    system  = _SYSTEM_PROMPT + "\n\n" + context

    prompt = (
        "Write a concise executive summary of this DPDP Act compliance scan. "
        "Structure your response in exactly three paragraphs:\n\n"
        "1. **Overall Compliance Posture** — summarise the score, critical issues, "
        "and the most serious risks to the organisation.\n"
        "2. **Most Urgent Violations** — call out the top 2–3 violations that need "
        "immediate remediation, with the specific DPDP section and why it is critical.\n"
        "3. **Remediation Roadmap** — a prioritised, actionable 3-step plan "
        "the engineering team can follow to reach compliance.\n\n"
        "Be specific: cite file paths and DPDP sections from the scan data. "
        "Keep the total response under 300 words."
    )
    return _llm_call(system, [{"role": "user", "content": prompt}])


def chat_completion(messages: list[dict], scan_data: dict) -> str:
    """
    Generate the next assistant turn in a compliance chatbot conversation.

    Parameters
    ----------
    messages  : list[dict]  — full conversation history {role, content}
                              (role is 'user' or 'assistant')
    scan_data : dict        — the /scan response payload for this session's scan

    Returns
    -------
    str  — assistant reply
    """
    context = _scan_context_text(scan_data)
    system  = _SYSTEM_PROMPT + "\n\n" + context
    return _llm_call(system, messages)
