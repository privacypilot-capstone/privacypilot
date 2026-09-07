import re
import socket
import requests
from urllib.parse import urlparse
from models.dataflow import DataFlowObject, PIICategory, Sensitivity

# ── Security: URL Validation ──────────────────────────────────────────────────

ALLOWED_SCHEMES = {"http", "https"}

BLOCKED_DOMAINS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "169.254.169.254",          # AWS EC2 metadata endpoint
    "metadata.google.internal", # GCP metadata endpoint
}

BLOCKED_IP_PREFIXES = (
    "127.",
    "10.",
    "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "169.254.",
    "::1",
)

def validate_policy_url(url: str) -> None:
    """
    Validates a user-supplied policy URL before making any HTTP request.
    Protects against SSRF attacks by blocking:
      - Non HTTP/HTTPS schemes (file://, ftp://, gopher:// etc.)
      - Private/internal IP address ranges (RFC 1918)
      - Loopback and link-local addresses
      - Known cloud metadata endpoints
      - Malformed or unresolvable URLs
    Raises ValueError with a descriptive message on any failure.
    """
    # Parse URL structure
    try:
        parsed = urlparse(url)
    except Exception:
        raise ValueError(f"Malformed URL — could not parse: {url}")

    # Validate scheme
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(
            f"URL scheme '{parsed.scheme}' is not permitted. "
            f"Only http and https are allowed."
        )

    # Validate domain present
    if not parsed.netloc:
        raise ValueError(
            "URL has no domain — invalid URL format."
        )

    # Strip port from netloc for domain check
    domain = parsed.netloc.split(":")[0].lower()

    # Check explicitly blocked domains
    if domain in BLOCKED_DOMAINS:
        raise ValueError(
            f"Domain '{domain}' is not allowed. "
            f"Localhost and internal service URLs are blocked."
        )

    # Resolve domain to IP and block private ranges (SSRF protection)
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        raise ValueError(
            f"Domain '{domain}' could not be resolved. "
            f"Please check the URL is correct and publicly accessible."
        )

    if ip.startswith(BLOCKED_IP_PREFIXES):
        raise ValueError(
            f"URL resolves to a private or internal IP address ({ip}). "
            f"Internal network URLs are blocked for security."
        )

    print(f"[security] URL validated: {url[:80]}")


# ── PII detection config ──────────────────────────────────────────────────────

# Keywords that indicate data collection context
COLLECTION_CONTEXT = [
    'collect', 'process', 'store', 'use', 'share',
    'disclose', 'transfer', 'receive', 'gather', 'obtain'
]

# PII keywords to look for in the policy
POLICY_PII_MAP = {
    'name':       PIICategory.NAME,
    'email':      PIICategory.EMAIL,
    'phone':      PIICategory.PHONE,
    'mobile':     PIICategory.PHONE,
    'location':   PIICategory.LOCATION,
    'address':    PIICategory.LOCATION,
    'health':     PIICategory.HEALTH,
    'medical':    PIICategory.HEALTH,
    'aadhaar':    PIICategory.AADHAAR,
    'pan':        PIICategory.PAN,
    'financial':  PIICategory.FINANCIAL,
    'bank':       PIICategory.FINANCIAL,
    'birth':      PIICategory.DOB,
    'dob':        PIICategory.DOB,
    'biometric':  PIICategory.BIOMETRIC,
    'password':   PIICategory.FINANCIAL,
    'contact':    PIICategory.PHONE,
    'identity':   PIICategory.NAME,
    'personal':   PIICategory.NAME,
}

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


# ── HTTP fetch ────────────────────────────────────────────────────────────────

def fetch_policy_text(url: str) -> str:
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
    }
    resp = requests.get(url, headers=headers, timeout=15)
    text = resp.text
    # Remove script and style blocks
    text = re.sub(r'<script[^>]*>.*?</script>', ' ', text, flags=re.DOTALL)
    text = re.sub(r'<style[^>]*>.*?</style>',  ' ', text, flags=re.DOTALL)
    # Remove all remaining HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)
    # Clean whitespace
    text = re.sub(r'\s+', ' ', text)
    return text.lower()


# ── Main parser ───────────────────────────────────────────────────────────────

def parse_privacy_policy(policy_url: str) -> list:
    findings = []
    seen = set()

    # Security: validate URL before making any HTTP request
    validate_policy_url(policy_url)

    print(f"[policy] Fetching: {policy_url}")
    text = fetch_policy_text(policy_url)
    print(f"[policy] Got {len(text)} characters")

    # Split into sentences for context-aware matching
    sentences = re.split(r'[.!?;]', text)

    for sentence in sentences:
        sentence = sentence.strip()
        if len(sentence) < 10:
            continue

        # Check if sentence has a collection context word
        has_context = any(word in sentence for word in COLLECTION_CONTEXT)

        for keyword, category in POLICY_PII_MAP.items():
            if keyword in sentence and category not in seen:
                # Match if sentence has collection context
                # OR keyword appears multiple times in full text
                if has_context or text.count(keyword) >= 2:
                    seen.add(category)
                    findings.append(DataFlowObject(
                        source="policy_parser",
                        file_path=None,
                        line_number=None,
                        raw_text=sentence[:300],
                        field_name=keyword,
                        pii_category=category,
                        sensitivity=SENSITIVITY_MAP.get(
                            category, Sensitivity.UNKNOWN
                        ),
                        third_party_sdk=None,
                    ))

    print(f"[policy] {len(findings)} PII types found in policy")
    return findings