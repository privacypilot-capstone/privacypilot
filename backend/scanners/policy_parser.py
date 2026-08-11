import re
import requests
from models.dataflow import DataFlowObject, PIICategory, Sensitivity

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

def fetch_policy_text(url: str) -> str:
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
    }
    resp = requests.get(url, headers=headers, timeout=15)
    text = resp.text
    # Remove script and style blocks
    text = re.sub(r'<script[^>]*>.*?</script>', ' ', text, flags=re.DOTALL)
    text = re.sub(r'<style[^>]*>.*?</style>', ' ', text, flags=re.DOTALL)
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)
    # Clean whitespace
    text = re.sub(r'\s+', ' ', text)
    return text.lower()

def parse_privacy_policy(policy_url: str) -> list:
    findings = []
    seen = set()

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
                # If sentence has collection context OR keyword appears multiple times
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