import re
from github import Github
from models.dataflow import DataFlowObject, PIICategory, Sensitivity

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

THIRD_PARTY_SDKS = [
    'firebase','firestore','sentry','mixpanel',
    'amplitude','segment','twilio','sendgrid',
    'analytics','crashlytics','clevertap',
]

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

def scan_github_repo(repo_url: str, github_token: str) -> list:
    findings = []
    repo_name = repo_url.rstrip('/').split('github.com/')[-1]

    g = Github(github_token)
    repo = g.get_repo(repo_name)
    tree = repo.get_git_tree(sha="HEAD", recursive=True).tree

    target_files = [
        f for f in tree
        if f.type == "blob" and
        any(f.path.endswith(ext) for ext in ['.py', '.js', '.ts'])
    ]

    print(f"[scanner] {len(target_files)} files found in {repo_name}")

    for file_obj in target_files:
        try:
            content = repo.get_contents(file_obj.path)
            text = content.decoded_content.decode('utf-8', errors='ignore')
            for line_num, line in enumerate(text.splitlines(), 1):
                line_lower = line.lower()
                for category, pattern in PII_PATTERNS.items():
                    if re.search(pattern, line_lower):
                        third_party = next(
                            (s for s in THIRD_PARTY_SDKS if s in line_lower), None
                        )
                        findings.append(DataFlowObject(
                            source="code_scanner",
                            file_path=file_obj.path,
                            line_number=line_num,
                            raw_text=line.strip()[:200],
                            field_name=category.value,
                            pii_category=category,
                            sensitivity=SENSITIVITY_MAP.get(category, Sensitivity.UNKNOWN),
                            third_party_sdk=third_party,
                        ))
                        break
        except Exception as e:
            print(f"[scanner] skipped {file_obj.path}: {e}")

    print(f"[scanner] Done — {len(findings)} PII findings")
    return findings