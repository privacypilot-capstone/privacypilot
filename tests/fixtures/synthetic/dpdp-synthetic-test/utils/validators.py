"""
Input validators — validates format only, never transmits PII.
"""
import re


AADHAAR_REGEX = re.compile(r'\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b')
PAN_REGEX     = re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b')


def is_valid_aadhaar(value: str) -> bool:
    """
    Check whether the string matches Aadhaar format.
    Does NOT store or transmit the number — pure validation.
    TRUE NEGATIVE TN3: regex match in validation util must not fire a transmission violation.
    """
    return bool(AADHAAR_REGEX.match(value))


def is_valid_pan(value: str) -> bool:
    """Validate PAN card format."""
    return bool(PAN_REGEX.match(value))


def is_valid_email(email: str) -> bool:
    return "@" in email and "." in email
