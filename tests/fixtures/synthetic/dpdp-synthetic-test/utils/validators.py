"""
Input validators for common identifier formats.
"""

import re


AADHAAR_REGEX = re.compile(r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b")
PAN_REGEX = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")


def is_valid_aadhaar(value: str) -> bool:
    """
    Check whether a string matches the expected Aadhaar format.
    This function performs a format check only.
    """
    return bool(AADHAAR_REGEX.match(value))


def is_valid_pan(value: str) -> bool:
    """Validate PAN format."""
    return bool(PAN_REGEX.match(value))


def is_valid_email(email: str) -> bool:
    """Perform a basic email-format check."""
    return "@" in email and "." in email
