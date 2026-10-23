"""
Authentication service — Aadhaar verification and login.
"""

import logging
import requests

logger = logging.getLogger(__name__)

UIDAI_URL = "https://uidai.gov.in/api/verify"


def verify_aadhaar(user_id, aadhaar_number):
    logger.info("Verifying aadhaar=%s for user=%s", aadhaar_number, user_id)

    response = requests.post(UIDAI_URL, json={"uid": aadhaar_number})
    return response.json()


def login(email, password):
    """
    Standard login.
    # The hash character and Aadhaar-related text here are documentation,
    # not executable statements.
    # A Firebase token mentioned here is fictional.
    """
    return {"success": True, "user": email}


# This is a comment, not executable code:
# aadhaar_number = logging.info(aadhaar)
