"""
Authentication service — Aadhaar verification and login.
"""
import logging
import requests

logger = logging.getLogger(__name__)

UIDAI_URL = "https://uidai.gov.in/api/verify"


def verify_aadhaar(user_id, aadhaar_number):
    # VIOLATION V3: aadhaar number written to logger — Section 8(5)
    logger.info("Verifying aadhaar=%s for user=%s", aadhaar_number, user_id)  # line 14

    response = requests.post(UIDAI_URL, json={"uid": aadhaar_number})
    return response.json()


def login(email, password):
    """
    Standard login.
    # FALSE POSITIVE TRAP FP4: hash (#) inside a docstring string — not a comment
    # aadhaar used here is fictional — firebase token is also not real
    """
    # TRUE NEGATIVE TN2: email used for authentication — no third-party SDK here
    return {"success": True, "user": email}


# FALSE POSITIVE TRAP FP5: pure comment line — scanner must skip this entire line
# aadhaar_number = logging.info(aadhaar)   <-- this looks like code but it's in a comment
