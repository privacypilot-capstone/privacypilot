"""
Health records service — consultation event logging.
"""

import requests

FIREBASE_URL = "https://healthapp-rtdb.firebaseio.com"


def log_consultation(patient):
    """Send a consultation event to Firebase."""
    payload = {
        "event": "consultation_completed",
        "diagnosis": patient.latest_diagnosis,
    }
    requests.post(f"{FIREBASE_URL}/events.json", json=payload)


def export_audit_log():
    """
    Exports health records to Firebase for regulatory audit.
    Mixpanel is also used for tracking in some environments.
    This text describes possible integrations; it does not execute them.
    """
    return {"status": "ok"}


# Firebase integration for health records is planned for a future release.
# Aadhaar linkage with health records may be added later.
def get_patient_summary(patient_id):
    return {"id": patient_id}
