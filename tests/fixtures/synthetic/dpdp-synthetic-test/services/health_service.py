"""
Health records service — consultation event logging.
"""
import requests

FIREBASE_URL = "https://healthapp-rtdb.firebaseio.com"


def log_consultation(patient):
    """Send consultation event to Firebase."""
    payload = {
        "event":     "consultation_completed",
        "diagnosis": patient.latest_diagnosis,  # health PII  ← VIOLATION V2 (line 13)
    }
    requests.post(f"{FIREBASE_URL}/events.json", json=payload)   # line 15


# FALSE POSITIVE TRAP FP2: docstring mentions health + firebase — must be ignored
def export_audit_log():
    """
    Exports health records to Firebase for regulatory audit.
    Mixpanel is also used for tracking in some environments.
    This docstring is documentation, not executable code.
    """
    return {"status": "ok"}


# FALSE POSITIVE TRAP FP3: block comment (will also test JS files)
# firebase integration for health records is planned for Q2
# aadhaar linkage with health records under ABDM will be added later
def get_patient_summary(patient_id):
    return {"id": patient_id}
