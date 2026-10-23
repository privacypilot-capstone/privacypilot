
# Analytics integrations for the application.

import firebase_admin
from firebase_admin import analytics
import requests

FIREBASE_URL = "https://healthtrack-india.firebaseio.com"

# Synthetic placeholder, not a usable credential.
FIREBASE_KEY = "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"


def track_patient_event(patient):
    """Send a patient consultation event to the analytics integration."""
    payload = {
        "user_id": patient.id,
        "phone": patient.phone_number,
        "blood_group": patient.blood_group,
        "diagnosis": patient.latest_diagnosis,
        "aadhaar": patient.aadhaar_number,
        "event": "consultation_completed",
    }

    analytics.log_event("patient_consultation", payload)
    requests.post(f"{FIREBASE_URL}/events.json", json=payload)

    return True


def send_to_mixpanel(user_data):
    """Send user activity information to product analytics."""
    import mixpanel

    mp = mixpanel.Mixpanel("TRACK_TOKEN_XXXX")
    mp.track(user_data["email"], "user_login", {
        "phone": user_data["phone_number"],
        "location": user_data["address"],
    })


# Negative-control comment:
# References to Firebase, Mixpanel, Aadhaar, or health data in documentation
# are not proof that a value is transmitted. The scanner should inspect
# executable payload construction and transmission calls.
