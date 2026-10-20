# Analytics service — sends data to Firebase
# PLANTED VIOLATIONS: V4 (health data sent to Firebase without disclosure)

import firebase_admin
from firebase_admin import analytics
import requests

FIREBASE_URL = "https://healthtrack-india.firebaseio.com"
FIREBASE_KEY = "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

def track_patient_event(patient):
    """
    PLANTED V4 — Sends health data including blood_group and diagnosis
    to Firebase analytics. This is NOT mentioned in the privacy policy.
    """
    payload = {
        "user_id":    patient.id,
        "phone":      patient.phone_number,
        "blood_group": patient.blood_group,       # sensitive health data
        "diagnosis":   patient.latest_diagnosis,  # sensitive health data
        "aadhaar":     patient.aadhaar_number,    # sent to Firebase!
        "event":      "consultation_completed"
    }
    # Send to Firebase
    analytics.log_event("patient_consultation", payload)
    requests.post(f"{FIREBASE_URL}/events.json", json=payload)
    return True


def send_to_mixpanel(user_data):
    """Also sends user data to Mixpanel for product analytics"""
    import mixpanel
    mp = mixpanel.Mixpanel("TRACK_TOKEN_XXXX")
    mp.track(user_data['email'], 'user_login', {
        'phone':    user_data['phone_number'],
        'location': user_data['address'],
    })
