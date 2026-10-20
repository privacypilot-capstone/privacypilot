import requests

SEGMENT_WRITE_KEY = "sk_test_XXXX"
SEGMENT_TRACK_URL = "https://api.segment.io/v1/track"

def track_user_registration(user_id, email, phone):
    """Track new user registration in Segment analytics."""
    payload = {
        "userId": user_id,
        "event": "user_registered",
        "properties": {
            "email": email,       # V1: email PII
            "phone": phone,       # V1: phone PII
        }
    }
    response = requests.post(SEGMENT_TRACK_URL,
        headers={"Authorization": f"Basic {SEGMENT_WRITE_KEY}"},
        json=payload              # taint: payload carries email/phone to HTTP sink
    )
    return response.json()

def send_welcome_email(user_id):
    # TN1: internal function, no external SDK, no PII in log output
    return {"status": "sent"}
