import requests

SEGMENT_WRITE_KEY = "sk_test_XXXX"
SEGMENT_TRACK_URL = "https://api.segment.io/v1/track"


def track_user_registration(user_id, email, phone):
    """Track a user registration event."""
    payload = {
        "userId": user_id,
        "event": "user_registered",
        "properties": {
            "email": email,
            "phone": phone,
        },
    }

    response = requests.post(
        SEGMENT_TRACK_URL,
        headers={"Authorization": f"Basic {SEGMENT_WRITE_KEY}"},
        json=payload,
    )
    return response.json()


def send_welcome_email(user_id):
    """Represent an internal welcome-email operation."""
    return {"status": "sent"}
