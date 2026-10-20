# Notification service — sends SMS via Twilio
# PLANTED VIOLATIONS: V5 (phone sent to Twilio, not in privacy policy)

from twilio.rest import Client

TWILIO_SID   = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
TWILIO_TOKEN = "your_auth_token_here"
TWILIO_FROM  = "+1234567890"

def send_appointment_sms(patient):
    """
    PLANTED V5 — Sends patient phone_number to Twilio (US servers).
    Cross-border data transfer not mentioned in privacy policy.
    """
    client = Client(TWILIO_SID, TWILIO_TOKEN)
    message = client.messages.create(
        body=f"Dear {patient.full_name}, your appointment is confirmed.",
        from_=TWILIO_FROM,
        to=patient.phone_number  # sent to Twilio without disclosure
    )
    return message.sid


def send_health_reminder(patient):
    """Sends health reminder with diagnosis info via SMS"""
    client = Client(TWILIO_SID, TWILIO_TOKEN)
    client.messages.create(
        body=f"Reminder: {patient.latest_diagnosis} checkup due.",
        from_=TWILIO_FROM,
        to=patient.phone_number
    )
