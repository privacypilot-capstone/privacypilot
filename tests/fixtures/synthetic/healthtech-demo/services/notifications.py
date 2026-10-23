
# Appointment notifications through an external SMS provider.

from twilio.rest import Client

# Synthetic placeholders, not usable credentials.
TWILIO_SID = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
TWILIO_TOKEN = "your_auth_token_here"
TWILIO_FROM = "+1234567890"


def send_appointment_sms(patient):
    """Send an appointment confirmation by SMS."""
    client = Client(TWILIO_SID, TWILIO_TOKEN)

    message = client.messages.create(
        body=f"Dear {patient.full_name}, your appointment is confirmed.",
        from_=TWILIO_FROM,
        to=patient.phone_number,
    )

    return message.sid


def send_health_reminder(patient):
    """Send a health reminder by SMS."""
    client = Client(TWILIO_SID, TWILIO_TOKEN)

    client.messages.create(
        body=f"Reminder: {patient.latest_diagnosis} checkup due.",
        from_=TWILIO_FROM,
        to=patient.phone_number,
    )
