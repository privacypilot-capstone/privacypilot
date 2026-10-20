# Notification service for ShopIndia
# Phone used for OTP — disclosed in privacy policy

from twilio.rest import Client

TWILIO_SID   = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
TWILIO_TOKEN = "your_auth_token"
TWILIO_FROM  = "+1234567890"

def send_order_confirmation(user):
    """
    Sends order confirmation SMS.
    Phone number use for SMS is disclosed in privacy policy
    under section 2 — Communication.
    """
    client = Client(TWILIO_SID, TWILIO_TOKEN)
    client.messages.create(
        body  = f"Dear {user.full_name}, your order is confirmed.",
        from_ = TWILIO_FROM,
        to    = user.phone_number
    )
