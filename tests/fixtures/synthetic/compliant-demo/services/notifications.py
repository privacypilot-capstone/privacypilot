"""Notification service for ShopIndia."""

from twilio.rest import Client

TWILIO_SID = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
TWILIO_TOKEN = "your_auth_token"
TWILIO_FROM = "+1234567890"


def send_order_confirmation(user):
    """Send an order confirmation SMS to the registered phone number."""
    client = Client(TWILIO_SID, TWILIO_TOKEN)
    client.messages.create(
        body="Your order is confirmed.",
        from_=TWILIO_FROM,
        to=user.phone_number,
    )
